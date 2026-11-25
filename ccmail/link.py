# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""cc:Mail packet link layer, answering side (spec/link-layer.md).

Frame (binary):  02 | L (LSEC: 1 byte; HSEC: 2 bytes LE) | ctl | p0 | hcrc(2) | [d1..d(L-1) | dcrc(2)]
CRC-16/GENIBUS over the header bytes after STX, and again from scratch over d1..d(L-1).
ctl = type(2) | N(S)(3) | N(R)(3); type 0 data, 1 ack (40h|N(R)), 2 control: NAK (80h|N(R), p0=04)
or a sequenced control frame (80h|seq<<3|N(R), p0=code, e.g. 0Fh accept / 10h refuse).
Window 4, sequence numbers mod 8, cumulative acks, N(R) = last sequence number delivered in order.

The link also has a "raw" mode (no packet protocol): the caller sends 80h directly.
"""
import logging
import select
import time

STX = 0x02
LSEC, HSEC, RAW = "LSEC", "HSEC", "RAW"
MAX_L = {LSEC: 0x79, HSEC: 0x3F8}
HDR_LEN = {LSEC: 6, HSEC: 7}
WINDOW = 4
CTL_ACCEPT = 0x0F
CTL_REFUSE = 0x10
CTL_NAK = 0x04

log = logging.getLogger("ccmail.link")

# Client timers (spec/link-layer.md 5.1), in BIOS ticks of 1193182/65536 Hz.
# 6 values per speed index (0 = 300, 1 = 1200, 2 = 2400 bps):
# 0-3 = retransmit timer of tx slots 0-3, 4 = ack delay (never started), 5 = rx frame
# assembly. Every value except index 4 becomes 70h above 2400 bps, with /LOCK, /FC or
# /ET, or in HSEC.
TICK_HZ = 1193182 / 65536
TIMER_ROWS = {0: (0x70, 0x70, 0x70, 0x70, 0x02, 0x70),
              1: (0x1C, 0x1C, 0x1C, 0x1C, 0x02, 0x1C),
              2: (0x0E, 0x0E, 0x0E, 0x0E, 0x02, 0x0E)}
SPEED_INDEX = {300: 0, 1200: 1, 2400: 2}


def timer_seconds(speed, mode, like="router"):
    """(retransmit, frame assembly) timeouts in seconds.
    like="router": the answering post office's timers, 70h ticks (6.2 s) at every
    speed (spec/router-answer.md). like="remote": the client's per-speed
    values above, for reference."""
    if like == "router":
        return 0x70 / TICK_HZ, 0x70 / TICK_HZ
    idx = SPEED_INDEX.get(speed)
    if idx is None or mode == HSEC:
        retx = assembly = 0x70
    else:
        row = TIMER_ROWS[idx]
        retx, assembly = row[0], row[5]
    return retx / TICK_HZ, assembly / TICK_HZ


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ 0xFFFF


ASCII_MAX_L = {LSEC: 0x4E, HSEC: 0x2A2}     # sender limit in ASCII mode


class AsciiEncoder:
    """Frame byte encoder in ASCII mode (spec 3.1). State runs across frames; reset only on link reset."""

    def __init__(self):
        self.state = 0
        self.hi = 0          # high bits shared by the run after a prefix

    def frame(self, data: bytes) -> bytes:
        out = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if self.state >= 2:
                if b >> 6 == self.hi:
                    out.append(0x30 + (b & 0x3F))
                    i += 1
                    continue
                self.state = 0
            if self.state == 0:                      # prefix with own and next high bits
                nxt = 0
                if i + 1 < len(data):
                    nxt = data[i + 1] >> 6
                    self.hi = nxt
                out.append(0x20 + ((b >> 6) | nxt << 2))
                self.state = 1
                continue
            out.append(0x30 + (b & 0x3F))            # the byte the prefix announced
            self.state = 2
            i += 1
        return bytes(out)


class AsciiDecoder:
    """ASCII mode receiver (spec 3.1): 20h-2Fh prefix, >=30h data, control chars ignored, bit 7 masked."""

    def __init__(self):
        self.prefix = 0
        self.count = 0

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        for c in data:
            c &= 0x7F
            if c < 0x20:
                continue                              # XON/XOFF/other control: no data
            if c < 0x30:
                self.prefix = c - 0x20
                self.count = 0
                continue
            out.append((c - 0x30) | (self.prefix & 3) << 6)
            if self.count == 0:
                self.prefix >>= 2                     # later chars use the next-byte bits
            self.count += 1
        return bytes(out)


class LinkClosed(Exception):
    pass


class LinkTimeout(Exception):
    pass


class Link:
    """One connection. Call the read/write methods; they pump the socket and the timers."""

    def __init__(self, sock, name="link", speed=None, mode=None):
        """speed = the CONNECT speed in bps (None: unknown/high, uses the 70h timer set).
        mode = LSEC/HSEC/RAW when this side calls and chooses the framing; None = answer and detect."""
        self.sock = sock
        self.name = name
        self.speed = speed
        self.mode = mode
        self.open_result = None         # caller: CTL_ACCEPT / CTL_REFUSE from the answerer's control frame
        self.ascii = False
        self.encoder = AsciiEncoder()
        self.decoder = AsciiDecoder()
        self.retx_seconds, self.assembly_seconds = timer_seconds(speed, None)
        # Line clock (spec/nak-storm.md §5 change 2), only when the line speed is known: when our
        # bytes have left the line. A post office starts a frame's retransmit timer when its copy has left
        # and builds the next frame only when the output queue is empty.
        self.byte_time = 10.0 / speed if speed else 0.0
        self.line_free = 0.0
        self.inbuf = bytearray()
        self.assembly_deadline = None   # timer 5: started at STX and after a good header
        self.header_ok = False
        self.rx_app = bytearray()
        self.tx_app = bytearray()
        self.rx_expected = 0
        self.rx_slots = {}            # seq -> (type, p0, payload)
        self.tx_next = 0
        self.tx_base = 0
        self.outstanding = {}         # seq -> [type, payload, last_sent_time (0 = now), nak_resent]
        self.ctl_queue = []           # control codes to send as sequenced type-2 frames
        self.ack_pending = False
        self.nak_pending = False
        self.closed = False
        self.stats = {"frames_rx": 0, "frames_tx": 0, "crc_errors": 0, "naks_rx": 0, "naks_tx": 0,
                      "retransmits": 0, "naks_ignored": 0}

    # ----- frame building -----

    @property
    def nr(self):
        return (self.rx_expected + 7) & 7

    def _frame(self, ctl, payload: bytes) -> bytes:
        n = len(payload)
        lenbytes = bytes([n]) if self.mode == LSEC else n.to_bytes(2, "little")
        hdr = lenbytes + bytes([ctl, payload[0]])
        out = bytes([STX]) + hdr + crc16(hdr).to_bytes(2, "big")
        if n > 1:
            data = payload[1:]
            out += data + crc16(data).to_bytes(2, "big")
        return out

    def _send_raw(self, data: bytes):
        """Send; returns when the last byte will have left the line (now if the speed is unknown)."""
        try:
            self.sock.sendall(data)
        except OSError as e:
            self.closed = True
            raise LinkClosed(str(e)) from e
        now = time.monotonic()
        if not self.byte_time:
            return now
        self.line_free = max(now, self.line_free) + len(data) * self.byte_time
        return self.line_free

    def _line_busy(self, now):
        return self.byte_time and self.line_free > now

    def _send_frame(self, ctl, payload, what):
        self.stats["frames_tx"] += 1
        log.debug("%s tx %s ctl=%02x L=%d p0=%02x", self.name, what, ctl, len(payload), payload[0])
        frame = self._frame(ctl, payload)
        return self._send_raw(self.encoder.frame(frame) if self.ascii else frame)

    @property
    def max_tx_l(self):
        return ASCII_MAX_L[self.mode] if self.ascii else MAX_L[self.mode]

    # ----- receive side -----

    def _detect_mode(self):
        """Before the mode is known: decide RAW / LSEC / HSEC from the first bytes (spec 6.3)."""
        while self.inbuf:
            b = self.inbuf[0]
            if b == 0x80:
                self.mode = RAW
                log.info("%s: caller uses no packet protocol (raw mode)", self.name)
                return True
            if b != STX:
                log.debug("%s skip pre-link byte %02x", self.name, b)
                del self.inbuf[0]
                continue
            if len(self.inbuf) >= 6 and crc16(bytes(self.inbuf[1:4])).to_bytes(2, "big") == bytes(self.inbuf[4:6]):
                self.mode = LSEC
            elif len(self.inbuf) >= 7 and crc16(bytes(self.inbuf[1:5])).to_bytes(2, "big") == bytes(self.inbuf[5:7]):
                self.mode = HSEC
            elif len(self.inbuf) >= 7:
                del self.inbuf[0]
                continue
            else:
                return False
            self.retx_seconds, self.assembly_seconds = timer_seconds(self.speed, self.mode)
            log.info("%s: packet mode %s (retransmit %.2f s, frame assembly %.2f s)", self.name, self.mode,
                     self.retx_seconds, self.assembly_seconds)
            return True
        return False

    def _start_assembly_timer(self):
        self.assembly_deadline = time.monotonic() + self.assembly_seconds

    def _parse_frames(self):
        while self.inbuf:
            if self.inbuf[0] != STX:
                del self.inbuf[0]
                continue
            if self.assembly_deadline is None:          # STX seen: start timer 5
                self._start_assembly_timer()
                self.header_ok = False
            hl = HDR_LEN[self.mode]
            if len(self.inbuf) < hl:
                return
            hdr = bytes(self.inbuf[1:hl - 2])
            if crc16(hdr).to_bytes(2, "big") != bytes(self.inbuf[hl - 2:hl]):
                self._bad_frame("header CRC")
                continue
            n = hdr[0] if self.mode == LSEC else hdr[0] | hdr[1] << 8
            ctl, p0 = hdr[-2], hdr[-1]
            if n < 1 or n > MAX_L[self.mode]:
                self._bad_frame(f"length {n}")
                continue
            payload = bytes([p0])
            end = hl
            if n > 1:
                if not self.header_ok:                  # good header: restart timer 5
                    self.header_ok = True
                    self._start_assembly_timer()
                need = hl + (n - 1) + 2
                if len(self.inbuf) < need:
                    return
                data = bytes(self.inbuf[hl:hl + n - 1])
                if crc16(data).to_bytes(2, "big") != bytes(self.inbuf[hl + n - 1:need]):
                    self._bad_frame("data CRC")
                    continue
                payload += data
                end = need
            del self.inbuf[:end]
            self.assembly_deadline = None
            self.header_ok = False
            self._handle_frame(ctl, payload)

    def _bad_frame(self, why):
        self.stats["crc_errors"] += 1
        log.info("%s: bad frame (%s), NAK", self.name, why)
        del self.inbuf[0]          # rescan from the byte after this STX
        self.assembly_deadline = None
        self.header_ok = False
        self.nak_pending = True

    def _process_ack(self, nr):
        while self.outstanding and ((nr - self.tx_base) & 7) < len(self.outstanding):
            self.outstanding.pop(self.tx_base, None)
            self.tx_base = (self.tx_base + 1) & 7

    def _handle_frame(self, ctl, payload):
        self.stats["frames_rx"] += 1
        typ, ns, nr = ctl >> 6, (ctl >> 3) & 7, ctl & 7
        p0 = payload[0]
        log.debug("%s rx ctl=%02x type=%d ns=%d nr=%d L=%d p0=%02x", self.name, ctl, typ, ns, nr, len(payload), p0)
        if typ == 1:
            self._process_ack(nr)
            return
        # NAK: clients and post offices send p0 = 04. The HP 200LX client
        # sends its NAK as 80h|N(R) with p0 = 00; callers never send a sequenced control frame,
        # so p0 = 00 on a type-2 frame is taken as a NAK too (spec/hp200lx-check.md)
        if typ == 2 and (p0 & 0x1F == CTL_NAK or p0 == 0):
            self.stats["naks_rx"] += 1
            self._process_ack(nr)
            seq = (nr + 1) & 7
            # Act on one NAK per frame until its retransmit timer fires again (spec/nak-storm.md §5,
            # change 1). the RCONNECT client NAKs every stale duplicate; on a slow line our
            # extra copies are still queued when the next NAK comes, and each would make another
            # copy. A cc:Mail post office never has a copy in flight when it acts on a NAK.
            entry = self.outstanding.get(seq)
            # with the line clock, a NAK for a frame whose copy is still on the line is ignored,
            # (the frame is not outstanding until it has left)
            if entry is not None and not entry[3] and entry[2] <= time.monotonic():
                entry[2] = 0                      # resend now
                entry[3] = True
            else:
                self.stats["naks_ignored"] += 1
            return
        self._process_ack(nr)
        offset = (ns - self.rx_expected) & 7
        if offset >= WINDOW:
            self.ack_pending = True               # duplicate: re-ack (clients do not, but it is harmless)
            return
        if ns in self.rx_slots:
            return
        self.rx_slots[ns] = (typ, p0, payload)
        if ns != self.rx_expected:
            self.nak_pending = True
        while self.rx_expected in self.rx_slots:
            t, code, data = self.rx_slots.pop(self.rx_expected)
            if t == 2:
                log.info("%s: control code %02x received", self.name, code & 0x1F)
                if code & 0x1F in (CTL_ACCEPT, CTL_REFUSE):      # the answerer's accept/refuse
                    self.open_result = code & 0x1F
            else:
                self.rx_app += data
            self.rx_expected = (self.rx_expected + 1) & 7
            self.ack_pending = True
            self.nak_pending = False

    # ----- scheduler -----

    def _schedule(self):
        if self.mode in (None, RAW):
            if self.mode == RAW and self.tx_app:
                data, self.tx_app = bytes(self.tx_app), bytearray()
                self._send_raw(data)
            return
        now = time.monotonic()
        if self.nak_pending:
            self.stats["naks_tx"] += 1
            self._send_frame(0x80 | self.nr, bytes([CTL_NAK]), "NAK")
            self.nak_pending = False
        for seq in sorted(self.outstanding, key=lambda s: (s - self.tx_base) & 7):
            typ, payload, sent, nak_resent = self.outstanding[seq]
            if now - sent >= self.retx_seconds:
                if self._line_busy(now):
                    break                       # one frame on the line at a time
                self.stats["retransmits"] += 1
                by_nak = sent == 0
                done = self._send_frame((typ << 6) | (seq << 3) | self.nr, payload,
                                        "retransmit (NAK)" if by_nak else "retransmit (timer)")
                self.outstanding[seq][2] = done
                if not by_nak:
                    self.outstanding[seq][3] = False   # timer resend: the next NAK counts again
                self.ack_pending = False
        while len(self.outstanding) < WINDOW and (self.ctl_queue or self.tx_app) and not self._line_busy(now):
            seq = self.tx_next
            if self.ctl_queue:
                typ, payload = 2, bytes([self.ctl_queue.pop(0)])
            else:
                n = min(len(self.tx_app), self.max_tx_l)
                typ, payload = 0, bytes(self.tx_app[:n])
                del self.tx_app[:n]
            done = self._send_frame((typ << 6) | (seq << 3) | self.nr, payload, "data" if typ == 0 else "control")
            self.outstanding[seq] = [typ, payload, done, False]
            self.tx_next = (seq + 1) & 7
            self.ack_pending = False
        if self.ack_pending:
            self._send_frame(0x40 | self.nr, b"\x00", "ack")
            self.ack_pending = False

    def pump(self, timeout=0.0):
        if self.closed:
            raise LinkClosed("closed")
        r, _, _ = select.select([self.sock], [], [], timeout)
        if r:
            try:
                data = self.sock.recv(65536)
            except OSError as e:
                data = b""
                log.info("%s: recv error %s", self.name, e)
            if not data:
                self.closed = True
                raise LinkClosed("peer closed the connection")
            if self.mode == RAW:
                self.rx_app += data
            elif self.ascii:
                self.inbuf += self.decoder.feed(data)
            elif self.mode is None and not self.inbuf:
                # Answer sniffer: skip noise until 80h (no packets), 02h (binary
                # packets) or a char with (c & 7Fh) == 20h (ASCII packets).
                for k, c in enumerate(data):
                    if c in (0x80, STX):
                        self.inbuf += data[k:]
                        break
                    if c & 0x7F == 0x20:
                        self.ascii = True
                        log.info("%s: ASCII packets", self.name)
                        self.inbuf += self.decoder.feed(data[k:])
                        break
            else:
                self.inbuf += data
        if self.mode is None:
            self._detect_mode()
            if self.mode == RAW:
                self.rx_app += self.inbuf
                self.inbuf = bytearray()
        if self.mode in (LSEC, HSEC):
            self._parse_frames()
            if self.assembly_deadline is not None and time.monotonic() > self.assembly_deadline:
                self._bad_frame("frame assembly timer")         # timer 5 expiry -> NAK
                self._parse_frames()
        self._schedule()

    # ----- interface for the session layer -----

    def call_open(self, opener: bytes, timeout=30.0):
        """Caller side: send the opener as the first data
        frame and wait for the answerer's control frame: 0Fh accept -> True, 10h refuse -> False."""
        self.retx_seconds, self.assembly_seconds = timer_seconds(self.speed, self.mode)
        self.write(opener)
        end = time.monotonic() + timeout
        while self.open_result is None:
            if time.monotonic() > end:
                raise LinkTimeout("no accept from the answering side")
            self.pump(0.05)
        return self.open_result == CTL_ACCEPT

    def wait_mode(self, timeout):
        end = time.monotonic() + timeout
        while self.mode is None:
            if time.monotonic() > end:
                raise LinkTimeout("no packet or session start from the caller")
            self.pump(0.1)
        return self.mode

    def read_exact(self, n, timeout):
        """Wait for n bytes; the timeout restarts whenever data moves in either direction,
        as a post office's reads do (spec/router-answer.md: TIMEOUT/ restarted on progress)."""
        end = time.monotonic() + timeout
        seen = (len(self.rx_app), len(self.inbuf), len(self.tx_app), len(self.outstanding))
        while len(self.rx_app) < n:
            if time.monotonic() > end:
                raise LinkTimeout(f"waiting for {n} bytes, have {len(self.rx_app)}")
            self.pump(0.05)
            now_seen = (len(self.rx_app), len(self.inbuf), len(self.tx_app), len(self.outstanding))
            if now_seen != seen:
                seen = now_seen
                end = time.monotonic() + timeout
        data = bytes(self.rx_app[:n])
        del self.rx_app[:n]
        return data

    def read_code(self, timeout):
        """One session code byte, skipping 91h fillers."""
        while True:
            b = self.read_exact(1, timeout)[0]
            if b != 0x91:
                return b

    def write(self, data: bytes):
        self.tx_app += data
        self.pump(0.0)

    def send_control(self, code):
        self.ctl_queue.append(code)
        self.pump(0.0)

    def drain(self, timeout):
        """Wait until everything queued has been sent and acknowledged."""
        end = time.monotonic() + timeout
        while self.tx_app or self.ctl_queue or self.outstanding:
            if time.monotonic() > end:
                raise LinkTimeout("peer did not acknowledge everything")
            self.pump(0.05)
