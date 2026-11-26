# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Telnet (RFC 854/855) on a TCP port, for bridges that speak it: tcpser and other modem
emulators, terminal servers, RFC 2217 clients.

    python3 -m ccmail.server serve --data DIR --telnet-port 2323

serve_connection() sits between the accepted socket and the call handler (a socket pair, as
ccmail/modem.py does for a serial port), so the link layer sees the plain byte stream:
- incoming: IAC sequences are taken out and answered; IAC IAC is a data byte FFh; while the peer
  does not send BINARY, CR NUL is CR (RFC 854 NVT); CR LF stays as it is.
- outgoing: FFh is doubled; while our BINARY is not agreed, CR goes out as CR NUL.
- negotiation: at connect we ask for BINARY both ways and SGA both ways (WILL/DO). We accept
  BINARY, SGA and COM-PORT-OPTION (44) in either direction and refuse every other option (DONT /
  WONT). We reply only when the state changes, so the two ends cannot loop (RFC 854).
- RFC 2217 COM-PORT-OPTION, as a server, so RFC 2217 clients (pyserial rfc2217://, Windows COM
  redirectors) can open us:
    SIGNATURE (empty = asked)    answered with our name
    SET-BAUDRATE, SET-DATASIZE,  acknowledged (code + 100) with the value; 0 = query, answered
    SET-PARITY, SET-STOPSIZE     with the last value. Logged only: nothing is changed (no port)
    SET-CONTROL                  acknowledged; queries (0, 4, 7, 10, 13) answered with "no flow
                                 control, BREAK off, DTR on, RTS on, no inbound flow control"
    SET-LINESTATE-MASK,          acknowledged with the value
    SET-MODEMSTATE-MASK,
    PURGE-DATA
    NOTIFY-MODEMSTATE            sent once when the option is agreed and when polled: CD, DSR,
                                 CTS on (B0h)
    FLOWCONTROL-SUSPEND/RESUME   logged, not acted on (the session paces itself)
  Not supported: line state notifications (none are sent), BREAK.
- other Telnet commands (NOP, GA, AYT, BRK, IP, AO, EC, EL, DM) are dropped.
"""
import logging
import select
import socket
import struct
import threading

log = logging.getLogger("ccmail.telnet")

SE, NOP, DM, BRK, IP, AO, AYT, EC, EL, GA, SB = range(240, 251)
WILL, WONT, DO, DONT, IAC = 251, 252, 253, 254, 255
BINARY, ECHO, SGA, COM_PORT = 0, 1, 3, 44
NAMES = {BINARY: "BINARY", ECHO: "ECHO", SGA: "SGA", COM_PORT: "COM-PORT-OPTION", 24: "TERMINAL-TYPE",
         31: "NAWS", 32: "TERMINAL-SPEED", 34: "LINEMODE", 36: "ENVIRON", 39: "NEW-ENVIRON"}
VERBS = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}

# RFC 2217 client-to-server codes (server answers code + 100)
SIGNATURE, SET_BAUDRATE, SET_DATASIZE, SET_PARITY, SET_STOPSIZE, SET_CONTROL = 0, 1, 2, 3, 4, 5
NOTIFY_LINESTATE, NOTIFY_MODEMSTATE, FLOW_SUSPEND, FLOW_RESUME = 6, 7, 8, 9
SET_LINESTATE_MASK, SET_MODEMSTATE_MASK, PURGE_DATA = 10, 11, 12
MODEMSTATE = 0x80 | 0x20 | 0x10        # CD, DSR, CTS

DATA, CMD, OPT, SUB, SUB_IAC = range(5)


def optname(opt):
    return NAMES.get(opt, str(opt))


class TelnetFilter:
    """The Telnet state machine for one connection. feed(bytes from the peer) -> data bytes;
    replies() -> bytes to send to the peer (negotiation); encode(data) -> bytes to send."""

    def __init__(self, name="telnet", com_port=True, signature="ccmulator"):
        self.name = name
        self.accept = {BINARY, SGA} | ({COM_PORT} if com_port else set())
        self.us = {}                # option -> enabled on our side (we WILL)
        self.him = {}               # option -> enabled on the peer's side (he WILL)
        self.asked_us = set()       # we sent WILL, no answer yet
        self.asked_him = set()      # we sent DO, no answer yet
        self.state = DATA
        self.verb = None
        self.cr = False
        self.sub = bytearray()
        self.out = bytearray()
        self.signature = signature
        self.com = {SET_BAUDRATE: struct.pack("!I", 9600), SET_DATASIZE: b"\x08",
                    SET_PARITY: b"\x01", SET_STOPSIZE: b"\x01"}
        self.com_notified = False

    # ----- negotiation -----

    def _send(self, verb, opt):
        log.debug("%s: -> %s %s", self.name, VERBS[verb], optname(opt))
        self.out += bytes([IAC, verb, opt])

    def start(self):
        """Our requests at connect: BINARY and SGA, both ways."""
        for opt in (BINARY, SGA):
            self.asked_us.add(opt)
            self._send(WILL, opt)
            self.asked_him.add(opt)
            self._send(DO, opt)
        return self.replies()

    def replies(self):
        out = bytes(self.out)
        self.out.clear()
        return out

    def _negotiate(self, verb, opt):
        log.debug("%s: <- %s %s", self.name, VERBS[verb], optname(opt))
        if verb in (DO, DONT):
            state, asked, yes, no = self.us, self.asked_us, WILL, WONT
            want = verb == DO
        else:
            state, asked, yes, no = self.him, self.asked_him, DO, DONT
            want = verb == WILL
        was_asked = opt in asked
        asked.discard(opt)
        if want:
            if opt not in self.accept:
                if was_asked or not state.get(opt):
                    self._send(no, opt)     # refused (and never enabled)
                log.info("%s: refused %s %s", self.name, VERBS[verb], optname(opt))
                return
            if not state.get(opt):
                state[opt] = True
                if not was_asked:
                    self._send(yes, opt)
                log.info("%s: %s %s", self.name, "we send" if verb == DO else "peer sends", optname(opt))
                if opt == COM_PORT:
                    self._notify_modemstate()
        else:
            if state.get(opt):
                state[opt] = False
                if not was_asked:
                    self._send(no, opt)
                log.info("%s: %s %s off", self.name, "we send" if verb == DONT else "peer sends", optname(opt))
            # a refusal of our request, or of something already off: no reply

    # ----- RFC 2217 -----

    def _sb(self, code, value=b""):
        self.out += bytes([IAC, SB, COM_PORT, code]) + value.replace(b"\xff", b"\xff\xff") + bytes([IAC, SE])

    def _notify_modemstate(self):
        self._sb(100 + NOTIFY_MODEMSTATE, bytes([MODEMSTATE]))
        self.com_notified = True

    def _subneg(self, data):
        if not data:
            return
        opt, rest = data[0], bytes(data[1:])
        if opt != COM_PORT or not (self.us.get(COM_PORT) or self.him.get(COM_PORT)):
            log.debug("%s: subnegotiation %s ignored", self.name, optname(opt))
            return
        if not rest:
            return
        code, value = rest[0], rest[1:]
        if code == SIGNATURE:
            if value:
                log.info("%s: RFC 2217 client signature %r", self.name, value.decode("latin-1"))
            else:
                self._sb(100 + SIGNATURE, self.signature.encode("ascii"))
        elif code in (SET_BAUDRATE, SET_DATASIZE, SET_PARITY, SET_STOPSIZE):
            size = 4 if code == SET_BAUDRATE else 1
            if len(value) != size:
                log.info("%s: RFC 2217 code %d with %d bytes, ignored", self.name, code, len(value))
                return
            if any(value):
                self.com[code] = value
                what = {SET_BAUDRATE: "speed", SET_DATASIZE: "data bits", SET_PARITY: "parity",
                        SET_STOPSIZE: "stop bits"}[code]
                v = struct.unpack("!I", value)[0] if size == 4 else value[0]
                log.info("%s: RFC 2217 %s %s (acknowledged; no port behind us)", self.name, what, v)
            self._sb(100 + code, self.com[code])
        elif code == SET_CONTROL:
            v = value[:1] or b"\x00"
            answer = {0: 1, 4: 6, 7: 8, 10: 11, 13: 14}.get(v[0])
            self._sb(100 + SET_CONTROL, bytes([answer]) if answer is not None else v)
        elif code in (SET_LINESTATE_MASK, SET_MODEMSTATE_MASK, PURGE_DATA):
            self._sb(100 + code, value)
        elif code == NOTIFY_MODEMSTATE:            # a poll (pyserial ?poll_modem)
            self._notify_modemstate()
        elif code in (FLOW_SUSPEND, FLOW_RESUME):
            log.info("%s: RFC 2217 flow control %s (not acted on)", self.name,
                     "suspend" if code == FLOW_SUSPEND else "resume")
        else:
            log.info("%s: RFC 2217 code %d not supported, ignored", self.name, code)

    # ----- data -----

    def feed(self, data):
        out = bytearray()
        binary = self.him.get(BINARY)
        for b in data:
            st = self.state
            if st == DATA:
                if b == IAC:
                    self.state = CMD
                    continue
                if not binary:
                    if self.cr and b == 0:
                        self.cr = False
                        continue                    # CR NUL = CR
                    self.cr = b == 0x0D
                out.append(b)
            elif st == CMD:
                if b == IAC:
                    out.append(IAC)
                    self.cr = False
                    self.state = DATA
                elif b in (WILL, WONT, DO, DONT):
                    self.verb = b
                    self.state = OPT
                elif b == SB:
                    self.sub.clear()
                    self.state = SUB
                else:
                    self.state = DATA               # NOP, GA, AYT, BRK...: dropped
            elif st == OPT:
                self._negotiate(self.verb, b)
                self.state = DATA
                binary = self.him.get(BINARY)
            elif st == SUB:
                if b == IAC:
                    self.state = SUB_IAC
                else:
                    self.sub.append(b)
            elif st == SUB_IAC:
                if b == IAC:
                    self.sub.append(IAC)
                    self.state = SUB
                else:                               # SE (or a broken sequence): the end
                    self._subneg(self.sub)
                    self.state = DATA
        return bytes(out)

    def encode(self, data):
        data = data.replace(b"\xff", b"\xff\xff")
        if not self.us.get(BINARY):
            data = data.replace(b"\r", b"\r\x00")
        return data


def serve_connection(conn, handler, name="telnet", com_port=True):
    """Run one Telnet connection: handler(sock) gets the plain byte stream on a socket pair;
    this thread is the only writer to `conn`. Returns when either side closes."""
    filt = TelnetFilter(name, com_port=com_port)
    ours, theirs = socket.socketpair()
    try:
        conn.sendall(filt.start())
    except OSError:
        conn.close()
        return
    t = threading.Thread(target=handler, args=(theirs,), daemon=True)
    t.start()
    try:
        while True:
            r, _, _ = select.select([conn, ours], [], [], 1.0)
            if conn in r:
                try:
                    data = conn.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    log.info("%s: peer closed", name)
                    break
                app = filt.feed(data)
                rep = filt.replies()
                if rep:
                    conn.sendall(rep)
                if app:
                    ours.sendall(app)
            if ours in r:
                data = ours.recv(65536)
                if not data:
                    break
                conn.sendall(filt.encode(data) + filt.replies())
    except OSError as e:
        log.info("%s: %s", name, e)
    finally:
        ours.close()
        t.join(5)
        conn.close()
