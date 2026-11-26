# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Our own Hayes modem on a serial port (answer and dial-out), for real phone lines.

    python3 -m ccmail.server serve --data DIR --serial /dev/ttyS0 --modem --baud 38400 --flow rtscts
    python3 -m ccmail.server call --data DIR BRANCH          # po.json "dial": "ATDT5551234"

ccmail/modem.py is the other way round (it *plays* a modem for a client on a cable); this file
*drives* a modem:
- init: each command of the init list (default ATZ, then AT E0 V1 Q0 &C1 &D2 S0=0) waits for OK
  (ok_timeout), up to `retries` rounds; a failed round escapes (+++ with guard times) and toggles
  DTR before the next. Echo and other lines are logged and skipped.
- answer: RING -> ATA (or with autoanswer N, S0=N in the init and just wait), then CONNECT.
  NO CARRIER / BUSY / ERROR / NO ANSWER / NO DIALTONE end the attempt; we re-init and wait again.
- CONNECT speed (as the clients parse it, spec/hp200lx-check.md §4): bare CONNECT = 300, else the
  digits after "CONNECT " up to the first non-digit (CONNECT 14400/ARQ -> 14400). A "CARRIER
  <speed>" report before it (modems with W1/W2 or S95 reporting) is the line speed itself and is
  used in preference; CONNECT can then be the DTE speed. This speed is the call's line_bps (link
  timers and line clock), whatever the port speed between us and the modem.
- during the call the far end's "+++" is data (it never reaches us as an escape); the call ends
  when the session ends, when DCD drops (watched once it has been seen high in this call, where
  the port can read it: a device, or rfc2217:// with the server's modem state), when the port
  fails, or on "NO CARRIER" at the end of the received data followed by `silence` seconds of quiet
  (so the text inside a message does not end a call).
- hang-up: drop DTR for `dtr_drop` s (with &D2 the modem hangs up), then ATH0; if it does not
  answer OK, +++ with guard times, then ATH0. Then re-init for the next call.
"""
import logging
import re
import select
import socket
import threading
import time

from .serialport import PortClosed, SettingsError

log = logging.getLogger("ccmail.hayes")

DEFAULT_INIT = ("ATZ", "AT E0 V1 Q0 &C1 &D2 S0=0")
MAX_COMMAND = 40            # characters after "AT": the command buffer of common modems
FAILURES = ("NO CARRIER", "BUSY", "ERROR", "NO ANSWER", "NO DIALTONE", "NO DIAL TONE")


class ModemError(Exception):
    pass


class DialFailed(ModemError):
    def __init__(self, result):
        super().__init__(result)
        self.result = result


def check_command(cmd, what="modem command"):
    """A command line for the modem: starts with AT, printable ASCII, no CR/LF, at most
    MAX_COMMAND characters after AT. Raises SettingsError saying what is wrong."""
    if not isinstance(cmd, str) or not cmd:
        raise SettingsError(f"{what}: empty")
    bad = [c for c in cmd if not 0x20 <= ord(c) <= 0x7E]
    if bad:
        raise SettingsError(f"{what} {cmd!r}: only printable ASCII, no CR/LF or control "
                            f"characters (found {bad[0]!r}); the CR is added when it is sent")
    if not cmd[:2].upper() == "AT":
        raise SettingsError(f"{what} {cmd!r}: must start with AT")
    if len(cmd) - 2 > MAX_COMMAND:
        raise SettingsError(f"{what} {cmd!r}: {len(cmd) - 2} characters after AT, modems take at "
                            f"most {MAX_COMMAND}; split it into several commands (;)")
    return cmd


def parse_init(text):
    """'ATZ;AT E0 V1' or a list -> checked tuple of commands; None/empty -> DEFAULT_INIT."""
    if not text:
        return DEFAULT_INIT
    items = text if isinstance(text, (list, tuple)) else text.split(";")
    cmds = tuple(check_command(c.strip(" "), "init command") for c in items if c.strip(" "))
    if not cmds:
        raise SettingsError(f"init {text!r}: no command")
    return cmds


def connect_speed(line):
    """Speed from a CONNECT result line: bare CONNECT -> 300; 'CONNECT 14400/ARQ' -> 14400;
    no digits (e.g. Telebit 'CONNECT FAST') -> None (unknown)."""
    s = line.strip().upper()
    if s == "CONNECT":
        return 300
    m = re.match(r"CONNECT\s*(\d+)", s)
    return int(m.group(1)) if m and int(m.group(1)) else None


class HayesModem:
    ok_timeout = 3.0        # per command
    atz_pause = 1.0         # after ATZ's OK (modems ignore commands while they reset)
    retries = 3             # init rounds
    guard = 1.1             # +++ guard time (S12 default 1 s)
    dtr_drop = 1.0          # DTR low at hang-up
    drain_pause = 1.0       # after the session ends, before the hang-up (modem buffers)
    answer_timeout = 60.0   # ATA -> CONNECT
    dial_timeout = 90.0     # ATD -> CONNECT
    silence = 0.5           # NO CARRIER then this much quiet = carrier lost
    dcd_poll = 0.5
    reinit_wait = 10.0      # after a failed init in serve()

    def __init__(self, port, init=DEFAULT_INIT, autoanswer=None, name="modem"):
        self.port = port
        self.init_cmds = tuple(init)
        if autoanswer is not None:
            if not 1 <= autoanswer <= 255:
                raise SettingsError(f"autoanswer {autoanswer}: rings 1-255")
            self.init_cmds += (f"ATS0={autoanswer}",)
        for c in self.init_cmds:
            check_command(c, "init command")
        self.autoanswer = autoanswer
        self.name = name
        self.buf = bytearray()
        self.skip_lf = False

    # ----- result lines -----

    def _fill(self, timeout):
        data = self.port.read(timeout)
        if data:
            if self.skip_lf and data[:1] == b"\n":
                data = data[1:]
            self.skip_lf = False
            self.buf += data
        return bool(data)

    def read_line(self, timeout):
        """Next non-empty line from the modem (str), or None after `timeout` (None = forever)."""
        end = None if timeout is None else time.monotonic() + timeout
        while True:
            m = re.search(rb"[\r\n]", self.buf)
            while m:
                text = bytes(self.buf[:m.start()])
                cut = m.end()
                if self.buf[m.start():m.start() + 2] == b"\r\n":
                    cut += 1
                elif self.buf[m.start():m.start() + 1] == b"\r" and cut == len(self.buf):
                    self.skip_lf = True
                del self.buf[:cut]
                line = text.decode("ascii", "replace").strip()
                if line:
                    log.info("%s: <- %s", self.name, line)
                    return line
                m = re.search(rb"[\r\n]", self.buf)
            left = None if end is None else end - time.monotonic()
            if left is not None and left <= 0:
                return None
            self._fill(1.0 if left is None else min(left, 1.0))

    def send(self, cmd):
        log.info("%s: -> %s", self.name, cmd)
        self.port.write(cmd.encode("ascii") + b"\r")

    def command(self, cmd, timeout=None):
        """Send one command; returns 'OK', a failure word, or None (no answer). Echo and
        information lines are skipped."""
        self.send(cmd)
        end = time.monotonic() + (timeout or self.ok_timeout)
        while True:
            line = self.read_line(max(0.0, end - time.monotonic()))
            if line is None:
                return None
            up = line.upper()
            if up == "OK" or up == "0":
                return "OK"
            if up in FAILURES or up == "4":
                return up

    def escape(self):
        """+++ with guard times: back to command mode from data mode (if it was there)."""
        time.sleep(self.guard)
        self.port.write(b"+++")
        time.sleep(self.guard)
        while self.read_line(0.5) is not None:
            pass

    def init(self):
        self.port.set_line("dtr", True)
        self.buf.clear()
        for attempt in range(1, self.retries + 1):
            for cmd in self.init_cmds:
                r = self.command(cmd)
                if r != "OK":
                    log.warning("%s: init %s -> %s (round %d of %d)", self.name, cmd,
                                r or "no answer", attempt, self.retries)
                    break
                if cmd.upper().replace(" ", "").startswith("ATZ"):
                    time.sleep(self.atz_pause)
            else:
                log.info("%s: initialised", self.name)
                return
            self.escape()
            if self.port.set_line("dtr", False):
                time.sleep(self.dtr_drop)
                self.port.set_line("dtr", True)
                time.sleep(0.2)
            self.buf.clear()
        raise ModemError(f"{self.name}: no OK to the init commands after {self.retries} rounds")

    # ----- connecting -----

    def wait_connect(self, timeout):
        """Until CONNECT: returns (line speed or None, bytes after the CONNECT line). Raises
        DialFailed(result) on a failure result or ModemError on timeout."""
        carrier = None
        end = time.monotonic() + timeout
        while True:
            line = self.read_line(max(0.0, end - time.monotonic()))
            if line is None:
                raise ModemError(f"{self.name}: no CONNECT within {timeout:.0f} s")
            up = line.upper()
            if up.startswith("CARRIER"):
                m = re.match(r"CARRIER\s*(\d+)", up)
                carrier = int(m.group(1)) if m else carrier
            elif up.startswith("CONNECT"):
                speed = connect_speed(up)
                if carrier and carrier != speed:
                    log.info("%s: CONNECT %s, line (CARRIER) %d bps", self.name, speed, carrier)
                    speed = carrier
                first = bytes(self.buf)
                self.buf.clear()
                log.info("%s: connected, line %s bps", self.name, speed or "unknown")
                return speed, first
            elif up in FAILURES or up in ("3", "4", "6", "7", "8"):
                raise DialFailed(up)

    def answer(self):
        """Wait for a call: RING -> ATA (or the modem's auto answer) -> CONNECT. Returns
        (speed, first bytes); raises DialFailed when the answer fails."""
        rings = 0
        while True:
            line = self.read_line(None)
            up = line.upper()
            if up in ("RING", "2"):
                rings += 1
                if self.autoanswer is None:
                    self.send("ATA")
                    return self.wait_connect(self.answer_timeout)
                log.info("%s: ring %d (auto answer after %d)", self.name, rings, self.autoanswer)
            elif up.startswith("CONNECT") or up.startswith("CARRIER"):
                self.buf[:0] = (line + "\r\n").encode("ascii")    # parse it in wait_connect
                return self.wait_connect(self.answer_timeout)
            elif up in FAILURES and rings:
                raise DialFailed(up)

    def dial(self, dial_string):
        check_command(dial_string, "dial string")
        self.send(dial_string)
        return self.wait_connect(self.dial_timeout)

    # ----- the call -----

    def data_mode(self, sock, first=b""):
        """Relay between the modem and the call's socket until the call ends; returns why."""
        try:
            if first:
                sock.sendall(first)
            return self._data_mode(sock)
        except OSError as e:           # the session closed its end while bytes were moving
            log.info("%s: relay: %s", self.name, e)
            return "session ended"

    def _data_mode(self, sock):
        tail = b""
        held = b""              # a "NO CARRIER" line at the end of a read: kept back until more
        no_carrier_at = None    # data shows it was data (or the silence shows it was the modem)
        armed = False
        poll = self.dcd_poll
        next_poll = 0.0
        while True:
            r, _, _ = select.select([self.port, sock], [], [], 0.2)
            now = time.monotonic()
            if self.port in r:
                try:
                    data = self.port.read()
                except PortClosed:
                    return "port closed"
                if self.skip_lf:                        # the LF of the CONNECT line's CR LF
                    self.skip_lf = False
                    data = data[1:] if data[:1] == b"\n" else data
                if data:
                    if armed and self.port.carrier() is False:
                        return "carrier lost (DCD)"     # what follows is the modem's result
                    tail = (tail + data)[-32:]
                    data, held = held + data, b""
                    m = re.search(rb"[\r\n]+NO CARRIER[\r\n]+$", tail)
                    no_carrier_at = None
                    if m:
                        no_carrier_at = now
                        keep = min(len(tail) - m.start(), len(data))
                        data, held = data[:-keep], data[-keep:]
                    if data:
                        sock.sendall(data)
            if no_carrier_at is not None and now - no_carrier_at >= self.silence:
                return "NO CARRIER"
            if poll is not None and now >= next_poll:
                next_poll = now + poll
                c = self.port.carrier()
                if c is None:
                    poll = None                 # cannot be read here: not watched
                elif c:
                    armed = True
                elif armed:
                    return "carrier lost (DCD)"
            if sock in r:
                try:
                    data = sock.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    return "session ended"
                self.port.write(data)

    def hangup(self):
        if self.port.set_line("dtr", False):
            time.sleep(self.dtr_drop)
            self.port.set_line("dtr", True)
            time.sleep(0.2)
        while self.read_line(0.3) is not None:
            pass
        if self.command("ATH0") != "OK":
            self.escape()
            r = self.command("ATH0")
            if r != "OK":
                log.warning("%s: hang-up: ATH0 -> %s", self.name, r or "no answer")
        log.info("%s: hung up", self.name)

    def run_call(self, handler, speed, first):
        """One connected call: handler(sock, speed) in a thread, the relay here, then hang-up."""
        ours, theirs = socket.socketpair()
        t = threading.Thread(target=handler, args=(theirs, speed), daemon=True)
        t.start()
        try:
            why = self.data_mode(ours, first)
            log.info("%s: call ended: %s", self.name, why)
            if why == "session ended":
                time.sleep(self.drain_pause)
        finally:
            ours.close()
            t.join(5)
        return why

    def serve(self, handler, calls=None):
        """Answer calls forever (or `calls` connected calls): init, answer, the call, hang-up.
        handler(sock, line_bps) runs one call and closes sock."""
        n = 0
        while calls is None or n < calls:
            try:
                try:
                    self.init()
                except ModemError as e:
                    log.error("%s; retrying in %.0f s", e, self.reinit_wait)
                    time.sleep(self.reinit_wait)
                    continue
                log.info("%s: waiting for RING on %s", self.name, self.port.port)
                try:
                    speed, first = self.answer()
                except ModemError as e:
                    log.info("%s: answer failed: %s", self.name, e)
                    continue
                n += 1
                why = self.run_call(handler, speed, first)
                if why == "port closed":
                    raise PortClosed(f"{self.name}: port closed")
                self.hangup()
            except PortClosed as e:
                log.warning("%s: %s; no more calls on this port", self.name, e)
                return
            except Exception:
                # e.g. a write to a port that just failed; the next init shows whether it is back
                log.exception("%s: error; re-init in %.0f s", self.name, self.reinit_wait)
                time.sleep(self.reinit_wait)
