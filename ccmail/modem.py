# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""A Hayes modem as a cc:Mail client (for example an HP 200LX) sees it, on a serial port.

    python3 -m ccmail.server serve --data DIR --serial /dev/ttyUSB0 --baud 9600 --capture call.bin
    python3 -m ccmail.server serve --data DIR --serial rfc2217://termserver:7001 --baud 2400

What the client's modem setup needs (spec/hp200lx-check.md §4):
- every command is a line ending in CR: "+++", "ATZ", "ATE0V1", "ATH0", "ATS0=0Q0X4", "ATS7=60S10=50",
  "ATM1L2", then "ATDT<number>" (or "ATX3S9=6D" for manual dial);
- verbose results framed CR LF text CR LF (V1 is required); "ATZ" is not waited for;
- after the dial it waits for "CONNECT <speed>" and takes the speed from that line (a bare CONNECT
  means 300, so the speed is always given here = the port's speed; on socket:// and loop://,
  which have none, --line-bps or 9600).
Then the line carries the cc:Mail session; when it ends we go back to command mode, ready for the
client's hang-up sequence and the next call.
A client set up for a null-modem cable sends no commands: its link opener frame (or 80h in raw
mode) switches straight to the call; other binary bytes in command mode are late bytes of the last
call and are dropped. During a call, "+++AT…" or "+++" and a pause ends the call and the commands
are answered, as a modem does when its user escapes and hangs up.

The port keeps DTR and RTS on, so a null-modem cable shows the client DSR, DCD and CTS.
The port is any pyserial port (ccmail/serialport.py: a device, rfc2217://, socket://, loop://),
read by a thread; --capture writes every chunk in tools/proxy.py's binary form (1 byte
direction: 0 = client to us, 1 = us to client; 8 bytes microseconds; 4 bytes length; data),
readable by tools/frames.py.
"""
import logging
import select
import socket
import threading
import time

from .serialport import Capture, Port, PortClosed, check_settings, open_port as _open_port

log = logging.getLogger("ccmail.modem")

__all__ = ["Capture", "Modem", "relay", "open_port", "ESCAPE_PAUSE"]

ESCAPE_PAUSE = 0.8      # "+++" then this much silence = escape (Hayes guard time is ~1 s)


def relay(port, sock, capture=None, first=b""):
    """Copy bytes between the serial port and one end of a socket pair until the call handler
    closes the other end (returns b"") or the client escapes to command mode like a modem
    user: "+++" followed by "AT" or by a pause (returns the bytes from the "AT" on). The HP
    200LX client hangs up that way (+++ATZ, ATE0V1, ATH0) without waiting for our side to
    finish; a real modem would then answer its commands, not pass them on.
    `port` is a serialport.Port (a plain pyserial object is wrapped). A failed port raises
    PortClosed."""
    if not isinstance(port, Port):
        port = Port(port, capture)
    if first:
        try:
            sock.sendall(first)
        except OSError:
            return b""
    tail = b""
    escape_at = None
    while True:
        r, _, _ = select.select([port, sock], [], [], 0.2)
        if port in r:
            data = port.read()
            if data:
                seen = tail + data
                k = seen.find(b"+++AT")
                if k >= 0:
                    log.info("modem: escape (+++AT) during the call")
                    return seen[k + 3:]
                if escape_at is not None:
                    escape_at = None        # more data: it was not an escape
                if seen.endswith(b"+++"):
                    escape_at = time.monotonic()
                try:
                    sock.sendall(data)
                except OSError:
                    return b""                  # the session closed its end meanwhile
                tail = seen[-4:]
        elif escape_at is not None and time.monotonic() - escape_at >= ESCAPE_PAUSE:
            log.info("modem: escape (+++ and a pause) during the call")
            return b"OK?"
        if sock in r:
            data = sock.recv(65536)
            if not data:
                return b""
            port.write(data)


class Modem:
    def __init__(self, ser, capture_path=None, name="modem", connect_speed=None):
        """ser: an open pyserial object (open_port). connect_speed: what CONNECT says (default
        the port's speed)."""
        self.ser = ser
        self.capture = Capture(capture_path)
        self.port = ser if isinstance(ser, Port) else Port(ser, self.capture, name)
        self.name = name
        self.connect_speed = connect_speed or getattr(ser, "baudrate", None) or 9600
        self.reset()

    def reset(self):
        self.echo = True
        self.verbose = True

    def _send(self, text):
        self.port.write(text.encode("ascii"))

    def result(self, word, code):
        if self.verbose:
            self._send(f"\r\n{word}\r\n")
        else:
            self._send(f"{code}\r")

    def command(self, line):
        """One command line; returns True when the call is connected."""
        up = line.strip().upper()
        log.info("%s: command %r", self.name, line)
        if up == "+++" or up == "":
            if up:
                self.result("OK", 0)
            return False
        up = up.lstrip("+ ")                # "+++" sent without CR runs into the next command
        if not up.startswith("AT"):
            log.info("%s: not a command, ignored", self.name)
            return False
        body = up[2:]
        dial = False
        i = 0
        while i < len(body):
            c = body[i]
            i += 1
            if c == "Z":
                self.reset()
            elif c in "EVQ":
                v = body[i] if i < len(body) and body[i].isdigit() else "0"
                if i < len(body) and body[i].isdigit():
                    i += 1
                if c == "E":
                    self.echo = v != "0"
                elif c == "V":
                    self.verbose = v != "0"
            elif c == "D":
                dial = True
                break                       # the rest is the number
            elif c == "S":
                while i < len(body) and (body[i].isdigit() or body[i] in "=?"):
                    i += 1
            else:
                while i < len(body) and body[i].isdigit():
                    i += 1
        if dial:
            number = body[i:].lstrip("TP")
            log.info("%s: dial %r -> CONNECT %d", self.name, number, self.connect_speed)
            time.sleep(0.5)
            self.result(f"CONNECT {self.connect_speed}", 1)
            return True
        self.result("OK", 0)
        return False

    def wait_call(self, initial=b""):
        """Command mode until a dial (returns b"") or a session start from a null-modem client
        (returns its bytes). `initial` = bytes already read (commands after an escape)."""
        line = bytearray()
        junk = bytearray()
        pending = initial
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = self.port.read(1.0)
                if not data:
                    continue
            for k, b in enumerate(data):
                if b >= 0x80 or b in (0x02, 0x00) or (b < 0x20 and b not in (0x0D, 0x0A, 0x08)):
                    # binary in command mode: a null-modem client starting a session (the link
                    # opener FF AA 55 11, or 80 in raw mode), else late bytes of the last call
                    junk += data[k:]
                    # the opener frame on the wire: 02 len ctl FF hcrc hcrc AA 55 11 dcrc dcrc
                    # (p0 = FF, the rest after the header CRC; captured 02 04 07 FF 68 C4 AA 55 11)
                    i = junk.find(b"\xaa\x55\x11")
                    opener = i >= 6 and junk[i - 3] == 0xFF and junk[i - 6] == 0x02
                    if opener or junk[:1] == b"\x80":
                        start = i - 6 if opener else 0
                        log.info("%s: session start without a dial (null modem): %s", self.name,
                                 bytes(junk[start:start + 16]).hex(" "))
                        return bytes(junk[start:])
                    if len(junk) > 4096:
                        del junk[:-8]
                    line.clear()
                    break
                if self.echo and b != 0x0A:
                    self._send(chr(b) if b != 0x0D else "\r")
                if b == 0x0D:
                    if self.command(line.decode("ascii", "replace")):
                        rest = bytes(data[k + 1:])
                        return rest if rest else b""
                    line.clear()
                elif b == 0x08:
                    del line[-1:]
                elif b != 0x0A:
                    line.append(b)

    def serve(self, handler, calls=None):
        """handler(sock) runs one call and closes sock; loops forever (or `calls` times), until
        the port fails."""
        try:
            self._serve(handler, calls)
        except PortClosed as e:
            log.warning("%s: %s; no more calls on this port", self.name, e)

    def _serve(self, handler, calls):
        n = 0
        while calls is None or n < calls:
            n += 1
            log.info("%s: waiting for a call on %s, CONNECT %d", self.name, self.port.port,
                     self.connect_speed)
            first = self.wait_call(getattr(self, "_after_escape", b""))
            self._after_escape = b""
            ours, theirs = socket.socketpair()
            t = threading.Thread(target=handler, args=(theirs,), daemon=True)
            t.start()
            try:
                rest = relay(self.port, ours, first=first)
            finally:
                ours.close()        # the session sees the line drop, as with NO CARRIER
                t.join(5)
            # the client's hang-up sequence (+++, ATZ, ATE0V1, ATH0) follows in command mode
            self.reset()
            if rest == b"OK?":
                self.result("OK", 0)            # "+++" with guard time: answered like a modem
            elif rest:
                self._after_escape = rest       # "+++AT...": run those commands now
            log.info("%s: call ended, back in command mode", self.name)


def open_port(device, baud=None, rtscts=False, framing=None, flow=None):
    """Open a device or pyserial URL for the emulator (settings checked as the cc:Mail line)."""
    settings, warnings = check_settings(device, baud, framing, flow or ("rtscts" if rtscts else None))
    for w in warnings:
        log.warning("%s: %s", device, w)
    return _open_port(device, settings)
