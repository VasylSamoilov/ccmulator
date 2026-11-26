# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""A scripted Hayes modem for the tests, shaped like a pyserial port (read/write/in_waiting,
dtr/rts, cd). It answers AT commands (E, V, Q, &C, &D, S0, Z, A, D, H, O), says RING when told,
connects with a scripted CONNECT line, relays data to `far` (the remote end of the phone line,
a socket the test holds), drops carrier when the far end closes or on drop(), hangs up on DTR
low (&D2) or ATH0, and leaves data mode on "+++" with guard times.
It can be used directly (ccmail.serialport.Port(fake)), behind an RFC 2217 server
(linekit.Rfc2217Server), or behind socket:// (linekit.DevSocketServer)."""
import select
import socket
import threading
import time

from linekit import SerialLike


class FakeModem(SerialLike):
    guard = 0.4

    def __init__(self, connect="CONNECT 2400", dial_results=None, has_dcd=True, silent_rounds=0,
                 pre_connect=()):
        super().__init__()
        self.connect_line = connect
        self.pre_connect = list(pre_connect)         # e.g. ["CARRIER 9600", "PROTOCOL: LAPM"]
        self.dial_results = dial_results or {}
        self.has_dcd = has_dcd
        self.silent = silent_rounds                  # first N commands get no answer at all
        self.lock = threading.Condition()
        self.out = bytearray()
        self.cmdbuf = bytearray()
        self.commands = []
        self.events = []
        self.echo = True
        self.verbose = True
        self.s0 = 0
        self.d_mode = 2
        self.rings = 0
        self.ringing = False
        self.online = False         # carrier up
        self.data = False           # data mode (vs. command mode while online)
        self.carrier = False
        self.far = None             # our end of the remote line
        self.far_line = None        # the test's end
        self.last_rx = 0.0
        self.plus = 0
        self.plus_at = None
        self.closed = False
        self._dtr = False
        threading.Thread(target=self._tick, daemon=True).start()

    # ----- pyserial surface -----

    @property
    def dtr(self):
        return self._dtr

    @dtr.setter
    def dtr(self, v):
        old = self.__dict__.get("_dtr", False)
        self.__dict__["_dtr"] = v
        if hasattr(self, "events"):
            self.events.append(("dtr", v))
        if old and not v and getattr(self, "d_mode", 0) == 2 and self.online:
            self.events.append(("hangup", "dtr"))
            self._hangup(say=True)

    @property
    def cd(self):
        if not self.has_dcd:
            raise OSError("no DCD on this cable")
        return self.carrier

    @property
    def in_waiting(self):
        with self.lock:
            return len(self.out)

    def read(self, n=1):
        end = time.monotonic() + (self.timeout or 0)
        with self.lock:
            while not self.out and not self.closed:
                left = end - time.monotonic()
                if left <= 0:
                    return b""
                self.lock.wait(left)
            if self.closed and not self.out:
                raise OSError("closed")
            data = bytes(self.out[:n])
            del self.out[:n]
            return data

    def write(self, data):
        now = time.monotonic()
        for b in bytes(data):
            self._byte(b, now)
        self.last_rx = now
        return len(data)

    def flush(self):
        pass

    def close(self):
        self.closed = True
        with self.lock:
            self.lock.notify_all()

    # ----- script -----

    def emit(self, data):
        with self.lock:
            self.out += data
            self.lock.notify_all()

    def result(self, word, code):
        if self.verbose:
            self.emit(f"\r\n{word}\r\n".encode())
        else:
            self.emit(f"{code}\r".encode())

    def ring(self):
        self.ringing = True
        self.rings += 1
        self.result("RING", 2)
        if self.s0 and self.rings >= self.s0:
            self._go_online(self.connect_line)

    def drop(self):
        """The far end hangs up (carrier lost)."""
        if self.far_line:
            self.far_line.close()

    def _go_online(self, line):
        from linekit import Line
        a, b = socket.socketpair()
        self.far = a
        self.far_line = Line(sock=b)
        self.online = self.data = self.carrier = True
        self.ringing = False
        self.rings = 0
        for extra in self.pre_connect:
            self.result(extra, 0)
        self.result(line, 1)
        threading.Thread(target=self._pump_far, args=(a,), daemon=True).start()

    def _pump_far(self, far):
        while True:
            try:
                r, _, _ = select.select([far], [], [], 0.2)
                if not r:
                    if self.far is not far:
                        return
                    continue
                d = far.recv(65536)
            except (OSError, ValueError):
                d = b""
            if not d:
                if self.far is far:
                    self.events.append(("hangup", "far"))
                    self._hangup(say=True)
                return
            if self.data:
                self.emit(d)

    def _hangup(self, say):
        was = self.online
        self.online = self.data = self.carrier = False
        far, self.far = self.far, None
        if far:
            try:
                far.close()
            except OSError:
                pass
        if was and say:
            self.result("NO CARRIER", 3)

    def _tick(self):
        while not self.closed:
            time.sleep(0.05)
            if self.plus_at and time.monotonic() - self.plus_at >= self.guard:
                self.plus_at = None
                self.plus = 0
                self.data = False
                self.events.append(("escape",))
                self.result("OK", 0)

    def _byte(self, b, now):
        if self.data:
            silent_before = now - self.last_rx >= self.guard
            if b == 0x2B and (self.plus or silent_before):
                self.plus += 1
                if self.plus == 3:
                    self.plus_at = now
                return
            if self.plus:
                pend = b"+" * self.plus
                self.plus = 0
                self.plus_at = None
                self._to_far(pend)
            self._to_far(bytes([b]))
            return
        if self.echo:
            self.emit(bytes([b]))
        if b == 0x0D:
            line = self.cmdbuf.decode("ascii", "replace").strip()
            self.cmdbuf.clear()
            if line:
                self._command(line)
        elif b != 0x0A:
            self.cmdbuf.append(b)

    def _to_far(self, data):
        if self.far:
            try:
                self.far.sendall(data)
            except OSError:
                pass

    def _command(self, line):
        if "AT" in line.upper():
            line = line[line.upper().index("AT"):]     # like a modem: garbage before AT is skipped
        self.commands.append(line)
        if self.silent:
            self.silent -= 1
            return
        up = line.upper().replace(" ", "")
        if not up.startswith("AT"):
            self.result("ERROR", 4)
            return
        body = up[2:]
        i = 0
        while i < len(body):
            c = body[i]
            i += 1

            def num():
                nonlocal i
                j = i
                while i < len(body) and body[i].isdigit():
                    i += 1
                return int(body[j:i]) if i > j else 0
            if c == "Z":
                self.echo, self.verbose, self.s0, self.d_mode = True, True, 0, 2
            elif c == "E":
                self.echo = num() != 0
            elif c == "V":
                self.verbose = num() != 0
            elif c == "Q":
                num()
            elif c == "&":
                k = body[i]
                i += 1
                v = num()
                if k == "D":
                    self.d_mode = v
            elif c == "S":
                reg = num()
                if i < len(body) and body[i] == "=":
                    i += 1
                    v = num()
                    if reg == 0:
                        self.s0 = v
            elif c == "H":
                num()
                if self.online:
                    self.events.append(("hangup", "ATH"))
                    self._hangup(say=False)
            elif c == "O":
                num()
                if self.online:
                    self.data = True
                    self.result("CONNECT", 1)
                    return
            elif c == "A":
                if self.ringing:
                    time.sleep(0.05)
                    self._go_online(self.connect_line)
                else:
                    self.result("NO CARRIER", 3)
                return
            elif c == "D":
                number = line[line.upper().index("D") + 1:].strip().lstrip("TPtp")
                self.events.append(("dial", number))
                res = self.dial_results.get(number, "NO ANSWER")
                if res.startswith("CONNECT"):
                    self._go_online(res)
                else:
                    self.result(res, 7)
                return
            else:
                num()
        self.result("OK", 0)
