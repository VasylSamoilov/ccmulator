# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""The Hayes modem emulator (ccmail/modem.py) as the HP 200LX client sees it: its modem command
sequence (spec/hp200lx-check.md §4), CONNECT <port speed>, a real Call through it, its +++ATZ
hang-up during a call, a null-modem session opener, and the capture file. Run on a pty (a local
serial device; skipped where there are no ptys), on socket:// and on rfc2217:// (pyserial's
PortManager on a test server), so the port loop works with any pyserial port. Plus the relay's two
escapes on their own. Needs pyserial (skipped without it)."""
import os
import socket
import struct
import time
import unittest

try:
    import serial  # noqa: F401
except ImportError:
    raise unittest.SkipTest("needs pyserial")

from ccmail import modem
from ccmail.serialport import Port
from linekit import (Line, CableDev, Rfc2217Server, make_po, raw_login, call_handler, counter,
                     tcp_server, thread)


def read_capture(path):
    out = []
    with open(path, "rb") as f:
        data = f.read()
    i = 0
    while i < len(data):
        d, t, n = struct.unpack_from("<BQI", data, i)
        i += 13
        out.append((d, data[i:i + n]))
        i += n
    return out


class EmulatorCase:
    def setUp(self):
        name = self.id().rsplit(".", 2)[-2] + "-" + self.id().rsplit(".", 1)[-1]
        self.root, self.po = make_po(name)
        self.capture = os.path.join(self.root, "call.bin")
        self.line = self.open_line()
        self.modem = modem.Modem(self.ser, self.capture, name="serial")
        self.calls = counter()
        thread(self.modem.serve, call_handler(self.po, self.calls))

    def tearDown(self):
        self.modem.port.close()
        self.modem.capture.f.close()
        self.line.close()

    def cmd(self, text, answer=b"OK\r\n"):
        self.line.sendall(text)
        return self.line.expect(answer)

    def test_hp_sequence_call_and_hangup(self):
        L = self.line
        time.sleep(0.2)
        L.sendall(b"+++")                    # the HP's ESCAPE, no CR, guard time after
        time.sleep(1.0)
        L.sendall(b"ATZ\r")                  # not waited for by the HP; answered anyway
        L.expect(b"OK\r\n")
        self.assertIn(b"ATE0V1\r", self.cmd(b"ATE0V1\r"))     # echoed (E was 1 until now)
        self.assertNotIn(b"ATH0", self.cmd(b"ATH0\r"))       # E0 now: no echo
        self.cmd(b"ATS0=0Q0X4\r")
        self.cmd(b"ATS7=60S10=50\r")
        self.cmd(b"ATM1L2\r")
        self.cmd(b"ATS9=6\r")
        got = self.cmd(b"ATDT555-1212,,\r", b"\r\n")
        got += L.expect(b"\r\n")
        self.assertEqual(got.strip(), b"CONNECT %d" % self.speed)
        self.assertEqual(raw_login(L), "MYPOST")
        L.sendall(b"+++ATZ\r")               # the HP hangs up in the middle of its call
        L.expect(b"OK\r\n")
        self.cmd(b"ATE0V1\r")
        self.cmd(b"ATH0\r")
        # second call: a null-modem client starts with 80h straight away
        self.assertEqual(raw_login(L), "MYPOST")
        L.sendall(b"\x88")                   # nothing to send: the server's turn, then its 88
        self.assertEqual(L.expect(b"\x88"), b"\x88")
        caps = read_capture(self.capture)
        to_us = b"".join(d for k, d in caps if k == 0)
        to_client = b"".join(d for k, d in caps if k == 1)
        self.assertIn(b"ATDT555-1212,,\r", to_us)
        self.assertIn(b"CONNECT %d" % self.speed, to_client)
        self.assertIn(b"\x81", to_client)


@unittest.skipUnless(hasattr(os, "openpty"), "needs a pty")
class PtyTest(EmulatorCase, unittest.TestCase):
    speed = 2400

    def open_line(self):
        master, slave = os.openpty()
        path = os.ttyname(slave)
        self.ser = modem.open_port(path, 2400)
        os.close(slave)
        return Line(fd=master)


class SocketUrlTest(EmulatorCase, unittest.TestCase):
    speed = 9600                             # socket:// has no speed: pyserial's default

    def open_line(self):
        srv, port = tcp_server()
        result = {}
        t = thread(lambda: result.setdefault("c", srv.accept()[0]))
        self.ser = modem.open_port(f"socket://127.0.0.1:{port}", None)
        t.join(5)
        srv.close()
        return Line(sock=result["c"])


class Rfc2217UrlTest(EmulatorCase, unittest.TestCase):
    speed = 19200

    def open_line(self):
        self.dev = CableDev()
        self.server = Rfc2217Server(self.dev)
        self.ser = modem.open_port(f"rfc2217://127.0.0.1:{self.server.port}", 19200, flow="rtscts",
                                   framing="8N2")
        return self.dev.far

    def tearDown(self):
        super().tearDown()
        self.server.close()

    def test_settings_reach_the_port(self):
        ch = dict(self.dev.changes)
        self.assertEqual(ch["baudrate"], 19200)
        self.assertEqual(ch["bytesize"], 8)
        self.assertEqual(ch["stopbits"], 2)
        self.assertEqual(ch["parity"], "N")
        self.assertIs(ch["rtscts"], True)
        self.assertIn(("dtr", True), self.dev.changes)


class RelayEscapeTest(unittest.TestCase):
    """relay() alone: the call side never answers, so only the escapes end it."""

    def setUp(self):
        self.dev = CableDev()
        self.port = Port(self.dev)
        self.ours, self.theirs = socket.socketpair()

    def tearDown(self):
        self.port.close()
        self.ours.close()
        self.theirs.close()

    def run_relay(self):
        out = {}
        t = thread(lambda: out.setdefault("r", modem.relay(self.port, self.ours)))
        return t, out

    def test_plus_and_pause(self):
        t, out = self.run_relay()
        self.dev.far.sendall(b"\x02data")
        time.sleep(0.3)
        self.dev.far.sendall(b"+++")
        t.join(5)
        self.assertEqual(out["r"], b"OK?")
        self.assertEqual(self.theirs.recv(100), b"\x02data+++")

    def test_plus_at(self):
        t, out = self.run_relay()
        self.dev.far.sendall(b"\x02data+++ATH0\r")
        t.join(5)
        self.assertEqual(out["r"], b"ATH0\r")

    def test_plus_then_data_is_data(self):
        t, out = self.run_relay()
        self.dev.far.sendall(b"+++")
        time.sleep(0.2)
        self.dev.far.sendall(b"more")
        time.sleep(1.2)
        self.assertNotIn("r", out)               # not an escape: data followed within the pause
        self.assertEqual(self.theirs.recv(100), b"+++more")
        self.theirs.close()                      # the session ends: relay returns b""
        t.join(5)
        self.assertEqual(out["r"], b"")


if __name__ == "__main__":
    unittest.main()
