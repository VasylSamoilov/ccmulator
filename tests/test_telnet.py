# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Telnet on a TCP port (ccmail/telnet.py): negotiation (BINARY and SGA accepted, others
refused, no reply loops), IAC handling one byte at a time (split IAC, SB with IAC IAC inside),
CR NUL outside BINARY, and real calls through the filter: a raw Telnet client logging in, and
pyserial's own RFC 2217 client (independent Telnet + COM-PORT-OPTION code) carrying an LSEC
packet call from another post office, whose frames contain FFh (skipped without pyserial)."""
import json
import os
import shutil
import socket
import struct
import time
import unittest

try:
    import serial
except ImportError:
    serial = None

from ccmail import server, telnet
from ccmail.telnet import IAC, DO, DONT, WILL, WONT, SB, SE, BINARY, SGA, ECHO, COM_PORT, TelnetFilter
from ccmail.store import PostOffice
from linekit import Line, WORK, make_po, raw_login, tcp_server, thread, counter


def feed_bytewise(f, data):
    return b"".join(f.feed(bytes([b])) for b in data)


class FilterTest(unittest.TestCase):
    def test_start_requests(self):
        f = TelnetFilter()
        self.assertEqual(f.start(), bytes([IAC, WILL, BINARY, IAC, DO, BINARY, IAC, WILL, SGA, IAC, DO, SGA]))

    def test_answers_to_our_requests_get_no_reply(self):
        f = TelnetFilter()
        f.start()
        self.assertEqual(f.feed(bytes([IAC, DO, BINARY, IAC, WILL, BINARY, IAC, DO, SGA, IAC, WILL, SGA])), b"")
        self.assertEqual(f.replies(), b"")
        self.assertTrue(f.us[BINARY] and f.him[BINARY])
        # the same again: already in that state, no reply (RFC 854: no loops)
        f.feed(bytes([IAC, DO, BINARY, IAC, WILL, SGA]))
        self.assertEqual(f.replies(), b"")

    def test_refuse_others(self):
        f = TelnetFilter()
        f.feed(bytes([IAC, DO, ECHO, IAC, WILL, 24, IAC, DO, 31]))
        self.assertEqual(f.replies(), bytes([IAC, WONT, ECHO, IAC, DONT, 24, IAC, WONT, 31]))

    def test_peer_requests_accepted(self):
        f = TelnetFilter()
        f.feed(bytes([IAC, WILL, BINARY, IAC, DO, SGA]))
        self.assertEqual(f.replies(), bytes([IAC, DO, BINARY, IAC, WILL, SGA]))
        f.feed(bytes([IAC, DONT, SGA]))
        self.assertEqual(f.replies(), bytes([IAC, WONT, SGA]))
        f.feed(bytes([IAC, DONT, SGA]))                   # already off: silence
        self.assertEqual(f.replies(), b"")

    def test_refusal_of_our_request(self):
        f = TelnetFilter()
        f.start()
        f.feed(bytes([IAC, DONT, BINARY, IAC, WONT, BINARY]))
        self.assertEqual(f.replies(), b"")
        self.assertFalse(f.us.get(BINARY))

    def test_bytewise_iac_and_sb(self):
        f = TelnetFilter()
        f.feed(bytes([IAC, WILL, BINARY]))
        f.replies()
        data = (b"\x02\x04" + bytes([IAC, IAC]) + b"\x68" + bytes([IAC, 241]) + b"A"     # IAC NOP dropped
                + bytes([IAC, SB, 24, 1, IAC, IAC, 2, IAC, SE]) + b"B" + bytes([IAC, IAC, IAC, IAC]))
        self.assertEqual(feed_bytewise(f, data), b"\x02\x04\xff\x68AB\xff\xff")

    def test_cr_nul_outside_binary(self):
        f = TelnetFilter()
        self.assertEqual(feed_bytewise(f, b"a\r\x00b\r\nc\r"), b"a\rb\r\nc\r")
        self.assertEqual(f.feed(b"\x00d"), b"d")          # CR at a chunk end, NUL in the next
        self.assertEqual(f.encode(b"\r\n\xff\r"), b"\r\x00\n\xff\xff\r\x00")

    def test_binary_keeps_nul(self):
        f = TelnetFilter()
        f.start()
        f.feed(bytes([IAC, DO, BINARY, IAC, WILL, BINARY]))
        self.assertEqual(f.feed(b"\r\x00\x00"), b"\r\x00\x00")
        self.assertEqual(f.encode(b"\r\x00\xff"), b"\r\x00\xff\xff")

    def test_com_port_acks(self):
        f = TelnetFilter()
        f.feed(bytes([IAC, WILL, COM_PORT]))
        rep = f.replies()
        self.assertEqual(rep[:3], bytes([IAC, DO, COM_PORT]))
        self.assertIn(bytes([IAC, SB, COM_PORT, 107, 0xB0, IAC, SE]), rep)   # modem state: CD DSR CTS
        baud = struct.pack("!I", 2400)
        f.feed(bytes([IAC, SB, COM_PORT, 1]) + baud + bytes([IAC, SE]))
        self.assertEqual(f.replies(), bytes([IAC, SB, COM_PORT, 101]) + baud + bytes([IAC, SE]))
        f.feed(bytes([IAC, SB, COM_PORT, 1, 0, 0, 0, 0, IAC, SE]))          # query
        self.assertEqual(f.replies(), bytes([IAC, SB, COM_PORT, 101]) + baud + bytes([IAC, SE]))
        f.feed(bytes([IAC, SB, COM_PORT, 5, 7, IAC, SE]))                    # DTR state?
        self.assertEqual(f.replies(), bytes([IAC, SB, COM_PORT, 105, 8, IAC, SE]))
        f.feed(bytes([IAC, SB, COM_PORT, 12, 3, IAC, SE]))                   # purge both
        self.assertEqual(f.replies(), bytes([IAC, SB, COM_PORT, 112, 3, IAC, SE]))
        f.feed(bytes([IAC, SB, COM_PORT, 0, IAC, SE]))
        self.assertEqual(f.replies(), bytes([IAC, SB, COM_PORT, 100]) + b"ccmulator" + bytes([IAC, SE]))

    def test_com_port_off_is_refused(self):
        f = TelnetFilter(com_port=False)
        f.feed(bytes([IAC, WILL, COM_PORT]))
        self.assertEqual(f.replies(), bytes([IAC, DONT, COM_PORT]))
        f.feed(bytes([IAC, SB, COM_PORT, 1, 0, 0, 9, 0x60, IAC, SE]))
        self.assertEqual(f.replies(), b"")


class TelnetServer:
    """serve_connection() on a test port with the real call handler."""

    def __init__(self, po):
        self.srv, self.port = tcp_server()
        calls = counter()

        def accept():
            while True:
                try:
                    conn, addr = self.srv.accept()
                except OSError:
                    return

                def h(sock, addr=addr):
                    server.handle(sock, addr, po, next(calls), None)
                thread(telnet.serve_connection, conn, h, "telnet-test")
        thread(accept)

    def close(self):
        self.srv.close()


class RawTelnetClientTest(unittest.TestCase):
    def setUp(self):
        self.root, self.po = make_po("telnet-raw")
        self.server = TelnetServer(self.po)

    def tearDown(self):
        self.server.close()

    def test_negotiate_and_login(self):
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=10)
        L = Line(sock=s)
        got = L.read(12)
        self.assertEqual(got, bytes([IAC, WILL, BINARY, IAC, DO, BINARY, IAC, WILL, SGA, IAC, DO, SGA]))
        # accept BINARY both ways, refuse their SGA requests, ask for ECHO (refused)
        s.sendall(bytes([IAC, DO, BINARY, IAC, WILL, BINARY, IAC, DONT, SGA, IAC, WONT, SGA, IAC, DO, ECHO]))
        self.assertEqual(L.read(3), bytes([IAC, WONT, ECHO]))
        # the login, sent in pieces with an IAC NOP in the middle of the name
        s.sendall(b"\x80")
        self.assertEqual(L.read(1), b"\x81")
        s.sendall(b"\x06us" + bytes([IAC, 241]) + b"er1\x00")
        self.assertEqual(L.read(1), b"\x8b")
        s.sendall(b"\x04123\x00")
        self.assertEqual(L.read(1), b"\x82")
        n = L.read(1)[0]
        self.assertEqual(L.read(n).split(b"\x00")[0], b"MYPOST")
        s.close()


@unittest.skipUnless(serial, "needs pyserial")
class Rfc2217ClientCallTest(unittest.TestCase):
    """OURPO calls MYPOST in LSEC packets over pyserial's rfc2217:// client to our Telnet port:
    the client's open() needs our COM-PORT acknowledgements; every FFh in the frames is IAC-
    escaped by the client and by us."""

    def setUp(self):
        self.root = os.path.join(WORK, "telnet-rfc2217")
        shutil.rmtree(self.root, ignore_errors=True)
        self.a_dir = os.path.join(self.root, "ourpo")
        self.b_dir = os.path.join(self.root, "mypost")
        os.makedirs(self.a_dir)
        os.makedirs(self.b_dir)
        with open(os.path.join(self.a_dir, "po.json"), "w") as f:
            json.dump({"post_office": "OURPO", "users": {"bob": "1"},
                       "post_offices": {"MYPOST": {"password": "p1", "call_password": "p2", "mode": "LSEC"}}}, f)
        with open(os.path.join(self.b_dir, "po.json"), "w") as f:
            json.dump({"post_office": "MYPOST", "users": {"user": "123"},
                       "post_offices": {"OURPO": {"password": "p2"}}}, f)
        self.a = PostOffice(self.a_dir)
        self.b = PostOffice(self.b_dir)
        self.server = TelnetServer(self.b)

    def tearDown(self):
        self.server.close()

    def test_call_over_rfc2217_client(self):
        from ccmail.message import compose
        from ccmail.link import LSEC
        from ccmail.serialport import Port
        from ccmail.session import call_post_office
        from ccmail.message import Message
        att = bytes(range(256)) * 8 + b"\xff\xff\r\x00\r\n"     # every byte value, IAC runs, CR NUL
        msg = compose("bob", ["user at MYPOST"], "via telnet", "text\r\n" * 50,
                      attachments=[("all.bin", att)])
        self.assertGreaterEqual(msg.body.count(b"\xff"), 8)    # stored scrambled, FFh still there
        self.a.route("MYPOST", msg)
        ser = serial.serial_for_url(f"rfc2217://127.0.0.1:{self.server.port}", baudrate=2400, timeout=0.2)
        self.assertTrue(ser.cd)                          # our NOTIFY-MODEMSTATE arrived
        port = Port(ser, name="client")
        ours, theirs = socket.socketpair()

        def pump():
            import select
            while True:
                r, _, _ = select.select([port, ours], [], [], 0.5)
                try:
                    if port in r:
                        d = port.read()
                        if d:
                            ours.sendall(d)
                    if ours in r:
                        d = ours.recv(65536)
                        if not d:
                            return
                        port.write(d)
                except OSError:
                    return
        thread(pump)
        call = call_post_office(self.a, "MYPOST", theirs, LSEC, "t")
        theirs.close()
        self.assertEqual(call.sent, 1)
        box = os.path.join(self.b_dir, "mail", "user")
        end = time.monotonic() + 10
        while time.monotonic() < end and not (os.path.isdir(box) and os.listdir(box)):
            time.sleep(0.05)
        texts = [open(os.path.join(box, n), encoding="utf-8", errors="replace").read()
                 for n in os.listdir(box) if n.endswith(".txt")]
        self.assertTrue(any("via telnet" in t for t in texts), texts)
        got = [Message.from_file(open(os.path.join(box, n), "rb").read())
               for n in os.listdir(box) if n.endswith(".msg")]
        self.assertEqual(got[0].body, msg.body)          # byte for byte through both filters
        port.close()


if __name__ == "__main__":
    unittest.main()
