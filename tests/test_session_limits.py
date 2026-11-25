# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""The post office's per-message rules on upload (spec/router-answer.md 2.2, spec/limits.md 3 and 7):
author check 96, MAXMSGS 9D, MSGSIZE 8E, 1000-recipient cap 83. Runs the real Call over a socket
pair in raw mode (first byte 80h) against a copy of data-test in a scratch directory."""
import json
import os
import shutil
import socket
import struct
import tempfile
import threading
import unittest

from ccmail.link import Link
from ccmail.message import compose
from ccmail.session import Call
from ccmail.store import PostOffice

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "session-tests")


def lstring(s):
    b = s.encode("cp850") + b"\x00"
    return bytes([len(b)]) + b


class Client:
    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def read(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d:
                raise AssertionError(f"closed, wanted {n}, have {self.buf.hex(' ')}")
            self.buf += d
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def code(self):
        while True:
            c = self.read(1)[0]
            if c != 0x91:
                return c

    def login(self, user, pw):
        self.s.sendall(b"\x80")
        assert self.code() == 0x81
        self.s.sendall(lstring(user))
        assert self.code() == 0x8B
        self.s.sendall(lstring(pw))
        assert self.code() == 0x82
        n = self.read(1)[0]
        self.read(n)
        self.s.sendall(b"\x82")

    def upload(self, msg):
        """Returns (verdicts, final code); sends the body after 86."""
        self.s.sendall(b"\x84")
        assert self.code() == 0x85
        self.s.sendall(struct.pack("<H", len(msg.record)) + msg.record)
        verdicts = [self.code() for _ in msg.recipients_to()]
        r = self.code()
        if r == 0x86:
            self.s.sendall(msg.body)
            r = self.code()
        return verdicts, r


class LimitsTest(unittest.TestCase):
    def setUp(self, **cfg):
        self.root = os.path.join(WORK, self.id().rsplit(".", 1)[-1])
        shutil.rmtree(self.root, ignore_errors=True)
        os.makedirs(self.root)
        with open(os.path.join(HERE, "data-test", "po.json"), encoding="utf-8") as f:
            conf = json.load(f)
        conf.pop("gateway", None)
        conf.pop("failed_attempts", None)
        conf.update(cfg)
        with open(os.path.join(self.root, "po.json"), "w", encoding="utf-8") as f:
            json.dump(conf, f)
        self.po = PostOffice(self.root)
        a, b = socket.socketpair()
        a.settimeout(30)
        self.client = Client(a)
        self.server_sock = b
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        try:
            Call(Link(self.server_sock, "t"), self.po, "t").run()
        except Exception:
            pass

    def tearDown(self):
        self.client.s.close()
        self.server_sock.close()
        self.t.join(5)
        shutil.rmtree(self.root, ignore_errors=True)

    def reconfigure(self, **cfg):
        self.tearDown()
        self.setUp(**cfg)

    def test_wrong_author_96(self):
        self.client.login("user1", "123")
        v, r = self.client.upload(compose("user", ["user2", "user"], "not mine", "x"))
        self.assertEqual((v, r), ([0x82, 0x82], 0x96))
        v, r = self.client.upload(compose("user1", ["user2"], "mine", "x"))
        self.assertEqual((v, r), ([0x82], 0x87))

    def test_recipient_cap(self):
        self.client.login("user1", "123")
        msg = compose("user1", ["user2"] * 1001, "many", "x")
        v, r = self.client.upload(msg)
        self.assertEqual(v.count(0x82), 1000)
        self.assertEqual(v[-1], 0x83)
        self.assertEqual(r, 0x87)

    def test_maxmsgs_9d(self):
        self.reconfigure(max_msgs=1)
        self.client.login("user1", "123")
        self.assertEqual(self.client.upload(compose("user1", ["user2"], "one", "x"))[1], 0x87)
        self.assertEqual(self.client.upload(compose("user1", ["user2"], "two", "x")),
                         ([0x82], 0x9D))

    def test_msgsize_8e(self):
        self.reconfigure(msg_size_kb=1)
        self.client.login("user1", "123")
        self.assertEqual(self.client.upload(compose("user1", ["user2"], "big", "y" * 3000)),
                         ([0x82], 0x8E))
        self.assertEqual(self.client.upload(compose("user1", ["user2"], "small", "y"))[1], 0x87)


if __name__ == "__main__":
    unittest.main()
