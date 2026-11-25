# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""NAK handling (spec/nak-storm.md §5 change 1 and §7 unit tests)."""
import socket
import unittest

from ccmail.link import Link, LSEC, CTL_NAK


class NakTest(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.b.setblocking(False)
        self.link = Link(self.a, "t")
        self.link.mode = LSEC
        self.link.retx_seconds, self.link.assembly_seconds = 6.2, 6.2
        self.link.tx_app += b"x" * 300          # three frames of 121 + one more
        self.link._schedule()
        self.drain()

    def tearDown(self):
        self.a.close()
        self.b.close()

    def drain(self):
        try:
            return self.b.recv(65536)
        except BlockingIOError:
            return b""

    def nak(self, nr):
        self.link._handle_frame(0x80 | nr, bytes([CTL_NAK]))
        self.link._schedule()

    def test_repeated_naks_one_resend(self):
        before = self.link.stats["retransmits"]
        for _ in range(5):
            self.nak(7)                         # N(R) = 7 asks for seq 0
        self.assertEqual(self.link.stats["retransmits"] - before, 1)
        self.assertEqual(self.link.stats["naks_ignored"], 4)

    def test_timer_resend_rearms(self):
        self.nak(7)
        self.nak(7)
        self.link.outstanding[0][2] -= 10       # the retransmit timer fires
        self.link._schedule()
        self.assertFalse(self.link.outstanding[0][3])
        before = self.link.stats["retransmits"]
        self.nak(7)
        self.assertEqual(self.link.stats["retransmits"] - before, 1)

    def test_nak_for_frame_not_outstanding(self):
        self.drain()
        self.nak(3)                             # asks for seq 4: never sent
        self.assertEqual(self.drain(), b"")
        self.assertEqual(self.link.stats["naks_ignored"], 1)

    def test_ack_clears(self):
        self.nak(7)
        self.link._handle_frame(0x40 | 0, b"\x00")   # ack seq 0
        self.assertNotIn(0, self.link.outstanding)


if __name__ == "__main__":
    unittest.main()
