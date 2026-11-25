# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Download order (router-answer.md 2.4): directory items, urgent, normal, low, arrival order kept."""
import unittest

from ccmail import directory
from ccmail.message import compose
from ccmail.session import send_order


class SendOrderTest(unittest.TestCase):
    def test_order(self):
        msgs = [("1-normal", compose("a", ["b"], "n1", "x")),
                ("2-low", compose("a", ["b"], "l", "x", priority=1)),
                ("3-urgent", compose("a", ["b"], "u1", "x", priority=2)),
                ("4-normal", compose("a", ["b"], "n2", "x")),
                ("5-dir", directory.update_message("PO", "b", [{"name": "c", "kind": "L", "addr": "PO"}])),
                ("6-urgent", compose("a", ["b"], "u2", "x", priority=2))]
        self.assertEqual([m for m, _ in send_order(msgs)],
                         ["5-dir", "3-urgent", "6-urgent", "1-normal", "4-normal", "2-low"])


if __name__ == "__main__":
    unittest.main()
