# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Inbound mail that cannot be converted: the user gets a notice instead, the original is kept."""
import json
import os
import shutil
import tempfile
import unittest

from ccmail.gateway import Gateway
from ccmail.store import PostOffice

WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "unconvertible-tests")

RAW = (b"From: =?utf-8?b?w5xtaXQ=?= <umit@example.com>\r\n"
       b"To: user@mypost.example\r\n"
       b"Date: Tue, 24 Nov 2026 10:00:00 +0000\r\n"
       b"Subject: Quarterly report\r\n"
       b"Message-ID: <q4@example.com>\r\n"
       b"MIME-Version: 1.0\r\n"
       b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n"
       b"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nNumbers are attached.\r\nRegards\r\n"
       b"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"q4.pdf\"\r\n"
       b"Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--b--\r\n")


class UnconvertibleTest(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        with open(os.path.join(WORK, "po.json"), "w") as f:
            json.dump({"post_office": "MYPOST", "users": {"user": "123"},
                       "gateway": {"post_office": "INTERNET", "domain": "mypost.example"}}, f)
        self.po = PostOffice(WORK)
        self.gw = Gateway(self.po)

        def broken(*a, **k):
            raise ValueError("item table overflow")
        self.gw.from_email = broken                     # any conversion failure

    def test_notice_instead_of_mail(self):
        self.gw.deliver_inbound(RAW, ["user"], source="imaps account bob at imap.example.com, "
                                                       "folder INBOX, UID 7")
        (mid, msg), = self.po.pending("user")
        self.assertTrue(msg.subject.startswith("Message could not be converted: Quarterly"))
        text = msg.to_text()
        for want in ("Came from: imaps account bob at imap.example.com, folder INBOX, UID 7",
                     "From: Ümit <umit@example.com>", "Subject: Quarterly report",
                     "Message-ID: <q4@example.com>", "Date: Tue, 24 Nov 2026",
                     "application/pdf 'q4.pdf'", "Numbers are attached.",
                     "ValueError: item table overflow", "inbound/"):
            self.assertIn(want, text)
        self.assertIn("Postmaster", text)
        kept = os.listdir(os.path.join(WORK, "inbound"))
        self.assertEqual(len(kept), 1)
        with open(os.path.join(WORK, "inbound", kept[0]), "rb") as f:
            self.assertEqual(f.read(), RAW)                  # the original is kept unchanged

    def test_garbage_still_gives_a_notice(self):
        junk = b"\xff\xfe not a mail at all \x00\x01"
        self.gw.deliver_inbound(junk, ["user"])
        (mid, msg), = self.po.pending("user")
        self.assertEqual(msg.subject, "Message could not be converted")
        text = msg.to_text()
        self.assertIn(f"Size: {len(junk)} bytes", text)
        self.assertNotIn("\x00", text)                       # control bytes are not passed on


if __name__ == "__main__":
    unittest.main()
