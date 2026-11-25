# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Non-delivery reports as a post office builds them (spec/router-to-router.md 3.5): the byte
layout from message.non_delivery, and the session cases over a real Call on a socket pair: a
post office refuses recipients (83 then 87, or 89), a client refuses a download (83, 89). The data
lives in a scratch directory (WORK)."""
import json
import os
import shutil
import socket
import struct
import tempfile
import threading
import unittest

from ccmail import message as M
from ccmail.link import Link
from ccmail.message import Message, compose
from ccmail.session import Call
from ccmail.store import PostOffice

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "session-tests")


def lstring(s):
    b = s.encode("cp850") + b"\x00"
    return bytes([len(b)]) + b


def tags(msg):
    return [(t, M.text(d) if t in (1, 3, 4, 5, 0x0B, 0x0F, 0x10) else d) for t, d in M.parse_tlvs(msg.record, 0x20)]


class Builder(unittest.TestCase):
    def setUp(self):
        self.orig = compose("bob", ["nosuchuser at MYPOST", "user at MYPOST"], "hello", "text line",
                            author_po="OURPO")
        self.sent = self.orig.for_post_office("MYPOST", "OURPO").mark_refused(b"\x83\x82")

    def report(self, **kw):
        to, target, routed = M.report_address(self.sent, "OURPO", lambda n: "MYPOST" if n.upper() == "MYPOST"
                                              else None, lambda n: "bob" if n == "bob" else None)
        self.assertEqual(target, ("local", "bob"))
        return M.non_delivery(self.sent, self.orig, "MYPOST", to, "OURPO", 437, routed=routed, **kw)

    def test_mark_refused(self):
        self.assertEqual([t for t, _ in self.sent.addr_tlvs if t in (3, 0x10)], [0x10, 3])

    def test_layout(self):
        rep = self.report()
        o = self.orig
        total, addr_off, word8, magic, copies, f0e, _d, _t, w1a, w1c, w1e = struct.unpack_from(
            "<IIHHHIIIHHH", rep.record, 0)
        self.assertEqual((magic, copies, f0e), (0x4D, 1, 0))
        self.assertEqual((w1a, w1c, w1e), (o.headings, o.items, o.items))
        tl = tags(rep)
        # 06 descriptors, the new 13 slot, kept tags (07, 21) before the new 01, then the new entries
        self.assertEqual([t for t, _ in tl[:3]], [6, 6, 0x13])
        names = [(t, d) for t, d in tl[3:] if t not in (0x07, 0x21)]
        self.assertEqual(names, [(1, "Administrator"), (0x0F, "MYPOST"), (5, "Message not deliverable"),
                                 (0x20, struct.pack("<H", 437)), (0x10, "nosuchuser"), (0x0F, "MYPOST"),
                                 (3, "bob"), (0x0F, "OURPO")])
        # word 8 = offset of the first 01; no 31, 22, 0E or original 01/03/04 entries left
        pos, first01 = 0x20, None
        for t, d in M.parse_tlvs(rep.record, 0x20):
            if t == 1 and first01 is None:
                first01 = pos
            pos += 2 + len(d)
        self.assertEqual(word8, first01)
        self.assertEqual(rep.part1_len, first01)
        # items renumbered 1..n, laid out from word 8; tag 13 after them, +0C = stored record length
        descs = rep.descriptors()
        self.assertEqual([d["number"] for d in descs], [1, 2])
        self.assertEqual(descs[0]["offset"], word8)
        self.assertEqual(descs[1]["offset"], word8 + descs[0]["length"])
        d13 = [d for t, d in M.parse_tlvs(rep.record, 0x20) if t == 0x13][0]
        self.assertEqual(d13[:8], bytes(8))
        kind, ln, off = struct.unpack_from("<HII", d13, 8)
        self.assertEqual((kind, ln), (2, len(o.record)))
        self.assertEqual(off, descs[1]["offset"] + descs[1]["length"])
        self.assertEqual(addr_off, off + ln)
        self.assertEqual(total, addr_off + len(rep.record) - word8)
        # the item data is the original's, the text still reads the same
        self.assertEqual(rep.logical_items()[0]["data"], o.logical_items()[0]["data"])
        # the embedded header is the stored record, magic 'F', in stored (transposed) form
        emb = rep.body[off - word8:off - word8 + ln]
        self.assertNotEqual(emb[:0x20], o.record[:0x20])
        back = M.read_embedded(emb)
        want = bytearray(o.record)
        struct.pack_into("<H", want, 0x0A, 0x46)
        self.assertEqual(back, bytes(want))

    def test_routed_author(self):
        # report about mail that a user at MYPOST sent through us: it goes back to MYPOST, and
        # Administrator's path ends with our post office
        orig = compose("user", ["nobody at OTHER"], "x", "y", author_po="MYPOST")
        sent = orig.mark_refused(b"\x83")
        to, target, routed = M.report_address(sent, "OURPO", lambda n: n.upper() if n.upper() in ("MYPOST", "OTHER")
                                              else None, lambda n: None)
        self.assertEqual((target, routed), (("route", "MYPOST"), True))
        rep = M.non_delivery(sent, orig, "OTHER", to, "OURPO", 437, routed=True)
        tl = [(t, d) for t, d in tags(rep) if t not in (6, 7, 0x13, 0x20, 0x21)]
        self.assertEqual(tl, [(1, "Administrator"), (0x0F, "OTHER"), (0x0F, "OURPO"),
                              (5, "Message not deliverable"), (0x10, "nobody"), (0x0F, "OTHER"),
                              (3, "user"), (0x0F, "MYPOST")])

    def test_unknown_author(self):
        sent = compose("ghost", ["x"], "s", "t").mark_refused(b"\x83")
        self.assertIsNone(M.report_address(sent, "OURPO", lambda n: None, lambda n: None))
        # a path to no known post office: no report either
        sent = compose("ghost", ["x"], "s", "t", author_po="NOWHERE").mark_refused(b"\x83")
        self.assertIsNone(M.report_address(sent, "OURPO", lambda n: None, lambda n: "ghost"))

    def test_report_of_report(self):
        # the report's author is Administrator at <refuser>; refused again it finds no sender
        rep = self.report()
        again = rep.mark_refused(b"\x83")
        self.assertIsNone(M.report_address(again, "OURPO", lambda n: None, lambda n: None))


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

    def download(self, answer):
        """Our turn after 88: answer(record) -> verdict bytes + final code (86 takes the body).
        Returns the records offered."""
        self.s.sendall(b"\x88")
        got = []
        while True:
            c = self.code()
            if c == 0x88:
                return got
            assert c == 0x84, hex(c)
            self.s.sendall(b"\x85")
            hl = struct.unpack("<H", self.read(2))[0]
            rec = self.read(hl)
            total, addr_off, p1 = struct.unpack_from("<IIH", rec, 0)
            reply = answer(rec)
            self.s.sendall(reply)
            got.append(rec)
            if reply[-1:] == b"\x86":
                self.read(addr_off - p1)
                self.s.sendall(b"\x87")


class SessionTest(unittest.TestCase):
    def setUp(self):
        self.root = os.path.join(WORK, self.id().rsplit(".", 1)[-1])
        shutil.rmtree(self.root, ignore_errors=True)
        os.makedirs(self.root)
        conf = {"post_office": "OURPO", "users": {"admin": "123", "bob": "123", "user": "123"},
                "post_offices": {"MYPOST": {"password": "SECRET", "call_password": "x"}}}
        with open(os.path.join(self.root, "po.json"), "w", encoding="utf-8") as f:
            json.dump(conf, f)
        self.po = PostOffice(self.root)

    def run_call(self, user, pw, answer):
        a, b = socket.socketpair()
        a.settimeout(30)
        client = Client(a)
        t = threading.Thread(target=lambda: Call(Link(b, "t"), self.po, "t").run(), daemon=True)
        t.start()
        try:
            client.login(user, pw)
            return client.download(answer)
        finally:
            a.close()
            t.join(10)
            b.close()

    def files(self, *parts):
        d = os.path.join(self.root, *parts)
        return sorted(f for f in os.listdir(d) if f.endswith(".msg")) if os.path.isdir(d) else []

    def load(self, *parts):
        with open(os.path.join(self.root, *parts), "rb") as f:
            return Message.from_file(f.read())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_post_office_83_then_87(self):
        msg = compose("bob", ["nosuchuser at MYPOST", "user at MYPOST"], "hello", "x", author_po="OURPO")
        self.po.route("MYPOST", msg)
        offered = self.run_call("MYPOST", "SECRET", lambda rec: b"\x83\x82\x86")
        self.assertEqual(len(offered), 1)
        self.assertEqual(self.files("route", "MYPOST"), [])
        self.assertEqual(len(self.files("route-sent", "MYPOST")), 1)
        (rep,) = self.files("mail", "bob")
        rep = self.load("mail", "bob", rep)
        self.assertEqual(rep.author, "Administrator")
        self.assertEqual(rep.subject, "Message not deliverable")
        self.assertEqual(rep.names(0x10), ["nosuchuser"])
        self.assertEqual(rep.recipients_to(), ["bob"])

    def test_post_office_89(self):
        msg = compose("bob", ["a at MYPOST", "b at MYPOST"], "hello", "x", author_po="OURPO")
        self.po.route("MYPOST", msg)
        self.run_call("MYPOST", "SECRET", lambda rec: b"\x83\x83\x89")
        self.assertEqual(self.files("route", "MYPOST"), [])
        rep = self.load("mail", "bob", self.files("mail", "bob")[0])
        self.assertEqual(rep.names(0x10), ["a", "b"])

    def test_post_office_other_refusal_kept(self):
        # 8A (no space) keeps the message for a later call; no report
        self.po.route("MYPOST", compose("bob", ["a at MYPOST"], "hello", "x", author_po="OURPO"))
        self.run_call("MYPOST", "SECRET", lambda rec: b"\x82\x8a")
        self.assertEqual(len(self.files("route", "MYPOST")), 1)
        self.assertEqual(self.files("mail", "bob"), [])

    def test_download_refused_and_report_downloaded(self):
        # a message in user's mailbox whose 03 is not user: the client answers 83, 89
        bad = compose("bob", ["someoneelse"], "misfiled", "x")
        self.po._write(os.path.join(self.root, "mail", "user"), "0001", bad)
        self.run_call("user", "123", lambda rec: b"\x83\x89")
        self.assertEqual(self.files("mail", "user"), [])
        self.assertEqual(self.files("delivered", "user"), ["0001.msg"])
        (name,) = self.files("mail", "bob")
        rep = self.load("mail", "bob", name)
        self.assertEqual([(t, M.text(d)) for t, d in rep.addr_tlvs if t in (1, 0x0F, 0x10, 3)],
                         [(1, "Administrator"), (0x0F, "user"), (0x10, "someoneelse"), (3, "bob"),
                          (0x0F, "OURPO")])
        # bob downloads the report: one 03 = bob, accepted
        offered = self.run_call("bob", "123", lambda rec: b"\x82\x86")
        self.assertEqual(len(offered), 1)
        self.assertEqual(self.files("delivered", "bob"), [name])

    def test_download_other_codepage(self):
        # user's client shows 866, the stored message is 850: the report keeps the stored copy's
        # text and its tag 21, so the text still decodes right
        self.po.update(lambda c: c["users"].__setitem__("user", {"password": "123", "codepage": 866}))
        bad = compose("bob", ["someoneelse"], "misfiled", "Größe über", codepage=850)
        self.po._write(os.path.join(self.root, "mail", "user"), "0001", bad)
        self.run_call("user", "123", lambda rec: b"\x83\x89")
        rep = self.load("mail", "bob", self.files("mail", "bob")[0])
        _names, _subj, text_cp = rep.codepages(437)
        self.assertEqual(text_cp, 850)
        self.assertEqual(rep.logical_items()[0]["data"], bad.logical_items()[0]["data"])
        self.assertIn("Größe über", rep.logical_items()[0]["data"].decode("cp850"))

    def test_report_of_forwarded_report(self):
        # a report embedded in a second report: both tag-13 entries get offsets, both read back
        orig = compose("user", ["nobody at OTHER"], "x", "y", author_po="MYPOST")
        known = lambda n: n.upper() if n.upper() in ("MYPOST", "OTHER") else None  # noqa: E731
        sent = orig.mark_refused(b"\x83")
        to, _t, routed = M.report_address(sent, "OURPO", known, lambda n: None)
        rep1 = M.non_delivery(sent, orig, "OTHER", to, "OURPO", 437, routed=True)
        # the first report goes out again (To user at MYPOST) and MYPOST refuses it
        out = rep1.for_post_office("MYPOST", "OURPO").mark_refused(b"\x83")
        to2, target2, routed2 = M.report_address(out, "OURPO", known, lambda n: None)
        self.assertEqual(target2, ("route", "OTHER"))
        rep2 = M.non_delivery(out, rep1, "MYPOST", to2, "OURPO", 437, routed=routed2)
        d13 = [d for t, d in rep2.part1_tlvs if t == 0x13]
        self.assertEqual(len(d13), 2)
        got = []
        for d in d13:
            _k, ln, off = struct.unpack_from("<HII", d, 8)
            got.append(M.read_embedded(rep2.body[off - rep2.part1_len:off - rep2.part1_len + ln]))
        self.assertEqual(got[0][12:], rep1.record[12:])            # new slot first: rep1's record
        self.assertEqual(got[1][12:], orig.record[12:])            # then rep1's own embedded one
        self.assertEqual(rep2.logical_items()[0]["data"], orig.logical_items()[0]["data"])

    def test_download_report_refused_again(self):
        bad = compose("bob", ["someoneelse"], "misfiled", "x")
        self.po._write(os.path.join(self.root, "mail", "user"), "0001", bad)
        self.run_call("user", "123", lambda rec: b"\x83\x89")
        self.run_call("bob", "123", lambda rec: b"\x83\x89")
        # the report's author is Administrator at user: not in the directory, no second report
        self.assertEqual(self.files("mail", "bob"), [])
        self.assertEqual(len(self.files("delivered", "bob")), 1)


if __name__ == "__main__":
    unittest.main()
