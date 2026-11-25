# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Interactive mode for HP 200LX clients (spec/hp200lx-check.md §5, our model §5.15): the real
Call over a socket pair in packet mode, driven by the simulated client (tools/hpclient.py), which
sends the client's call sequences and decodes replies with the client's size rules."""
import json
import os
import shutil
import socket
import struct
import tempfile
import threading
import unittest

from ccmail import vimblock as V
from ccmail.link import Link, HSEC, LSEC
from ccmail.message import compose
from ccmail.session import Call, OPENER
from ccmail.store import PostOffice
from tools.hpclient import HP, HPError, VimFailed, S

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "session-tests")


class Base(unittest.TestCase):
    mode = HSEC
    users = {"admin": "123", "user1": "123", "user2": "123", "Doe, John": "pw"}

    def setUp(self):
        self.root = os.path.join(WORK, "hp-" + self.id().rsplit(".", 1)[-1])
        shutil.rmtree(self.root, ignore_errors=True)
        os.makedirs(self.root)
        with open(os.path.join(HERE, "data-test", "po.json"), encoding="utf-8") as f:
            conf = json.load(f)
        conf.pop("gateway", None)
        conf.pop("failed_attempts", None)
        conf["users"] = dict(self.users)
        with open(os.path.join(self.root, "po.json"), "w", encoding="utf-8") as f:
            json.dump(conf, f)
        self.po = PostOffice(self.root)
        a, b = socket.socketpair()
        a.settimeout(30)
        self.client_sock, self.server_sock = a, b
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        try:
            Call(Link(self.server_sock, "t"), self.po, "t").run()
        except Exception:
            pass

    def tearDown(self):
        self.client_sock.close()
        self.server_sock.close()
        self.t.join(5)
        shutil.rmtree(self.root, ignore_errors=True)

    def mail(self, to, subject, text="body\n", author="user2", **kw):
        return self.po.deposit(to, compose(author, [to], subject, text, **kw))

    def hp(self, user="user1", pw="123"):
        hp = HP(self.client_sock, mode=self.mode)
        hp.connect(user, pw, "MYPOST")
        hp.open_session(user, pw)
        return hp


class TranscriptTest(Base):
    """§5.7 transcript and §5.9 test vectors, byte for byte."""
    mode = LSEC

    def test_vectors(self):
        b = V.build("fzzzds", 3, b"cc:Mail", b"John Doe", b"pw", 100, 18)
        self.assertEqual(b, bytes.fromhex("03 00 22 00 00 00 19 00 00 00 16 00 00 00 64 00 00 00 12 00 00 00"
                                          "70 77 00 4A 6F 68 6E 20 44 6F 65 00 63 63 3A 4D 61 69 6C 00"))
        self.assertEqual(V.build("fh", 0x208, 0x00010002), bytes.fromhex("08 02 02 00 01 00"))
        self.assertEqual(V.parse_request("fzzzds", b), [3, b"cc:Mail", b"John Doe", b"pw", 100, 18])

    def test_transcript(self):
        link = Link(self.client_sock, "hp", mode=LSEC)
        self.assertTrue(link.call_open(OPENER))

        def exch(send, want):
            link.write(bytes.fromhex(send))
            w = bytes.fromhex(want)
            self.assertEqual(link.read_exact(len(w), 10).hex(" "), w.hex(" "))

        exch("AD", "AE")
        exch("AF 01 01 00 00 00 06 00 53 56 49 4D 64 00", "AF 01 01 80 00 00 00 00")
        exch("AF 01 02 00 00 00 02 00 2C 01", "AF 01 02 80 00 00 00 00")
        exch("AF 01 03 00 00 00 04 00 00 00 00 00", "AF 01 03 80 00 00 00 00")
        exch("AF 01 08 00 00 00 00 00", "AF 01 09 00 00 00 00 00")
        exch("80", "81")
        link.write(b"\x09John Doe\x00")       # stored as "Doe, John"; the client turns it around (§3.4)
        self.assertEqual(link.read_exact(1, 10), b"\x8B")
        exch("03 70 77 00", "82 07" + b"MYPOST\x00".hex())
        link.write(b"\x82")
        exch("01 01 00 04 00 00 00 00 00", "01 03 00 04 00 00 00 00 00")
        vec = V.build("fzzzds", 3, b"cc:Mail", b"John Doe", b"pw", 100, 18)
        exch("00 2A 00" + vec.hex(), "00 08 00 00 00 00 00 01 00 01 00")
        exch("00 0A 00 00 02 01 00 01 00 00 00 00 00", "00 08 00 00 00 00 00 02 00 01 00")
        exch("00 0E 00 0F 00 04 00 00 00 04 00 00 00 00 00 00 00", "00 04 00 00 00 00 00")   # ping
        exch("00 06 00 08 02 02 00 01 00", "00 04 00 00 00 00 00")
        exch("00 06 00 05 00 01 00 01 00", "00 04 00 00 00 00 00")
        exch("01 02 00 01 00 00", "01 02 00 01 00 00")


class ReadTest(Base):
    def test_inbox_read_mark(self):
        self.mail("user1", "first", "line one\nline two\n")
        self.po.deposit("user1", compose("user2", ["user1"], "second", "x", extra=[(0x0B, "admin", None)]))
        hp = self.hp()
        self.assertEqual(hp.counts(), (2, 2))
        rows = hp.page(0, 20)
        subjects = [r[S["SUBJECT"]].split(b"\0")[0] for r in rows]
        self.assertEqual(subjects, [b"second", b"first"])       # newest at the top (skip -1)
        self.assertEqual(rows[0][S["FROM_NAME"]].split(b"\0")[0], b"user2")
        self.assertEqual(rows[0][S["UNREAD_MAIL"]], b"\x01\x00")
        self.assertEqual(struct.unpack("<I", rows[0][S["DATE"]][:4])[0], S["LOCAL"])
        m = hp.read_message(rows[1][S["REF"]])
        self.assertEqual(m["text"], b"line one\r\nline two\r\n")
        self.assertEqual(m["header"][S["SUBJECT"]].split(b"\0")[0], b"first")
        self.assertEqual(V.parse_recipient_struct(m["header"][S["FROM"]])["value"], "user2")
        self.assertEqual(m["recipients"][S["TO"]], ["user1"])
        hp.close_message(m["handle"])
        m2 = hp.read_message(rows[0][S["REF"]])
        self.assertEqual(m2["recipients"][S["CC"]], ["admin"])
        hp.close_message(m2["handle"])
        self.assertEqual(hp.counts(), (0, 2))
        self.assertFalse(hp.query_new())
        self.mail("user1", "third")
        self.assertTrue(hp.query_new())
        hp.ping()
        self.assertEqual(hp.close_session(), (2, b"\x00"))
        # reading interactively keeps the mail on the server (still pending for a batch call)
        self.assertEqual(len(self.po.pending("user1")), 3)

    def test_paging(self):
        for i in range(25):
            self.mail("user1", f"m{i:02d}")
        hp = self.hp()
        subj = lambda rows: [r[S["SUBJECT"]].split(b"\0")[0].decode() for r in rows]  # noqa: E731
        self.assertEqual(subj(hp.page(0, 20)), [f"m{i:02d}" for i in range(24, 4, -1)])
        self.assertEqual(subj(hp.page(0, 20)), [f"m{i:02d}" for i in range(4, -1, -1)])
        self.assertFalse(hp.views[0]["more"])
        # the client's paging: the second page moved the top edge down by 5, so paging up
        # from there brings back the 5 rows above it, in display order
        self.assertEqual(subj(hp.page(0, -20)), [f"m{i:02d}" for i in range(24, 19, -1)])
        self.assertEqual(len(hp.all_refs()), 25)

    def test_attachment_detach(self):
        data = bytes(range(256)) * 40
        self.mail("user1", "with file", "see file", attachments=[("REPORT.BIN", data)])
        hp = self.hp()
        rows = hp.page(0, 20)
        m = hp.read_message(rows[0][S["REF"]])
        self.assertEqual(len(m["attachments"]), 1)
        att = m["attachments"][0]
        self.assertEqual((att["cls"], att["name"], att["size"]), (S["ATTACH"], "REPORT.BIN", len(data)))
        self.assertEqual(hp.detach(m["handle"], att), data)

    def test_unknown_proc_and_bad_handle(self):
        hp = self.hp()
        self.assertEqual(hp.call(0x0777, "fh", [hp.container], "t", ok=(16,))[0], 16)
        self.assertEqual(hp.call(0x0405, "fhSA", [1, S["ENTITY"], (1, [])], "t", ok=(16,))[0], 16)
        self.assertEqual(hp.call(0x0208, "fh", [0x00019999], "t", ok=(10,))[0], 10)
        hp.close_session()


class FolderTest(Base):
    def test_file_move_delete(self):
        mid = self.mail("user1", "keep me")
        self.mail("user1", "other")
        hp = self.hp()
        rows = hp.page(0, 20)
        ref = rows[1][S["REF"]]                 # "keep me"
        hp.file(ref, "Projects")
        self.assertEqual(hp.folders(), ["Projects"])
        self.assertEqual(hp.folder_count("Projects"), 1)
        # filed: out of the batch queue, still in the inbox until removed there
        self.assertEqual([m for m, _ in self.po.pending("user1")].count(mid), 0)
        self.assertEqual(hp.counts()[1], 2)
        hp.delete(ref)                            # 0203 in the inbox view
        self.assertEqual(hp.counts()[1], 1)
        self.assertEqual(hp.folder_count("Projects"), 1)
        hp.file(ref, "Archive", move_from="Projects")
        self.assertEqual(hp.folders(), ["Archive"])
        hp.delete(ref, folder="Archive")         # 0602 in the folder view: last place -> deleted/
        self.assertEqual(hp.folders(), [])
        self.assertTrue(os.path.exists(os.path.join(self.root, "deleted", "user1", mid + ".msg")))
        hp.close_session()


class SendTest(Base):
    def test_send(self):
        hp = self.hp()
        missing = hp.send(to=["user2"], cc=["admin"], subject="hi there", text="hello\nworld")
        self.assertEqual(missing, [])
        got = self.po.pending("user2")
        self.assertEqual(len(got), 1)
        msg = got[0][1]
        self.assertEqual((msg.author, msg.subject), ("user1", "hi there"))
        self.assertIn(b"hello\r\nworld", msg.logical_items()[0]["data"])
        self.assertEqual(len(self.po.pending("admin")), 1)
        self.assertEqual(hp.send(to=["user2", "nobody"], subject="x", text="y"), ["nobody"])

    def test_attachment_without_data_refused(self):
        hp = self.hp()
        with self.assertRaises(VimFailed) as cm:
            hp.send(to=["user2"], subject="file", text="t", attachments=["C:\\_DAT\\A.TXT"])
        self.assertEqual(cm.exception.status, 4)
        self.assertEqual(self.po.pending("user2"), [])
        hp.close_session()

    def test_reply_and_draft(self):
        self.mail("user1", "question", "why?\n")
        hp = self.hp()
        ref = hp.page(0, 20)[0][S["REF"]]
        hp.send(to=["user2"], subject="Re: question", text="because", derive=(ref, S["REPLY"], 2))
        msg = self.po.pending("user2")[0][1]
        self.assertEqual(msg.subject, "Re: question")
        self.assertIn(b"why?", msg.logical_items()[0]["data"])      # INHERIT_CONTENTS
        hp.send(to=["user2"], subject="later", text="draft text", flags=2)
        self.assertEqual(len(self.po.pending("user2")), 1)
        drafts = os.listdir(os.path.join(self.root, "vim", "user1", "drafts"))
        self.assertEqual(len([d for d in drafts if d.endswith(".msg")]), 1)
        self.assertEqual(hp.counts(S["DRAFT"])[1], 1)
        hp.close_session()


class BookTest(Base):
    def test_books(self):
        hp = self.hp()
        book = hp.open_book(b"")
        names = [e["name"] for e in hp.book_entries(book)]
        self.assertEqual(names, sorted(["admin", "user1", "user2", "Doe, John"], key=str.lower))
        ref = hp.match(book, "USER2")
        self.assertIsNotNone(ref)
        e = hp.entry(book, ref)
        self.assertEqual((e["name"], e["address"], e["type"]), ("user2", "user2", S["ENTITY"]))
        self.assertIsNotNone(hp.match(book, "us", S["PARTIAL"]))
        self.assertIsNone(hp.match(book, "nobody"))
        hp.close_book(book)
        priv = hp.open_book(b"VIM_PRIVATE")
        self.assertEqual(hp.book_entries(priv), [])
        hp.close_book(priv)
        self.assertEqual(hp.call(0x0401, "fhz", [hp.session, b"OTHER"], "th", ok=(15,))[0], 15)
        hp.close_session()


class VectorTest(unittest.TestCase):
    """Blocks worked out by hand from VRBuildDBHelper / VRBreakDataBlock (spec §5.9), so the codec
    is not only checked against itself."""

    def test_request_vectors(self):
        h = lambda s: bytes.fromhex(s)  # noqa: E731
        # 0201 page with a SUBJECT filter: p = u16 length + offset, data after the rest ("da")
        self.assertEqual(V.build("fhEiSpda", 0x201, 0x00010002, 0, -1, 0x5B, b"hi", 0, (20, [(0x4C, 8)])),
                         h("01 02 02 00 01 00 00 00 00 00 FF FF FF FF 5B 00 00 00 02 00 2C 00 00 00"
                           "00 00 00 00 01 00 14 00 4C 00 00 00 08 00 00 00 00 00 00 00 68 69"))
        # 0103: N = offset of the struct that follows, empty strings offset 0, value after
        self.assertEqual(V.build("fhSN", 0x103, 0x00010003, 0x61, V.recipient("Bob", 0x65)),
                         h("03 01 03 00 01 00 61 00 00 00 0E 00 00 00 65 00 00 00 00 00 00 00 00 00 00 00"
                           "26 00 00 00 00 00 00 00 00 00 00 00 42 6F 62 00"))
        # 0104 text inline: z placed after the rest; C = descriptor, Buffer field = data offset
        self.assertEqual(V.build("fhSzSzC", 0x104, 0x00010003, 0x3E, b"VIM_UNWRAPPED_TEXT", 0x37, None,
                                 (4, b"ab\r\n", 0, None)),
                         h("04 01 03 00 01 00 3E 00 00 00 2A 00 00 00 37 00 00 00 00 00 00 00"
                           "04 00 00 00 26 00 00 00 00 00 00 00 00 00 00 00 61 62 0D 0A")
                         + b"VIM_UNWRAPPED_TEXT\x00")
        # 0104 attachment by name: Size 0, Buffer 0, FileName field = the (empty) data offset
        self.assertEqual(V.build("fhSzSzC", 0x104, 0x00010003, 0x06, None, 0x37, b"A.TXT", (0, None, 0, b"A.TXT")),
                         h("04 01 03 00 01 00 06 00 00 00 00 00 00 00 37 00 00 00 26 00 00 00"
                           "00 00 00 00 00 00 00 00 00 00 00 00 26 00 00 00 41 2E 54 58 54 00"))
        p = V.parse_request("fhSzSzC", V.build("fhSzSzC", 0x104, 3, 6, None, 0x37, b"A.TXT", (0, None, 0, b"A.TXT")))
        self.assertEqual((p[5], p[6]["size"], p[6]["by_name"]), (b"A.TXT", 0, True))

    def test_reply_vectors(self):
        h = lambda s: bytes.fromhex(s)  # noqa: E731
        ref = h("07 00 00 00 00 00 00 00")
        tEbA = h("00 00 00 00 05 00 00 00 00 00 01 00 01 00 4C 00 00 00 08 00 00 00 1A 00 00 00") + ref
        self.assertEqual(V.build_reply("tEbA", 0, 5, 0, (1, [(0x4C, 8, ref)])), tEbA)
        self.assertEqual(V.break_reply("tEbA", tEbA, sizes=[8]), [0, 5, 0, (1, [(0x4C, 8, ref)])])
        with self.assertRaises(V.BlockError):         # a wire Size larger than the buffer
            V.break_reply("tEbA", tEbA, sizes=[4])
        comp = h("00 00 00 00 01 00 00 00 00 00 01 00 01 00 4B 00 00 00 0C 09 00 00 1A 00 00 00"
                 "1A 00 00 00 00 00 00 00 32 00 00 00 33 00 00 00 00 00 00 00 37 00 00 00 00 42 6F 62 00 00")
        self.assertEqual(V.build_reply_recipient(0, 1, V.recipient("Bob", 0x1A)), comp)
        self.assertEqual(V.break_reply("tEbA", comp)[3][1][0][2]["value"], "Bob")
        tEbwD = (h("00 00 00 00 01 00 00 00 00 00 01 00 3E 00 00 00 28 00 00 00 31 00 00 00 32 00 00 00"
                   "14 00 00 00 01 00 00 00 01 00 00 00") + b"VIM_TEXT\x00\x00\x00")
        item = dict(cls=0x3E, type="VIM_TEXT", name="", path="", size=20, ref=h("01 00 00 00 01 00 00 00"))
        self.assertEqual(V.build_reply("tEbwD", 0, 1, 0, 1, [item]), tEbwD)
        self.assertEqual(V.break_reply("tEbwD", tEbwD)[4], [item])
        tdC = h("00 00 00 00 03 00 00 00 61 62 63")
        self.assertEqual(V.build_reply("tdC", 0, 3, b"abc"), tdC)
        self.assertEqual(V.break_reply("tdC", tdC, desc_size=3)[2], b"abc")
        with self.assertRaises(V.BlockError):         # more than the caller's desc.Size
            V.break_reply("tdC", tdC, desc_size=2)
        tEbwp = h("00 00 00 00 02 00 00 00 00 00 02 00 04 00 12 00 00 00 41 00 42 00")
        self.assertEqual(V.build_reply("tEbwp", 0, 2, 0, 2, b"A\x00B\x00"), tEbwp)
        self.assertEqual(V.break_reply("tEbwp", tEbwp)[4], b"A\x00B\x00")
        self.assertEqual(V.build_reply("tEbA", 16), h("10 00 00 00"))   # a status alone


class MoreFlowsTest(Base):
    def test_filters(self):
        import datetime
        self.mail("user1", "hello world", author="user2", when=datetime.datetime(2026, 3, 4, 10, 20, 30))
        self.mail("user1", "other thing", author="admin", when=datetime.datetime(2026, 5, 6, 7, 8, 9))
        hp = self.hp()
        self.assertEqual(hp.counts(S["SUBJECT"], b"HELLO")[1], 1)
        self.assertEqual(hp.counts(S["FROM"], b"admin")[1], 1)
        rng = struct.pack("<IIIIII", S["LOCAL"], 2026 << 16 | 3 << 8 | 1, 0,
                          S["LOCAL"], 2026 << 16 | 3 << 8 | 31, 0x173B3B63)
        self.assertEqual(hp.counts(S["DATE"], rng)[1], 1)
        rows = hp.page(0, 20)
        date = rows[1][S["DATE"]]                  # "hello world", the older one
        self.assertEqual(struct.unpack("<III", date), (S["LOCAL"], 2026 << 16 | 3 << 8 | 4,
                                                       10 << 24 | 20 << 16 | 30 << 8))
        m = hp.read_message(rows[1][S["REF"]])
        self.assertEqual(m["header"][S["DATE"]], date)
        hp.close_message(m["handle"])
        self.assertEqual(hp.call(0x0201, "fhEiSpda", [hp.container, 0, 1, 0x52, None, 0, (1, [])], "tEbA",
                                 ok=(12,))[0], 12)
        hp.close_session()

    def test_transfer_and_forward(self):
        self.po.deposit("user1", compose("user2", ["user1"], "orig", "original text",
                                         extra=[(0x0B, "admin", None)], attachments=[("F.BIN", b"xyz")]))
        hp = self.hp()
        ref = hp.page(0, 20)[0][S["REF"]]
        t = hp.transfer(ref)
        self.assertEqual(t["header"][S["TYPE"]].split(b"\0")[0], b"VIM_MAIL")
        self.assertEqual(t["header"][S["SUBJECT"]].split(b"\0")[0], b"orig")
        self.assertEqual(t["recipients"], {S["TO"]: ["user1"], S["CC"]: ["admin"], S["BCC"]: []})
        self.assertEqual([(it["cls"], d) for it, d in t["items"]],
                         [(S["NOTE_PART"], b"original text\r\n"), (S["ATTACH"], b"xyz")])
        hp.send(to=["user2"], subject="Fw: orig", text="see below", derive=(ref, S["FORWARD"], 1))
        msg = self.po.pending("user2")[0][1]
        items = msg.logical_items()
        self.assertIn(b"original text", items[0]["data"])
        self.assertEqual(items[1]["data"], b"xyz")
        hp.close_session()

    def test_folder_paging_back_and_group(self):
        for f in ("Alpha", "Beta", "Gamma"):
            hp_ref = self.mail("user1", f)
        hp = self.hp()
        for row in hp.page(0, 20):
            hp.file(row[S["REF"]], row[S["SUBJECT"]].split(b"\0")[0].decode())
        self.assertEqual(hp.folders(), ["Alpha", "Beta", "Gamma"])
        vals = hp.call(0x0202, "fhSEiww", [hp.container, S["CATEGORY"], 0, -1, 0x50, 20], "tEbwp")
        names = [vals[4][i * 0x50:(i + 1) * 0x50].split(b"\0")[0] for i in range(vals[3])]
        self.assertEqual(names, [b"Gamma", b"Beta", b"Alpha"])
        vals = hp.call(0x0202, "fhSEiww", [hp.container, S["CATEGORY"], 2, -1, 0x50, 1], "tEbwp")
        self.assertEqual(vals[4][:6], b"Alpha\0")
        book = hp.open_book(b"")
        ref = hp.match(book, "user2")
        vals = hp.call(0x040F, "fhRzEia", [book, ref, None, 0, 1, (20, [(S["NAME"], 0x504)])], "tEbA",
                       sizes=[0x504])
        self.assertEqual(vals[3][0], 0)
        self.assertTrue(hp_ref)
        hp.close_session()

    def test_failed_send_keeps_older_draft(self):
        hp = self.hp()
        hp.send(to=["user2"], subject="older draft", text="d1", flags=2)
        with self.assertRaises(VimFailed):
            hp.send(to=["user2"], subject="with file", text="t", attachments=["A.TXT"], flags=2)
        self.assertEqual(hp.counts(S["DRAFT"])[1], 1)
        hp.close_session()


class LoginTest(Base):
    def test_unknown_user_refused(self):
        hp = HP(self.client_sock, mode=self.mode)
        with self.assertRaises(HPError):
            hp.connect("stranger", "x", "MYPOST")

    def test_comma_name(self):
        hp = HP(self.client_sock, mode=self.mode)
        hp.connect("John Doe", "pw", "MYPOST")
        hp.open_session("John Doe", "pw")
        self.assertEqual(hp.counts(), (0, 0))
        hp.close_session()


if __name__ == "__main__":
    unittest.main()
