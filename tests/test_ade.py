# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Directory exchange with other post offices (ccmail/ade.py, spec/router-to-router.md 4)."""
import datetime
import json
import os
import shutil
import struct
import tempfile
import unittest

from ccmail import admin, ade, directory
from ccmail.message import Message, TAG_FROM, TAG_PATH, TAG_TO, build_tlvs, text, untranspose
from ccmail.store import PostOffice

WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "ade-tests")


def item(msg):
    return ade.item_data(msg)


def from_partner(po, kind, data, partner="MYPOST", author_po="MYPOST"):
    """An ADE message as the partner would send it to us."""
    class Fake:
        name = partner
        codepage = 437
    msg = ade.build(Fake, po.name, kind, data)
    if author_po != partner:
        tl = [list(x) for x in msg.addr_tlvs]
        if author_po is None:
            del tl[1]
        else:
            tl[1][1] = author_po.encode() + b"\0"
        addr = build_tlvs(tl)
        p1 = bytearray(msg.record[:msg.part1_len])
        struct.pack_into("<I", p1, 0, msg.addr_off + len(addr))
        msg = Message(bytes(p1) + addr, msg.body)
    return msg


class AdeTest(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        with open(os.path.join(WORK, "po.json"), "w") as f:
            json.dump({"post_office": "OURPO", "users": {"admin": "1", "bob": "1", "alice": "1"},
                       "post_offices": {"MYPOST": {"password": "x", "ade": True},
                                        "OTHER": {"password": "y"}}}, f)
        self.po = PostOffice(WORK)

    # ----- text -----

    def test_title_and_prop(self):
        when = datetime.datetime(2026, 11, 5, 15, 4)
        self.assertEqual(ade.title(ade.UPDATE, when), "CCMUPDAT 11/5/26 3:04PM")
        self.assertEqual(ade.title(ade.REQUEST, when.replace(hour=0)), "CCMSYNCH.REQ 11/5/26 12:04AM")
        self.assertEqual(ade.prop_text(0x0011), "1100")
        self.assertEqual(ade.prop_text(0xC0E0), "0E0C")
        self.assertEqual(ade.parse_prop("0E0C"), 0xC0E0)
        self.assertEqual(ade.swap_nibbles(0xE0), 0x0E)

    def test_parse(self):
        data = (b"Synch: /postofc=MYPOST\r\nREM comment\r\nName: user1\r\nLocn: L\r\nAddr: MYPOST\r\n"
                b"Cmts: one\r\nName: gone\r\nLocn: DL\r\nAddr: MYPOST\r\nName: x\r\nLocn: L\r\nLocn: L\r\n"
                b"Name: y\r\nLocn: Q\r\nName: hq\r\nLocn: P 0E0C\r\n\x1a")
        header, recs = ade.parse(data, ade.SYNCH)
        self.assertEqual(header, ["Synch: /postofc=MYPOST"])
        self.assertEqual([(r["name"], r.get("letter"), r.get("delete"), r["error"]) for r in recs],
                         [("user1", "L", False, 0), ("gone", "L", True, 0), ("x", "L", False, 4),
                          ("y", None, None, 5), ("hq", "P", False, 0)])
        self.assertEqual(recs[4]["prop"], 0xC0E0)
        self.assertEqual(ade.synch_scope(header, "OURPO", "MYPOST"), 0x40)
        self.assertEqual(ade.synch_scope(["Synch: /directory", "Synch: -/postofc=OURPO"], "OURPO", "MYPOST"),
                         0xC0)

    def test_classify(self):
        for kind in (ade.UPDATE, ade.SYNCH, ade.REQUEST):
            self.assertEqual(ade.classify(ade.build(self.po, "MYPOST", kind, b"x")), kind)
        from ccmail.message import compose
        self.assertEqual(ade.classify(compose("a", ["b"], "s", "t")), 0)

    def test_built_message(self):
        msg = ade.build(self.po, "MYPOST", ade.UPDATE, b"Name: bob\r\n")
        self.assertEqual([(t, text(d)) for t, d in msg.addr_tlvs if t in (TAG_FROM, TAG_PATH, TAG_TO)],
                         [(1, "Administrator"), (0x0F, "OURPO"), (3, "Administrator"), (0x0F, "MYPOST")])
        self.assertEqual([d for t, d in msg.addr_tlvs if t == 0x1C], [b"\x02\x00"])
        self.assertEqual(item(msg), b"Name: bob\r\n")
        self.assertEqual(ade.origin(msg), ("Administrator", "OURPO"))
        # the per-destination copy made when forwarding leaves it intact
        out = msg.for_post_office("MYPOST", "OURPO")
        self.assertEqual(out.recipients_to(), ["Administrator"])
        self.assertEqual(ade.classify(out), ade.UPDATE)

    # ----- receiving -----

    def test_update_learned_and_routed(self):
        msg = from_partner(self.po, ade.UPDATE,
                           b"Name: user1\r\nLocn: L\r\nAddr: MYPOST\r\nCmts: user 1\r\n"
                           b"Name: far\r\nLocn: L\r\nAddr: REMOTEPO\r\nCmts: \r\n")
        self.assertTrue(ade.is_ade(self.po, "MYPOST", msg))
        self.assertFalse(ade.is_ade(self.po, "OTHER", msg))      # no ADE with OTHER: admin mailbox
        r = ade.handle(self.po, "MYPOST", msg)
        self.assertIn("3 change(s)", r)    # far's unknown home REMOTEPO also becomes a P entry
        self.assertEqual(ade.lookup(self.po, "REMOTEPO")["locn"], "P")
        self.assertEqual(ade.lookup(self.po, "USER1")["addr"], "MYPOST")
        self.assertEqual(ade.user_route(self.po, "user1"), "MYPOST")
        self.assertEqual(ade.user_route(self.po, "far"), "MYPOST")     # via the partner
        # our client users get the change, and the whole directory lists it
        mid, upd = self.po.pending("bob")[-1]
        self.assertIn(b"Name: user1\r\nLocn: L\r\nAddr: MYPOST\r\nCmts: user 1\r\n", item(upd))
        names = [(e["name"], e["kind"]) for e in directory.directory_entries(self.po)]
        self.assertIn(("user1", "L"), names)
        self.assertIn(("REMOTEPO", "P"), names)
        # names learned are taken
        with self.assertRaises(admin.AdminError):
            admin.add_user(self.po, "User1", "pw")

    def test_update_rename_delete_and_errors(self):
        ade.handle(self.po, "MYPOST", from_partner(self.po, ade.UPDATE,
                   b"Name: user1\r\nLocn: L\r\nAddr: MYPOST\r\nName: hq\r\nLocn: P\r\n"))
        self.assertEqual(ade.lookup(self.po, "hq")["addr"], "MYPOST")   # P without Addr: via sender
        r = ade.handle(self.po, "MYPOST", from_partner(self.po, ade.UPDATE,
                       b"Name: user1\r\nChng: User One\r\nLocn: L\r\nAddr: MYPOST\r\n"
                       b"Name: hq\r\nLocn: L\r\nAddr: MYPOST\r\n"            # P -> L: 11
                       b"Name: bob\r\nLocn: L\r\nAddr: MYPOST\r\n"           # our user: 14
                       b"Name: OURPO\r\nLocn: P\r\n"))                       # ourselves: no change
        self.assertIn("2 not applied", r)
        self.assertIsNone(ade.lookup(self.po, "user1"))
        self.assertEqual(ade.lookup(self.po, "user one")["name"], "User One")
        # the refused records go back to Administrator at MYPOST with CCMUPDAT.UND
        mid, ret = self.po.routed("MYPOST")[-1]
        self.assertEqual(ret.subject, "ADE message received (attached updates cannot be applied)")
        und = [it["data"] for it in ret.logical_items() if it["title"] == "CCMUPDAT.UND"][0]
        self.assertIn(b"Error: /code=11 /text=Invalid location change\r\n", und)
        self.assertIn(b"Error: /code=14 /text=Update not allowed\r\n", und)
        ade.handle(self.po, "MYPOST", from_partner(self.po, ade.UPDATE,
                   b"Name: User One\r\nLocn: DL\r\nAddr: MYPOST\r\n"))
        self.assertIsNone(ade.lookup(self.po, "user one"))

    def test_authorisation(self):
        # no 0F after the author -> rejected, nothing learned
        msg = from_partner(self.po, ade.UPDATE, b"Name: user1\r\nLocn: L\r\nAddr: MYPOST\r\n", author_po=None)
        self.assertIn("rejected", ade.handle(self.po, "MYPOST", msg))
        self.assertIsNone(ade.lookup(self.po, "user1"))
        self.assertEqual(self.po.routed("MYPOST")[-1][1].subject,
                         "ADE message rejected (author cannot update directory)")
        # a prop without receive bits (the usual default 0011h)
        def change(cfg):
            cfg["post_offices"]["MYPOST"]["ade"] = {"prop": "0x11"}
        self.po.update(change)
        msg = from_partner(self.po, ade.UPDATE, b"Name: user1\r\nLocn: L\r\nAddr: MYPOST\r\n")
        self.assertIn("C0E0h", ade.handle(self.po, "MYPOST", msg))
        self.assertIsNone(ade.lookup(self.po, "user1"))
        # Recv_Remote only: an entry at a third post office is not allowed (Recv_Other)
        def change2(cfg):
            cfg["post_offices"]["MYPOST"]["ade"] = {"prop": "0x40"}
        self.po.update(change2)
        ade.handle(self.po, "MYPOST", from_partner(self.po, ade.UPDATE,
                   b"Name: a\r\nLocn: L\r\nAddr: MYPOST\r\nName: b\r\nLocn: L\r\nAddr: ELSE\r\n"))
        self.assertIsNotNone(ade.lookup(self.po, "a"))
        self.assertIsNone(ade.lookup(self.po, "b"))

    def test_synch_deletes_in_scope(self):
        ade.handle(self.po, "MYPOST", from_partner(self.po, ade.UPDATE,
                   b"Name: u1\r\nLocn: L\r\nAddr: MYPOST\r\nName: u2\r\nLocn: L\r\nAddr: MYPOST\r\n"
                   b"Name: far\r\nLocn: L\r\nAddr: REMOTEPO\r\n"))
        r = ade.handle(self.po, "MYPOST", from_partner(self.po, ade.SYNCH,
                       b"Synch: /postofc=MYPOST\r\nName: u1\r\nLocn: L\r\nAddr: MYPOST\r\n"
                       b"Name: u3\r\nLocn: L\r\nAddr: MYPOST\r\nName: MYPOST\r\nLocn: P\r\n"))
        self.assertIn("synch", r)
        self.assertIsNotNone(ade.lookup(self.po, "u1"))
        self.assertIsNone(ade.lookup(self.po, "u2"))          # at MYPOST, in scope, not listed
        self.assertIsNotNone(ade.lookup(self.po, "u3"))
        self.assertIsNotNone(ade.lookup(self.po, "far"))      # outside /postofc=MYPOST
        self.assertEqual(sorted(self.po.users), ["admin", "alice", "bob"])
        # a synch with a malformed record is not applied at all
        ade.handle(self.po, "MYPOST", from_partner(self.po, ade.SYNCH,
                   b"Synch: /directory\r\nName: u9\r\nLocn: L\r\nAddr: MYPOST\r\nName: bad\r\nLocn: Q\r\n"))
        self.assertIsNone(ade.lookup(self.po, "u9"))
        self.assertIsNotNone(ade.lookup(self.po, "far"))

    def test_synch_request_answered(self):
        r = ade.handle(self.po, "MYPOST", from_partner(self.po, ade.REQUEST, b"Synch: /postofc=OURPO\r\n"))
        self.assertIn("synch queued", r)
        mid, s = self.po.routed("MYPOST")[-1]
        self.assertEqual(ade.classify(s), ade.SYNCH)
        self.assertEqual(item(s), b"Synch: /postofc=OURPO\r\n"
                         b"Name: admin\r\nLocn: L\r\nAddr: OURPO\r\nCmts: \r\n"
                         b"Name: alice\r\nLocn: L\r\nAddr: OURPO\r\nCmts: \r\n"
                         b"Name: bob\r\nLocn: L\r\nAddr: OURPO\r\nCmts: \r\n")
        # asking for more than we send it (Send_Other) is refused
        r = ade.handle(self.po, "MYPOST", from_partner(self.po, ade.REQUEST, b"Synch: /directory\r\n"))
        self.assertIn("refused", r)

    # ----- sending -----

    def test_admin_changes_go_to_partners(self):
        admin.add_user(self.po, "carol", "pw", comments="new")
        mid, m = self.po.routed("MYPOST")[-1]
        self.assertEqual(item(m), b"Name: carol\r\nLocn: L\r\nAddr: OURPO\r\nCmts: new\r\n")
        self.assertEqual(self.po.routed("OTHER"), [])          # no ADE with OTHER
        admin.rename_user(self.po, "carol", "Carol C")
        self.assertEqual(item(self.po.routed("MYPOST")[-1][1]),
                         b"Name: carol\r\nChng: Carol C\r\nLocn: L\r\nAddr: OURPO\r\nCmts: new\r\n")
        admin.delete_user(self.po, "Carol C", force=True)
        self.assertEqual(item(self.po.routed("MYPOST")[-1][1]),
                         b"Name: Carol C\r\nLocn: DL\r\nAddr: OURPO\r\nCmts: \r\n")
        n = len(self.po.routed("MYPOST"))
        admin.add_post_office(self.po, "BRANCH", "pw")          # P records need Send_Other
        self.assertEqual(len(self.po.routed("MYPOST")), n)

    def test_forward_to_other_partners(self):
        def change(cfg):
            cfg["post_offices"]["OTHER"]["ade"] = True
        self.po.update(change)
        ade.handle(self.po, "MYPOST", from_partner(self.po, ade.UPDATE,
                   b"Name: user1\r\nLocn: L\r\nAddr: MYPOST\r\n"))
        self.assertEqual(self.po.routed("MYPOST"), [])         # never back to the origin
        # OTHER gets it only if it is sent entries of third post offices (Send_Other)
        self.assertEqual(self.po.routed("OTHER"), [])
        def change2(cfg):
            cfg["post_offices"]["OTHER"]["ade"] = {"prop": hex(ade.DEFAULT_PROP | ade.SEND_OTHER)}
        self.po.update(change2)
        ade.handle(self.po, "MYPOST", from_partner(self.po, ade.UPDATE,
                   b"Name: user2\r\nLocn: L\r\nAddr: MYPOST\r\n"))
        self.assertEqual(item(self.po.routed("OTHER")[-1][1]),
                         b"Name: user2\r\nLocn: L\r\nAddr: MYPOST\r\nCmts: \r\n")


class AdeSessionTest(unittest.TestCase):
    """A client user uploads mail for names learned by ADE (the real Call over a socket pair)."""

    def setUp(self):
        import socket
        import threading
        from ccmail.link import Link
        from ccmail.session import Call
        from tests.test_session_limits import Client
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        with open(os.path.join(WORK, "po.json"), "w") as f:
            json.dump({"post_office": "OURPO", "users": {"bob": "123"},
                       "post_offices": {"MYPOST": {"password": "x", "ade": True}}}, f)
        self.po = PostOffice(WORK)
        ade.handle(self.po, "MYPOST", from_partner(self.po, ade.UPDATE,
                   b"Name: user1\r\nLocn: L\r\nAddr: MYPOST\r\nName: far\r\nLocn: L\r\nAddr: REMOTEPO\r\n"))
        a, b = socket.socketpair()
        a.settimeout(30)
        self.client, self.server_sock = Client(a), b

        def serve():
            try:
                Call(Link(b, "t"), self.po, "t").run()
            except Exception:
                pass
        self.t = threading.Thread(target=serve, daemon=True)
        self.t.start()

    def tearDown(self):
        self.client.s.close()
        self.server_sock.close()
        self.t.join(5)

    def test_learned_names_are_routed_with_their_path(self):
        from ccmail.message import compose
        self.client.login("bob", "123")
        msg = compose("bob", ["user1", "far at REMOTEPO", "nobody"], "hi", "x")
        self.assertEqual(self.client.upload(msg), ([0x82, 0x82, 0x83], 0x87))
        (mid, routed), = self.po.routed("MYPOST")
        out = routed.for_post_office("MYPOST", "OURPO")
        self.assertIsNotNone(out)          # without the appended 0F the copy would be dropped
        pend = [(n, p) for _, n, p in out.entries((TAG_TO,))]
        self.assertEqual(pend, [("user1", ["MYPOST"]), ("far", ["REMOTEPO", "MYPOST"])])


if __name__ == "__main__":
    unittest.main()
