# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Address book commands (ccmail/admin.py): po.json changes and the directory updates they queue."""
import json
import os
import shutil
import tempfile
import unittest

from ccmail import admin
from ccmail.directory import item_text
from ccmail.message import untranspose
from ccmail.store import PostOffice

WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "admin-tests")


def update_text(po, user):
    """Item text of the newest directory update waiting for user."""
    mid, msg = po.pending(user)[-1]
    d = msg.descriptors()[0]
    return untranspose(msg.body[d["offset"] - msg.part1_len:][:d["length"]])


class AdminTest(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        with open(os.path.join(WORK, "po.json"), "w") as f:
            json.dump({"post_office": "MYPOST", "users": {"user": "123", "bob": "123"}}, f)
        self.po = PostOffice(WORK)

    def test_add_user(self):
        q = admin.add_user(self.po, "Smith, Ann", "pw", comments="Sales")
        self.assertEqual(sorted(u for u, _ in q), ["Smith, Ann", "bob", "user"])
        self.assertEqual(update_text(self.po, "bob"),
                         item_text([{"name": "Smith, Ann", "kind": "L", "addr": "MYPOST", "cmts": "Sales"}]))
        # the new user gets the whole directory
        self.assertIn(b"Name: user\r\n", update_text(self.po, "Smith, Ann"))
        # another PostOffice (a running server) sees the new user and its password
        other = PostOffice(WORK)
        self.assertEqual(other.user("ann smith"), "Smith, Ann")
        self.assertTrue(other.check_password("Smith, Ann", b"pw\0"))

    def test_hp_name_rewrite(self):
        # hp200lx-check.md 3.4: the HP 200LX client sends "Last, First" as "First Last"
        for stored, sent in (("Doe, John Q", "John Q Doe"), ("Van Dyke, Jo", "Jo Van Dyke"),
                             ("Smith,Ann", "Ann Smith")):
            admin.add_user(self.po, stored, "pw", notify=False)
            self.assertEqual(self.po.user(sent), stored)

    def test_duplicate_and_bad_names(self):
        for bad in ("USER", "MYPOST", "x at Y", "a@b", "", "n" * 127):
            with self.assertRaises(admin.AdminError, msg=bad):
                admin.add_user(self.po, bad, "pw")
        admin.add_post_office(self.po, "BRANCH", "secret")
        with self.assertRaises(admin.AdminError):
            admin.add_user(self.po, "branch", "pw")

    def test_rename(self):
        admin.rename_user(self.po, "bob", "Brown, Bob")
        self.assertEqual(update_text(self.po, "user"),
                         b"Name: bob\r\nLocn: L\r\nChng: Brown, Bob\r\nAddr: MYPOST\r\n")
        self.assertIsNone(self.po.user("bob"))
        self.assertEqual(len(self.po.pending("Brown, Bob")), 1)   # mailbox moved with the name

    def test_delete(self):
        admin.add_user(self.po, "temp", "pw", notify=False)
        with open(os.path.join(WORK, "po.json")) as f:
            self.assertIn("temp", json.load(f)["users"])
        q = admin.delete_user(self.po, "temp")
        self.assertEqual(sorted(u for u, _ in q), ["bob", "user"])
        self.assertEqual(update_text(self.po, "user"), b"Name: temp\r\nLocn: DL\r\n")
        self.assertIsNone(self.po.user("temp"))

    def test_delete_with_mail_needs_force(self):
        admin.add_user(self.po, "temp", "pw")          # its full directory is waiting for it
        with self.assertRaises(admin.AdminError):
            admin.delete_user(self.po, "temp", notify=False)
        admin.delete_user(self.po, "temp", force=True, notify=False)
        moved = [d for d in os.listdir(os.path.join(WORK, "deleted")) if d.startswith("temp-")]
        self.assertEqual(len(moved), 1)
        self.assertTrue(os.listdir(os.path.join(WORK, "deleted", moved[0], "mail")))

    def test_delete_moves_all_state_and_settings(self):
        admin.add_user(self.po, "temp", "pw", notify=False)

        def change(cfg):
            cfg["users"]["temp"] = {"password": "pw", "email": "temp@example.org",
                                    "fetch": {"protocol": "imaps", "host": "imap.example.org",
                                              "user": "temp", "password": "secret"}}
            cfg["gateway"] = {"post_office": "INTERNET", "aliases": {"sales": "temp", "info": "user"}}
        self.po.update(change)
        os.makedirs(os.path.join(WORK, "fetch"))
        with open(os.path.join(WORK, "fetch", "temp.json"), "w") as f:
            f.write("{}")
        open(os.path.join(WORK, "fetch", "temp.json.lock"), "w").close()
        os.makedirs(os.path.join(WORK, "vim", "temp"))
        canon, lines = admin.user_state(self.po, "temp")
        text = "\n".join(lines)
        self.assertIn("fetch state", text)
        self.assertIn("temp@imap.example.org", text)
        self.assertIn("gateway aliases removed: sales", text)
        self.assertNotIn("secret", text)                       # never shows a password
        admin.delete_user(self.po, "temp", notify=False)
        with open(os.path.join(WORK, "po.json")) as f:
            cfg = json.load(f)
        self.assertNotIn("temp", cfg["users"])
        self.assertEqual(cfg["gateway"]["aliases"], {"info": "user"})
        self.assertFalse(os.path.exists(os.path.join(WORK, "fetch", "temp.json")))
        self.assertFalse(os.path.exists(os.path.join(WORK, "fetch", "temp.json.lock")))
        self.assertFalse(os.path.exists(os.path.join(WORK, "vim", "temp")))
        moved = os.path.join(WORK, "deleted", os.listdir(os.path.join(WORK, "deleted"))[0])
        self.assertTrue(os.path.exists(os.path.join(moved, "fetch.json")))
        self.assertTrue(os.path.isdir(os.path.join(moved, "vim")))

    def test_post_office(self):
        admin.add_post_office(self.po, "BRANCH", "secret", connect="127.0.0.1:5004", mode="LSEC")
        self.assertEqual(update_text(self.po, "bob"), b"Name: BRANCH\r\nLocn: P\r\nAddr: MYPOST\r\n")
        self.assertTrue(self.po.check_po_password("BRANCH", b"SECRET\0"))
        admin.delete_post_office(self.po, "branch")
        self.assertEqual(update_text(self.po, "bob"), b"Name: BRANCH\r\nLocn: DP\r\n")
        self.assertIsNone(self.po.post_office("BRANCH"))

    def test_password_and_lockout_survive(self):
        self.po.record_login("bob", False)
        admin.set_password(self.po, "bob", "new")
        po2 = PostOffice(WORK)
        self.assertTrue(po2.check_password("bob", b"new\0"))
        self.assertEqual(po2.failed_attempts("bob"), 1)


if __name__ == "__main__":
    unittest.main()
