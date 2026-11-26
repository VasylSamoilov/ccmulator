# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Gateway: per-user email address, per-user outgoing SMTP, aliases, the precedence rule (a user
without settings behaves as before; user settings win; no fallback to the smarthost), the MIME
part layout of smtp-link.md §2.4 and the product name; inbound mail for peer post office users
and subaddresses; smarthost TLS. Fake SMTP servers on localhost threads (TLS with a self-signed
certificate made at test time, if openssl is installed), no network. Data in a scratch directory
(CCMAIL_TEST_DIR, else the system temp directory)."""
import base64
import email
import email.policy
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from ccmail import PRODUCT, admin, ade
from ccmail import message as M
from ccmail.gateway import Gateway
from ccmail.link import Link
from ccmail.message import compose
from ccmail.session import Call
from ccmail.store import PostOffice

WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "gateway-tests")


def make_cert(folder):
    """Self-signed certificate for 127.0.0.1 (CN and IP SAN): (server context, cert path) or
    None without openssl."""
    if not shutil.which("openssl"):
        return None
    cert, key = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                       capture_output=True)
    if r.returncode:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx, cert


class FakeSMTP:
    """Records each transaction: {"from", "rcpt", "data", "auth", "tls"}; reject = RCPT reply
    code; tls = server context for STARTTLS, or for implicit TLS with implicit_tls."""

    def __init__(self, reject=None, tls=None, implicit_tls=False):
        self.mails, self.reject = [], reject
        self.tls, self.implicit_tls = tls, implicit_tls
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def close(self):
        self.srv.close()

    def _session(self, conn):
        cur = {"from": None, "rcpt": [], "auth": None, "tls": False}
        try:
            if self.implicit_tls:
                conn = self.tls.wrap_socket(conn, server_side=True)
                cur["tls"] = True
        except (OSError, ssl.SSLError):
            conn.close()
            return
        f = conn.makefile("rb")

        def send(s):
            conn.sendall(s.encode() + b"\r\n")
        send("220 fake ESMTP")
        try:
            while True:
                line = f.readline()
                if not line:
                    return
                cmd = line.decode("latin-1").strip()
                verb = cmd[:4].upper()
                if verb == "EHLO":
                    send("250-fake")
                    if self.tls and not cur["tls"]:
                        send("250-STARTTLS")
                    send("250 AUTH PLAIN")
                elif verb == "STAR" and self.tls and not cur["tls"]:
                    send("220 go ahead")
                    conn = self.tls.wrap_socket(conn, server_side=True)
                    f = conn.makefile("rb")
                    cur["tls"] = True
                elif verb == "AUTH":
                    _authzid, user, pw = base64.b64decode(cmd.split()[2]).split(b"\0")   # AUTH PLAIN
                    cur["auth"] = (user.decode(), pw.decode())
                    send("235 ok")
                elif verb == "MAIL":
                    cur["from"] = cmd[10:].strip().strip("<>")
                    send("250 ok")
                elif verb == "RCPT":
                    if self.reject:
                        send(f"{self.reject} no such user")
                    else:
                        cur["rcpt"].append(cmd[8:].strip().strip("<>"))
                        send("250 ok")
                elif verb == "DATA":
                    send("354 go")
                    data = bytearray()
                    while True:
                        ln = f.readline()
                        if not ln or ln in (b".\r\n", b".\n"):
                            break
                        data += ln[1:] if ln.startswith(b"..") else ln
                    cur["data"] = bytes(data)
                    self.mails.append(dict(cur))
                    send("250 stored")
                elif verb == "QUIT":
                    send("221 bye")
                    return
                else:
                    send("250 ok")
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class GatewayBase(unittest.TestCase):
    def setUp(self):
        self.root = os.path.join(WORK, self.id().rsplit(".", 1)[-1])
        shutil.rmtree(self.root, ignore_errors=True)
        os.makedirs(self.root)
        self.smarthost = FakeSMTP()
        self.own = FakeSMTP()
        self.addCleanup(self.smarthost.close)
        self.addCleanup(self.own.close)

    def configure(self, gateway="default", post_offices=None, **users):
        conf = {"post_office": "MYPOST", "codepage": 437,
                "users": {"Smith, Ann": "123", "bob": "123", "user": "123", "admin": "123"}}
        if post_offices:
            conf["post_offices"] = post_offices
        if gateway == "default":
            gateway = {"post_office": "INTERNET", "domain": "mypost.example",
                       "smarthost": f"127.0.0.1:{self.smarthost.port}", "retry_seconds": 0, "retry_times": 2}
        if gateway is not None:
            conf["gateway"] = gateway
        for name, extra in users.items():
            name = {"ann": "Smith, Ann"}.get(name, name)
            conf["users"][name] = dict({"password": "123"}, **extra)
        with open(os.path.join(self.root, "po.json"), "w", encoding="utf-8") as f:
            json.dump(conf, f)
        self.po = PostOffice(self.root)
        self.gw = self.po.gateway = Gateway(self.po)
        return self.gw

    def ann_smtp(self, **kw):
        return dict({"host": "127.0.0.1", "port": self.own.port, "security": "none",
                     "user": "ann@isp.example", "password": "pw"}, **kw)

    def send(self, author, to="bob@example.com"):
        msg = compose(author, [f"{to} at INTERNET"], "hello", "text line", author_po="MYPOST")
        mid = self.gw.queue_outbound(msg, [to])
        self.gw.send_queue()
        return mid

    def parsed(self, mail):
        return email.message_from_bytes(mail["data"], policy=email.policy.default)

    def mailbox(self, user):
        return [m for _, m in self.po.pending(user)]


class MimeTest(GatewayBase):
    def test_text_and_file_no_empty_part(self):
        gw = self.configure()
        msg = compose("bob", ["x@example.com at INTERNET"], "s", "the note", attachments=[("A.TXT", b"abc")])
        em = gw.to_email(msg, ["x@example.com"])
        parts = list(em.iter_parts())
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0].get_content().strip(), "the note")
        self.assertEqual(parts[0]["Content-Description"], '"cc:Mail Note Part"')
        self.assertEqual(parts[1].get_filename(), "A.TXT")
        self.assertEqual(parts[1].get_payload(decode=True), b"abc")
        self.assertEqual(em["MIME-Version"], "1.0")
        self.assertTrue(all(p["MIME-Version"] is None for p in parts))   # only the top level
        self.assertNotIn(b"\n\n\n--", em.as_bytes().replace(b"\r", b""))

    def test_file_only_no_text_part(self):
        gw = self.configure()
        msg = compose("bob", ["x@example.com at INTERNET"], "s", "", attachments=[("A.BIN", b"\0\1\2")])
        # compose always makes a text item; holding only CR LF it is empty and gets no part
        self.assertEqual([it["data"] for it in msg.logical_items() if it["type"] == "text"], [b"\r\n"])
        em = gw.to_email(msg, ["x@example.com"])
        self.assertEqual([p.get_content_type() for p in em.iter_parts()], ["application/octet-stream"])

    def test_two_text_items_two_parts(self):
        gw = self.configure()
        msg = compose("bob", ["x@example.com at INTERNET"], "s", "first")
        items = msg.logical_items()
        second = dict(items[0], index=items[0]["index"] + 1, data=b"second\r\n")
        msg.logical_items = lambda: items + [second]
        parts = list(gw.to_email(msg, ["x@example.com"]).iter_parts())
        self.assertEqual([p.get_content().strip() for p in parts], ["first", "second"])

    def test_single_text_not_multipart(self):
        gw = self.configure()
        em = gw.to_email(compose("bob", ["x@example.com at INTERNET"], "s", "just text"), ["x@example.com"])
        self.assertEqual(em.get_content_type(), "text/plain")
        self.assertEqual(em.get_content().strip(), "just text")

    def test_product_name(self):
        gw = self.configure()
        raw = gw.to_email(compose("bob", ["x@example.com at INTERNET"], "s", "t"), ["x@example.com"]).as_bytes()
        self.assertIn(f"({PRODUCT})".encode(), raw)
        self.assertNotIn(b"ccmail-server", raw)
        em = email.message_from_bytes(raw, policy=email.policy.default)
        self.assertIn(f"({PRODUCT})", em["X-Mailer"])
        self.assertIn(f"({PRODUCT})", str(em["Received"]))


class OutboundTest(GatewayBase):
    def test_no_settings_as_before(self):
        self.configure()
        self.send("bob")
        self.assertEqual(len(self.smarthost.mails), 1)
        m = self.smarthost.mails[0]
        self.assertEqual((m["from"], m["rcpt"], m["auth"]), ("bob@mypost.example", ["bob@example.com"], None))
        self.assertEqual(self.parsed(m)["From"].addresses[0].addr_spec, "bob@mypost.example")
        self.assertEqual(self.own.mails, [])

    def test_email_only_uses_smarthost(self):
        self.configure(ann={"email": "ann@isp.example"})
        self.send("Smith, Ann")
        m = self.smarthost.mails[0]
        self.assertEqual(m["from"], "ann@isp.example")
        self.assertEqual(self.parsed(m)["From"].addresses[0].addr_spec, "ann@isp.example")
        self.assertEqual(self.parsed(m)["From"].addresses[0].display_name, "Smith, Ann")

    def test_user_smtp_routing(self):
        self.configure(ann={"email": "ann.smith@isp.example", "smtp": self.ann_smtp()})
        self.send("Smith, Ann")
        self.send("bob")
        self.assertEqual(len(self.own.mails), 1)
        m = self.own.mails[0]
        self.assertEqual((m["from"], m["rcpt"], m["auth"]),
                         ("ann.smith@isp.example", ["bob@example.com"], ("ann@isp.example", "pw")))
        self.assertEqual(self.parsed(m)["From"].addresses[0].addr_spec, "ann.smith@isp.example")
        self.assertEqual([x["from"] for x in self.smarthost.mails], ["bob@mypost.example"])
        self.assertEqual(os.listdir(os.path.join(self.root, "outbound")), [])

    def test_smtp_user_as_address(self):
        self.configure(ann={"smtp": self.ann_smtp()})
        self.send("Smith, Ann")
        self.assertEqual(self.own.mails[0]["from"], "ann@isp.example")

    def test_smtp_without_address_refused(self):
        self.configure(ann={"smtp": self.ann_smtp(user="ann")})
        self.assertTrue(any("no \"email\"" in e for e in self.gw.config_errors()))
        self.send("Smith, Ann")
        self.assertEqual((self.own.mails, self.smarthost.mails), ([], []))
        reports = self.mailbox("Smith, Ann")
        self.assertEqual(len(reports), 1)
        self.assertIn('set "email"', reports[0].to_text())
        self.assertEqual(len(os.listdir(os.path.join(self.root, "failed"))), 1)

    def test_no_fallback_to_smarthost(self):
        self.configure(ann={"email": "ann@isp.example", "smtp": self.ann_smtp(port=closed_port())})
        self.send("Smith, Ann")
        self.assertEqual(len(os.listdir(os.path.join(self.root, "outbound"))), 2)    # kept for retry
        self.gw.send_queue()                                   # retry_times 2: gives up now
        self.assertEqual(self.smarthost.mails, [])
        self.assertEqual(os.listdir(os.path.join(self.root, "outbound")), [])
        reports = self.mailbox("Smith, Ann")
        self.assertEqual(len(reports), 1)
        self.assertIn("gave up after 2 attempts", reports[0].to_text())

    def test_user_smtp_removed_after_queueing(self):
        self.configure(ann={"email": "ann@isp.example", "smtp": self.ann_smtp(port=closed_port())})
        msg = compose("Smith, Ann", ["bob@example.com at INTERNET"], "hello", "t", author_po="MYPOST")
        self.gw.queue_outbound(msg, ["bob@example.com"])
        self.po.update(lambda cfg: cfg["users"]["Smith, Ann"].pop("smtp"))
        self.gw.send_queue()
        self.gw.send_queue()
        self.assertEqual(self.smarthost.mails, [])
        self.assertIn("no \"smtp\" settings", self.mailbox("Smith, Ann")[0].to_text())

    def test_starttls_not_offered(self):
        self.configure(ann={"email": "ann@isp.example", "smtp": self.ann_smtp(security="starttls")})
        self.send("Smith, Ann")
        self.assertEqual((self.own.mails, self.smarthost.mails), ([], []))
        with open(os.path.join(self.root, "outbound", os.listdir(os.path.join(self.root, "outbound"))[0]
                               .rsplit(".", 1)[0] + ".json")) as f:
            meta = json.load(f)
        self.assertEqual((meta["via"], meta["tries"]), ("Smith, Ann", 1))
        self.assertIn("STARTTLS", meta["error"])

    def test_relay_refusal_bounces(self):
        self.own.reject = 550
        self.configure(ann={"email": "ann@isp.example", "smtp": self.ann_smtp()})
        self.send("Smith, Ann")
        self.assertIn("550", self.mailbox("Smith, Ann")[0].to_text())

    def test_without_gateway_section(self):
        """Only a user's smtp: no listen, no smarthost, no "gateway" at all."""
        self.configure(gateway=None, ann={"email": "ann@isp.example", "smtp": self.ann_smtp()})
        self.assertTrue(self.gw.enabled)
        self.assertTrue(self.gw.enabled_for("Smith, Ann"))
        self.assertFalse(self.gw.enabled_for("bob"))
        self.send("Smith, Ann")
        self.assertEqual(self.own.mails[0]["from"], "ann@isp.example")
        # bob (no settings) is not sent anywhere: no smarthost, the message stays queued
        self.send("bob")
        self.assertEqual(len(self.own.mails), 1)

    def test_no_settings_no_gateway_unchanged(self):
        self.configure(gateway=None)
        self.assertFalse(self.gw.enabled)
        self.assertFalse(self.gw.enabled_for("bob"))


class InboundTest(GatewayBase):
    def setUp(self):
        super().setUp()
        gw = {"post_office": "INTERNET", "domain": "mypost.example",
              "aliases": {"sales": "Smith, Ann", "info@company.com": "user", "Help@Company.com": "bob",
                          "ghost": "nobody"}}
        self.configure(gateway=gw, ann={"email": "Ann@ISP.example"})

    def test_local_user(self):
        lu = self.gw.local_user
        self.assertEqual(lu("sales@mypost.example"), "Smith, Ann")
        self.assertEqual(lu("<info@company.com>"), "user")
        self.assertEqual(lu("help@company.com"), "bob")             # case-insensitive keys
        self.assertIsNone(lu("sales@other.example"))                # local-part alias: our domain only
        self.assertEqual(lu("ann@isp.example"), "Smith, Ann")       # Ann's own address, any domain
        self.assertEqual(lu("bob@mypost.example"), "bob")           # generated rules still work
        self.assertEqual(lu('"Smith,_Ann"@mypost.example'), "Smith, Ann")
        self.assertEqual(lu("postmaster@mypost.example"), "admin")
        self.assertIsNone(lu("ghost@mypost.example"))               # alias to no user: not found
        self.assertIsNone(lu("someone@isp.example"))

    def test_unknown_charset_delivered(self):
        raw = b'From: a@example.net\r\nSubject: x\r\nContent-Type: text/plain; charset="x-unknown"\r\n\r\nhell\xe9\r\n'
        self.gw.deliver_inbound(raw, ["bob"])
        self.assertIn("hellé", self.mailbox("bob")[0].to_text())

    def test_po_json_mode_kept(self):
        path = os.path.join(self.root, "po.json")
        os.chmod(path, 0o600)
        admin.set_user(self.po, "bob", email="bob@isp.example", notify=False)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_alias_before_rules(self):
        self.po.update(lambda cfg: cfg["gateway"]["aliases"].__setitem__("bob", "user"))
        self.assertEqual(self.gw.local_user("bob@mypost.example"), "user")

    def test_smtp_listener(self):
        a, b = socket.socketpair()
        threading.Thread(target=self.gw._smtp_session, args=(b, ("t", 0)), daemon=True).start()
        f = a.makefile("rb")
        f.readline()
        raw = (b"From: Carol <carol@example.net>\r\nTo: ann@isp.example, Sales <sales@mypost.example>, "
               b"dave@example.net\r\nSubject: hi\r\n\r\nbody\r\n")
        for cmd in (b"HELO x", b"MAIL FROM:<carol@example.net>", b"RCPT TO:<ann@isp.example>",
                    b"RCPT TO:<info@company.com>", b"DATA"):
            a.sendall(cmd + b"\r\n")
            self.assertTrue(f.readline()[:1] in (b"2", b"3"), cmd)
        a.sendall(raw + b".\r\n")
        self.assertEqual(f.readline()[:3], b"250")
        a.sendall(b"QUIT\r\n")
        a.close()
        ann, user = self.mailbox("Smith, Ann"), self.mailbox("user")
        self.assertEqual((len(ann), len(user)), (1, 1))
        # Ann's own address and the alias are local, not shown again as "addr at INTERNET"
        gw_names = [M.text(d) for t, d in ann[0].addr_tlvs if t in (M.TAG_SENT_TO, M.TAG_CC_SENT)]
        self.assertIn("dave@example.net", gw_names)
        self.assertFalse({"ann@isp.example", "sales@mypost.example"} & {n.lower() for n in gw_names})


class PeerInboundTest(GatewayBase):
    """Inbound mail for users of peer post offices (Name_at_PO, Name+PO), subaddressing for our
    own users, and the peer address form outbound."""

    def setUp(self):
        super().setUp()
        self.gw_cfg = {"post_office": "INTERNET", "domain": "mypost.example",
                       "smarthost": f"127.0.0.1:{self.smarthost.port}", "retry_seconds": 0,
                       "aliases": {"sales": "Smith, Ann"}}
        pos = {"BRANCH": {"password": "x"}, "WEST_HUB": {"password": "x"}, "EAST-1": {"password": "x"}}
        self.configure(gateway=self.gw_cfg, post_offices=pos)

    def learn(self, *entries):
        """ADE directory entries as learned from a partner: (name, locn, addr, via)."""
        def change(state):
            for name, locn, addr, via in entries:
                state["entries"][name.lower()] = {"name": name, "locn": locn, "addr": addr, "cmts": "",
                                                  "via": via}
        ade.update(self.po, change)

    def rcpt(self, local):
        return self.gw.recipient(f"{local}@mypost.example")

    def smtp(self, *rcpts, raw=b"From: Carol <carol@example.net>\r\nSubject: hi\r\n\r\nbody\r\n"):
        """One SMTP transaction to our listener: the RCPT reply codes."""
        a, b = socket.socketpair()
        threading.Thread(target=self.gw._smtp_session, args=(b, ("t", 0)), daemon=True).start()
        f = a.makefile("rb")
        f.readline()
        codes = []
        for cmd in [b"HELO x", b"MAIL FROM:<carol@example.net>"] + [b"RCPT TO:<%s>" % r.encode() for r in rcpts]:
            a.sendall(cmd + b"\r\n")
            codes.append(f.readline()[:3].decode())
        codes = codes[2:]
        if "250" in codes:
            a.sendall(b"DATA\r\n")
            self.assertEqual(f.readline()[:3], b"354")
            a.sendall(raw + b".\r\n")
            self.assertEqual(f.readline()[:3], b"250")
        a.sendall(b"QUIT\r\n")
        f.readline()
        a.close()
        return codes

    def sent_copy(self, po):
        """What the call to po would send (session.py: routed() + for_post_office())."""
        out = [m.for_post_office(po, self.po.name) for _, m in self.po.routed(po)]
        return [m for m in out if m is not None]

    @staticmethod
    def pending_to(msg):
        """(name, 0F run) of each pending 03 entry."""
        tl, out = list(msg.addr_tlvs), []
        for i, (t, d) in enumerate(tl):
            if t == M.TAG_TO:
                run, j = [], i + 1
                while j < len(tl) and tl[j][0] == M.TAG_PATH:
                    run.append(M.text(tl[j][1]))
                    j += 1
                out.append((M.text(d), run))
        return out

    def test_peer_user_at_form(self):
        self.assertEqual(self.rcpt("Kit_Walker_at_BRANCH"), ("peer", "Kit Walker", "BRANCH", "BRANCH"))
        self.assertEqual(self.rcpt("kit_walker_at_branch"), ("peer", "kit walker", "BRANCH", "BRANCH"))
        self.assertIsNone(self.rcpt("Kit_Walker_at_NOWHERE"))           # unknown post office: 550
        self.assertEqual(self.rcpt("bob_at_MYPOST"), ("local", "bob"))  # our own post office
        self.assertIsNone(self.rcpt("nobody_at_MYPOST"))
        self.assertEqual(self.rcpt("Kit_at_WEST__HUB"), ("peer", "Kit", "WEST_HUB", "WEST_HUB"))
        self.assertEqual(self.rcpt("Kit_at_EAST-1"), ("peer", "Kit", "EAST-1", "EAST-1"))

    def test_peer_user_plus_form(self):
        self.assertEqual(self.rcpt("Kit_Walker+BRANCH"), ("peer", "Kit Walker", "BRANCH", "BRANCH"))
        self.assertEqual(self.rcpt("Kit+WEST__HUB"), ("peer", "Kit", "WEST_HUB", "WEST_HUB"))
        self.assertEqual(self.rcpt("bob+MYPOST"), ("local", "bob"))
        # a post office detail wins over our own user of that name; no silent fallback
        self.assertEqual(self.rcpt("bob+BRANCH"), ("peer", "bob", "BRANCH", "BRANCH"))
        self.assertIsNone(self.rcpt("+BRANCH"))

    def test_subaddress_local(self):
        self.assertEqual(self.rcpt("bob+lists"), ("local", "bob"))
        self.assertEqual(self.rcpt('"Smith,_Ann+news"'), ("local", "Smith, Ann"))
        self.assertEqual(self.rcpt("Ann_Smith+anything"), ("local", "Smith, Ann"))
        self.assertEqual(self.rcpt("sales+promo"), ("local", "Smith, Ann"))    # alias of the base
        self.assertEqual(self.rcpt("postmaster+x"), ("local", "admin"))
        self.assertIsNone(self.rcpt("nobody+lists"))
        self.assertEqual(self.rcpt("bob_at_MYPOST+x"), ("local", "bob"))
        self.assertEqual(self.rcpt("Kit_at_BRANCH+x"), ("peer", "Kit", "BRANCH", "BRANCH"))

    def test_subaddress_own_email(self):
        self.po.update(lambda cfg: cfg["users"].__setitem__("bob", {"password": "1", "email": "rb@isp.example"}))
        self.assertEqual(self.gw.recipient("rb+news@isp.example"), ("local", "bob"))
        self.po.update(lambda cfg: cfg["users"].__setitem__("bob", {"password": "1", "email": "rb@mypost.example"}))
        self.assertEqual(self.rcpt("rb+news"), ("local", "bob"))
        self.assertEqual(self.rcpt("rb+BRANCH"), ("peer", "rb", "BRANCH", "BRANCH"))   # a post office wins

    def test_user_with_plus_in_name(self):
        self.po.update(lambda cfg: cfg["users"].__setitem__("A+B", "123"))
        self.assertEqual(self.rcpt("A+B"), ("local", "A+B"))              # the exact name first

    def test_peer_directory_known(self):
        """With entries learned from BRANCH the name must be one of them; the stored spelling wins."""
        self.learn(("Walker, Kit", "L", "BRANCH", "BRANCH"))
        self.assertEqual(self.rcpt('"walker,_kit_at_BRANCH"'), ("peer", "Walker, Kit", "BRANCH", "BRANCH"))
        self.assertEqual(self.rcpt('"Walker,_Kit+BRANCH"'), ("peer", "Walker, Kit", "BRANCH", "BRANCH"))
        self.assertIsNone(self.rcpt("Somebody_Else_at_BRANCH"))
        self.assertIsNotNone(self.rcpt("Somebody_Else_at_EAST-1"))       # nothing learned from EAST-1

    def test_learned_post_office(self):
        """A post office known only through directory exchange: queued for the partner that
        reaches it, with the next hop added to the route (ade.add_routes)."""
        self.learn(("FARAWAY", "P", "BRANCH", "BRANCH"), ("Kit Walker", "L", "FARAWAY", "BRANCH"))
        self.assertEqual(self.rcpt("Kit_Walker_at_FARAWAY"), ("peer", "Kit Walker", "FARAWAY", "BRANCH"))
        self.assertEqual(self.smtp("Kit_Walker+FARAWAY@mypost.example"), ["250"])
        copies = self.sent_copy("BRANCH")
        self.assertEqual(len(copies), 1)
        self.assertEqual(self.pending_to(copies[0]), [("Kit Walker", ["FARAWAY", "BRANCH"])])

    def test_round_trip_outbound_inbound(self):
        """address_of() for a peer user, fed back to RCPT, finds that user again (both forms)."""
        names = [("Kit Walker", "BRANCH"), ("Walker, Kit", "BRANCH"), ("Kit_Walker", "WEST_HUB"),
                 ("Kit Walker (ACME)", "EAST-1"), ("J. Doe", "BRANCH")]
        for mode in ("at", "plus"):
            self.gw.peer_address = mode
            for name, po in names:
                addr = self.gw.address_of(name, [po])
                self.assertIn("_at_" if mode == "at" else "+", addr)
                r = self.gw.recipient(addr)
                want = name.split(" (")[0]
                self.assertEqual(r, ("peer", want, po, po), (mode, addr))
        self.gw.peer_address = "at"
        self.assertEqual(self.gw.address_of("Kit Walker", ["BRANCH"]), "Kit_Walker_at_BRANCH@mypost.example")
        # made from "name at PO" as before (and as the cc:Mail gateway): the comment leaves "__"
        self.assertEqual(self.gw.address_of("Kit Walker (ACME)", ["BRANCH"]), "Kit_Walker__at_BRANCH@mypost.example")
        self.assertEqual(self.gw.address_of("Kit_Walker", ["BRANCH"]), "Kit__Walker_at_BRANCH@mypost.example")
        self.assertEqual(self.rcpt("Kit_Walker__at_BRANCH"), ("peer", "Kit Walker", "BRANCH", "BRANCH"))
        self.assertEqual(self.rcpt("Kit__Walker_at_BRANCH"), ("peer", "Kit_Walker", "BRANCH", "BRANCH"))
        self.assertEqual(self.rcpt("Kit___at_BRANCH"), ("peer", "Kit_", "BRANCH", "BRANCH"))
        self.assertEqual(self.rcpt("bob__at_MYPOST"), ("local", "bob"))
        self.gw.peer_address = "plus"
        self.assertEqual(self.gw.address_of("Kit Walker", ["BRANCH"]), "Kit_Walker+BRANCH@mypost.example")
        self.assertEqual(self.gw.address_of("Walker, Kit", ["BRANCH"]), '"Walker,_Kit+BRANCH"@mypost.example')
        self.assertEqual(self.gw.address_of("bob", ["MYPOST"]), "bob@mypost.example")

    def test_peer_address_option_from(self):
        """From of a peer user's mail through our gateway, in both forms."""
        for mode, want in (("at", "Kit_Walker_at_BRANCH@mypost.example"),
                           ("plus", "Kit_Walker+BRANCH@mypost.example")):
            self.po.update(lambda cfg: cfg["gateway"].__setitem__("peer_address", mode))
            self.gw = self.po.gateway = Gateway(self.po)
            msg = compose("Kit Walker", ["x@example.com at INTERNET"], "s", "t", author_po="BRANCH")
            self.assertEqual(self.gw.to_email(msg, ["x@example.com"])["From"].addresses[0].addr_spec, want)
        self.po.update(lambda cfg: cfg["gateway"].__setitem__("peer_address", "dots"))
        self.assertTrue(any("peer_address" in e for e in Gateway(self.po).config_errors()))

    def test_smtp_mixed_local_and_peer(self):
        codes = self.smtp("bob@mypost.example", "Kit_Walker_at_BRANCH@mypost.example",
                          "Jo+EAST-1@mypost.example", "nobody_at_BRANCH@mypost.example",
                          "x_at_NOWHERE@mypost.example", "kit+NOWHERE@mypost.example")
        # nobody_at_BRANCH: nothing learned from BRANCH, so BRANCH decides; kit+NOWHERE: NOWHERE
        # is no post office, so it is the subaddress of "kit", who is not ours
        self.assertEqual(codes, ["250", "250", "250", "250", "550", "550"])
        bob = self.mailbox("bob")
        self.assertEqual(len(bob), 1)
        self.assertEqual(self.pending_to(bob[0]), [("bob", [])])
        branch = self.sent_copy("BRANCH")
        self.assertEqual(len(branch), 1)
        self.assertEqual(self.pending_to(branch[0]), [("Kit Walker", ["BRANCH"]), ("nobody", ["BRANCH"])])
        self.assertIn("body", branch[0].to_text())
        self.assertEqual(branch[0].author, "Carol <carol@example.net>")
        east = self.sent_copy("EAST-1")
        self.assertEqual([self.pending_to(m) for m in east], [[("Jo", ["EAST-1"])]])
        self.assertEqual(self.sent_copy("WEST_HUB"), [])

    def test_peer_unconvertible_notice_routed(self):
        with mock.patch.object(Gateway, "from_email", side_effect=ValueError("broken")):
            self.gw.deliver_inbound(b"Subject: x\r\n\r\ny\r\n", [], peers=[("Kit", "BRANCH", "BRANCH")])
        copies = self.sent_copy("BRANCH")
        self.assertEqual(len(copies), 1)
        self.assertIn("could not be converted", copies[0].subject)
        self.assertEqual(self.pending_to(copies[0]), [("Kit", ["BRANCH"])])


class SmarthostTLSTest(GatewayBase):
    """The shared smarthost: STARTTLS and implicit TLS check the certificate (verify_tls)."""

    def setUp(self):
        super().setUp()
        made = make_cert(self.root)
        if not made:
            self.skipTest("no openssl")
        self.ctx, self.cert = made

    def relay(self, **kw):
        srv = FakeSMTP(tls=self.ctx, implicit_tls=kw.pop("implicit", False))
        self.addCleanup(srv.close)
        gw = dict({"post_office": "INTERNET", "domain": "mypost.example", "smarthost": f"127.0.0.1:{srv.port}",
                   "retry_seconds": 0, "retry_times": 3}, **kw)
        self.configure(gateway=gw)
        return srv

    def queued_error(self):
        out = os.path.join(self.root, "outbound")
        metas = [f for f in os.listdir(out) if f.endswith(".json")]
        self.assertEqual(len(metas), 1)
        with open(os.path.join(out, metas[0])) as f:
            return json.load(f)["error"]

    def test_starttls_self_signed_refused(self):
        srv = self.relay(starttls=True)
        self.send("bob")
        self.assertEqual(srv.mails, [])
        self.assertIn("CERTIFICATE_VERIFY_FAILED", self.queued_error())

    def test_security_starttls_self_signed_refused(self):
        srv = self.relay(security="starttls", username="u", password="p")
        self.send("bob")
        self.assertEqual(srv.mails, [])
        self.assertIn("CERTIFICATE_VERIFY_FAILED", self.queued_error())

    def test_starttls_no_verify(self):
        srv = self.relay(starttls=True, verify_tls=False, username="u", password="p")
        self.send("bob")
        self.assertEqual(len(srv.mails), 1)
        self.assertEqual((srv.mails[0]["tls"], srv.mails[0]["auth"]), (True, ("u", "p")))

    def test_starttls_trusted_certificate(self):
        """Verification on, the certificate trusted (SSL_CERT_FILE): delivered."""
        srv = self.relay(security="starttls")
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": self.cert}):
            self.send("bob")
        self.assertEqual(len(srv.mails), 1)
        self.assertTrue(srv.mails[0]["tls"])

    def test_implicit_tls(self):
        srv = self.relay(security="ssl", implicit=True)
        self.send("bob")
        self.assertEqual(srv.mails, [])
        self.assertIn("CERTIFICATE_VERIFY_FAILED", self.queued_error())
        self.po.update(lambda cfg: cfg["gateway"].__setitem__("verify_tls", False))
        self.gw = self.po.gateway = Gateway(self.po)
        self.gw.send_queue()
        self.assertEqual(len(srv.mails), 1)
        self.assertTrue(srv.mails[0]["tls"])

    def test_starttls_not_offered(self):
        self.configure(gateway={"post_office": "INTERNET", "domain": "mypost.example", "security": "starttls",
                                "smarthost": f"127.0.0.1:{self.smarthost.port}", "retry_seconds": 0,
                                "retry_times": 3, "username": "u", "password": "p"})
        self.send("bob")
        self.assertEqual(self.smarthost.mails, [])
        self.assertIn("STARTTLS", self.queued_error())

    def test_plain_as_before(self):
        self.configure()
        self.send("bob")
        self.assertEqual(len(self.smarthost.mails), 1)
        self.assertFalse(self.smarthost.mails[0]["tls"])

    def test_config_errors(self):
        self.relay(security="tls")
        self.assertTrue(any('"security"' in e for e in self.gw.config_errors()))
        self.send("bob")
        self.assertIn('"security"', self.queued_error())        # kept, retried, not sent plain
        self.relay(security="none", starttls=True)
        self.assertTrue(any("contradicts" in e for e in self.gw.config_errors()))


class SessionTest(GatewayBase):
    """Upload over a real Call: internet recipients are accepted for a user with their own smtp
    when there is no gateway section; for others as before (83)."""

    def upload(self, user, msg):
        a, b = socket.socketpair()
        a.settimeout(30)
        t = threading.Thread(target=lambda: _quiet(Call(Link(b, "t"), self.po, "t").run), daemon=True)
        t.start()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        buf = bytearray()

        def code():
            while True:
                while not buf:
                    buf.extend(a.recv(65536))
                c = buf.pop(0)
                if c != 0x91:
                    return c

        def read(n):
            while len(buf) < n:
                buf.extend(a.recv(65536))
            out = bytes(buf[:n])
            del buf[:n]
            return out

        def lstring(s):
            x = s.encode("cp850") + b"\0"
            return bytes([len(x)]) + x
        a.sendall(b"\x80")
        self.assertEqual(code(), 0x81)
        a.sendall(lstring(user))
        self.assertEqual(code(), 0x8B)
        a.sendall(lstring("123"))
        self.assertEqual(code(), 0x82)
        read(read(1)[0])
        a.sendall(b"\x82\x84")
        self.assertEqual(code(), 0x85)
        a.sendall(struct.pack("<H", len(msg.record)) + msg.record)
        verdict = code()
        r = code()
        if r == 0x86:
            a.sendall(msg.body)
            r = code()
        return verdict, r

    def test_user_smtp_accepts_internet(self):
        self.configure(gateway=None, ann={"email": "ann@isp.example", "smtp": self.ann_smtp()})
        msg = compose("Smith, Ann", ["bob@example.com at INTERNET"], "out", "t")
        self.assertEqual(self.upload("Smith, Ann", msg), (0x82, 0x87))
        self.assertEqual(len([f for f in os.listdir(os.path.join(self.root, "outbound")) if f.endswith(".json")]), 1)

    def test_no_settings_refused_as_before(self):
        self.configure(gateway=None, ann={"email": "ann@isp.example", "smtp": self.ann_smtp()})
        msg = compose("bob", ["carol@example.com at INTERNET"], "out", "t")
        self.assertEqual(self.upload("bob", msg), (0x83, 0x89))


class AdminTest(GatewayBase):
    def test_set_email_keeps_other_keys(self):
        self.configure(ann={"fetch": {"protocol": "pop3", "host": "h", "user": "u"}})
        admin.set_user(self.po, "Smith, Ann", email="ann@isp.example", notify=False)
        e = self.po.user_entry("Smith, Ann")
        self.assertEqual((e["email"], e["fetch"]["host"]), ("ann@isp.example", "h"))
        with self.assertRaises(admin.AdminError):
            admin.set_user(self.po, "bob", email="ANN@isp.example", notify=False)
        with self.assertRaises(admin.AdminError):
            admin.set_user(self.po, "bob", email="not an address", notify=False)
        admin.set_user(self.po, "Smith, Ann", email="", notify=False)
        self.assertNotIn("email", self.po.user_entry("Smith, Ann"))
        admin.set_user(self.po, "bob", email="bob@isp.example", notify=False)
        self.assertEqual(self.po.user_entry("bob"), {"password": "123", "email": "bob@isp.example"})

    def test_rename_moves_fetch_state_and_aliases(self):
        gw = {"post_office": "INTERNET", "domain": "mypost.example", "aliases": {"sales": "Smith, Ann"}}
        self.configure(gateway=gw, ann={"fetch": {"protocol": "pop3", "host": "h", "user": "u"}})
        from ccmail.fetch import Fetcher
        fx = Fetcher(self.po)
        fx.save_state("Smith, Ann", {"account": "pop3://u@h", "uidls": ["a"]})
        admin.rename_user(self.po, "Smith, Ann", "Jones, Ann", notify=False)
        self.assertFalse(os.path.exists(fx.state_path("Smith, Ann")))
        self.assertTrue(os.path.exists(fx.state_path("Jones, Ann")))
        self.assertEqual(self.gw.local_user("sales@mypost.example"), "Jones, Ann")


def _quiet(f):
    try:
        f()
    except Exception:
        pass


if __name__ == "__main__":
    unittest.main()
