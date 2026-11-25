# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Per-user fetching (ccmail/fetch.py) against small fake POP3 and IMAP servers on localhost
threads: what is taken, the state files, after=seen/delete, UIDVALIDITY changes, restarts,
STLS/STARTTLS refusal, TLS with a self-signed certificate made at test time in the scratch
directory (skipped without openssl), and the fetch at the start of a call. No real accounts,
no network. Data in a scratch directory (CCMAIL_TEST_DIR, else the system temp directory)."""
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from ccmail import fetch as F
from ccmail.fetch import Fetcher, FetchError
from ccmail.gateway import ConfigError
from ccmail.link import Link
from ccmail.session import Call
from ccmail.store import PostOffice

WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "fetch-tests")
HAVE_OPENSSL = shutil.which("openssl") is not None


def mail(n, sender="Alice <alice@example.com>", to="ann@isp.example", mid=True):
    h = f"From: {sender}\r\nTo: {to}\r\nSubject: message {n}\r\nDate: Thu, 26 Nov 2026 10:00:{n:02d} +0000\r\n"
    if mid:
        h += f"Message-ID: <m{n}@example.com>\r\n"
    return (h + f"\r\nbody of message {n}\r\n.line starting with a dot\r\n").encode()


def make_cert(folder):
    """Self-signed certificate for 127.0.0.1, or None without openssl."""
    if not shutil.which("openssl"):
        return None
    cert, key = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-days", "1", "-subj", "/CN=127.0.0.1"], capture_output=True)
    if r.returncode:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


class FakeServer:
    """Accept loop on 127.0.0.1:<free port>; handle(conn) per connection."""

    def __init__(self, tls=None, implicit_tls=False, delay=0):
        self.tls, self.implicit_tls, self.delay = tls, implicit_tls, delay
        self.commands = []
        self.lock = threading.Lock()
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
            threading.Thread(target=self._run, args=(conn,), daemon=True).start()

    def _run(self, conn):
        try:
            if self.delay:
                time.sleep(self.delay)
            if self.implicit_tls:
                conn = self.tls.wrap_socket(conn, server_side=True)
            self.handle(conn)
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def close(self):
        self.srv.close()

    def log(self, cmd):
        with self.lock:
            self.commands.append(cmd)

    def verbs(self):
        return [c.split(" ")[0].upper() for c in self.commands]


class FakePOP3(FakeServer):
    def __init__(self, messages, stls=False, uidl=True, **kw):
        super().__init__(**kw)
        self.msgs = [[f"uid-{i}", m] for i, m in enumerate(messages, 1)]
        self.next = len(self.msgs) + 1
        self.stls, self.uidl = stls, uidl

    def add(self, m):
        with self.lock:
            self.msgs.append([f"uid-{self.next}", m])
            self.next += 1

    def handle(self, conn):
        f = conn.makefile("rb")
        send = lambda s: conn.sendall(s.encode() + b"\r\n")  # noqa: E731
        send("+OK fake POP3")
        with self.lock:
            snap = list(self.msgs)
        deleted, authed, user = set(), False, None
        while True:
            line = f.readline()
            if not line:
                return
            cmd = line.decode().strip()
            self.log(cmd)
            verb, _, arg = cmd.partition(" ")
            verb = verb.upper()
            if verb == "CAPA":
                send("+OK")
                for c in ["USER"] + (["UIDL"] if self.uidl else []) + (["STLS"] if self.stls and self.tls else []):
                    send(c)
                send(".")
            elif verb == "STLS" and self.stls and self.tls:
                send("+OK begin TLS")
                conn = self.tls.wrap_socket(conn, server_side=True)
                f = conn.makefile("rb")
                send = lambda s, c=conn: c.sendall(s.encode() + b"\r\n")  # noqa: E731
            elif verb == "USER":
                user = arg
                send("+OK")
            elif verb == "PASS":
                authed = (user, arg) == ("ann", "secret")
                send("+OK" if authed else "-ERR bad login")
            elif not authed:
                send("-ERR not logged in")
            elif verb == "STAT":
                send(f"+OK {len(snap)} {sum(len(m) for _, m in snap)}")
            elif verb == "UIDL" and self.uidl:
                send("+OK")
                for i, (uid, _) in enumerate(snap, 1):
                    if i not in deleted:
                        send(f"{i} {uid}")
                send(".")
            elif verb == "LIST":
                send("+OK")
                for i, (_, m) in enumerate(snap, 1):
                    send(f"{i} {len(m)}")
                send(".")
            elif verb == "RETR":
                m = snap[int(arg) - 1][1]
                send("+OK")
                for ln in m.split(b"\r\n")[:-1]:
                    conn.sendall((b"." + ln if ln.startswith(b".") else ln) + b"\r\n")
                send(".")
            elif verb == "DELE":
                deleted.add(int(arg))
                send("+OK")
            elif verb == "QUIT":
                with self.lock:
                    gone = {snap[i - 1][0] for i in deleted}
                    self.msgs = [m for m in self.msgs if m[0] not in gone]
                send("+OK bye")
                return
            else:
                send("-ERR unknown")


def uid_set(spec, uids):
    """IMAP sequence set over UIDs; n:* matches the largest UID even below n (RFC 3501)."""
    top = max(uids) if uids else 0
    out = set()
    for part in spec.split(","):
        a, _, b = part.partition(":")
        lo = top if a == "*" else int(a)
        hi = lo if not b else (top if b == "*" else int(b))
        lo, hi = min(lo, hi), max(lo, hi)
        out |= {u for u in uids if lo <= u <= hi}
    return out


class FakeIMAP(FakeServer):
    def __init__(self, messages, uidvalidity=7, starttls=False, uid_last=False, **kw):
        super().__init__(**kw)
        self.uidvalidity, self.uid_last = uidvalidity, uid_last
        self.msgs = []          # dicts: uid, data, flags
        self.next_uid = 1
        self.starttls = starttls
        for m in messages:
            self.add(m)

    def add(self, m):
        with self.lock:
            self.msgs.append({"uid": self.next_uid, "data": m, "flags": set()})
            self.next_uid += 1

    def renumber(self, first_uid, uidvalidity):
        with self.lock:
            self.uidvalidity = uidvalidity
            for i, m in enumerate(self.msgs):
                m["uid"] = first_uid + i
            self.next_uid = first_uid + len(self.msgs)

    def flags(self):
        return [sorted(m["flags"]) for m in self.msgs]

    def handle(self, conn):
        f = conn.makefile("rb")
        state = {"conn": conn, "tls": self.implicit_tls}

        def send(s):
            state["conn"].sendall(s if isinstance(s, bytes) else s.encode() + b"\r\n")

        send("* OK fake IMAP ready")
        authed, readonly = False, True
        while True:
            line = f.readline()
            if not line:
                return
            cmd = line.decode().strip()
            self.log(" ".join(cmd.split(" ")[1:]))
            tag, _, rest = cmd.partition(" ")
            verb, _, arg = rest.partition(" ")
            verb = verb.upper()
            if verb == "CAPABILITY":
                caps = "IMAP4rev1" + (" STARTTLS" if self.starttls and self.tls and not state["tls"] else "")
                send(f"* CAPABILITY {caps}")
                send(f"{tag} OK done")
            elif verb == "STARTTLS" and self.starttls and self.tls:
                send(f"{tag} OK begin TLS")
                state["conn"] = self.tls.wrap_socket(state["conn"], server_side=True)
                state["tls"] = True
                f = state["conn"].makefile("rb")
            elif verb == "LOGIN":
                u, p = [x.strip('"') for x in arg.split(" ", 1)]
                authed = (u, p) == ("ann", "secret")
                send(f"{tag} OK logged in" if authed else f"{tag} NO bad login")
            elif verb == "LOGOUT":
                send("* BYE")
                send(f"{tag} OK bye")
                return
            elif verb == "NOOP":
                send(f"{tag} OK")
            elif not authed:
                send(f"{tag} BAD not logged in")
            elif verb in ("SELECT", "EXAMINE"):
                readonly = verb == "EXAMINE"
                with self.lock:
                    send(f"* {len(self.msgs)} EXISTS")
                    send(f"* OK [UIDVALIDITY {self.uidvalidity}] UIDs valid")
                    send(f"* OK [UIDNEXT {self.next_uid}] next")
                send(f"{tag} OK [{'READ-ONLY' if readonly else 'READ-WRITE'}] selected")
            elif verb == "UID":
                sub, _, args = arg.partition(" ")
                sub = sub.upper()
                with self.lock:
                    uids = [m["uid"] for m in self.msgs]
                    if sub == "SEARCH":
                        a = args.split(" ")
                        found = uids if a[0].upper() == "ALL" else sorted(uid_set(a[1], uids))
                        send("* SEARCH" + "".join(f" {u}" for u in found))
                    elif sub == "FETCH":
                        spec, items = args.split(" ", 1)
                        want = uid_set(spec, uids)
                        for seq, m in enumerate(self.msgs, 1):
                            if m["uid"] not in want:
                                continue
                            if "HEADER" in items.upper():
                                data, name = m["data"].split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n", "BODY[HEADER]"
                            else:
                                data, name = m["data"], "BODY[]"
                                if "PEEK" not in items.upper() and not readonly:
                                    m["flags"].add("\\Seen")
                            if self.uid_last:           # data items in the other order
                                send(f"* {seq} FETCH ({name} {{{len(data)}}}\r\n".encode() + data
                                     + f" UID {m['uid']})\r\n".encode())
                            else:
                                send(f"* {seq} FETCH (UID {m['uid']} {name} {{{len(data)}}}\r\n".encode()
                                     + data + b")\r\n")
                    elif sub == "STORE":
                        spec, op, fl = args.split(" ", 2)
                        if readonly:
                            send(f"{tag} NO read-only")
                            continue
                        for m in self.msgs:
                            if m["uid"] in uid_set(spec, uids) and op.upper().startswith("+FLAGS"):
                                m["flags"] |= set(fl.strip("()").split())
                send(f"{tag} OK done")
            elif verb == "EXPUNGE":
                with self.lock:
                    for seq in range(len(self.msgs), 0, -1):
                        if "\\Deleted" in self.msgs[seq - 1]["flags"]:
                            del self.msgs[seq - 1]
                            send(f"* {seq} EXPUNGE")
                send(f"{tag} OK expunged")
            else:
                send(f"{tag} BAD unknown")


class FetchBase(unittest.TestCase):
    def setUp(self):
        self.root = os.path.join(WORK, self.id().rsplit(".", 1)[-1])
        shutil.rmtree(self.root, ignore_errors=True)
        os.makedirs(self.root)
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.close()

    def configure(self, server, **fetch):
        fetch.setdefault("host", "127.0.0.1")
        fetch.setdefault("port", server.port)
        fetch.setdefault("user", "ann")
        fetch.setdefault("password", "secret")
        fetch.setdefault("security", "none")
        conf = {"post_office": "MYPOST", "codepage": 437,
                "users": {"Smith, Ann": {"password": "123", "fetch": fetch}, "bob": "123"}}
        with open(os.path.join(self.root, "po.json"), "w", encoding="utf-8") as f:
            json.dump(conf, f)
        self.servers.append(server)
        return self.fetcher()

    def fetcher(self):
        """New objects each time: a restart reads only the state file."""
        return Fetcher(PostOffice(self.root))

    def mailbox(self):
        return PostOffice(self.root).pending("Smith, Ann")

    def subjects(self):
        return sorted(m.subject for _, m in self.mailbox())

    def state(self):
        with open(os.path.join(self.root, "fetch", "Smith, Ann.json"), encoding="utf-8") as f:
            return json.load(f)


class POP3Test(FetchBase):
    def test_takes_all_then_nothing_then_new_once(self):
        srv = FakePOP3([mail(1), mail(2), mail(3)])
        fx = self.configure(srv, protocol="pop3")
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 3)
        self.assertEqual(self.subjects(), ["message 1", "message 2", "message 3"])
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])
        srv.add(mail(4))
        taken = fx.fetch_user("Smith, Ann")
        self.assertEqual([t["subject"] for t in taken], ["message 4"])
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])
        self.assertEqual(len(self.mailbox()), 4)
        self.assertEqual(self.state()["uidls"], ["uid-1", "uid-2", "uid-3", "uid-4"])
        self.assertEqual(len(srv.msgs), 4)                  # keep: nothing deleted
        # converted as the gateway does: author is the sender at the gateway post office
        _, m = self.mailbox()[0]
        self.assertIn("alice@example.com", m.author)
        self.assertIn(".line starting with a dot", m.to_text())

    def test_restart_does_not_refetch(self):
        srv = FakePOP3([mail(1), mail(2)])
        self.configure(srv, protocol="pop3").fetch_user("Smith, Ann")
        retr = srv.verbs().count("RETR")
        self.assertEqual(self.fetcher().fetch_user("Smith, Ann"), [])
        self.assertEqual(srv.verbs().count("RETR"), retr)    # no body downloaded again
        self.assertEqual(len(self.mailbox()), 2)

    def test_delete_and_prune(self):
        srv = FakePOP3([mail(1), mail(2)])
        fx = self.configure(srv, protocol="pop3", after="delete")
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 2)
        self.assertEqual(srv.msgs, [])
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])
        self.assertEqual(self.state()["uidls"], [])          # gone from the server: pruned

    def test_prune_keep(self):
        srv = FakePOP3([mail(1), mail(2)])
        fx = self.configure(srv, protocol="pop3")
        fx.fetch_user("Smith, Ann")
        srv.msgs = srv.msgs[1:]                              # deleted by another client
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])
        self.assertEqual(self.state()["uidls"], ["uid-2"])

    def test_no_uidl_refused(self):
        srv = FakePOP3([mail(1)], uidl=False)
        fx = self.configure(srv, protocol="pop3")
        with self.assertRaises(FetchError):
            fx.fetch_user("Smith, Ann")
        self.assertEqual(self.mailbox(), [])
        self.assertNotIn("RETR", srv.verbs())

    def test_starttls_not_offered(self):
        srv = FakePOP3([mail(1)])
        fx = self.configure(srv, protocol="pop3", security="starttls")
        with self.assertRaises(FetchError):
            fx.fetch_user("Smith, Ann")
        self.assertNotIn("USER", srv.verbs())
        self.assertNotIn("PASS", srv.verbs())
        self.assertEqual(self.mailbox(), [])

    def test_failed_store_not_taken(self):
        srv = FakePOP3([mail(1), mail(2)])
        fx = self.configure(srv, protocol="pop3", after="delete")
        real = fx.gateway.deliver_inbound
        calls = []

        def flaky(raw, users, source=None):
            calls.append(raw)
            if len(calls) == 2:
                raise OSError("disk full")
            return real(raw, users)
        fx.gateway.deliver_inbound = flaky
        with self.assertRaises(OSError):
            fx.fetch_user("Smith, Ann")
        self.assertEqual(self.state()["uidls"], ["uid-1"])
        self.assertEqual(len(srv.msgs), 2)                   # no QUIT: no deletion committed
        fx.gateway.deliver_inbound = real
        self.assertEqual([t["subject"] for t in fx.fetch_user("Smith, Ann")], ["message 2"])
        self.assertEqual(srv.msgs, [])                       # the taken one deleted again
        self.assertEqual(len(self.mailbox()), 2)

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl for a test certificate")
    def test_stls(self):
        ctx = make_cert(self.root)
        if not ctx:
            self.skipTest("no openssl")
        srv = FakePOP3([mail(1)], stls=True, tls=ctx)
        fx = self.configure(srv, protocol="pop3", security="starttls", verify_tls=False)
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 1)
        v = srv.verbs()
        self.assertLess(v.index("STLS"), v.index("USER"))
        # verify_tls true refuses the self-signed certificate
        fx = self.configure(srv, protocol="pop3", security="starttls")
        with self.assertRaises(ssl.SSLError):
            fx.fetch_user("Smith, Ann")

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl for a test certificate")
    def test_pop3s(self):
        ctx = make_cert(self.root)
        if not ctx:
            self.skipTest("no openssl")
        srv = FakePOP3([mail(1), mail(2)], tls=ctx, implicit_tls=True)
        fx = self.configure(srv, protocol="pop3s", security=None, verify_tls=False)
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 2)


class IMAPTest(FetchBase):
    def test_takes_all_then_nothing_then_new_once_keep(self):
        srv = FakeIMAP([mail(1), mail(2), mail(3)])
        fx = self.configure(srv, protocol="imap")
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 3)
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])
        srv.add(mail(4))
        self.assertEqual([t["subject"] for t in fx.fetch_user("Smith, Ann")], ["message 4"])
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])
        self.assertEqual(self.subjects(), ["message 1", "message 2", "message 3", "message 4"])
        st = self.state()["folders"]["INBOX"]
        self.assertEqual((st["uidvalidity"], st["last_uid"]), (7, 4))
        self.assertEqual(srv.flags(), [[]] * 4)              # keep: \Seen not set
        self.assertIn("EXAMINE", srv.verbs())
        self.assertNotIn("SELECT", srv.verbs())

    def test_seen(self):
        srv = FakeIMAP([mail(1), mail(2)])
        fx = self.configure(srv, protocol="imap", after="seen")
        fx.fetch_user("Smith, Ann")
        self.assertEqual(srv.flags(), [["\\Seen"]] * 2)
        self.assertEqual(len(srv.msgs), 2)

    def test_delete(self):
        srv = FakeIMAP([mail(1), mail(2)])
        fx = self.configure(srv, protocol="imap", after="delete")
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 2)
        self.assertEqual(srv.msgs, [])
        srv.add(mail(3))
        self.assertEqual([t["subject"] for t in fx.fetch_user("Smith, Ann")], ["message 3"])

    def test_restart_does_not_refetch(self):
        srv = FakeIMAP([mail(1), mail(2)])
        self.configure(srv, protocol="imap").fetch_user("Smith, Ann")
        n = len(srv.commands)
        self.assertEqual(self.fetcher().fetch_user("Smith, Ann"), [])
        fetches = [c for c in srv.commands[n:] if c.upper().startswith("UID FETCH")]
        self.assertEqual(fetches, [])                        # no body or header fetched again
        self.assertEqual(len(self.mailbox()), 2)

    def test_uidvalidity_change_no_duplicates(self):
        # one message without a Message-ID: matched by its Date/From/To/Subject hash
        srv = FakeIMAP([mail(1), mail(2, mid=False), mail(3)])
        fx = self.configure(srv, protocol="imap")
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 3)
        srv.renumber(100, uidvalidity=8)
        srv.add(mail(4))
        n = len(srv.commands)
        self.assertEqual([t["subject"] for t in fx.fetch_user("Smith, Ann")], ["message 4"])
        bodies = [c for c in srv.commands[n:] if c.upper().startswith("UID FETCH") and "HEADER" not in c.upper()]
        self.assertEqual(bodies, ["UID FETCH 103 (BODY.PEEK[])"])   # only the new body
        st = self.state()["folders"]["INBOX"]
        self.assertEqual((st["uidvalidity"], st["last_uid"]), (8, 103))
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])
        self.assertEqual(len(self.mailbox()), 4)

    def test_uidvalidity_change_known_after_new(self):
        # new message gets a lower UID than known ones after the change: last_uid must not skip it
        srv = FakeIMAP([mail(1), mail(2)])
        fx = self.configure(srv, protocol="imap")
        fx.fetch_user("Smith, Ann")
        srv.msgs.insert(0, {"uid": 0, "data": mail(5), "flags": set()})
        srv.renumber(10, uidvalidity=9)                      # mail 5 = UID 10, 1 = 11, 2 = 12
        self.assertEqual([t["subject"] for t in fx.fetch_user("Smith, Ann")], ["message 5"])
        self.assertEqual(self.state()["folders"]["INBOX"]["last_uid"], 12)
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])
        self.assertEqual(len(self.mailbox()), 3)

    def test_uid_after_literal(self):
        srv = FakeIMAP([mail(1), mail(2)], uid_last=True)
        fx = self.configure(srv, protocol="imap")
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 2)
        srv.renumber(50, uidvalidity=99)
        self.assertEqual(fx.fetch_user("Smith, Ann"), [])          # headers matched: no duplicates
        self.assertEqual(len(self.mailbox()), 2)

    def test_starttls_not_offered(self):
        srv = FakeIMAP([mail(1)])
        fx = self.configure(srv, protocol="imap", security="starttls")
        with self.assertRaises(FetchError):
            fx.fetch_user("Smith, Ann")
        self.assertNotIn("LOGIN", srv.verbs())
        self.assertEqual(self.mailbox(), [])

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl for a test certificate")
    def test_starttls(self):
        ctx = make_cert(self.root)
        if not ctx:
            self.skipTest("no openssl")
        srv = FakeIMAP([mail(1)], starttls=True, tls=ctx)
        fx = self.configure(srv, protocol="imap", security=None, verify_tls=False)   # default: starttls
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 1)
        v = srv.verbs()
        self.assertLess(v.index("STARTTLS"), v.index("LOGIN"))

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl for a test certificate")
    def test_imaps(self):
        ctx = make_cert(self.root)
        if not ctx:
            self.skipTest("no openssl")
        srv = FakeIMAP([mail(1), mail(2)], tls=ctx, implicit_tls=True)
        fx = self.configure(srv, protocol="imaps", security=None, verify_tls=False)  # default: ssl
        self.assertEqual(len(fx.fetch_user("Smith, Ann")), 2)

    def test_folder(self):
        srv = FakeIMAP([mail(1)])
        fx = self.configure(srv, protocol="imap", folder="Mail Lists")
        fx.fetch_user("Smith, Ann")
        self.assertIn('EXAMINE "Mail Lists"', srv.commands)
        self.assertIn("Mail Lists", self.state()["folders"])


class ConfigTest(unittest.TestCase):
    def test_defaults(self):
        c = F.fetch_config({"protocol": "imaps", "host": "h", "user": "u"}, "x")
        self.assertEqual((c["security"], c["port"], c["folder"], c["interval"], c["after"], c["verify_tls"]),
                         ("ssl", 993, "INBOX", 300, "keep", True))
        c = F.fetch_config({"protocol": "pop3", "host": "h", "user": "u"}, "x")
        self.assertEqual((c["security"], c["port"]), ("starttls", 110))
        self.assertEqual(F.fetch_config({"protocol": "pop3s", "host": "h", "user": "u"}, "x")["port"], 995)
        self.assertEqual(F.fetch_config({"protocol": "imap", "host": "h", "user": "u", "security": "none"},
                                        "x")["port"], 143)
        for bad in ({"protocol": "nntp", "host": "h", "user": "u"}, {"protocol": "pop3", "user": "u"},
                    {"protocol": "pop3", "host": "h", "user": "u", "after": "move"},
                    {"protocol": "pop3", "host": "h", "user": "u", "security": "tls"}):
            with self.assertRaises(ConfigError):
                F.fetch_config(bad, "x")

    def test_key(self):
        self.assertEqual(F.message_key(mail(1)), "id:<m1@example.com>")
        self.assertEqual(F.message_key(mail(2, mid=False)),
                         F.message_key(mail(2, mid=False).split(b"\r\n\r\n")[0] + b"\r\n\r\n"))


class CallFetchTest(FetchBase):
    """The fetch at the start of a user's call: the fetched mail is offered in the same call; a
    slow server does not hold the call up beyond the wait."""

    def call(self, srv, wait=10):
        self.configure(srv, protocol="pop3")
        po = PostOffice(self.root)
        po.fetcher = Fetcher(po)
        a, b = socket.socketpair()
        a.settimeout(30)
        old = F.CALL_WAIT
        F.CALL_WAIT = wait
        self.addCleanup(setattr, F, "CALL_WAIT", old)
        t = threading.Thread(target=lambda: _quiet(Call(Link(b, "t"), po, "t").run), daemon=True)
        t.start()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        c = Client(a)
        c.login("Smith, Ann", "123")
        c.s.sendall(b"\x88")                                 # nothing to upload
        return c

    def test_fetched_mail_offered_in_the_call(self):
        c = self.call(FakePOP3([mail(1)]))
        self.assertEqual(c.code(), 0x84)                     # the fetched message
        c.s.sendall(b"\x83")                                 # declined: stays waiting
        self.assertEqual(c.code(), 0x88)
        self.assertEqual(self.subjects(), ["message 1"])

    def test_slow_server_does_not_block(self):
        srv = FakePOP3([mail(1)], delay=4)
        t0 = time.monotonic()
        c = self.call(srv, wait=1)
        self.assertEqual(c.code(), 0x88)                     # our turn without the mail
        self.assertLess(time.monotonic() - t0, 3.5)


class Client:
    """The client's side of a raw-mode call (as in test_session_limits)."""

    def __init__(self, sock):
        self.s, self.buf = sock, b""

    def read(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d:
                raise AssertionError("closed")
            self.buf += d
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def code(self):
        while True:
            c = self.read(1)[0]
            if c != 0x91:
                return c

    def login(self, user, pw):
        def lstring(s):
            b = s.encode("cp850") + b"\x00"
            return bytes([len(b)]) + b
        self.s.sendall(b"\x80")
        assert self.code() == 0x81
        self.s.sendall(lstring(user))
        assert self.code() == 0x8B
        self.s.sendall(lstring(pw))
        assert self.code() == 0x82
        self.read(self.read(1)[0])
        self.s.sendall(b"\x82")


def _quiet(f):
    try:
        f()
    except Exception:
        pass


if __name__ == "__main__":
    unittest.main()
