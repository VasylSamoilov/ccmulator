# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Per-user fetching of internet mail from a POP3 or IMAP account (a built-in fetchmail).

po.json, in a user's entry (users can be "name": "password" or "name": {"password": .., ...}):
    "fetch": {"protocol": "pop3" | "pop3s" | "imap" | "imaps",
              "host": "mail.isp.example", "port": 995,       # default 110/995, 143/993 by security
              "security": "ssl" | "starttls" | "none",       # default ssl for pop3s/imaps, else
                                                             # starttls; starttls fails when the
                                                             # server does not offer it
              "user": "ann@isp.example", "password": "..",
              "folder": "INBOX",                             # IMAP only
              "interval": 300,                               # seconds between polls
              "after": "keep" | "seen" | "delete",           # what to do on the server once stored
              "verify_tls": true}

Each message is converted like inbound SMTP mail (Gateway.deliver_inbound: the user's code page,
author = the sender "at INTERNET") and deposited in the user's mailbox. "seen" sets the IMAP
\\Seen flag (POP3 has none: same as keep); "keep" leaves IMAP flags alone (EXAMINE, BODY.PEEK).

State, <data>/fetch/<user>.json, written atomically after every stored message:
- POP3: {"account": "pop3://user@host", "uidls": [...]}: the UIDLs taken. A message counts as
  taken once it is stored; UIDLs no longer on the server are dropped after a complete UIDL
  listing. A server without UIDL is refused (old mail could not be told from new). With
  "delete", a taken message still on the server is deleted again (an earlier QUIT may have
  failed before the deletion was committed).
- IMAP: {"account": "imap://user@host", "folders": {"INBOX": {"uidvalidity": V, "last_uid": U,
  "keys": [...]}}}: messages with UID > U are new. "keys" remembers each taken message by its
  Message-ID (or, without one, a hash of Date/From/To/Subject), at most KEYS_MAX. When
  UIDVALIDITY changes, only the headers of the folder are fetched and a message is taken only if
  its key is not remembered, so nothing is delivered twice and no old body is downloaded again.
  A new UID whose key is already remembered is not delivered either (same Message-ID twice).
- Another account (user or host changed) starts with empty state: everything there is new.
Order per message: store, save state, then flag/delete on the server. A crash between storing and
saving can deliver one message twice; a message is never marked taken before it is stored.
"""
import contextlib
import email.parser
import email.policy
import fcntl
import hashlib
import imaplib
import json
import logging
import os
import poplib
import re
import threading
import time
import urllib.parse

from .gateway import ConfigError, Gateway, tls_context

log = logging.getLogger("ccmail.fetch")

PROTOCOLS = ("pop3", "pop3s", "imap", "imaps")
SECURITY = ("ssl", "starttls", "none")
AFTER = ("keep", "seen", "delete")
PORTS = {("pop3", True): 995, ("pop3", False): 110, ("imap", True): 993, ("imap", False): 143}
KEYS_MAX = 20000
CALL_WAIT = 10          # seconds a call waits for its fetch before mail is sent to the caller
POLL_TIMEOUT = 60       # socket timeout of the background poll


class FetchError(Exception):
    pass


def fetch_config(cfg, user) -> dict:
    """A user's "fetch" entry with defaults applied. Raises ConfigError."""
    if not isinstance(cfg, dict):
        raise ConfigError(f'user {user}: "fetch" must be an object')
    proto = str(cfg.get("protocol", "")).lower()
    if proto not in PROTOCOLS:
        raise ConfigError(f'user {user}: fetch "protocol" must be one of {", ".join(PROTOCOLS)}')
    kind = proto.rstrip("s")
    sec = str(cfg.get("security") or ("ssl" if proto.endswith("s") else "starttls")).lower()
    if sec not in SECURITY:
        raise ConfigError(f'user {user}: fetch "security" must be one of {", ".join(SECURITY)}')
    after = str(cfg.get("after", "keep")).lower()
    if after not in AFTER:
        raise ConfigError(f'user {user}: fetch "after" must be one of {", ".join(AFTER)}')
    for k in ("host", "user"):
        if not cfg.get(k):
            raise ConfigError(f'user {user}: fetch needs "{k}"')
    try:
        port = int(cfg.get("port") or PORTS[(kind, sec == "ssl")])
        interval = max(10, int(cfg.get("interval", 300)))
    except (TypeError, ValueError):
        raise ConfigError(f'user {user}: fetch "port" and "interval" must be numbers') from None
    return {"kind": kind, "host": cfg["host"], "security": sec, "port": port,
            "user": cfg["user"], "password": cfg.get("password", ""),
            "folder": cfg.get("folder") or "INBOX", "interval": interval,
            "after": after, "verify_tls": bool(cfg.get("verify_tls", True))}


def message_key(raw: bytes) -> str:
    """Identity of a message from its header (the full message or only its header gives the same
    key): the Message-ID, else a hash of Date, From, To and Subject."""
    h = email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(raw)
    mid = " ".join(str(h.get("Message-ID", "")).split())
    if mid:
        return "id:" + mid
    fields = "\n".join(" ".join(str(h.get(k, "")).split()) for k in ("Date", "From", "To", "Subject"))
    return "h:" + hashlib.sha256(fields.encode("utf-8", "replace")).hexdigest()[:32]


def _imap_quote(s):
    if s and not re.search(r'[\s"\\(){}%*\]]', s):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Fetcher:
    def __init__(self, po, gateway=None):
        self.po = po
        self.gateway = gateway or getattr(po, "gateway", None) or Gateway(po)
        self.dir = os.path.join(po.root, "fetch")
        self._next = {}
        self._reported = set()

    # ----- configuration and state -----

    def users(self):
        """Users with a "fetch" entry."""
        self.po.refresh()
        return [canon for canon, _ in sorted(self.po.users.values())
                if self.po.user_entry(canon).get("fetch")]

    def has(self, user):
        return bool(user) and bool(self.po.user_entry(user).get("fetch"))

    def config(self, user):
        canon = self.po.user(user)
        if not canon:
            raise ConfigError(f"unknown user {user}")
        cfg = self.po.user_entry(canon).get("fetch")
        if not cfg:
            raise ConfigError(f'user {canon} has no "fetch" entry in po.json')
        return canon, fetch_config(cfg, canon)

    def state_path(self, user):
        return os.path.join(self.dir, urllib.parse.quote(user, safe=" ,'-_.()") + ".json")

    def load_state(self, user, cfg):
        account = f"{cfg['kind']}://{cfg['user']}@{cfg['host'].lower()}"
        try:
            with open(self.state_path(user), encoding="utf-8") as f:
                state = json.load(f)
        except FileNotFoundError:
            state = None
        if state and state.get("account") != account:
            log.info("fetch %s: account changed from %s to %s, starting afresh", user,
                     state.get("account"), account)
            state = None
        return state or {"account": account}

    def save_state(self, user, state):
        os.makedirs(self.dir, exist_ok=True)
        path = self.state_path(user)
        tmp = path + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=1, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    @contextlib.contextmanager
    def _locked(self, user, wait):
        """One fetch per user at a time, across threads and processes (the CLI next to serve)."""
        os.makedirs(self.dir, exist_ok=True)
        with open(self.state_path(user) + ".lock", "w") as lk:
            end = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > end:
                        raise FetchError("another fetch for this user is still running")
                    time.sleep(0.1)
            try:
                yield
            finally:
                fcntl.flock(lk, fcntl.LOCK_UN)

    # ----- fetching -----

    def fetch_user(self, user, timeout=POLL_TIMEOUT, lock_wait=None):
        """Fetch new mail for one user now. Returns [{"author", "subject"}] of what was stored.
        Raises ConfigError, FetchError, OSError or the protocol library's errors."""
        canon, cfg = self.config(user)
        with self._locked(canon, timeout if lock_wait is None else lock_wait):
            if cfg["kind"] == "pop3":
                return self._pop3(canon, cfg, timeout)
            return self._imap(canon, cfg, timeout)

    def safe_fetch(self, user, timeout=POLL_TIMEOUT, lock_wait=None):
        """fetch_user that logs instead of raising (the poller, the call)."""
        try:
            taken = self.fetch_user(user, timeout, lock_wait)
            if taken:
                log.info("fetch %s: %d new message(s)", user, len(taken))
            return taken
        except ConfigError as e:
            log.error("fetch %s: %s", user, e)
        except Exception as e:      # noqa: BLE001 - a broken account must not stop the server
            log.warning("fetch %s failed: %s: %s", user, type(e).__name__, e)
        return None

    def start(self, user, timeout=CALL_WAIT):
        """Fetch for a caller in a thread (the call keeps its link serviced while it waits)."""
        t = threading.Thread(target=self.safe_fetch, args=(user, timeout, timeout), daemon=True,
                             name=f"fetch-{user}")
        t.start()
        return t

    def run(self, tick=5):
        """Background poller: each user at her "interval"; po.json changes are picked up."""
        while True:
            try:
                self._poll_once()
            except Exception:       # noqa: BLE001 - e.g. a po.json being edited: try again later
                log.exception("fetch poller")
            time.sleep(tick)

    def _poll_once(self):
        now = time.monotonic()
        for user in self.users():
            try:
                _, cfg = self.config(user)
            except ConfigError as e:
                if str(e) not in self._reported:
                    self._reported.add(str(e))
                    log.error("fetch %s: %s", user, e)
                continue
            if self._next.get(user, 0) <= now:
                self._next[user] = now + cfg["interval"]
                self.safe_fetch(user)

    def _deliver(self, user, raw, source=None):
        msg = self.gateway.deliver_inbound(raw, [user], source=source)
        return {"author": msg.author, "subject": msg.subject}

    # ----- POP3 -----

    def _pop3_connect(self, cfg, timeout):
        ctx = tls_context(cfg["verify_tls"])
        if cfg["security"] == "ssl":
            return poplib.POP3_SSL(cfg["host"], cfg["port"], timeout=timeout, context=ctx)
        conn = poplib.POP3(cfg["host"], cfg["port"], timeout=timeout)
        if cfg["security"] == "starttls":
            try:
                caps = conn.capa()
            except poplib.error_proto:
                caps = {}
            if "STLS" not in caps:
                conn.close()
                raise FetchError(f"{cfg['host']} does not offer STLS; not sending the password in clear "
                                 f'text (set "security": "none" to allow it)')
            conn.stls(context=ctx)
        return conn

    def _pop3(self, user, cfg, timeout):
        state = self.load_state(user, cfg)
        taken = []
        conn = self._pop3_connect(cfg, timeout)
        try:
            conn.user(cfg["user"])
            conn.pass_(cfg["password"])
            try:
                _, lines, _ = conn.uidl()
            except poplib.error_proto as e:
                raise FetchError(f"{cfg['host']} has no UIDL ({e}); not fetching, old mail could not be "
                                 f"told from new")
            listing = {}
            for ln in lines:
                n, uid = ln.decode("latin-1").split(None, 1)
                listing[uid.strip()] = int(n)
            # complete listing: forget UIDLs that are gone from the server
            known = set(state.get("uidls", [])) & set(listing)
            state["uidls"] = sorted(known)
            self.save_state(user, state)
            for uid, n in sorted(listing.items(), key=lambda x: x[1]):
                if uid in known:
                    if cfg["after"] == "delete":
                        conn.dele(n)
                    continue
                _, msg_lines, _ = conn.retr(n)
                raw = b"\r\n".join(msg_lines) + b"\r\n"
                taken.append(self._deliver(user, raw, f"POP3 ({cfg['security']}) account {cfg['user']} "
                                                      f"at {cfg['host']}, message UIDL {uid}"))
                known.add(uid)
                state["uidls"] = sorted(known)
                self.save_state(user, state)
                if cfg["after"] == "delete":
                    conn.dele(n)
            conn.quit()                     # commits the deletions
        finally:
            conn.close()
        return taken

    # ----- IMAP -----

    def _imap_connect(self, cfg, timeout):
        ctx = tls_context(cfg["verify_tls"])
        if cfg["security"] == "ssl":
            return imaplib.IMAP4_SSL(cfg["host"], cfg["port"], ssl_context=ctx, timeout=timeout)
        conn = imaplib.IMAP4(cfg["host"], cfg["port"], timeout=timeout)
        if cfg["security"] == "starttls":
            if "STARTTLS" not in conn.capabilities:
                conn.shutdown()
                raise FetchError(f"{cfg['host']} does not offer STARTTLS; not sending the password in clear "
                                 f'text (set "security": "none" to allow it)')
            conn.starttls(ssl_context=ctx)
        return conn

    @staticmethod
    def _search(conn, *criteria):
        typ, data = conn.uid("SEARCH", *criteria)
        if typ != "OK":
            raise FetchError(f"UID SEARCH failed: {data}")
        return sorted({int(x) for d in data if d for x in d.split()})

    @staticmethod
    def _fetch(conn, uids, what):
        """{uid: bytes} for UID FETCH uids (what)."""
        typ, data = conn.uid("FETCH", uids, f"({what})")
        if typ != "OK":
            raise FetchError(f"UID FETCH failed: {data}")
        out = {}
        for i, item in enumerate(data):
            if isinstance(item, tuple):
                # data items come in any order (RFC 3501 7.4.2): UID before the literal is in
                # the tuple's first half, UID after it in the next element (b" UID 5)")
                m = re.search(rb"UID (\d+)", item[0])
                if not m and i + 1 < len(data) and isinstance(data[i + 1], bytes):
                    m = re.search(rb"UID (\d+)", data[i + 1])
                if m:
                    out[int(m.group(1))] = item[1]
                else:
                    log.warning("UID FETCH answer without a UID: %r", item[0][:80])
        return out

    def _imap(self, user, cfg, timeout):
        state = self.load_state(user, cfg)
        taken = []
        folder = cfg["folder"]
        conn = self._imap_connect(cfg, timeout)
        try:
            conn.login(cfg["user"], cfg["password"])
            typ, data = conn.select(_imap_quote(folder), readonly=cfg["after"] == "keep")
            if typ != "OK":
                raise FetchError(f"cannot open folder {folder}: {data}")
            uv = conn.response("UIDVALIDITY")[1]
            if not uv or not uv[0]:
                raise FetchError(f"{cfg['host']} gave no UIDVALIDITY for {folder}")
            uv = int(uv[0])
            folders = state.setdefault("folders", {})
            old = folders.get(folder)
            if old is not None and old.get("uidvalidity") == uv:
                fst = old
                last = fst["last_uid"]
                todo = [u for u in self._search(conn, "UID", f"{last + 1}:*") if u > last]  # n:* gives the last
                skip = []
            else:
                # first sync, or UIDVALIDITY changed: compare headers with the remembered keys
                keys = old.get("keys", []) if old else []
                if old is not None:
                    log.info("fetch %s: UIDVALIDITY of %s changed (%s -> %s), matching by Message-ID",
                             user, folder, old.get("uidvalidity"), uv)
                fst = folders[folder] = {"uidvalidity": uv, "last_uid": 0, "keys": keys}
                todo = self._search(conn, "ALL")
                known = set(keys)
                headers = self._fetch(conn, "1:*", "BODY.PEEK[HEADER]") if known and todo else {}
                skip = [u for u in todo if u in headers and message_key(headers[u]) in known]
                todo = [u for u in todo if u not in skip]
                # last_uid may pass known messages only up to the first one still to take
                if skip:
                    fst["last_uid"] = max(skip) if not todo else max(0, min(max(skip), todo[0] - 1))
                self.save_state(user, state)
            deleted = False
            for uid in todo:
                raw = self._fetch(conn, str(uid), "BODY.PEEK[]").get(uid)
                if raw is None:
                    log.warning("fetch %s: UID %d of %s listed but not fetched (gone?)", user, uid, folder)
                    continue
                key = message_key(raw)
                if key in set(fst.get("keys", [])):
                    # taken before under its key (a resync interrupted after this UID): not again
                    log.info("fetch %s: UID %d of %s is %s, taken before: skipped", user, uid, folder, key)
                    fst["last_uid"] = max(fst["last_uid"], uid)
                    self.save_state(user, state)
                    continue
                taken.append(self._deliver(user, raw, f"IMAP ({cfg['security']}) account {cfg['user']} "
                                                      f"at {cfg['host']}, folder {folder}, UID {uid}"))
                fst["last_uid"] = max(fst["last_uid"], uid)
                fst["keys"] = (fst.get("keys", []) + [key])[-KEYS_MAX:]
                self.save_state(user, state)
                if cfg["after"] == "seen":
                    conn.uid("STORE", str(uid), "+FLAGS.SILENT", r"(\Seen)")
                elif cfg["after"] == "delete":
                    conn.uid("STORE", str(uid), "+FLAGS.SILENT", r"(\Deleted)")
                    deleted = True
            if skip and fst["last_uid"] < max(skip):
                fst["last_uid"] = max(skip)             # everything up to there is taken now
                self.save_state(user, state)
            if deleted:
                conn.expunge()
            conn.logout()
        except BaseException:
            try:
                conn.shutdown()
            except OSError:
                pass
            raise
        return taken
