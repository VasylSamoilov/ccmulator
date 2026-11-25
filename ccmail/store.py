# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Post office data: users and passwords, and one mailbox folder per user.

Layout under the data directory:
    po.json                      {"post_office": "MYPOST", "users": {"user": "123", ...}}
    mail/<user>/<id>.msg         message waiting for delivery (Message.to_file form)
    mail/<user>/<id>.txt         readable copy
    received/<id>.msg/.txt       every message accepted from a client, as received
    delivered/<user>/<id>.*      messages handed over to that user's client
"""
import datetime
import fcntl
import json
import os
import threading

from .message import Message

_lock = threading.Lock()


class PostOffice:
    def __init__(self, root):
        self.root = root
        self._path = os.path.join(root, "po.json")
        self._mtime = None
        self.refresh()
        tb = self._cfg.get("ccintl") or os.path.join(root, "CCINTL.TB")
        if os.path.exists(tb):
            from . import codepage
            codepage.load(tb)

    def _apply(self, cfg):
        self.name = cfg["post_office"]
        # users: "name": "password"  or  "name": {"password": "...", "codepage": 866, "comments": ".."}
        self.users = {u.lower(): (u, p["password"] if isinstance(p, dict) else p)
                      for u, p in cfg["users"].items()}
        self._cfg = cfg
        # code pages (spec/codepages.md 5): the post office default (437 when unset) and
        # one per user = the DOS code page of that user's PC; the protocol cannot tell it
        from . import codepage
        self.codepage = codepage.parse(cfg.get("codepage", 437))

    def refresh(self):
        """Reload po.json if another process (the admin commands) changed it."""
        try:
            mtime = os.stat(self._path).st_mtime_ns
        except OSError:
            return
        if mtime == self._mtime:
            return
        with open(self._path, encoding="utf-8") as f:
            cfg = json.load(f)
        self._mtime = mtime
        self._apply(cfg)

    def update(self, change):
        """Read po.json, apply change(cfg), write it back; one writer at a time across processes.
        Returns what change returned."""
        with _lock, open(self._path + ".lock", "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            with open(self._path, encoding="utf-8") as f:
                cfg = json.load(f)
            result = change(cfg)
            tmp = self._path + ".new"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp, self._path)
            self._mtime = os.stat(self._path).st_mtime_ns
            self._apply(cfg)
            return result

    def user_codepage(self, user):
        from . import codepage
        entry = self._cfg["users"].get(self.users.get((user or "").lower(), (user, None))[0])
        if isinstance(entry, dict) and entry.get("codepage"):
            return codepage.parse(entry["codepage"])
        return self.codepage

    def user(self, name: str):
        """Canonical user name, or None. Accepts the clients' "B A" form as well as the plain name."""
        self.refresh()
        key = name.strip().lower()
        if key in self.users:
            return self.users[key][0]
        if " " in key:
            first, rest = key.split(" ", 1)
            alt = f"{rest}, {first}"
            if alt in self.users:
                return self.users[alt][0]
            # the HP 200LX client turns "Last, First" around before every connect (hp200lx-check.md 3.4):
            # text before the first comma goes to the end after one blank, blanks after
            # the comma dropped; covers "Doe, John Q" -> "John Q Doe", "Van Dyke, Jo" -> "Jo Van Dyke"
            for stored, (canon, _) in self.users.items():
                if "," in stored:
                    before, after = stored.split(",", 1)
                    if f"{after.lstrip(' ')} {before}" == key:
                        return canon
        return None

    # ----- other post offices (spec/router-to-router.md) -----
    # po.json: "post_offices": {"MYPOST": {"password": "<what it sends us>",
    #            "call_password": "<what we send it>", "connect": "host:port", "mode": "LSEC"}}

    def post_office(self, name: str):
        """Canonical name of a configured post office, or None."""
        self.refresh()
        for po in self._cfg.get("post_offices", {}):
            if po.lower() == name.strip().lower():
                return po
        return None

    def post_office_cfg(self, name: str):
        return self._cfg.get("post_offices", {}).get(self.post_office(name) or "", {})

    def check_po_password(self, po: str, sent: bytes) -> bool:
        """Password of a post-office caller: up to 3 NUL-separated strings, case-insensitive, no
        lockout or policy (router-to-router.md 2.2)."""
        want = self.post_office_cfg(po).get("password", "")
        parts = [p.decode("cp850", "replace") for p in sent.split(b"\x00") if p][:3]
        return any(p.upper() == want.upper() for p in parts)

    def route(self, po: str, msg: Message):
        """Queue a message for another post office. Names known only through ADE get their route
        appended first (ade.add_routes)."""
        from . import ade
        msg = ade.add_routes(self, msg)
        mid = self._new_id()
        self._write(os.path.join(self.root, "route", po), mid, msg)
        return mid

    def routed(self, po: str):
        folder = os.path.join(self.root, "route", po)
        if not os.path.isdir(folder):
            return []
        out = []
        for fn in sorted(os.listdir(folder)):
            if fn.endswith(".msg"):
                with open(os.path.join(folder, fn), "rb") as f:
                    out.append((fn[:-4], Message.from_file(f.read())))
        return out

    def route_sent(self, po: str, mid: str):
        src = os.path.join(self.root, "route", po)
        dst = os.path.join(self.root, "route-sent", po)
        os.makedirs(dst, exist_ok=True)
        for ext in (".msg", ".txt"):
            p = os.path.join(src, mid + ext)
            if os.path.exists(p):
                os.replace(p, os.path.join(dst, mid + ext))

    @property
    def allow_readonly(self):
        """Unknown callers get a read-only connection (the default); false = NOR/O."""
        return bool(self._cfg.get("allow_readonly", True))

    @property
    def max_msgs(self):
        """MAXMSGS/n: messages accepted per call and direction; 0 = no limit (default)."""
        return int(self._cfg.get("max_msgs", 0))

    @property
    def msg_size_kb(self):
        """MSGSIZE/n: largest message in units of 1000 bytes; 0 = no limit (default)."""
        return int(self._cfg.get("msg_size_kb", 0))

    @property
    def admin_mailbox(self):
        """Where requests to "Administrator" (directory updates) are kept."""
        return self.user(self._cfg.get("admin", "admin")) or "Administrator"

    # ----- lockout after repeated wrong passwords (refusal reason 97 with the count) -----

    @property
    def lock_after(self):
        return int(self._cfg.get("lock_after", 0))

    def failed_attempts(self, user):
        return int(self._cfg.get("failed_attempts", {}).get(self.users[user.lower()][0], 0))

    def is_locked(self, user):
        return self.lock_after > 0 and self.failed_attempts(user) >= self.lock_after

    def record_login(self, user, ok):
        canon = self.users[user.lower()][0]

        def change(cfg):
            fails = cfg.setdefault("failed_attempts", {})
            if ok:
                fails.pop(canon, None)
            else:
                fails[canon] = fails.get(canon, 0) + 1
            return fails.get(canon, 0)
        return self.update(change)

    def unlock(self, user):
        self.record_login(user, True)

    def check_password(self, user: str, sent: bytes) -> bool:
        """sent = the password field: "pw\\0", or "new\\0old1\\0[old2\\0]" for a password change."""
        parts = [p.decode("cp850", "replace") for p in sent.split(b"\x00") if p]
        if not parts:
            return False
        current = self.users[user.lower()][1]
        if parts[0].lower() == current.lower():
            # HP 200LX client order: "current\0new\0new\0" (hp200lx-check.md);
            # the other clients' order "new\0old1\0old2\0" is handled below
            if len(parts) == 3 and parts[1] == parts[2] and parts[1].lower() != current.lower():
                self._set_password(user, parts[1])
            return True
        if any(p.lower() == current.lower() for p in parts[1:]):
            self._set_password(user, parts[0])
            return True
        return False

    def _set_password(self, user, new):
        canon = self.users[user.lower()][0]

        def change(cfg):
            if isinstance(cfg["users"].get(canon), dict):
                cfg["users"][canon]["password"] = new
            else:
                cfg["users"][canon] = new
        self.update(change)

    @staticmethod
    def _new_id():
        return datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")

    def _write(self, folder, mid, msg: Message):
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, mid + ".msg"), "wb") as f:
            f.write(msg.to_file())
        with open(os.path.join(folder, mid + ".txt"), "w", encoding="utf-8") as f:
            f.write(msg.to_text())

    def accept(self, msg: Message, recipients):
        """Store a message received from a client, one copy per accepted local recipient."""
        mid = self._new_id()
        self._write(os.path.join(self.root, "received"), mid, msg)
        for r in recipients:
            self._write(os.path.join(self.root, "mail", r), mid, msg.for_recipient(r))
        return mid

    def non_delivery(self, sent: Message, stored: Message, refused_by: str):
        """Build the non-delivery report (message.non_delivery) and store it like any message:
        a local author's mailbox or the route queue of the author's post office. Returns its id,
        or None when the author is not in the mail directory.
        po.json "ndr_cc_admin": true = the post office policy flag for this: a cc to
        "Administrator" (local: the admin mailbox)."""
        from . import message as M
        import logging
        log = logging.getLogger("ccmail.store")
        cp = self.codepage
        found = M.report_address(sent, self.name, self.post_office, self.user, cp)
        if not found:
            log.info("non-delivery report: sender %r not in mail directory, no report", sent.author)
            return None
        to, (kind, where), routed = found
        cc, admin = (), None
        if self._cfg.get("ndr_cc_admin"):
            if routed:      # 0B Administrator + the author's path, same target
                cc = [[M.TAG_CC, M.cstr(M.ADMINISTRATOR, cp)]] + [list(x) for x in to[1:]]
            else:           # 0B Administrator 0F <own>, the admin entry (+120)
                cc = [[M.TAG_CC, M.cstr(M.ADMINISTRATOR, cp)], [M.TAG_PATH, M.cstr(self.name, cp)]]
                admin = self.admin_mailbox
        rep = M.non_delivery(sent, stored, refused_by, to, self.name, cp, routed=routed, cc_tlvs=cc,
                             targets=1 + (admin is not None and admin != where))
        if kind == "route":
            mid = self.route(where, rep)
        else:
            mid = self._new_id()
            self._write(os.path.join(self.root, "mail", where), mid, rep)
        if admin and admin != where:
            # our mailboxes hold per-recipient copies: the admin's gets its own 03 entry
            self._write(os.path.join(self.root, "mail", admin), mid, rep.for_recipient(admin))
        log.info("non-delivery report %s to %s%s", mid, where, " (post office)" if kind == "route" else "")
        return mid

    def deposit(self, user: str, msg: Message):
        mid = self._new_id()
        self._write(os.path.join(self.root, "mail", user), mid, msg.for_recipient(user))
        return mid

    def pending(self, user: str):
        folder = os.path.join(self.root, "mail", user)
        if not os.path.isdir(folder):
            return []
        out = []
        for fn in sorted(os.listdir(folder)):
            if fn.endswith(".msg"):
                with open(os.path.join(folder, fn), "rb") as f:
                    out.append((fn[:-4], Message.from_file(f.read())))
        return out

    def delivered(self, user: str, mid: str):
        src = os.path.join(self.root, "mail", user)
        dst = os.path.join(self.root, "delivered", user)
        os.makedirs(dst, exist_ok=True)
        for ext in (".msg", ".txt"):
            p = os.path.join(src, mid + ext)
            if os.path.exists(p):
                os.replace(p, os.path.join(dst, mid + ext))
