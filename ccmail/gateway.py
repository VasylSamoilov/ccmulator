# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Internet mail gateway: cc:Mail messages <-> RFC 822 / MIME, compatible with the cc:Mail SMTP
gateway and POP3/IMAP servers R8.1.

Rules come from spec/smtp-link.md and spec/pop3-imap.md; section numbers below refer to those
specs. Where the conventions differ, the choice is noted.

Addressing: the gateway is a post office in the directory, e.g. "Internet-Mail"; users write
"jvalentine@silver.com at Internet-Mail". On the wire that is a name entry plus a tag-0F path
entry with the gateway post office.

po.json:
    "gateway": {
        "post_office": "INTERNET",        # the gateway's post office name in the directory
        "domain": "example.org",          # local users are <name>@domain
        "listen": "127.0.0.1:2525",       # inbound SMTP (internet -> cc:Mail)
        "smarthost": "127.0.0.1:2526",    # outbound SMTP relay (cc:Mail -> internet)
        "security": "none",               # smarthost: "none" (default) | "starttls" | "ssl"
        "verify_tls": true,               # check the smarthost's certificate (starttls/ssl)
        "starttls": false,                # older form of "security": "starttls"
        "username": "", "password": "",
        "retry_seconds": 3600, "retry_times": 72,   # defaults (smtp-link.md §7)
        "rfc822_header_item": false,      # attach the header as RFC822.TXT (needs file items)
        "aliases": {"sales": "Smith, Ann", "info@company.com": "user"}   # inbound, before the rules
    }
    "users": {"Smith, Ann": {"password": "..",
        "email": "ann@isp.example",       # her From/envelope sender; inbound to it reaches her
        "smtp": {"host": "smtp.isp.example", "port": 587, "security": "starttls",
                 "user": "ann@isp.example", "password": "..", "verify_tls": true},
        "fetch": {...}}}                  # ccmail/fetch.py

Precedence: every per-user setting is optional and a user without them is handled as before.
A user's "email" replaces the generated address (From, envelope sender, inbound matching); a
user's "smtp" replaces the shared smarthost for mail she writes, with no fallback to the
smarthost (failures are retried, then reported to her, as for the smarthost). Per-user settings
work without "listen"/"smarthost", even without a "gateway" section (post office "INTERNET").
"""
import datetime
import email
import email.policy
import email.utils
import html
import json
import logging
import os
import re
import smtplib
import socket
import ssl
import threading
import time
from email.message import EmailMessage, MIMEPart

from . import PRODUCT, limits
from . import message as M

log = logging.getLogger("ccmail.gateway")

IMPORTANCE = {"normal": ("normal", "normal"), "low": ("low", "non-urgent"), "urgent": ("high", "urgent")}
LINK_VERSION = f"ccMail Link to SMTP R8.10.00 compatible ({PRODUCT})"
SMTP_SECURITY = ("starttls", "ssl", "none")


class ConfigError(Exception):
    pass


def tls_context(verify=True):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def smtp_config(cfg: dict, user: str) -> dict:
    """A user's "smtp" entry with defaults: port 587 (465 for "ssl"), security starttls,
    verify_tls true. Raises ConfigError."""
    if not isinstance(cfg, dict) or not cfg.get("host"):
        raise ConfigError(f'user {user}: "smtp" needs a "host"')
    sec = str(cfg.get("security", "starttls")).lower()
    if sec not in SMTP_SECURITY:
        raise ConfigError(f'user {user}: smtp "security" must be one of {", ".join(SMTP_SECURITY)}')
    try:
        port = int(cfg.get("port") or (465 if sec == "ssl" else 587))
    except (TypeError, ValueError):
        raise ConfigError(f'user {user}: smtp "port" must be a number') from None
    return {"host": cfg["host"], "port": port,
            "security": sec, "user": cfg.get("user", ""), "password": cfg.get("password", ""),
            "verify_tls": bool(cfg.get("verify_tls", True))}


def open_smtp(host, port, security, user="", password="", verify_tls=True, timeout=60):
    """Connected (and logged in) smtplib object. "starttls" fails if the server does not offer
    it (smtplib raises SMTPNotSupportedError), so the password never goes out in clear text."""
    if security == "ssl":
        s = smtplib.SMTP_SSL(host, port, timeout=timeout, context=tls_context(verify_tls))
    else:
        s = smtplib.SMTP(host, port, timeout=timeout)
    try:
        if security == "starttls":
            s.starttls(context=tls_context(verify_tls))
        if user:
            s.login(user, password)
    except BaseException:
        s.close()
        raise
    return s


class _Recoded:
    """View of a Message whose names and subject are decoded with the right code page."""

    def __init__(self, msg, name, subject):
        self._m, self._name, self.subject = msg, name, subject

    def __getattr__(self, a):
        return getattr(self._m, a)

    @property
    def author(self):
        return self._name(self._m.author)

    def entries(self, tags):
        return [(t, self._name(n), [self._name(p) for p in path]) for t, n, path in self._m.entries(tags)]


def is_internet(name: str) -> bool:
    return bool(re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", name.strip()))


def bare_address(name: str) -> str:
    """Outbound recipient text -> address: take <...> if present, drop (comments) and "quotes",
    remove spaces (smtp-link.md §2.1)."""
    s = name.strip()
    m = re.search(r"<([^<>]*)>", s)
    if m:
        s = m.group(1)
    s = re.sub(r"\([^()]*\)", "", s).replace('"', "")
    return re.sub(r"\s+", "", s)


def local_part(name: str) -> str:
    """cc:Mail name -> address local part: "_" -> "__", space -> "_" (the SMTP gateway
    convention lowercases, the POP3/IMAP one keeps case; we keep case, smtp-link.md 7 item 1)."""
    s = re.sub(r"\([^()]*\)", "", name).replace('"', "").strip()
    s = s.replace("_", "__").replace(" ", "_")
    s = re.sub(r"[^A-Za-z0-9!#$%&'*+/=?^_`{|}~.,-]", "", s)
    if "," in s:
        s = '"' + s + '"'                        # specials quoted, e.g. "Last,_First"
    return s or "unknown"


class Gateway:
    def __init__(self, po):
        self.po = po
        cfg = po._cfg.get("gateway") or {}
        self.gw_po = cfg.get("post_office", "INTERNET")
        self.domain = cfg.get("domain", "localhost")
        self.listen = cfg.get("listen")
        self.smarthost = cfg.get("smarthost")
        self.starttls = cfg.get("starttls", False)
        self.security = str(cfg.get("security") or ("starttls" if self.starttls else "none")).lower()
        self.verify_tls = bool(cfg.get("verify_tls", True))
        self.username = cfg.get("username", "")
        self.password = cfg.get("password", "")
        self.retry_seconds = cfg.get("retry_seconds", 3600)
        self.retry_times = cfg.get("retry_times", 72)
        self.outbox = os.path.join(po.root, "outbound")
        self.inbox_log = os.path.join(po.root, "inbound")

    # ----- per-user settings (read live: po.json is reloaded when the admin commands change it) -----

    def _user_entries(self):
        self.po.refresh()
        for canon, _ in self.po.users.values():
            e = self.po._cfg["users"].get(canon)
            if isinstance(e, dict):
                yield canon, e

    @property
    def enabled(self):
        """A "gateway" section, or any user with her own email/smtp/fetch settings."""
        self.po.refresh()
        return bool(self.po._cfg.get("gateway")) or any(
            e.get("email") or e.get("smtp") or e.get("fetch") for _, e in self._user_entries())

    def enabled_for(self, user) -> bool:
        """Whether mail from this caller to the internet is accepted: with a "gateway" section
        as before (queued for the smarthost), else only for a user with her own "smtp"."""
        self.po.refresh()
        return bool(self.po._cfg.get("gateway")) or bool(self.po.user_entry(user).get("smtp"))

    @property
    def aliases(self):
        """gateway "aliases": {"local part" or "full@address": user}, keys lowercased."""
        self.po.refresh()
        a = (self.po._cfg.get("gateway") or {}).get("aliases") or {}
        return {k.strip().lower(): v for k, v in a.items()}

    def user_email(self, user):
        """(address, error) of a local user: her "email"; else her smtp "user" when it is an
        address; ("", error) when she has "smtp" but neither; (None, None) = generated address."""
        e = self.po.user_entry(user)
        if e.get("email"):
            return e["email"].strip(), None
        if e.get("smtp"):
            u = str((e["smtp"] or {}).get("user", "")).strip()
            if is_internet(u):
                return u, None
            return "", (f'user {self.po.user(user)} has "smtp" but no "email", and the smtp "user" '
                        f'is not an address: set "email" in po.json')
        return None, None

    def config_errors(self):
        """Problems in the gateway and per-user settings, for the log at start."""
        from . import fetch
        out = []
        seen = {}
        try:
            self.smarthost_security()
        except ConfigError as x:
            out.append(str(x))
        for canon, e in self._user_entries():
            if e.get("smtp"):
                try:
                    smtp_config(e["smtp"], canon)
                except ConfigError as x:
                    out.append(str(x))
                err = self.user_email(canon)[1]
                if err:
                    out.append(err)
            if e.get("fetch"):
                try:
                    fetch.fetch_config(e["fetch"], canon)
                except ConfigError as x:
                    out.append(str(x))
            if e.get("email"):
                key = e["email"].strip().lower()
                if key in seen:
                    out.append(f'users {seen[key]} and {canon} have the same "email" {key}')
                seen[key] = canon
        return out

    def _local_author(self, msg):
        """Post office user who wrote msg (author at no post office or at ours), or None."""
        author = next(iter(msg.entries((M.TAG_FROM,))), (None, msg.author, []))
        if author[2] and author[2][-1].strip().lower() != self.po.name.lower():
            return None
        return self.po.user(author[1])

    # ----- cc:Mail -> internet -----

    def _is_gw(self, path):
        return bool(path) and path[-1].strip().lower() == self.gw_po.lower()

    def is_external(self, name: str, path) -> bool:
        """Anything addressed "at <gateway>" (the address is the text before the last " at "), or
        a bare internet address that the client routed to the home post office."""
        if path:
            return self._is_gw(path) and bool(bare_address(name))
        return is_internet(name)

    def address_of(self, name: str, path=()) -> str:
        """cc:Mail name (+ post office path) -> internet address."""
        if self._is_gw(path) or (not path and is_internet(name)):
            return bare_address(name)
        lp = local_part(name)
        if path and path[-1].strip().lower() != self.po.name.lower():
            lp = local_part(f"{name} at {path[-1].strip()}")    # Name_at_PO (Kit_Walker__at_PO)
        return f"{lp}@{self.domain}"

    def sender_address(self, msg: M.Message):
        """(From address, local user or None, config error or None). A local author's own
        "email" wins over the generated address (smtp-link.md §2.2)."""
        user = self._local_author(msg)
        if user:
            addr, err = self.user_email(user)
            if addr or err:
                return addr, user, err
        author = next(iter(msg.entries((M.TAG_FROM,))), (None, msg.author, []))
        return self.address_of(author[1], author[2]), user, None

    def to_email(self, msg: M.Message, recipients) -> EmailMessage:
        from .codepage import tables
        from_addr = self.sender_address(msg)[0]
        names_cp, subject_cp, text_cp = msg.codepages(self.po.user_codepage(msg.author))
        # Message decodes header strings as cp850, which maps all 256 bytes: get the bytes back
        # and decode them with the message's real code page (codepages.md 5.4)
        u = lambda s, cp: tables().decode(s.encode("cp850"), cp)   # noqa: E731
        msg = _Recoded(msg, lambda s: u(s, names_cp), u(msg.subject, subject_cp))
        em = EmailMessage(policy=email.policy.SMTP)
        em["Received"] = f"from ccMail by {self.domain} ({PRODUCT}); " + email.utils.format_datetime(
            datetime.datetime.now().astimezone())
        em["Message-ID"] = email.utils.make_msgid(domain=self.domain)
        em["X-Mailer"] = LINK_VERSION
        when = msg.when or datetime.datetime.now()
        em["Date"] = email.utils.format_datetime(when.astimezone())    # DST applied
        author = next(iter(msg.entries((M.TAG_FROM,))), (None, msg.author, []))
        em["From"] = email.utils.formataddr((msg.author, from_addr)) if not self._is_gw(author[2]) else from_addr
        if any(t == M.TAG_RECEIPT for t, _ in msg.addr_tlvs):
            em["Return-Receipt-To"] = from_addr
        bcc = {n.lower() for _, n, _ in msg.entries((M.TAG_BCC, M.TAG_BCC_SENT))}
        cc_entries = msg.entries((M.TAG_CC, M.TAG_CC_SENT))
        cc_names = {n.lower() for _, n, _ in cc_entries}
        # the client appends a 03 entry for every cc and bcc on the wire: show each person once,
        # never show bcc (no Bcc header is written, smtp-link.md 7 item 2)
        to = [self.address_of(n, p) for _, n, p in msg.entries((M.TAG_TO, M.TAG_SENT_TO))
              if n.lower() not in bcc and n.lower() not in cc_names]
        cc = [self.address_of(n, p) for _, n, p in cc_entries]
        if to:
            em["To"] = ", ".join(dict.fromkeys(to))
        if cc:
            em["Cc"] = ", ".join(dict.fromkeys(cc))
        em["Subject"] = msg.subject
        imp, pri = IMPORTANCE.get(msg.priority, IMPORTANCE["normal"])
        em["Importance"], em["Priority"] = imp, pri                  # always both
        items = msg.logical_items()
        # a text item of only line ends/blanks (a message with just an attachment) is empty
        texts = [it["data"] for it in items if it["type"] == "text" and it["data"].strip()]
        others = [it for it in items if it["type"] != "text"]
        parts = [tables().decode(t, text_cp).replace("\r\n", "\n") for t in texts]
        if len(parts) <= 1 and not others:
            self._set_text(em, parts[0] if parts else "")       # one item: not multipart (§2.4)
        else:
            # several items: multipart/mixed with one part per item and nothing else (smtp-link.md
            # §2.4). make_mixed() on an empty message gives an empty part list; a
            # set_content("") before it became an empty text/plain first part
            em["MIME-Version"] = "1.0"
            em.make_mixed()
            for p in parts:
                sub = MIMEPart(policy=email.policy.SMTP)
                self._set_text(sub, p)
                em.attach(sub)
            fax_n = 0
            for it in others:
                self._attach(em, it, fax_n)
                fax_n += it["type"] == "fax"
        return em

    @staticmethod
    def _attach(em, it, fax_n):
        """One non-text item as a MIME attachment (file-items.md 6, 7.2): files under their title
        (date stamp stripped), base64; fax items with a PCX header (byte 2 = 1) as FAXnn.PCX;
        T.4-coded fax, graphics and Mac files as opaque data (UNKNOWNs in file-items.md)."""
        import mimetypes
        data = it["data"]
        if it["type"] in ("file", "macfile"):
            name = it["title"].split(" ")[0] if it["title"] else f"FILE{it['index']}.DAT"
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        elif it["type"] == "fax" and len(data) > 2 and data[2] == 1:
            name, ctype = f"FAX{fax_n + 1:02d}.PCX", "image/x-pcx"
        else:
            name, ctype = f"ITEM{it['index']}.{it['type'][:3].upper()}", "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        part = MIMEPart(policy=email.policy.SMTP)        # a part carries no MIME-Version of its own
        part.set_content(data, maintype=maintype, subtype=subtype, disposition="attachment", filename=name)
        em.attach(part)

    @staticmethod
    def _set_text(part, text):
        # 850 -> ISO-8859-1 (smtp-link.md §2.4); UTF-8 when the text does not fit
        try:
            text.encode("iso-8859-1")
            part.set_content(text, charset="iso-8859-1")
        except UnicodeEncodeError:
            part.set_content(text, charset="utf-8")
        part["Content-Description"] = '"cc:Mail Note Part"'

    def queue_outbound(self, msg: M.Message, recipients):
        os.makedirs(self.outbox, exist_ok=True)
        mid = self.po._new_id()
        em = self.to_email(msg, recipients)
        rcpt = [bare_address(r) for r in recipients]
        from_addr, user, error = self.sender_address(msg)
        meta = {"rcpt": rcpt, "from": from_addr, "author": msg.author, "subject": msg.subject,
                "tries": 0, "next": 0}
        # the route is fixed here, since From is written into the .eml now: "via" = the user whose
        # own smtp sends it; no "via" (also in older queue files) = the shared smarthost
        if user and self.po.user_entry(user).get("smtp"):
            meta["via"] = user
        if error:
            meta["config_error"] = error
            log.error("outbound %s: %s", mid, error)
        with open(os.path.join(self.outbox, mid + ".eml"), "wb") as f:
            f.write(em.as_bytes())
        with open(os.path.join(self.outbox, mid + ".json"), "w") as f:
            json.dump(meta, f)
        log.info("queued %s for %s%s", mid, ", ".join(rcpt), f" via {user}'s smtp" if meta.get("via") else "")
        return mid

    def _route(self, meta):
        """(open connection function, description) for a queued message. A user route uses only
        that user's server: ConfigError if her settings are gone or wrong (retried, never sent
        through the smarthost)."""
        via = meta.get("via")
        if via:
            cfg = self.po.user_entry(via).get("smtp")
            if not cfg:
                raise ConfigError(f'user {via} has no "smtp" settings any more')
            c = smtp_config(cfg, via)
            return (lambda: open_smtp(c["host"], c["port"], c["security"], c["user"], c["password"],
                                      c["verify_tls"])), f"{via}'s smtp {c['host']}:{c['port']}"
        if not self.smarthost:
            return None, None
        host, port = self.smarthost.rsplit(":", 1)
        security = self.smarthost_security()
        # the certificate is checked like a user's smtp (verify_tls); "starttls" fails if the
        # relay does not offer it, so the password never goes out in clear text
        return (lambda: open_smtp(host, int(port), security, self.username, self.password,
                                  self.verify_tls)), self.smarthost

    def smarthost_security(self):
        """The smarthost's "security" ("starttls": true is the older form). Raises ConfigError."""
        if self.security not in SMTP_SECURITY:
            raise ConfigError(f'gateway "security" must be one of {", ".join(SMTP_SECURITY)}')
        if self.starttls and self.security != "starttls":
            raise ConfigError(f'gateway "starttls": true contradicts "security": "{self.security}"')
        return self.security

    def send_queue(self):
        if not os.path.isdir(self.outbox):
            return
        for fn in sorted(os.listdir(self.outbox)):
            if not fn.endswith(".json"):
                continue
            mid = fn[:-5]
            meta_path = os.path.join(self.outbox, fn)
            with open(meta_path) as f:
                meta = json.load(f)
            if meta["next"] > time.time():
                continue
            with open(os.path.join(self.outbox, mid + ".eml"), "rb") as f:
                data = f.read()
            # a sender without a usable address (smtp but no email) is refused at once
            permanent = meta.get("config_error")
            route = "not sent"
            try:
                if not permanent:
                    connect, route = self._route(meta)
                    if connect is None:
                        continue                    # shared mail and no smarthost: stays queued
                    with connect() as s:
                        refused = s.sendmail(meta["from"], meta["rcpt"], data)
                        if refused:
                            permanent = "; ".join(f"{a}: {c} {r.decode(errors='replace')}"
                                                  for a, (c, r) in refused.items())
            except ConfigError as e:
                log.error("outbound %s: %s", mid, e)
                self._retry(meta, meta_path, mid, str(e))
                continue
            except smtplib.SMTPRecipientsRefused as e:
                permanent = "; ".join(f"{a}: {c} {r.decode(errors='replace')}" for a, (c, r) in e.recipients.items())
            except smtplib.SMTPResponseException as e:
                if 500 <= e.smtp_code < 600:
                    permanent = f"{e.smtp_code} {e.smtp_error.decode(errors='replace')}"
                else:
                    self._retry(meta, meta_path, mid, str(e))
                    continue
            except (OSError, smtplib.SMTPException) as e:
                self._retry(meta, meta_path, mid, str(e))
                continue
            if permanent:
                # a relay refusal is reported into the sender's cc:Mail mailbox (smtp-link.md §4.2)
                self._report_failure(meta, permanent)
            folder = os.path.join(self.po.root, "sent" if not permanent else "failed")
            os.makedirs(folder, exist_ok=True)
            os.replace(os.path.join(self.outbox, mid + ".eml"), os.path.join(folder, mid + ".eml"))
            os.remove(meta_path)
            log.info("%s %s to %s via %s%s", "refused" if permanent else "sent", mid, ", ".join(meta["rcpt"]),
                     route, f": {permanent}" if permanent else "")

    def _retry(self, meta, meta_path, mid, error):
        meta["tries"] += 1
        meta["next"] = time.time() + self.retry_seconds
        meta["error"] = error
        if meta["tries"] >= self.retry_times:
            self._report_failure(meta, f"gave up after {meta['tries']} attempts: {error}")
            folder = os.path.join(self.po.root, "failed")
            os.makedirs(folder, exist_ok=True)
            os.replace(os.path.join(self.outbox, mid + ".eml"), os.path.join(folder, mid + ".eml"))
            os.remove(meta_path)
            return
        with open(meta_path, "w") as f:
            json.dump(meta, f)
        log.info("send %s failed (%s), retry %d/%d later", mid, error, meta["tries"], self.retry_times)

    def _report_failure(self, meta, reason):
        user = self.po.user(meta.get("author", ""))
        if not user:
            return
        text = (f"Your message could not be delivered to the Internet.\n\n"
                f"Subject: {meta.get('subject', '')}\nTo: {', '.join(meta['rcpt'])}\n\nReason: {reason}\n")
        self.po.deposit(user, M.compose(self.gw_po, [user], "cc:Mail Link to SMTP Undeliverable Message", text))

    # ----- internet -> cc:Mail -----

    def local_user(self, address: str):
        """Recipient address -> post office user. First ours: gateway "aliases" (full address,
        then the local part when the domain is ours), a user's own "email" (any domain). Then
        the gateway's rules (smtp-link.md §3.3, Smart Addressing): exact name, "_"/"." as space,
        Name_at_PO for our post office, postmaster/root -> administrator."""
        addr = email.utils.parseaddr(address)[1]
        if "@" not in addr:
            return None
        local, dom = addr.rsplit("@", 1)
        ours = dom.lower() == self.domain.lower()
        aliases = self.aliases
        for key in (addr.lower(),) + ((local.strip('"').lower(),) if ours else ()):
            if key in aliases:
                u = self.po.user(aliases[key])
                if u:
                    return u
                log.warning("gateway alias %s -> %r: no such user", key, aliases[key])
        for canon, e in self._user_entries():
            if (e.get("email") or e.get("smtp")) and (self.user_email(canon)[0] or "").lower() == addr.lower():
                return canon
        if not ours:
            return None
        local = local.strip('"')
        m = re.fullmatch(r"(.+?)_at_(.+)", local, re.I)
        if m and m.group(2).replace("_", " ").lower() == self.po.name.lower():
            local = m.group(1)
        if local.lower() in ("postmaster", "root", "administrator"):
            return self.po.admin_mailbox
        for cand in (local, local.replace("__", "\0").replace("_", " ").replace("\0", "_"),
                     local.replace(".", " ")):
            u = self.po.user(cand)
            if u:
                return u
        return None

    def from_email(self, raw: bytes, rcpt_users, codepage=None):
        """codepage = the recipient's code page (names, subject and text are encoded for it)."""
        codepage = codepage or self.po.codepage
        em = email.message_from_bytes(raw, policy=email.policy.default)
        # author: Reply-To, else Resent-From, else From, else Return-Path (smtp-link.md §3.2)
        src = em.get("Reply-To") or em.get("Resent-From") or em.get("From") or em.get("Return-Path") or ""
        name, addr = email.utils.parseaddr(str(src))
        author = f"{name} <{addr}>" if name and addr else (f"<{addr}>" if addr else "unknown")
        limit = 126 - len(" at ") - len(self.gw_po)
        if len(author) > limit:
            author = f"<{addr}>" if len(addr) + 2 <= limit else author[:limit - 1] + "~"
        subject = str(em.get("Subject", ""))[:60]                       # cut to 60
        when = None
        try:
            # converted to local time (deliberate; the SMTP gateway convention keeps the sender's clock time)
            when = email.utils.parsedate_to_datetime(em["Date"]).astimezone().replace(tzinfo=None)
        except (TypeError, ValueError):
            pass
        body = em.get_body(preferencelist=("plain", "html"))
        text = ""
        if body is not None:
            try:
                text = body.get_content()
            except (LookupError, UnicodeError):
                # unknown charset label: UTF-8 if it is that, else byte for byte (ISO-8859-1),
                # so one odd message cannot stop delivery (or a user's fetch) for good
                data = body.get_payload(decode=True) or b""
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    text = data.decode("iso-8859-1")
            if body.get_content_type() == "text/html":
                text = html.unescape(re.sub(r"<[^>]+>", "", text))
        # attachments -> file items, named from Content-Type name / Content-Disposition filename /
        # Content-Description (file-items.md 7.3); DOS clients need 8.3 names, so
        # the original names are listed in the text
        attachments, renamed = [], []
        for n, part in enumerate(em.iter_attachments(), start=1):
            fname = part.get_filename() or part.get("Content-Description") or f"ATTACH{n}.DAT"
            data = part.get_payload(decode=True) or b""
            short = M.dos_name(fname)
            attachments.append((short, data))
            if short != fname:
                renamed.append(f"{short} = {fname}")
        if renamed:
            text += "\n\n[Attachments: " + "; ".join(renamed) + "]\n"
        imp = f"{em.get('Importance', '')} {em.get('Priority', '')} {em.get('X-Priority', '')}".lower()
        priority = 2 if ("high" in imp or "urgent" in imp.replace("non-urgent", "") or
                         re.search(r"\b[12]\b", em.get("X-Priority", ""))) else (
            1 if ("low" in imp or "non-urgent" in imp) else 0)
        # other header recipients outside our domain: kept as "addr at GATEWAY" so Reply-All works
        extra = []
        for tag, hdr in ((M.TAG_SENT_TO, "To"), (M.TAG_CC_SENT, "Cc")):
            for _, a in email.utils.getaddresses(em.get_all(hdr, [])):
                # local users (also by alias or own "email", e.g. fetched mail) are not repeated
                if a and not a.lower().endswith("@" + self.domain.lower()) and not self.local_user(a):
                    extra.append((tag, a, self.gw_po))
        receipt = bool(em.get("Return-Receipt-To"))
        if len(text) > 60000:
            text = text[:60000] + "\n[truncated]\n"
        return M.compose(author, rcpt_users, subject, text, when=when, priority=priority,
                         author_po=self.gw_po, extra=extra, receipt=receipt, codepage=codepage,
                         attachments=attachments)

    # ----- SMTP listener -----

    def serve_smtp(self):
        host, port = self.listen.rsplit(":", 1)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, int(port)))
        srv.listen(8)
        log.info("SMTP listener on %s for @%s", self.listen, self.domain)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self._smtp_session, args=(conn, addr), daemon=True).start()

    def _smtp_session(self, conn, addr):
        f = conn.makefile("rb")

        def reply(line):
            conn.sendall(line.encode() + b"\r\n")

        rcpts = []
        hops = 0
        mail_from = ""
        try:
            reply(f"220 {self.domain} {PRODUCT} ESMTP")
            while True:
                line = f.readline(1000)
                if not line:
                    return
                cmd = line.decode("latin-1").strip()
                verb = cmd[:4].upper()
                if verb in ("HELO", "EHLO"):
                    reply(f"250 {self.domain}")
                elif verb == "MAIL":
                    rcpts = []
                    mail_from = cmd[5:].strip()
                    reply("250 OK")
                elif verb == "RCPT":
                    user = self.local_user(cmd[8:].strip().strip("<>"))
                    if user:
                        rcpts.append(user)
                        reply("250 OK")
                    else:
                        reply("550 no such user here")
                elif verb == "DATA":
                    if not rcpts:
                        reply("503 need RCPT")
                        continue
                    reply("354 end with .")
                    data = bytearray()
                    while True:
                        ln = f.readline(65536)
                        if not ln or ln in (b".\r\n", b".\n"):
                            break
                        data += ln[1:] if ln.startswith(b"..") else ln
                    hops = sum(1 for ln in bytes(data).split(b"\n") if ln.lower().startswith(b"received:"))
                    if hops > 30:
                        reply("554 too many hops (mail loop)")         # loop guard
                    else:
                        self.deliver_inbound(bytes(data), rcpts,
                                             source=f"SMTP from {addr[0]}, {mail_from or 'MAIL FROM:<>'}")
                        reply("250 queued for cc:Mail")
                    rcpts = []
                elif verb == "RSET":
                    rcpts = []
                    reply("250 OK")
                elif verb == "NOOP":
                    reply("250 OK")
                elif verb == "QUIT":
                    reply("221 bye")
                    return
                else:
                    reply("502 not implemented")
        except OSError:
            pass
        finally:
            conn.close()

    def deliver_inbound(self, raw: bytes, users, source=None):
        """Convert and deposit for each user. source = where it came from (SMTP peer, fetch
        account), used in the notice when the mail cannot be converted. The raw mail is kept as
        inbound/<id>.eml either way."""
        users = list(dict.fromkeys(users))
        os.makedirs(self.inbox_log, exist_ok=True)
        mid = self.po._new_id()
        eml = os.path.join(self.inbox_log, mid + ".eml")
        with open(eml, "wb") as f:
            f.write(raw)
        msg = None
        for u in users:                     # each recipient gets the text in its own code page
            cp = self.po.user_codepage(u)
            try:
                msg = self.from_email(raw, users, codepage=cp)
            except Exception as e:          # noqa: BLE001 - any failure: tell the user, keep the raw mail
                log.exception("inbound %s for %s cannot be converted", mid, u)
                msg = self.unconvertible_notice(raw, u, e, source, os.path.relpath(eml, self.po.root), cp)
            self.po.deposit(u, msg)
        log.info("inbound %s from %r for %s: %r", mid, msg.author, ", ".join(users), msg.subject)
        return msg

    def unconvertible_notice(self, raw, user, error, source, kept, codepage):
        """A plain message for the user about mail that could not be converted: where and when it
        came from, every header that can still be read, the parts, a text excerpt if one is
        readable, and why the conversion failed."""
        import email.header
        import email.parser

        def hdr(v):
            if v is None:
                return ""
            try:
                return str(email.header.make_header(email.header.decode_header(str(v))))
            except Exception:       # noqa: BLE001 - an undecodable header is shown as it is
                return str(v)

        lines = ["A message could not be converted to cc:Mail and was not delivered as such.", ""]
        lines.append(f"Received: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
        if source:
            lines.append(f"Came from: {source}")
        lines.append(f"Size: {len(raw)} bytes")
        try:
            em = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(raw)
        except Exception:           # noqa: BLE001
            em = None
        try:
            hd = em or email.parser.BytesHeaderParser(policy=email.policy.compat32).parsebytes(raw)
        except Exception:           # noqa: BLE001
            hd = None
        subject = ""
        if hd is not None:
            lines.append("")
            for name in ("From", "Sender", "Reply-To", "To", "Cc", "Date", "Subject", "Message-ID",
                         "Content-Type"):
                for v in hd.get_all(name) or []:
                    lines.append(f"{name}: {hdr(v)}")
            subject = hdr(hd.get("Subject")).strip()
        excerpt = None
        if em is not None and em.is_multipart():
            parts = []
            for part in em.walk():
                if part.is_multipart():
                    continue
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:   # noqa: BLE001
                    payload = b""
                name = part.get_filename()
                parts.append(f"  {part.get_content_type()}" + (f" {hdr(name)!r}" if name else "")
                             + f", {len(payload)} bytes")
                if excerpt is None and part.get_content_type() == "text/plain" and not name:
                    excerpt = payload
            if parts:
                lines += ["", "Parts:"] + parts
        elif em is not None:
            try:
                excerpt = em.get_payload(decode=True)
            except Exception:       # noqa: BLE001
                excerpt = None
        if excerpt:
            text = excerpt.decode("utf-8", "replace") if isinstance(excerpt, bytes) else str(excerpt)
            body = ["".join(ch if ch.isprintable() or ch == "\t" else "?" for ch in ln.rstrip())
                    for ln in text.splitlines()][:20]
            lines += ["", "Beginning of the text:"] + ["  " + ln for ln in body]
        lines += ["", f"Why it could not be converted: {type(error).__name__}: {error}",
                  f"The original is kept on the post office as {kept}."]
        title = "Message could not be converted"
        if subject:
            title = (title + ": " + subject)[:limits.SUBJECT_MAX]
        return M.compose("Postmaster", [user], title, "\r\n".join(lines), author_po=self.gw_po,
                         codepage=codepage)

    def run_sender(self):
        while True:
            try:
                self.send_queue()
            except Exception:
                log.exception("outbound queue")
            time.sleep(10)
