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
        "starttls": false, "username": "", "password": "",
        "retry_seconds": 3600, "retry_times": 72,   # defaults (smtp-link.md §7)
        "rfc822_header_item": false       # attach the header as RFC822.TXT (needs file items)
    }
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
import threading
import time
from email.message import EmailMessage

from . import message as M

log = logging.getLogger("ccmail.gateway")

IMPORTANCE = {"normal": ("normal", "normal"), "low": ("low", "non-urgent"), "urgent": ("high", "urgent")}
LINK_VERSION = "ccMail Link to SMTP R8.10.00 compatible (ccmail-server)"


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
        self.enabled = bool(cfg)
        self.gw_po = cfg.get("post_office", "INTERNET")
        self.domain = cfg.get("domain", "localhost")
        self.listen = cfg.get("listen")
        self.smarthost = cfg.get("smarthost")
        self.starttls = cfg.get("starttls", False)
        self.username = cfg.get("username", "")
        self.password = cfg.get("password", "")
        self.retry_seconds = cfg.get("retry_seconds", 3600)
        self.retry_times = cfg.get("retry_times", 72)
        self.outbox = os.path.join(po.root, "outbound")
        self.inbox_log = os.path.join(po.root, "inbound")

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

    def to_email(self, msg: M.Message, recipients) -> EmailMessage:
        from .codepage import tables
        names_cp, subject_cp, text_cp = msg.codepages(self.po.user_codepage(msg.author))
        # Message decodes header strings as cp850, which maps all 256 bytes: get the bytes back
        # and decode them with the message's real code page (codepages.md 5.4)
        u = lambda s, cp: tables().decode(s.encode("cp850"), cp)   # noqa: E731
        msg = _Recoded(msg, lambda s: u(s, names_cp), u(msg.subject, subject_cp))
        em = EmailMessage(policy=email.policy.SMTP)
        em["Received"] = f"from ccMail by {self.domain} (ccmail-server); " + email.utils.format_datetime(
            datetime.datetime.now().astimezone())
        em["Message-ID"] = email.utils.make_msgid(domain=self.domain)
        em["X-Mailer"] = LINK_VERSION
        when = msg.when or datetime.datetime.now()
        em["Date"] = email.utils.format_datetime(when.astimezone())    # DST applied
        author = next(iter(msg.entries((M.TAG_FROM,))), (None, msg.author, []))
        from_addr = self.address_of(author[1], author[2])
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
        texts = [it["data"] for it in items if it["type"] == "text" and it["data"]]
        others = [it for it in items if it["type"] != "text"]
        parts = [tables().decode(t, text_cp).replace("\r\n", "\n") for t in texts] or [""]
        if len(parts) == 1 and not others:
            self._set_text(em, parts[0])
        else:
            em.set_content("")
            em.make_mixed()
            for p in parts:
                sub = EmailMessage(policy=email.policy.SMTP)
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
        em.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)

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
        author = next(iter(msg.entries((M.TAG_FROM,))), (None, msg.author, []))
        with open(os.path.join(self.outbox, mid + ".eml"), "wb") as f:
            f.write(em.as_bytes())
        with open(os.path.join(self.outbox, mid + ".json"), "w") as f:
            json.dump({"rcpt": rcpt, "from": self.address_of(author[1], author[2]),
                       "author": msg.author, "subject": msg.subject, "tries": 0, "next": 0}, f)
        log.info("queued %s for %s", mid, ", ".join(rcpt))
        return mid

    def send_queue(self):
        if not self.smarthost or not os.path.isdir(self.outbox):
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
            host, port = self.smarthost.rsplit(":", 1)
            permanent = None
            try:
                with smtplib.SMTP(host, int(port), timeout=60) as s:
                    if self.starttls:
                        s.starttls()
                    if self.username:
                        s.login(self.username, self.password)
                    refused = s.sendmail(meta["from"], meta["rcpt"], data)
                    if refused:
                        permanent = "; ".join(f"{a}: {c} {r.decode(errors='replace')}" for a, (c, r) in refused.items())
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
            log.info("%s %s to %s via %s", "refused" if permanent else "sent", mid, ", ".join(meta["rcpt"]),
                     self.smarthost)

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
        """Recipient address -> post office user (smtp-link.md §3.3, Smart Addressing): exact name,
        "_"/"." as space, Name_at_PO for our post office, postmaster/root -> administrator."""
        addr = email.utils.parseaddr(address)[1]
        if "@" not in addr:
            return None
        local, dom = addr.rsplit("@", 1)
        if dom.lower() != self.domain.lower():
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
            text = body.get_content()
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
                if a and not a.lower().endswith("@" + self.domain.lower()):
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
        try:
            reply(f"220 {self.domain} ccmail-server ESMTP")
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
                        self.deliver_inbound(bytes(data), rcpts)
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

    def deliver_inbound(self, raw: bytes, users):
        users = list(dict.fromkeys(users))
        os.makedirs(self.inbox_log, exist_ok=True)
        mid = self.po._new_id()
        with open(os.path.join(self.inbox_log, mid + ".eml"), "wb") as f:
            f.write(raw)
        msg = None
        for u in users:                     # each recipient gets the text in its own code page
            msg = self.from_email(raw, users, codepage=self.po.user_codepage(u))
            self.po.deposit(u, msg)
        log.info("inbound %s from %r for %s: %r", mid, msg.author, ", ".join(users), msg.subject)

    def run_sender(self):
        while True:
            try:
                self.send_queue()
            except Exception:
                log.exception("outbound queue")
            time.sleep(10)
