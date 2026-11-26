# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Post office side of a cc:Mail client call (spec/session-layer.md).

Order: link opener (ff aa 55 11 -> control 0Fh), 80 -> 81, name, 8B, password,
82 + post office name, caller 82 (right post office) / 83 (wrong one);
the caller sends its messages (84 ...), then 88 (or 8D: will not receive);
the post office sends its messages for that user, then 88.
Per message: 84 | 85 | len(2) record | one verdict per tag-03 entry (82/83) | 86 (or 89/8A/8E/8F)
| body | 87.
"""
import logging
import struct
import time

import shutil

from . import ade, directory, limits
from .link import Link, LinkClosed, LinkTimeout, RAW, CTL_ACCEPT, CTL_REFUSE
from .message import Message, parse_tlvs, text, FIXED_LEN, TAG_FROM, TAG_FORWARDED_BY

log = logging.getLogger("ccmail.session")

OPENER = bytes([0xFF, 0xAA, 0x55, 0x11])
C_SESSION, C_SESSION_OK = 0x80, 0x81
C_YES, C_NO = 0x82, 0x83
C_HAVE_MSG, C_SEND_IT, C_SEND_BODY, C_STORED = 0x84, 0x85, 0x86, 0x87
C_DONE, C_UNKNOWN_RCPTS, C_NO_SPACE, C_PASSWORD, C_REFUSED = 0x88, 0x89, 0x8A, 0x8B, 0x8C
C_DONE_NO_RECV, C_TOO_LARGE, C_CANNOT_STORE = 0x8D, 0x8E, 0x8F
R_LOCKED, R_WRONG_PASSWORD = 0x97, 0x98      # reasons after 8C
# the post office's message filters (router-answer.md 2.2 step 4): 82 for every 03, then one of
C_MAXMSGS, C_WRONG_AUTHOR = 0x9D, 0x96
C_MBOX_SYNC, C_DIR_SYNC, C_SYNC_NOT_AVAILABLE = 0xA2, 0xA5, 0xA7   # newer clients (newer-client-check.md)

T_CODE = 30          # TIMEOUT/ default 30 s, restarted whenever data moves (router-answer.md)
T_LONG = 330         # MSGWAIT/ default 330 s for verdicts, 86 and 87
T_OPENER = 30        # wait 30 s (+CONNWAIT/) for ff aa 55 11, then refuse with control 10h


class Refused(Exception):
    pass


def read_lstring(link: Link, timeout=T_CODE) -> bytes:
    n = link.read_exact(1, timeout)[0]
    if n == 0 or n > 0x80:
        raise Refused(f"bad string length {n}")
    return link.read_exact(n, timeout)


def lstring(b: bytes) -> bytes:
    return bytes([len(b)]) + b


class Call:
    def __init__(self, link: Link, po, name="call"):
        self.link = link
        self.po = po
        self.name = name
        self.user = None
        self.received = 0
        self.sent = 0

    def run(self):
        link = self.link
        mode = link.wait_mode(60)
        if mode != RAW and not self.wait_opener():
            return
        # stray bytes before 80 are ignored; a calling post office (Router 6.x) sends B0 80 and
        # is content with a plain 81.
        while True:
            code = link.read_code(T_CODE)
            if code == C_SESSION:
                break
            if code == 0xAD:
                # HP 200LX client's interactive probe (hp200lx-check.md §5.2): AE, negotiation, login,
                # then remote VIM calls instead of 84..88 (vimserver.py)
                from .vimserver import Interactive
                Interactive(self).run()
                return
            log.info("%s: ignoring %02x before 80", self.name, code)
        link.write(bytes([C_SESSION_OK]))
        if not self.login():
            return
        log.info("%s: %s logged in%s (%s)", self.name, self.user or "unknown caller",
                 " read-only" if self.readonly else "", mode)
        fetching = self.start_fetch()
        if self.receive_messages():
            if not self.readonly:
                self.wait_fetch(fetching)
                self.send_messages()
            link.write(bytes([C_DONE]))
        # after 8D the post office sends no 88 and hangs up
        link.drain(30)
        log.info("%s: done, %d received, %d sent", self.name, self.received, self.sent)

    def start_fetch(self):
        """A user with her own "fetch" account (fetch.py): fetch it now, in a thread, while the
        caller uploads; (thread, deadline) or None."""
        fetcher = getattr(self.po, "fetcher", None)
        if not fetcher or not self.user or self.caller_po or self.readonly or not fetcher.has(self.user):
            return None
        from .fetch import CALL_WAIT
        log.info("%s: fetching %s's internet mail", self.name, self.user)
        return fetcher.start(self.user, CALL_WAIT), time.monotonic() + CALL_WAIT

    def wait_fetch(self, fetching):
        """Before our turn: wait for the fetch up to its deadline, servicing the link meanwhile
        (the link is pumped by this thread); a slow server is logged and the call goes on."""
        if not fetching:
            return
        thread, deadline = fetching
        while thread.is_alive() and time.monotonic() < deadline:
            self.link.pump(0.1)
        if thread.is_alive():
            log.info("%s: fetch for %s still running, sending what is here", self.name, self.user)

    def wait_opener(self):
        """Look for ff aa 55 11 anywhere in the delivered data; after 30 s refuse the
        link with control code 10h. Then accept with 0Fh."""
        link = self.link
        buf = b""
        try:
            while OPENER not in buf:
                buf = (buf + link.read_exact(1, T_OPENER))[-8:]
        except LinkTimeout:
            log.info("%s: no opener within %d s, refusing the link (10h)", self.name, T_OPENER)
            link.send_control(CTL_REFUSE)
            link.drain(10)
            return False
        link.send_control(CTL_ACCEPT)
        return True

    readonly = False
    caller_po = None          # set when the caller is another post office

    def login(self):
        """The post office's answer: known name -> 8B, password,
        82 or 8C+reason; unknown name -> 83 (read-only, no password), or bare 8C when read-only
        callers are refused (NOR/O). Then the post office name and the caller's 82/83."""
        link = self.link
        name = read_lstring(link).split(b"\x00", 1)[0].decode("cp850", "replace")
        caller_po = self.po.post_office(name)
        if caller_po:
            # another post office (router-to-router.md 2.2)
            link.write(bytes([C_PASSWORD]))
            password = read_lstring(link)
            if not self.po.check_po_password(caller_po, password):
                log.info("%s: wrong call password from post office %s (sent %d bytes)", self.name, caller_po,
                         len(password))
                log.debug("%s: call password sent: %r", self.name, password)
                link.write(bytes([C_REFUSED, R_WRONG_PASSWORD, 0]))
                link.drain(10)
                return False
            self.caller_po = self.user = caller_po
            link.write(bytes([C_YES]) + lstring(self.po.name.encode("cp850") + b"\x00"))
            reply = link.read_code(T_CODE)
            if reply != C_YES:
                log.info("%s: post office %s rejected our name (%02x)", self.name, caller_po, reply)
                return False
            return True
        user = self.po.user(name)
        if not user:
            if not self.po.allow_readonly:
                log.info("%s: unknown caller %r refused (read-only callers not allowed)", self.name, name)
                link.write(bytes([C_REFUSED]))
                link.drain(10)
                return False
            log.info("%s: unknown caller %r, read-only connection", self.name, name)
            self.readonly = True
            answer = C_NO
        else:
            link.write(bytes([C_PASSWORD]))
            password = read_lstring(link)
            if self.po.is_locked(user):
                # later calls after the lockout: 8C 97 <configured limit>
                log.info("%s: %s is locked, refused", self.name, user)
                link.write(bytes([C_REFUSED, R_LOCKED, min(self.po.lock_after, 255)]))
                link.drain(10)
                return False
            if not self.po.check_password(user, password):
                # every wrong password, including the one that locks the mailbox: 8C 98 00
                n = self.po.record_login(user, False)
                log.info("%s: wrong password for %s (%d failed)%s", self.name, user, n,
                         ", now locked" if self.po.is_locked(user) else "")
                link.write(bytes([C_REFUSED, R_WRONG_PASSWORD, 0]))
                link.drain(10)
                return False
            self.po.record_login(user, True)
            self.user = user
            answer = C_YES
        link.write(bytes([answer]) + lstring(self.po.name.encode("cp850") + b"\x00"))
        reply = link.read_code(T_CODE)
        if reply != C_YES:
            log.info("%s: caller says wrong post office (%02x)", self.name, reply)
            return False
        return True

    def receive_messages(self):
        """The caller's turn. Returns False if the caller does not want to receive (8D)."""
        link = self.link
        while True:
            code = link.read_code(T_LONG)
            if code == C_DONE:
                return True
            if code == C_DONE_NO_RECV:
                return False
            if code == C_DIR_SYNC:
                # newer client's address book sync request: any byte other than
                # 84 refuses it; the client goes on with its turn (newer-client-check.md item 27)
                log.info("%s: address book sync requested, refused (83)", self.name)
                link.write(bytes([C_NO]))
                continue
            if code == C_MBOX_SYNC:
                # mailbox sync request: A7 = not available for a remote-only
                # account; silence would end the call
                log.info("%s: mailbox sync requested, not available (A7)", self.name)
                link.write(bytes([C_SYNC_NOT_AVAILABLE]))
                continue
            if code != C_HAVE_MSG:
                # the post office treats any other byte in the caller's turn like 88
                log.info("%s: %02x in the caller's turn, taken as 88", self.name, code)
                return True
            link.write(bytes([C_SEND_IT]))
            hl = struct.unpack("<H", link.read_exact(2, T_CODE))[0]
            record = link.read_exact(hl, T_CODE)
            total, addr_off, part1 = struct.unpack_from("<IIH", record, 0)
            entries = _to_entries(record, part1)
            refusal = self._filter(record, part1, total)
            if refusal:
                # 82 for every 03 entry, then the filter's code; the
                # caller keeps the message
                link.write(bytes([C_YES]) * len(entries) + bytes([refusal]))
                log.info("%s: message refused with %02x", self.name, refusal)
                continue
            gw = getattr(self.po, "gateway", None)
            own = self.po.name.lower()
            accepted, external, routed = [], [], []
            verdicts = bytearray()
            n_accepted = 0
            for name, path in entries:                      # one verdict per tag-03 entry, in order
                if n_accepted >= limits.RECIPIENTS_MAX:
                    # the post office answers 83 for every entry once the count reaches 1000
                    verdicts.append(C_NO)
                    continue
                lpath = [p.strip().lower() for p in path]
                local = route_to = None
                if not lpath or own in lpath:
                    local = self.po.user(name)
                    if not local and name.strip().lower() == "administrator":
                        # a client's directory update request goes to "Administrator"; the post
                        # office accepts it. Kept in the admin queue until updates are served.
                        local = self.po.admin_mailbox
                    if not local:
                        route_to = ade.user_route(self.po, name)   # learned by ADE (ade.py)
                else:
                    # route to the last known post office in the 0F run, scanning up to
                    # a 0F naming this post office (router-to-router.md 3.2)
                    for p in path:
                        if p.strip().lower() == own:
                            break
                        if self.po.post_office(p):
                            route_to = self.po.post_office(p)
                        elif ade.po_route(self.po, p):
                            route_to = ade.po_route(self.po, p)    # a post office learned by ADE
                if local:
                    verdicts.append(C_YES)
                    if local not in accepted:
                        accepted.append(local)
                elif route_to:
                    verdicts.append(C_YES)
                    if route_to not in routed:
                        routed.append(route_to)
                elif gw and gw.enabled_for(self.user) and gw.is_external(name, path):
                    verdicts.append(C_YES)
                    if name not in external:
                        external.append(name)
                else:
                    verdicts.append(C_NO)
                if verdicts[-1] == C_YES:
                    n_accepted += 1
            link.write(bytes(verdicts))
            if not accepted and not external and not routed:
                link.write(bytes([C_UNKNOWN_RCPTS]))
                log.info("%s: message refused, no known recipients", self.name)
                continue
            if shutil.disk_usage(self.po.root).free < total + 0x200:
                # the clients' own receive rule; the post office answers 8A when it
                # cannot create the message. The caller keeps the message.
                link.write(bytes([C_NO_SPACE]))
                log.error("%s: no disk space for a %d-byte message", self.name, total)
                continue
            link.write(bytes([C_SEND_BODY]))
            body = link.read_exact(addr_off - part1, T_LONG)
            stored_total = addr_off + len(record) - part1
            if stored_total != total:
                # the HP 200LX client leaves dword[0] without the 03 copies it appends for the wire
                # (captured 2026-11-25: 183 for a 191-byte message). The record is read by
                # the sent length and the body by word[8]..dword[4]; dword[0] only feeds MSGSIZE/
                # and grows as a post office adds tags (router-answer.md 2.2, router-to-router.md 3.2), so take the real size
                log.info("%s: header says %d bytes, record and body make %d; corrected",
                         self.name, total, stored_total)
                record = struct.pack("<I", stored_total) + record[4:]
            try:
                msg = Message(record, body)
                if not self.caller_po and not any(t in (0x31, 0x20, 0x21) for t, _ in msg.tlvs):
                    # old clients send no code page tags: the bytes are in the uploader's DOS
                    # code page (codepages.md 5.2); store raw, tagged
                    msg = msg.with_codepage(self.po.user_codepage(self.user))
                ade_msg = (self.po.admin_mailbox in accepted and ade.is_ade(self.po, self.caller_po, msg))
                if ade_msg:
                    # the post office applies it instead of delivering it (type 23; ade.py)
                    accepted.remove(self.po.admin_mailbox)
                mid = self.po.accept(msg, accepted)
                if ade_msg:
                    try:
                        log.info("%s: ADE %s", self.name, ade.handle(self.po, self.caller_po, msg))
                    except Exception:
                        log.exception("%s: ADE message %s not processed", self.name, mid)
                for p in routed:
                    self.po.route(p, msg)
                if external:
                    gw.queue_outbound(msg, external)
            except (OSError, ValueError) as e:
                # the post office swallows the body and answers 8F when it cannot store the message
                log.error("%s: cannot store message: %s", self.name, e)
                link.write(bytes([C_CANNOT_STORE]))
                continue
            link.write(bytes([C_STORED]))
            self.received += 1
            after = directory.request_after(msg) if self.user and not self.caller_po else None
            if after is not None:
                # a client's directory update request (directory-updates.md §1). A cc:Mail post
                # office never answers it; answering with the whole directory is our own
                # addition, delivered in this same call (our turn comes next)
                upd = directory.update_message(self.po.name, self.user, directory.directory_entries(self.po),
                                               cp=self.po.user_codepage(self.user))
                self.po.deposit(self.user, upd)
                log.info("%s: directory update request (after %s): directory queued for %s",
                         self.name, after, self.user)
            log.info("%s: received %s from %s for %s: %r", self.name, mid, msg.author,
                     ", ".join(accepted + external + [f"post office {p}" for p in routed]), msg.subject)

    def _filter(self, record, part1, total):
        """The post office's per-message filters before the verdicts (router-answer.md 2.2
        step 4, in that order); returns the refusal code or 0. EXCH/ and PRI/ are not offered."""
        tlvs = parse_tlvs(record[:part1], FIXED_LEN) + parse_tlvs(record[part1:], 0)
        if any(t == 0x32 for t, _ in tlvs):
            return 0                                    # mailbox-sync copy: all 82
        kind = 0
        for t, d in tlvs:
            if t == 0x1C and len(d) >= 2:               # message kind: &2 directory, &4 bulletin
                kind = struct.unpack_from("<H", d)[0] & 6
        if self.po.max_msgs and self.received >= self.po.max_msgs:
            return C_MAXMSGS                            # MAXMSGS/
        if not kind and self.po.msg_size_kb and total > self.po.msg_size_kb * 1000:
            return C_TOO_LARGE                          # MSGSIZE/ KB*1000 < dword[0], mail only
        if not self.caller_po and self.user:
            # author = the last 02 (forwarded by), else the 01
            fwd = [text(d) for t, d in tlvs if t == TAG_FORWARDED_BY]
            frm = [text(d) for t, d in tlvs if t == TAG_FROM]
            author = fwd[-1] if fwd else (frm[0] if frm else "")
            if self.po.user(author) != self.user:
                log.info("%s: author %r is not the caller %r", self.name, author, self.user)
                return C_WRONG_AUTHOR
        return 0

    def send_messages(self):
        """Our turn: a user caller gets its mailbox; a post-office caller gets its route queue,
        each message as the per-destination copy (router-to-router.md 3.3)."""
        if self.caller_po:
            for mid, msg in send_order(self.po.routed(self.caller_po)):
                out = msg.for_post_office(self.caller_po, self.po.name)
                if out is None:
                    self.po.route_sent(self.caller_po, mid)
                    continue
                r = self.send_one(mid, out)
                if self._returned(r, mid, out, msg, self.caller_po) or r == C_STORED:
                    self.po.route_sent(self.caller_po, mid)
            return
        cp = self.po.user_codepage(self.user)
        for mid, msg in send_order(self.po.pending(self.user)):
            # send side: MAXMSGS/ ends the turn, MSGSIZE/ skips larger
            # messages without offering them; both off by default
            if self.po.max_msgs and self.sent >= self.po.max_msgs:
                break
            if self.po.msg_size_kb and msg.total > self.po.msg_size_kb * 1000:
                log.info("%s: %s is larger than MSGSIZE, kept", self.name, mid)
                continue
            # convert to the code page this user's client shows and rewrite the tags, since
            # clients keep and forward tags unchanged (codepages.md 5.3)
            src = msg.codepages(self.po.codepage)
            out = msg.with_codepage(cp, convert_from=src) if src != (cp, cp, cp) else msg
            r = self.send_one(mid, out)
            # the report is built from the stored copy (a cc:Mail post office does no conversion
            # and sends the stored record): names, tag 21 and the item bytes then agree. with_codepage
            # keeps the 03 entries in order, so the verdicts still line up
            if self._returned(r, mid, msg, msg, self.user) or r == C_STORED:
                self.po.delivered(self.user, mid)

    def _returned(self, r, mid, sent, stored, refused_by):
        """After one message: 87 with any 83 verdict, or 89: the 83 entries become tag 10, a
        non-delivery report goes to the author, and the message counts as sent
        (also when no report could be built). Other refusals keep the message."""
        if not (r == C_UNKNOWN_RCPTS or (r == C_STORED and C_NO in self.last_verdicts)):
            return False
        log.info("%s: %s: unknown recipients. Notifying sender", self.name, mid)
        try:
            self.po.non_delivery(sent.mark_refused(self.last_verdicts), stored, refused_by)
        except (OSError, ValueError) as e:
            log.error("%s: %s: cannot build the non-delivery report: %s", self.name, mid, e)
        return True

    last_verdicts = b""

    def send_one(self, mid, msg):
        """84 | 85 | len + record | one verdict per 03 | 86 | body | 87 (session-layer.md 4.1)."""
        link = self.link
        self.last_verdicts = b""
        link.write(bytes([C_HAVE_MSG]))
        r = link.read_code(T_CODE)
        if r != C_SEND_IT:
            log.info("%s: peer declined message %s (%02x)", self.name, mid, r)
            return r
        link.write(struct.pack("<H", len(msg.record)) + msg.record)
        verdicts = [link.read_code(T_LONG) for _ in msg.recipients_to()]
        self.last_verdicts = bytes(verdicts)
        r = link.read_code(T_LONG)
        if r != C_SEND_BODY:
            log.info("%s: peer will not take %s: verdicts %s, reply %02x", self.name, mid,
                     bytes(verdicts).hex(" "), r)
            return r
        link.write(msg.body)
        r = link.read_code(T_LONG)
        if r == C_STORED:
            self.sent += 1
            log.info("%s: delivered %s (verdicts %s)", self.name, mid, bytes(verdicts).hex(" "))
        else:
            log.info("%s: peer did not store %s (%02x)", self.name, mid, r)
        return r


def send_order(messages):
    """The post office's order for the sender's turn: directory items, then mail urgent, normal, low, then
    bulletins; arrival order within each class (router-answer.md 2.4;
    router-to-router.md 3.3 for a post-office caller). Directory = tag 1C bit 2 or a CCMUPDAT /
    CCMSYNCH title (ours carry no tag 1C); bulletin = tag 1C bit 4."""
    def rank(item):
        msg = item[1]
        kind = 0
        for t, d in msg.tlvs:
            if t == 0x1C and len(d) >= 2:
                kind = struct.unpack_from("<H", d)[0] & 6
        title = " ".join(msg.titles())
        if kind & 2 or title.startswith(("CCMUPDAT", "CCMSYNCH")):
            return 0
        if kind & 4:
            return 4
        return {"urgent": 1, "normal": 2, "low": 3}.get(msg.priority, 2)
    return sorted(messages, key=rank)          # sorted() is stable: arrival order kept per class


def call_post_office(po, dest, sock, mode, name="out", line_bps=None):
    """We call another post office (router-to-router.md 1.3/1.4 and 7.2): opener (packet mode),
    80 -> 81, our name, 8B -> call password, its 82/83 + its name, our 82; we send first (its route
    queue), then 88, then receive its messages until its 88. line_bps = the line's speed when
    known (a modem's CONNECT), for the link's line clock."""
    link = Link(sock, name, mode=mode, speed=line_bps)
    call = Call(link, po, name)
    if mode != RAW:
        if not link.call_open(OPENER):
            log.info("%s: %s refused the link (control 10h)", name, dest)
            return call
    else:
        link.retx_seconds = link.assembly_seconds = 6.2
    link.write(bytes([C_SESSION]))
    while link.read_code(T_CODE) != C_SESSION_OK:
        pass
    link.write(lstring(po.name.encode("cp850") + b"\x00"))
    x = link.read_code(T_CODE)
    if x == C_PASSWORD:
        pw = po.post_office_cfg(dest).get("call_password", "")
        link.write(lstring(pw.encode("cp850") + b"\x00"))
        x = link.read_code(T_CODE)
    if x == C_REFUSED:
        log.info("%s: %s refused our login (wrong call password?)", name, dest)
        return call
    if x not in (C_YES, C_NO):
        log.info("%s: unexpected reply %02x from %s", name, x, dest)
        return call
    their = read_lstring(link).split(b"\x00", 1)[0].decode("cp850", "replace")
    if their.strip().lower() != dest.lower():
        log.info("%s: answered as %r, not %s", name, their, dest)
        link.write(bytes([C_NO]))
        link.drain(10)
        return call
    link.write(bytes([C_YES]))
    log.info("%s: connected to post office %s%s (%s)", name, dest, "" if x == C_YES else " read-only", mode)
    call.caller_po = call.user = po.post_office(dest)
    call.send_messages()
    link.write(bytes([C_DONE]))
    call.receive_messages()
    link.drain(30)
    log.info("%s: done, %d sent, %d received", name, call.sent, call.received)
    return call


def _to_entries(record, part1):
    """[(name, [post office path])] for each tag-03 entry of the addressing part."""
    out = []
    current = None
    pos = part1
    while pos + 2 <= len(record):
        t, n = record[pos], record[pos + 1]
        data = record[pos + 2:pos + 2 + n].split(b"\x00", 1)[0].decode("cp850", "replace")
        pos += 2 + n
        if t == 0x0F and current is not None:
            current[1].append(data)
        elif t == 0x03:
            current = (data, [])
            out.append(current)
        elif t != 0x14:
            current = None
    return out
