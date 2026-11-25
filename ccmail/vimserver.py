# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Interactive mode (HP 200LX clients): the server side of the remote VIM ("SVIM") calls
(spec/hp200lx-check.md §5; our server-side model: spec/hp200lx-check.md §5.15).

Entered from session.Call.run when the caller sends AD before 80:
1. AD -> AE (§5.2); further AD bytes of the client's retries are skipped, never answered twice;
2. phase A: the client's AF 01 packets, hello "SVIM"/100, 2 idle timeout, 3 max message size, 8 end;
   phase B: we have nothing to ask and send AF 01 09 00 00 00 00 00 (§5.3);
3. the normal login (session.Call.login): an unknown name gets 83 and the client hangs up (§5.4);
4. the client's control record type 1 -> our control record type 3, u32 0 (§5.4 step 9-10);
5. data records 00 len block: one remote VIM call per record, one reply record each (§5.5, §5.9);
   control record type 2 = disconnect, answered with type 2, 00 (§5.6).

The mailbox model (inbox, folders, drafts, read flags) is ours; see Mailbox.
"""
import bisect
import datetime
import json
import logging
import os
import struct
import threading

from . import ade
from . import message as M
from . import vimblock as V
from .link import LinkClosed, LinkTimeout

log = logging.getLogger("ccmail.vim")

C_PROBE, C_PROBE_OK, MAGIC = 0xAD, 0xAE, 0xAF
NEG_HELLO, NEG_IDLE, NEG_MAXSIZE, NEG_END, NEG_END_REPLY = 1, 2, 3, 8, 9
HELLO_ID, HELLO_VERSION = b"SVIM", 100
REC_DATA, REC_CONTROL = 0x00, 0x01
CTL_LOGIN, CTL_DISCONNECT, CTL_LOGIN_REPLY = 1, 2, 3
T_READ = 31                 # the client's own reads time out after 23Ah ticks (31 s)

# ----- VIM.H / VIMEXT.H values -----
SEL = dict(ADDRESS=0x01, ATTACH=0x06, BCC=0x09, CC=0x0A, CLASS=0x0D, CP1252=0x10, CP437=0x11,
           CP850=0x12, DATE=0x13, DRAFT=0x17, ENTITY=0x1A, FORWARD=0x21, FROM=0x22, FROM_NAME=0x23,
           FULL=0x24, GROUP=0x26, LOCAL=0x2D, NAME=0x35, NATIVE=0x37, NO_FILTER=0x3A, NOTE_PART=0x3E,
           APP_DEFINED=0x04, PARTIAL=0x43, PRIORITY=0x47, RDN=0x49, RECIPIENT=0x4B, REF=0x4C, REPLY=0x4D,
           SAVE=0x51, SENT=0x53, SUBJECT=0x5B, TO=0x61, TYPE=0x62, UNKNOWN_RECIP_TYPE=0x65,
           UNREAD_MAIL=0x67, CATEGORY=0x100)
SUCCESS, FAILURE, ALL_PARAMS_REQUIRED, ATTACHMENT_NOT_FOUND, BAD_PARAM = 0, 1, 3, 4, 5
BUF_TOO_SMALL, INVALID_OBJECT, INVALID_SELECTOR, NAME_NOT_FOUND, NOT_SUPPORTED = 6, 10, 12, 15, 16
NO_MATCH, OPEN_FAILURE, READ_FAILURE, UNSUP_TYPE, UNSUP_VERSION, WRITE_FAILURE = 19, 22, 24, 25, 26, 27
UNREADONLY = 1
INHERIT_CONTENTS, ALL_RECIPIENTS, HISTORY = 2, 4, 1
CHARSETS = {SEL["CP850"]: 850, SEL["CP437"]: 437, SEL["CP1252"]: 1252}

# procedure -> (name, request format, reply format) (spec §5.9 table)
PROCS = {
    0x0003: ("OpenSession", "fzzzds", "th"), 0x0005: ("CloseSession", "fh", "t"),
    0x000F: ("Ping", "", "t"),
    0x0100: ("CreateMessage", "fhz", "th"), 0x0101: ("CreateDerivedMailMessage", "fhSd", "th"),
    0x0102: ("SetMessageHeader", "fhSp", "t"), 0x0103: ("SetMessageRecipient", "fhSN", "t"),
    0x0104: ("SetMessageItem", "fhSzSzC", "t"), 0x0105: ("SendMessage", "fh", "t"),
    0x0106: ("CloseMessage", "fh", "t"),
    0x0200: ("OpenMessageContainer", "fhz", "th"), 0x0201: ("EnumerateMessages", "fhEiSpda", "tEbA"),
    0x0202: ("EnumerateMsgAttrValues", "fhSEiww", "tEbwp"), 0x0203: ("RemoveMessage", "fhR", "t"),
    0x0204: ("QueryNewMessages", "fh", "tb"), 0x0205: ("QueryUnreadMailCount", "fh", "td"),
    0x0208: ("CloseMessageContainer", "fh", "t"),
    0x0300: ("OpenMessage", "fhRz", "th"), 0x0301: ("MarkMessageAsRead", "fhR", "t"),
    0x0302: ("GetMessageHeader", "fha", "tA"), 0x0304: ("EnumerateMessageItems", "fhEiwSp", "tEbwD"),
    0x0306: ("OpenMessageItem", "fhRzd", "th"), 0x0307: ("ReadMessageItem", "fhc", "tdC"),
    0x0308: ("CloseMessageItem", "fh", "t"), 0x0309: ("EnumerateMessageRecipients", "fhSEia", "tEbA"),
    0x0400: ("EnumerateAddressBooks", "fhEia", "tEbA"), 0x0401: ("OpenAddressBook", "fhz", "th"),
    0x0402: ("SetCurrentSubtree", "fhRz", "t"), 0x0403: ("GetCurrentSubtree", "fhw", "tRwz"),
    0x0404: ("EnumerateAddressBookEntries", "fhRzEiSpa", "tEbA"),
    0x0405: ("CreateAddressBookEntry", "fhSA", "t"), 0x0406: ("MatchAddressBook", "fhRzSpSR", "tRh"),
    0x0407: ("GetABEntryAttributes", "fhRza", "tA"), 0x040C: ("RemoveAddressBookEntry", "fhRz", "t"),
    0x040D: ("AddGroupMember", "fhRzszz", "t"), 0x040F: ("EnumerateGroupMembers", "fhRzEia", "tEbA"),
    0x0410: ("CloseAddressBook", "fh", "t"),
    0x0601: ("SetMessageCategory", "fhRz", "t"), 0x0602: ("RemoveMessageCategory", "fhRz", "t"),
    0x0603: ("RemoveCategory", "fhzb", "t"),
}
# accepted on the wire but refused: our books are read-only; the client does not send
# 0400/0402/0403, and 0603 only for its local container (spec §5.13, §5.14)
UNSUPPORTED = {0x0400, 0x0402, 0x0403, 0x0405, 0x040C, 0x040D, 0x0603}

SESSION_HANDLE = 0x00010001          # SERVER numbering of CCHANDLE.H: 0001xxxx, ISLOCAL bit clear


def ref_bytes(a, b=0):
    return struct.pack("<II", a, b)


def ref_ints(r):
    return struct.unpack("<II", r)


def vim_date(when: datetime.datetime):
    """vimDate {Zone, Date = year<<16 | month<<8 | day, Time = h<<24 | m<<16 | s<<8 | 1/100 s}."""
    if when is None:
        return struct.pack("<III", SEL["LOCAL"], 0xFFFFFFFF, 0xFFFFFFFF)
    return struct.pack("<III", SEL["LOCAL"], when.year << 16 | when.month << 8 | when.day,
                       when.hour << 24 | when.minute << 16 | when.second << 8)


def _pad(b: bytes, size):
    """A binary value at exactly the requested size (strings are already cut by _fixed_str)."""
    return b[:size].ljust(size, b"\x00")


def _date_key(d, t):
    return (d << 32) | t


def _fixed_str(b: bytes, size):
    b = b[:max(size - 1, 0)]
    return b + bytes(size - len(b))


def walk(n, start, skip, count):
    """VIM enumeration over n entries in server order (our model of skipCount, spec §5.15):
    start = index of the position entry, or None for the position 0 (outside the list: skip +1
    goes to the first entry, skip -1 to the last). The first entry returned is skip steps away;
    then up to count entries in the direction of skip (0 counts forward). Returns (indexes,
    more): more = entries remain beyond the last one returned in that direction."""
    step = -1 if skip < 0 else 1
    if start is None:
        first = (n + skip) if skip < 0 else (skip - 1 if skip > 0 else 0)
    else:
        first = start + skip
    out = []
    i = first
    while 0 <= i < n and len(out) < count:
        out.append(i)
        i += step
    return out, 0 <= i < n


# ----- the mailbox -----

class Mailbox:
    """Our model (spec §5.15), one per user under <root>/vim/<user>/:
    - every message has a ref serial, a read flag, an inbox flag and a list of folders
      (state.json); refs stay the same across calls;
    - inbox = the pending mail in mail/<user>/ (what a batch call would deliver) plus kept
      messages with the inbox flag;
    - a message filed into a folder (0601) moves to vim/<user>/kept/, so a later batch call does
      not take it away; it stays in the inbox until removed there (0203);
    - a message in no folder and not in the inbox is moved to deleted/<user>/ (never destroyed);
    - drafts (0106 of a created message with DRAFT = 1) are kept in vim/<user>/drafts/, listed
      only by the DRAFT filter;
    - a batch call still delivers pending mail as before (read or not); it then leaves the inbox."""
    _locks = {}

    def __init__(self, po, user):
        self.po, self.user = po, user
        self.base = os.path.join(po.root, "vim", user)
        self.pending_dir = os.path.join(po.root, "mail", user)
        self.dirs = {"mail": self.pending_dir, "kept": os.path.join(self.base, "kept"),
                     "draft": os.path.join(self.base, "drafts")}
        self.state_path = os.path.join(self.base, "state.json")
        self.lock = Mailbox._locks.setdefault(os.path.abspath(self.base), threading.RLock())
        self.state = {"next_ref": 1, "msgs": {}}
        self.load()

    def load(self):
        with self.lock:
            try:
                with open(self.state_path, encoding="utf-8") as f:
                    self.state = json.load(f)
            except (OSError, ValueError):
                self.state = {"next_ref": 1, "msgs": {}}
            msgs = self.state["msgs"]
            seen = set()
            for where, d in self.dirs.items():
                if not os.path.isdir(d):
                    continue
                for fn in sorted(os.listdir(d)):
                    if not fn.endswith(".msg"):
                        continue
                    mid = fn[:-4]
                    seen.add(mid)
                    e = msgs.get(mid)
                    if e is None:
                        e = msgs[mid] = {"ref": self.state["next_ref"], "read": False,
                                         "inbox": where != "draft", "folders": [], "where": where}
                        self.state["next_ref"] += 1
                    e["where"] = where
            for mid in list(msgs):
                if mid not in seen:            # delivered by a batch call, or deleted elsewhere
                    del msgs[mid]
            self.save()

    def save(self):
        os.makedirs(self.base, exist_ok=True)
        tmp = self.state_path + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=1)
        os.replace(tmp, self.state_path)

    def path(self, mid):
        return os.path.join(self.dirs[self.state["msgs"][mid]["where"]], mid + ".msg")

    def read(self, mid) -> M.Message:
        with open(self.path(mid), "rb") as f:
            return M.Message.from_file(f.read())

    def by_ref(self, ref):
        a, _ = ref_ints(ref)
        for mid, e in self.state["msgs"].items():
            if e["ref"] == a:
                return mid
        return None

    def ref_of(self, mid):
        return ref_bytes(self.state["msgs"][mid]["ref"])

    def listing(self, sel, data, flags, match=None):
        """Message ids in server order (oldest first) for a filter."""
        self.load()
        out = []
        for mid in sorted(self.state["msgs"]):
            e = self.state["msgs"][mid]
            if sel == SEL["DRAFT"]:
                ok = e["where"] == "draft"
            elif sel == SEL["CATEGORY"]:
                name = (data or b"").split(b"\x00", 1)[0].decode("cp850", "replace").lower()
                ok = e["where"] != "draft" and name in [x.lower() for x in e["folders"]]
            elif sel == SEL["SENT"]:
                ok = False                     # no sent copies are kept (spec §5.15)
            else:
                ok = e["where"] != "draft" and e["inbox"]
                if ok and match:
                    ok = match(mid)
            if ok and flags & UNREADONLY:
                ok = not e["read"]
            if ok:
                out.append(mid)
        return out

    def _move(self, mid, where):
        e = self.state["msgs"][mid]
        if e["where"] == where:
            return
        src, dst = self.dirs[e["where"]], self.dirs[where]
        os.makedirs(dst, exist_ok=True)
        for ext in (".msg", ".txt"):
            p = os.path.join(src, mid + ext)
            if os.path.exists(p):
                os.replace(p, os.path.join(dst, mid + ext))
        e["where"] = where

    def _drop_if_unused(self, mid):
        e = self.state["msgs"][mid]
        if e["inbox"] and e["where"] != "draft" or e["folders"]:
            return False
        src = self.dirs[e["where"]]
        dst = os.path.join(self.po.root, "deleted", self.user)
        os.makedirs(dst, exist_ok=True)
        for ext in (".msg", ".txt"):
            p = os.path.join(src, mid + ext)
            if os.path.exists(p):
                os.replace(p, os.path.join(dst, mid + ext))
        del self.state["msgs"][mid]
        return True

    def mark_read(self, mid):
        with self.lock:
            self.state["msgs"][mid]["read"] = True
            self.save()

    def remove(self, mid):
        """0203: out of the inbox (a draft: deleted); kept while in a folder."""
        with self.lock:
            e = self.state["msgs"][mid]
            e["inbox"] = False
            if e["where"] == "draft":
                e["folders"] = []
            self._drop_if_unused(mid)
            self.save()

    def add_folder(self, mid, name):
        with self.lock:
            e = self.state["msgs"][mid]
            if name.lower() not in [x.lower() for x in e["folders"]]:
                e["folders"].append(name)
            if e["where"] == "mail":
                self._move(mid, "kept")
            self.save()

    def remove_folder(self, mid, name):
        with self.lock:
            e = self.state["msgs"][mid]
            before = len(e["folders"])
            e["folders"] = [x for x in e["folders"] if x.lower() != name.lower()]
            if len(e["folders"]) == before:
                return False
            self._drop_if_unused(mid)
            self.save()
            return True

    def folders(self):
        self.load()
        names = {}
        for e in self.state["msgs"].values():
            for x in e["folders"]:
                names.setdefault(x.lower(), x)
        return [names[k] for k in sorted(names)]

    def save_draft(self, msg: M.Message):
        with self.lock:
            mid = self.po._new_id()
            os.makedirs(self.dirs["draft"], exist_ok=True)
            with open(os.path.join(self.dirs["draft"], mid + ".msg"), "wb") as f:
                f.write(msg.to_file())
            with open(os.path.join(self.dirs["draft"], mid + ".txt"), "w", encoding="utf-8") as f:
                f.write(msg.to_text())
            # kept as read: after a failed send the client looks for its half-made message with
            # VIM_UNREADONLY and must not find, and remove, an older draft
            self.state["msgs"][mid] = {"ref": self.state["next_ref"], "read": True, "inbox": False,
                                       "folders": [], "where": "draft"}
            self.state["next_ref"] += 1
            self.save()
            return mid


# ----- session objects -----

class Opened:
    """An opened message (0300): the stored message converted to the session code page."""
    def __init__(self, mid, msg, cp, po):
        self.mid = mid
        self.msg = msg.with_codepage(cp, convert_from=msg.codepages(po.codepage))
        self.items = []
        for it in self.msg.logical_items():
            if it["type"] == "text":
                cls, typ = SEL["NOTE_PART"], "VIM_TEXT"
            elif it["type"] in ("file", "macfile"):
                cls, typ = SEL["ATTACH"], ""
            else:
                cls, typ = SEL["APP_DEFINED"], ""
            self.items.append(dict(cls=cls, type=typ, name=it["title"], path="", size=len(it["data"]),
                                   data=it["data"]))


class Draft:
    """A message being built (0100 / 0101)."""
    def __init__(self, derived=None, how=None, flags=0):
        self.subject = ""
        self.priority = 0
        self.save = self.draft = False
        self.recipients = []            # (class, name, path)
        self.text = []                  # bytes in the session code page
        self.files = []                 # (name, bytes)
        self.derived, self.how, self.flags = derived, how, flags
        # a Set* call refused: the client's cleanup follows; such a draft is not kept,
        # so its DRAFT-filter lookup cannot find and remove an older draft instead
        self.failed = False


class Book:
    def __init__(self, name, entries):
        self.name = name
        self.entries = entries          # [(display name, address, type)] sorted by name


def _recipients_of(msg: M.Message, cls):
    tags = {SEL["TO"]: (M.TAG_TO, M.TAG_SENT_TO, M.TAG_TO_LIST), SEL["CC"]: (M.TAG_CC, M.TAG_CC_SENT, M.TAG_CC_LIST),
            SEL["BCC"]: (M.TAG_BCC, M.TAG_BCC_SENT)}.get(cls, ())
    out = []
    for _t, name, path in msg.entries(tags):
        out.append(f"{name} at {path[-1]}" if path else name)
    return out


class Interactive:
    def __init__(self, call):
        self.call = call
        self.link = call.link
        self.po = call.po
        self.name = call.name
        self.idle = 300
        self.max_size = 0
        self.handles = {}
        self.next_handle = SESSION_HANDLE + 1
        self.session = False
        self.cp = 850
        self.box = None
        self.seen = set()               # message ids listed so far (0204)
        self.refmid = {}                # ref serial -> message id, for positions (0201)
        self.calls = 0

    # ----- link-level steps -----

    def run(self):
        link = self.link
        link.write(bytes([C_PROBE_OK]))
        log.info("%s: AD received, answered AE (HP interactive mode)", self.name)
        try:
            if not self.negotiate():
                return
            while True:
                code = link.read_code(T_READ)
                if code == 0x80:
                    break
                log.info("%s: ignoring %02x before 80", self.name, code)
            link.write(bytes([0x81]))
            if not self.call.login():
                return
            if self.call.caller_po or self.call.readonly:
                log.info("%s: interactive mode only for users; ending", self.name)
                return
            self.user = self.call.user
            log.info("%s: %s logged in, interactive", self.name, self.user)
            if not self.control_login():
                return
            self.box = Mailbox(self.po, self.user)
            self.loop()
        except LinkTimeout as e:
            log.info("%s: interactive call timed out: %s", self.name, e)
        except LinkClosed:
            log.info("%s: interactive call: line closed", self.name)
        finally:
            log.info("%s: interactive call ended after %d VIM calls", self.name, self.calls)

    def _read_packet_start(self):
        while True:
            b = self.link.read_exact(1, T_READ)[0]
            if b == C_PROBE:                    # a retry of the probe that crossed our AE
                log.info("%s: extra AD skipped", self.name)
                continue
            if b != MAGIC:
                log.info("%s: negotiation packet starts with %02x, not AF", self.name, b)
            return self.link.read_exact(1, T_READ)[0]

    def _send_entry(self, typ, status, data=b""):
        self.link.write(bytes([MAGIC, 1]) + struct.pack("<HHH", typ, status, len(data)) + data)

    def negotiate(self):
        """Phase A (the client's requests) and phase B (ours: none), spec §5.3."""
        link = self.link
        while True:
            n = self._read_packet_start()
            for _ in range(n):
                typ, status, ln = struct.unpack("<HHH", link.read_exact(6, T_READ))
                data = link.read_exact(ln, T_READ) if ln else b""
                log.info("%s: negotiation H> type %d status %d data %s", self.name, typ, status, data.hex(" "))
                if typ == NEG_HELLO:
                    ok = data[:4] == HELLO_ID and len(data) >= 6 and struct.unpack_from("<H", data, 4)[0] == HELLO_VERSION
                    # status 3 = unknown hello, as a post office answers it (negotiation.md); the
                    # client then fails with F011h
                    self._send_entry(0x8000 | typ, 0 if ok else 3)
                    if not ok:
                        log.info("%s: hello %r is not SVIM/100", self.name, data)
                        link.drain(10)
                        return False
                elif typ == NEG_IDLE and ln >= 2:
                    self.idle = struct.unpack_from("<H", data)[0]
                    self._send_entry(0x8000 | typ, 0)
                elif typ == NEG_MAXSIZE and ln >= 4:
                    self.max_size = struct.unpack_from("<I", data)[0]
                    self._send_entry(0x8000 | typ, 0)
                elif typ == NEG_END:
                    # phase B: nothing to ask; the client ends phase B on our type 9 (spec §5.3)
                    self._send_entry(NEG_END_REPLY, 0)
                    log.info("%s: negotiated: idle timeout %d s, max message size %d", self.name,
                             self.idle, self.max_size)
                    return True
                else:
                    self._send_entry(0x8000 | typ, 7)

    def _read_record(self, timeout):
        link = self.link
        while True:
            b = link.read_exact(1, timeout)[0]
            if b == REC_DATA:
                n = struct.unpack("<H", link.read_exact(2, T_READ))[0]
                return REC_DATA, None, link.read_exact(n, T_READ)
            if b == REC_CONTROL:
                typ, n = struct.unpack("<HH", link.read_exact(4, T_READ))
                return REC_CONTROL, typ, link.read_exact(n, T_READ) if n else b""
            log.info("%s: byte %02x between records skipped", self.name, b)

    def control_login(self):
        kind, typ, data = self._read_record(T_READ)
        if kind != REC_CONTROL:
            log.info("%s: expected the post-login control record, got data %s", self.name, data.hex(" "))
            return False
        log.info("%s: control H> type %d data %s", self.name, typ, data.hex(" "))
        # type 3 + u32: the client does not use the value (spec §5.4, §7.1); 0 is our choice
        self.link.write(bytes([REC_CONTROL]) + struct.pack("<HHI", CTL_LOGIN_REPLY, 4, 0))
        return True

    def loop(self):
        # the client pings every idle - 30 s (spec §5.10); wait a little longer than one interval
        wait = max(self.idle, 60) + 60
        while True:
            kind, typ, data = self._read_record(wait)
            if kind == REC_CONTROL:
                log.info("%s: control H> type %d data %s", self.name, typ, data.hex(" "))
                if typ == CTL_DISCONNECT:
                    self.link.write(bytes([REC_CONTROL]) + struct.pack("<HH", CTL_DISCONNECT, 1) + b"\x00")
                    try:
                        self.link.drain(10)
                    except (LinkTimeout, LinkClosed):
                        pass                    # the client hangs up without waiting (spec §5.6)
                    return
                continue
            self.calls += 1
            reply = self.dispatch(data)
            log.debug("%s: vim< %s", self.name, reply.hex(" "))
            self.link.write(bytes([REC_DATA]) + struct.pack("<H", len(reply)) + reply)

    # ----- VIM calls -----

    def dispatch(self, block: bytes) -> bytes:
        log.debug("%s: vim> %s", self.name, block.hex(" "))
        if len(block) < 2:
            log.info("%s: vim> short block %s", self.name, block.hex(" "))
            return V.build_reply("t", BAD_PARAM)
        proc = struct.unpack_from("<H", block)[0]
        entry = PROCS.get(proc)
        if entry is None or proc in UNSUPPORTED:
            log.info("%s: vim> %04x %s not supported: %s", self.name, proc, entry[0] if entry else "unknown",
                     block[:64].hex(" "))
            return V.build_reply("t", NOT_SUPPORTED)
        name, req, rep = entry
        try:
            args = V.parse_request(req, block)[1:] if req else []
        except V.BlockError as e:
            log.info("%s: vim> %04x %s: bad block (%s): %s", self.name, proc, name, e, block[:64].hex(" "))
            return V.build_reply("t", BAD_PARAM)
        shown = args[:2] + [b"***"] + args[3:] if proc == 0x0003 and len(args) > 2 else args
        log.info("%s: vim> %04x %s %s", self.name, proc, name, _show(shown))
        if proc not in (0x0003, 0x000F) and not self.session:
            out = V.build_reply("t", INVALID_OBJECT)
        else:
            try:
                out = getattr(self, "p%04x" % proc)(*args)
            except Exception as e:      # any failure is answered: the client would wait 31 s otherwise
                log.exception("%s: %s failed: %s", self.name, name, e)
                out = V.build_reply("t", FAILURE)
        status = struct.unpack_from("<I", out)[0]
        log.info("%s: vim< %04x %s status %d, %d bytes%s", self.name, proc, name, status, len(out),
                 "" if status else " " + _show_reply(rep, out))
        return out

    def _new(self, obj):
        h = self.next_handle
        self.next_handle += 1
        self.handles[h] = obj
        return h

    def _get(self, h, cls):
        obj = self.handles.get(h)
        return obj if isinstance(obj, cls) else None

    def _enc(self, s: str) -> bytes:
        from .codepage import tables
        return tables().encode(s or "", self.cp)

    def _dec(self, b: bytes) -> str:
        from .codepage import tables
        return tables().decode((b or b"").split(b"\x00", 1)[0], self.cp)

    # session

    def p0003(self, path, name, password, version, charset):
        if self.session:
            return V.build_reply("t", FAILURE)       # one remote session at a time
        who = self.po.user(self._dec(name)) if name else None
        if who != self.user:
            log.info("%s: OpenSession for %r, but %s logged in", self.name, name, self.user)
            return V.build_reply("t", NAME_NOT_FOUND)
        if version != 100:
            return V.build_reply("t", UNSUP_VERSION)
        if charset not in CHARSETS:
            return V.build_reply("t", INVALID_SELECTOR)
        # the password was checked by the login of the link (spec §5.4); not again here
        self.cp = CHARSETS[charset]
        self.session = True
        return V.build_reply("th", SUCCESS, SESSION_HANDLE)

    def p0005(self, h):
        if h != SESSION_HANDLE:
            return V.build_reply("t", INVALID_OBJECT)
        self.handles.clear()
        self.session = False
        return V.build_reply("t", SUCCESS)

    def p000f(self):
        return V.build_reply("t", SUCCESS)

    # container

    def p0200(self, h, cname):
        if h != SESSION_HANDLE:
            return V.build_reply("t", INVALID_OBJECT)
        if cname:                                     # the client passes NULL = the inbox
            return V.build_reply("t", NAME_NOT_FOUND)
        return V.build_reply("th", SUCCESS, self._new("container"))

    def _container(self, h):
        return self.handles.get(h) == "container"

    def p0208(self, h):
        if not self._container(h):
            return V.build_reply("t", INVALID_OBJECT)
        del self.handles[h]
        return V.build_reply("t", SUCCESS)

    def _match(self, sel, data):
        if sel in (SEL["NO_FILTER"], SEL["CATEGORY"], SEL["DRAFT"], SEL["SENT"]):
            return None, True
        box = self.box
        if sel in (SEL["SUBJECT"], SEL["FROM"]):
            # our choice: case-insensitive substring ("Messages Re:" / "Messages From:"); both
            # sides are session code page bytes read as cp850, which keeps every byte
            want = (data or b"").split(b"\x00", 1)[0].decode("cp850").lower()

            def m(mid):
                conv = self._converted(mid)
                return want in (conv.subject if sel == SEL["SUBJECT"] else self._author(conv)).lower()
            return m, True
        if sel == SEL["DATE"] and data and len(data) >= 24:
            _z1, d1, t1, _z2, d2, t2 = struct.unpack_from("<IIIIII", data)
            lo, hi = _date_key(d1, t1), _date_key(d2, t2)

            def m(mid):
                when = box.read(mid).when
                if when is None:
                    return False
                _z, d, t = struct.unpack("<III", vim_date(when))
                return lo <= _date_key(d, t) <= hi
            return m, True
        return None, False

    def _start(self, mids, pos, skip):
        """walk() start for a message position: the index of the entry whose ref serial is pos;
        None for 0 or a position never listed. A position whose message has left the list since
        keeps its place by message id (server order), between its neighbours."""
        if pos == 0:
            return None
        for i, mid in enumerate(mids):
            if self.box.state["msgs"][mid]["ref"] == pos:
                return i
        gone = self.refmid.get(pos)
        if gone is None:
            return None
        k = bisect.bisect_left(mids, gone)       # entries before k are older than the gone one
        return k if skip < 0 else k - 1

    def _msg_attr(self, mid, attr, size, conv=None):
        box = self.box
        e = box.state["msgs"][mid]
        if attr == SEL["REF"]:
            return box.ref_of(mid)
        if attr == SEL["UNREAD_MAIL"]:
            return struct.pack("<H", 0 if e["read"] else 1)
        msg = conv or self._converted(mid)
        if attr == SEL["SUBJECT"]:
            return _fixed_str(msg.subject.encode("cp850", "replace"), size)
        if attr == SEL["DATE"]:
            return vim_date(msg.when)
        if attr == SEL["FROM_NAME"]:
            return _fixed_str(self._author(msg).encode("cp850", "replace"), size)
        if attr == SEL["FROM"]:
            r = V.recipient(self._author(msg), SEL["ENTITY"])
            return V.recipient_struct(r) if size >= V.RECIP_SIZE else _fixed_str(r["value"].encode("cp850"), size)
        if attr == SEL["PRIORITY"]:
            return struct.pack("<H", {"low": 0, "urgent": 2}.get(msg.priority, 1))
        if attr == SEL["TYPE"]:
            return _fixed_str(b"VIM_MAIL", size)
        log.info("%s: attribute %#x not served, zeros", self.name, attr)
        return bytes(size)

    def _converted(self, mid):
        msg = self.box.read(mid)
        return msg.with_codepage(self.cp, convert_from=msg.codepages(self.po.codepage))

    @staticmethod
    def _author(msg):
        # the message is converted to the session code page; text() decodes as cp850, which keeps
        # every byte, so .encode("cp850") gives the session bytes back
        for t, name, path in msg.entries((M.TAG_FROM,)):
            return f"{name} at {path[-1]}" if path else name
        return ""

    def p0201(self, h, pos, skip, sel, data, flags, attrs):
        if not self._container(h):
            return V.build_reply("t", INVALID_OBJECT)
        count, descs = attrs
        match, ok = self._match(sel, data)
        if not ok:
            log.info("%s: message filter %#x not supported", self.name, sel)
            return V.build_reply("t", INVALID_SELECTOR)
        mids = self.box.listing(sel, data, flags, match)
        self.seen.update(self.box.state["msgs"])
        idx, more = walk(len(mids), self._start(mids, pos, skip), skip, count)
        chosen = [mids[i] for i in idx]
        for mid in chosen:
            self.refmid[self.box.state["msgs"][mid]["ref"]] = mid
        newpos = self.box.state["msgs"][chosen[-1]]["ref"] if chosen else pos
        entries = []
        conv = {mid: self._converted(mid) for mid in chosen} if any(
            a not in (SEL["REF"], SEL["UNREAD_MAIL"]) for a, _ in descs) else {}
        for attr, size in descs:
            data_b = b"".join(_pad(self._msg_attr(mid, attr, size, conv.get(mid)), size) for mid in chosen)
            entries.append((attr, size, data_b))
        return V.build_reply("tEbA", SUCCESS, newpos, 1 if more else 0, (len(chosen), entries))

    def p0202(self, h, sel, pos, skip, entry_size, count):
        if not self._container(h):
            return V.build_reply("t", INVALID_OBJECT)
        if sel != SEL["CATEGORY"]:
            return V.build_reply("t", INVALID_SELECTOR)
        names = self.box.folders()
        start = pos - 1 if 0 < pos <= len(names) else None
        idx, more = walk(len(names), start, skip, count)
        newpos = idx[-1] + 1 if idx else pos
        data = b"".join(_fixed_str(self._enc(names[i]), entry_size) for i in idx) if entry_size else b""
        return V.build_reply("tEbwp", SUCCESS, newpos, 1 if more else 0, len(idx), data)

    def _ref_mid(self, h, ref):
        if not self._container(h):
            return None
        mid = self.box.by_ref(ref)
        if mid is None:
            self.box.load()
            mid = self.box.by_ref(ref)
        return mid

    def p0203(self, h, ref):
        mid = self._ref_mid(h, ref)
        if mid is None:
            return V.build_reply("t", INVALID_OBJECT)
        self.box.remove(mid)
        log.info("%s: %s removed from the inbox", self.name, mid)
        return V.build_reply("t", SUCCESS)

    def p0204(self, h):
        if not self._container(h):
            return V.build_reply("t", INVALID_OBJECT)
        self.box.load()
        new = any(m not in self.seen for m in self.box.state["msgs"])
        return V.build_reply("tb", SUCCESS, 1 if new else 0)

    def p0205(self, h):
        if not self._container(h):
            return V.build_reply("t", INVALID_OBJECT)
        return V.build_reply("td", SUCCESS, len(self.box.listing(SEL["NO_FILTER"], None, UNREADONLY)))

    def p0601(self, h, ref, folder):
        mid = self._ref_mid(h, ref)
        if mid is None or self.box.state["msgs"][mid]["where"] == "draft":
            return V.build_reply("t", INVALID_OBJECT)
        if not folder:
            return V.build_reply("t", BAD_PARAM)
        self.box.add_folder(mid, self._dec(folder))
        return V.build_reply("t", SUCCESS)

    def p0602(self, h, ref, folder):
        mid = self._ref_mid(h, ref)
        if mid is None:
            return V.build_reply("t", INVALID_OBJECT)
        if not folder or not self.box.remove_folder(mid, self._dec(folder)):
            return V.build_reply("t", NAME_NOT_FOUND)
        return V.build_reply("t", SUCCESS)

    # reading a message

    def p0300(self, h, ref, key):
        mid = self._ref_mid(h, ref)
        if mid is None:
            return V.build_reply("t", INVALID_OBJECT)
        return V.build_reply("th", SUCCESS, self._new(Opened(mid, self.box.read(mid), self.cp, self.po)))

    def p0301(self, h, ref):
        mid = self._ref_mid(h, ref)
        if mid is None:
            return V.build_reply("t", INVALID_OBJECT)
        self.box.mark_read(mid)
        return V.build_reply("t", SUCCESS)

    def p0302(self, h, attrs):
        m = self._get(h, Opened)
        if m is None:
            return V.build_reply("t", INVALID_OBJECT)
        _n, descs = attrs
        entries = [(a, s, _pad(self._msg_attr(m.mid, a, s, m.msg), s)) for a, s in descs]
        return V.build_reply("tA", SUCCESS, (1, entries))

    def p0304(self, h, pos, skip, count, sel, data):
        m = self._get(h, Opened)
        if m is None:
            return V.build_reply("t", INVALID_OBJECT)
        items = list(enumerate(m.items))
        if sel == SEL["CLASS"] and data and len(data) >= 4:
            want = struct.unpack_from("<I", data)[0]
            items = [x for x in items if x[1]["cls"] == want]
        elif sel not in (0, SEL["NO_FILTER"]):
            return V.build_reply("t", INVALID_SELECTOR)
        keys = [i + 1 for i, _ in items]
        start = keys.index(pos) if pos in keys else None
        idx, more = walk(len(items), start, skip, count)
        out = []
        mref = self.box.state["msgs"].get(m.mid, {}).get("ref", 0)
        for k in idx:
            i, it = items[k]
            # item ref = (item number from 1, message ref serial); titles are session bytes
            out.append(dict(cls=it["cls"], type=it["type"], name=it["name"].encode("cp850", "replace"),
                            path="", size=it["size"], ref=ref_bytes(i + 1, mref)))
        newpos = keys[idx[-1]] if idx else pos
        return V.build_reply("tEbwD", SUCCESS, newpos, 1 if more else 0, len(out), out)

    def p0306(self, h, ref, convert, flags):
        m = self._get(h, Opened)
        if m is None:
            return V.build_reply("t", INVALID_OBJECT)
        i, _ = ref_ints(ref)
        if not 1 <= i <= len(m.items):
            return V.build_reply("t", INVALID_OBJECT)
        if convert not in (None, b"", b"VIM_TEXT") and m.items[i - 1]["cls"] == SEL["NOTE_PART"]:
            return V.build_reply("t", 7)               # VIMSTS_CONV_NOT_SUPPORTED
        return V.build_reply("th", SUCCESS, self._new(("item", m.items[i - 1]["data"])))

    def p0307(self, h, cdesc):
        obj = self.handles.get(h)
        if not (isinstance(obj, tuple) and obj[0] == "item"):
            return V.build_reply("t", INVALID_OBJECT)
        offset, size = cdesc
        data = obj[1][offset:offset + min(size, V.BLOCK_MAX - 8)]
        return V.build_reply("tdC", SUCCESS, len(data), data)

    def p0308(self, h):
        obj = self.handles.get(h)
        if not (isinstance(obj, tuple) and obj[0] == "item"):
            return V.build_reply("t", INVALID_OBJECT)
        del self.handles[h]
        return V.build_reply("t", SUCCESS)

    def p0309(self, h, cls, pos, skip, attrs):
        m = self._get(h, Opened)
        if m is None:
            return V.build_reply("t", INVALID_OBJECT)
        count, descs = attrs
        names = _recipients_of(m.msg, cls)
        start = pos - 1 if 0 < pos <= len(names) else None
        idx, more = walk(len(names), start, skip, count)
        newpos = idx[-1] + 1 if idx else pos
        if len(descs) == 1 and descs[0][0] == SEL["RECIPIENT"] and len(idx) == 1:
            # a lone 4Bh attribute is answered with a compact vimRecipient (spec §5.9 A)
            r = V.recipient(names[idx[0]], SEL["ENTITY"])
            return V.build_reply_recipient(1 if more else 0, newpos, r, descs[0][1])
        entries = []
        for attr, size in descs:
            vals = []
            for i in idx:
                r = V.recipient(names[i], SEL["ENTITY"])
                if attr == SEL["RECIPIENT"] and size >= V.RECIP_SIZE:
                    v = V.recipient_struct(r)
                elif attr == SEL["NAME"] and size >= V.DNAME_SIZE:
                    v = V.dname_struct(names[i])
                elif attr in (SEL["NAME"], SEL["RECIPIENT"]):
                    # a buffer smaller than the struct: the plain name (our choice, spec §5.15)
                    v = _fixed_str(names[i].encode("cp850", "replace"), size)
                elif attr == SEL["TYPE"]:
                    v = struct.pack("<I", SEL["ENTITY"])
                else:
                    log.info("%s: recipient attribute %#x not served, zeros", self.name, attr)
                    v = b""
                vals.append(v[:size].ljust(size, b"\x00"))
            entries.append((attr, size, b"".join(vals)))
        return V.build_reply("tEbA", SUCCESS, newpos, 1 if more else 0, (len(idx), entries))

    def p0106(self, h):
        obj = self.handles.get(h)
        if isinstance(obj, Opened):
            del self.handles[h]
            return V.build_reply("t", SUCCESS)
        if isinstance(obj, Draft):
            del self.handles[h]
            if obj.draft and not obj.failed:
                msg = self._compose(obj)
                mid = self.box.save_draft(msg)
                log.info("%s: draft %s kept (%r)", self.name, mid, obj.subject)
            else:
                log.info("%s: message %r closed unsent, dropped", self.name, obj.subject)
            return V.build_reply("t", SUCCESS)
        return V.build_reply("t", INVALID_OBJECT)

    # sending

    def p0100(self, h, mtype):
        if h != SESSION_HANDLE:
            return V.build_reply("t", INVALID_OBJECT)
        if mtype not in (None, b"VIM_MAIL"):
            return V.build_reply("t", UNSUP_TYPE)
        return V.build_reply("th", SUCCESS, self._new(Draft()))

    def p0101(self, h, sel, flags):
        m = self._get(h, Opened)
        if m is None:
            return V.build_reply("t", INVALID_OBJECT)
        if sel not in (SEL["REPLY"], SEL["FORWARD"]):
            return V.build_reply("t", INVALID_SELECTOR)
        return V.build_reply("th", SUCCESS, self._new(Draft(m, sel, flags)))

    def p0102(self, h, sel, data):
        d = self._get(h, Draft)
        if d is None:
            return V.build_reply("t", INVALID_OBJECT)
        data = data or b""
        if sel == SEL["SUBJECT"]:
            d.subject = self._dec(data)
        elif sel == SEL["PRIORITY"] and len(data) >= 2:
            d.priority = {0: 1, 2: 2}.get(struct.unpack_from("<H", data)[0] & 0xFF, 0)
        elif sel == SEL["SAVE"]:
            d.save = bool(data and data[0])
        elif sel == SEL["DRAFT"]:
            d.draft = bool(data and data[0])
        else:
            log.info("%s: header %#x ignored (%s)", self.name, sel, data.hex(" "))
        return V.build_reply("t", SUCCESS)

    def _resolve(self, name, path):
        """Where mail for this name goes, as session.Call.receive_messages decides: ("local", user)
        / ("route", post office) / ("external", name) / None."""
        own = self.po.name.lower()
        lpath = [p.strip().lower() for p in path]
        if not lpath or own in lpath:
            local = self.po.user(name)
            if local:
                return "local", local
            r = ade.user_route(self.po, name)
            if r:
                return "route", r
        else:
            route = None
            for p in path:
                if p.strip().lower() == own:
                    break
                if self.po.post_office(p):
                    route = self.po.post_office(p)
            if route:
                return "route", route
        gw = getattr(self.po, "gateway", None)
        if gw and gw.enabled and gw.is_external(name, path):
            return "external", name
        return None

    def p0103(self, h, cls, r):
        d = self._get(h, Draft)
        if d is None:
            return V.build_reply("t", INVALID_OBJECT)
        if cls not in (SEL["TO"], SEL["CC"], SEL["BCC"]):
            return V.build_reply("t", INVALID_SELECTOR)
        # the address when the client gave one (Address.Type 37h NATIVE), else the name (spec §5.12)
        text = r["addr"] if r["addr_type"] == SEL["NATIVE"] and r["addr"] else r["value"]
        text = text.strip()
        name, _, at = text.partition(" at ")
        path = [at.strip()] if at.strip() else []
        if not name.strip() or self._resolve(name.strip(), path) is None:
            log.info("%s: recipient %r not found", self.name, text)
            return V.build_reply("t", NAME_NOT_FOUND)
        d.recipients.append((cls, name.strip(), path))
        return V.build_reply("t", SUCCESS)

    def p0104(self, h, cls, itype, flags, iname, desc):
        d = self._get(h, Draft)
        if d is None:
            return V.build_reply("t", INVALID_OBJECT)
        if cls == SEL["NOTE_PART"]:
            d.text.append(desc["data"])
            return V.build_reply("t", SUCCESS)
        if cls == SEL["ATTACH"]:
            if not desc["size"]:
                # the client sends only the file name, 0 data bytes (spec §5.12): we cannot attach
                # a file we do not have, and refuse rather than send a message without it
                log.info("%s: attachment %r arrived without data, refused", self.name, iname)
                d.failed = True
                return V.build_reply("t", ATTACHMENT_NOT_FOUND)
            d.files.append((self._dec(iname or b"FILE"), desc["data"]))
            return V.build_reply("t", SUCCESS)
        d.failed = True
        return V.build_reply("t", INVALID_SELECTOR)

    def _compose(self, d: Draft):
        from .codepage import tables
        tb = tables()
        text = "".join(tb.decode(t, self.cp) for t in d.text)
        files = list(d.files)
        if d.derived is not None:
            orig = d.derived.items
            if d.how == SEL["REPLY"] and d.flags & INHERIT_CONTENTS or d.how == SEL["FORWARD"] and d.flags & HISTORY:
                for it in orig:
                    if it["cls"] == SEL["NOTE_PART"]:
                        text += ("\r\n" if text and not text.endswith("\n") else "") + tb.decode(it["data"], self.cp)
            if d.how == SEL["FORWARD"]:
                files += [(it["name"] or "FILE", it["data"]) for it in orig if it["cls"] == SEL["ATTACH"]]
        to, extra = [], []
        for cls, name, path in d.recipients:
            full = f"{name} at {path[-1]}" if path else name
            if cls == SEL["TO"]:
                to.append(full)
            else:
                extra.append((M.TAG_CC if cls == SEL["CC"] else M.TAG_BCC, name, path[-1] if path else None))
        return M.compose(self.user, to, d.subject, text, priority=d.priority, extra=extra,
                         codepage=self.cp, attachments=files)

    def _inherited(self, d: Draft):
        """A reply without recipients of its own: the original author, and with
        VIM_ALL_RECIPIENTS its To and cc names (our choice, spec §5.15)."""
        msg = d.derived.msg
        out = []
        for _t, name, path in msg.entries((M.TAG_FROM,)):
            out.append((SEL["TO"], name, path[-1:]))
            break
        if d.flags & ALL_RECIPIENTS:
            for cls in (SEL["TO"], SEL["CC"]):
                for full in _recipients_of(msg, cls):
                    name, _, at = full.partition(" at ")
                    if name.lower() != self.user.lower():
                        out.append((cls, name, [at] if at else []))
        return [r for r in out if self._resolve(r[1], r[2])]

    def p0105(self, h):
        d = self._get(h, Draft)
        if d is None:
            return V.build_reply("t", INVALID_OBJECT)
        if not d.recipients and d.derived is not None and d.how == SEL["REPLY"]:
            d.recipients = self._inherited(d)
        if not d.recipients:
            return V.build_reply("t", ALL_PARAMS_REQUIRED)
        msg = self._compose(d)
        local, routed, external = [], [], []
        for _cls, name, path in d.recipients:
            where = self._resolve(name, path)
            if where is None:
                continue
            kind, target = where
            lst = local if kind == "local" else routed if kind == "route" else external
            if target not in lst:
                lst.append(target)
        mid = self.po.accept(msg, local)
        for p in routed:
            self.po.route(p, msg)
        if external:
            self.po.gateway.queue_outbound(msg, external)
        del self.handles[h]
        log.info("%s: sent %s from %s to %s: %r", self.name, mid, self.user,
                 ", ".join(local + external + [f"post office {p}" for p in routed]), d.subject)
        return V.build_reply("t", SUCCESS)

    # address books

    def p0401(self, h, bname):
        if h != SESSION_HANDLE:
            return V.build_reply("t", INVALID_OBJECT)
        if bname in (None, b"", b"VIM_PUBLIC"):
            entries = self._directory()
        elif bname == b"VIM_PRIVATE":
            entries = []                              # no private books on the server (our choice)
        else:
            return V.build_reply("t", NAME_NOT_FOUND)
        return V.build_reply("th", SUCCESS, self._new(Book(bname, entries)))

    def _directory(self):
        from .directory import directory_entries
        out = []
        for e in directory_entries(self.po):
            if e.get("kind") == "P":
                continue                              # post offices are not addressable people
            name = e["name"]
            addr = e.get("addr") or ""
            full = name if not addr or addr.lower() == self.po.name.lower() else f"{name} at {addr}"
            out.append((name, full, SEL["ENTITY"]))
        out.sort(key=lambda x: x[0].lower())
        return out

    def _entry_attr(self, e, attr, size):
        name, full, typ = e
        if attr == SEL["RDN"] or attr == SEL["NAME"] and size < V.DNAME_SIZE:
            return _fixed_str(self._enc(name), size)
        if attr == SEL["NAME"]:
            return V.dname_struct(self._enc(name))[:size]
        if attr == SEL["TYPE"]:
            return struct.pack("<I", typ)[:size].ljust(size, b"\x00")
        if attr == SEL["ADDRESS"]:
            if size >= V.ADDRESS_SIZE:
                return V.address_struct(self._enc(full), SEL["NATIVE"])[:size]
            return _fixed_str(self._enc(full), size)
        log.info("%s: entry attribute %#x not served, zeros", self.name, attr)
        return bytes(size)

    def p0404(self, h, sref, sname, pos, skip, sel, data, attrs):
        b = self._get(h, Book)
        if b is None:
            return V.build_reply("t", INVALID_OBJECT)
        entries = b.entries
        if sel not in (SEL["NO_FILTER"], SEL["ENTITY"], SEL["GROUP"]):
            return V.build_reply("t", INVALID_SELECTOR)
        if sel != SEL["NO_FILTER"]:
            entries = [e for e in entries if e[2] == sel]
        count, descs = attrs
        start = pos - 1 if 0 < pos <= len(entries) else None
        idx, more = walk(len(entries), start, skip, count)
        newpos = idx[-1] + 1 if idx else pos
        out = []
        for attr, size in descs:
            if attr == SEL["REF"]:
                out.append((attr, size, b"".join(ref_bytes(i + 1, 0)[:size].ljust(size, b"\x00") for i in idx)))
            else:
                out.append((attr, size, b"".join(self._entry_attr(entries[i], attr, size) for i in idx)))
        return V.build_reply("tEbA", SUCCESS, newpos, 1 if more else 0, (len(idx), out))

    def p0406(self, h, sref, sname, sel, data, how, eref):
        b = self._get(h, Book)
        if b is None:
            return V.build_reply("t", INVALID_OBJECT)
        if sel not in (SEL["RDN"], SEL["NAME"]):
            return V.build_reply("t", INVALID_SELECTOR)
        want = self._dec(data or b"").strip().lower()
        for i, e in enumerate(b.entries):
            n = e[0].lower()
            if n == want or how == SEL["PARTIAL"] and n.startswith(want):
                return V.build_reply("tRh", SUCCESS, ref_bytes(i + 1, 0), i + 1)
        return V.build_reply("t", NO_MATCH)

    def _book_entry(self, b, ref, ename):
        if ename:
            want = self._dec(ename).lower()
            for e in b.entries:
                if e[0].lower() == want:
                    return e
            return None
        i, _ = ref_ints(ref)
        return b.entries[i - 1] if 1 <= i <= len(b.entries) else None

    def p0407(self, h, ref, ename, attrs):
        b = self._get(h, Book)
        if b is None:
            return V.build_reply("t", INVALID_OBJECT)
        e = self._book_entry(b, ref, ename)
        if e is None:
            return V.build_reply("t", NAME_NOT_FOUND)
        _n, descs = attrs
        i = b.entries.index(e)
        out = [(a, s, ref_bytes(i + 1, 0)[:s].ljust(s, b"\x00") if a == SEL["REF"] else self._entry_attr(e, a, s))
               for a, s in descs]
        return V.build_reply("tA", SUCCESS, (1, out))

    def p040f(self, h, ref, ename, pos, skip, attrs):
        b = self._get(h, Book)
        if b is None:
            return V.build_reply("t", INVALID_OBJECT)
        if self._book_entry(b, ref, ename) is None:
            return V.build_reply("t", NAME_NOT_FOUND)
        # no groups in our books: an entity has no members
        return V.build_reply("tEbA", SUCCESS, pos, 0, (0, [(a, s, b"") for a, s in attrs[1]]))

    def p0410(self, h):
        if self._get(h, Book) is None:
            return V.build_reply("t", INVALID_OBJECT)
        del self.handles[h]
        return V.build_reply("t", SUCCESS)


def _show(args):
    out = []
    for a in args:
        if isinstance(a, int):
            out.append(f"{a:#x}" if a >= 0 else str(a))
        elif isinstance(a, bytes):
            out.append(repr(a) if len(a) != 8 else "ref:" + a.hex())
        elif isinstance(a, tuple) and len(a) == 2 and isinstance(a[1], list):
            out.append(f"n={a[0]}[" + ",".join(f"{e[0]:x}/{e[1]:x}" for e in a[1]) + "]")
        elif isinstance(a, dict) and "data" in a:
            out.append(f"desc(size={a['size']},offset={a['offset']},by_name={a['by_name']},{a['data'][:40]!r})")
        else:
            out.append(repr(a))
    return " ".join(out)


def _show_reply(fmt, block):
    try:
        vals = V.break_reply(fmt, block)
    except V.BlockError as e:
        return f"(unreadable by the HP: {e})"
    out = []
    for v in vals[1:]:
        if isinstance(v, tuple) and len(v) == 2 and isinstance(v[1], list):
            out.append(f"n={v[0]}[" + ",".join(f"{a:x}/{s:x}" for a, s, _d in v[1]) + "]")
        elif isinstance(v, list):
            out.append("[" + ",".join(f"{it['cls']:x}:{it['name']}:{it['size']}" for it in v) + "]")
        elif isinstance(v, bytes):
            out.append(repr(v[:40]) if len(v) != 8 else "ref:" + v.hex())
        else:
            out.append(f"{v:#x}")
    return " ".join(out)
