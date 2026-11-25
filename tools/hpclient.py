# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Simulated HP 200LX client in interactive mode (spec/hp200lx-check.md §5): the link steps
(connect, record send and receive, disconnect) and the call sequences on the wire (§5.10-5.14)
with the selectors, sizes and counts the client uses. Replies are decoded with the client's
size checks (ccmail.vimblock.break_reply), so a reply the real client could not read fails here.

Usage against a running server:
    python3 tools/hpclient.py host:port user password [--po MYPOST] [--hsec]
"""
import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccmail import vimblock as V                          # noqa: E402
from ccmail.link import Link, HSEC, LSEC, LinkTimeout     # noqa: E402
from ccmail.session import OPENER                         # noqa: E402

S = dict(ADDRESS=0x01, ATTACH=0x06, BCC=0x09, CC=0x0A, CLASS=0x0D, CP850=0x12, DATE=0x13, DRAFT=0x17,
         ENTITY=0x1A, FORWARD=0x21, FROM=0x22, FROM_NAME=0x23, FULL=0x24, LOCAL=0x2D, NAME=0x35, NATIVE=0x37,
         NO_FILTER=0x3A, NOTE_PART=0x3E, PARTIAL=0x43, PRIORITY=0x47, RDN=0x49, RECIPIENT=0x4B, REF=0x4C,
         REPLY=0x4D, SAVE=0x51, SENT=0x53, SUBJECT=0x5B, TO=0x61, TYPE=0x62, UNKNOWN_RECIP_TYPE=0x65,
         UNREAD_MAIL=0x67, CATEGORY=0x100)

# attributes the client asks for (§5.11, §5.13)
INBOX_PAGE = [(S["REF"], 8), (S["UNREAD_MAIL"], 2), (S["SUBJECT"], 0x41), (S["DATE"], 0x0C), (S["FROM_NAME"], 0xFE)]
HEADER = [(S["SUBJECT"], 0x41), (S["DATE"], 0x0C), (S["FROM"], 0x90C), (S["PRIORITY"], 2)]
AB_BROWSE = [(S["REF"], 8), (S["RDN"], 0x7F), (S["TYPE"], 4)]
AB_ENTRY = [(S["RDN"], 0x7F), (S["ADDRESS"], 0x404), (S["TYPE"], 4)]
PING = bytes.fromhex("0F 00 04 00 00 00 04 00 00 00 00 00 00 00")   # the client's fixed ping block


class HPError(Exception):
    pass


class VimFailed(HPError):
    def __init__(self, proc, status):
        super().__init__(f"proc {proc:04x}: status {status}")
        self.proc, self.status = proc, status


def lstring(b: bytes) -> bytes:
    return bytes([len(b)]) + b


class HP:
    def __init__(self, sock, mode=HSEC, idle_minutes=5, maxmsgsize=0, name="hp"):
        self.link = Link(sock, name, mode=mode)
        self.idle_s = idle_minutes * 60
        self.maxmsgsize = maxmsgsize
        self.log = []                    # (request block, reply block)
        self.session = self.container = None

    # ----- link: connect -----

    def connect(self, user, password, po_name, change_to=None):
        link = self.link
        if not link.call_open(OPENER):
            raise HPError("link refused")
        self.probe()
        self.negotiate()
        # login
        link.write(b"\x80")
        end = time.monotonic() + 31
        while link.read_exact(1, 31)[0] != 0x81:
            if time.monotonic() > end:
                raise HPError("no 81")
        link.write(lstring(user.encode("cp850") + b"\x00"))
        r = link.read_exact(1, 31)[0]
        if r == 0x8B:
            pw = password.encode("cp850") + b"\x00"
            if change_to:
                pw += (change_to.encode("cp850") + b"\x00") * 2
            link.write(lstring(pw))
            r = link.read_exact(1, 31)[0]
        if r == 0x8C:
            raise HPError("connection refused (8C)")
        n = link.read_exact(1, 31)[0]
        their = link.read_exact(n, 31).split(b"\x00", 1)[0].decode("cp850")
        if r == 0x83 or their.lower() != po_name.lower():
            link.write(b"\x83")                   # send-only refused in interactive mode
            raise HPError(f"login answered {r:02x}, post office {their!r}")
        link.write(b"\x82")
        link.write(b"\x01" + struct.pack("<HH", 1, 4) + bytes(4))    # control record type 1
        if link.read_exact(1, 31)[0] != 0x01:
            raise HPError("no control record after the login")
        typ, ln = struct.unpack("<HH", link.read_exact(4, 31))
        data = link.read_exact(ln, 31) if ln else b""
        self.login_reply = (typ, data)
        if typ == 4 and struct.unpack_from("<H", data)[0] not in (1, 2, 3):
            pass                                  # read and accepted whatever the value

    def probe(self):
        """AD, wait 5Fh ticks for AE, 3 tries."""
        for _ in range(3):
            self.link.write(b"\xAD")
            end = time.monotonic() + 0x5F / 18.2
            while time.monotonic() < end:
                try:
                    if self.link.read_exact(1, max(end - time.monotonic(), 0.01))[0] == 0xAE:
                        return
                except LinkTimeout:
                    break
        raise HPError("F012h: the Router does NOT support interactive mode")

    def _entry(self, typ, status, data=b""):
        self.link.write(bytes([0xAF, 1]) + struct.pack("<HHH", typ, status, len(data)) + data)

    def _read_reply_entry(self, want):
        hdr = self.link.read_exact(2, 31)
        if hdr[1] != 1:
            raise HPError(f"reply packet with {hdr[1]} entries")
        typ, status, ln = struct.unpack("<HHH", self.link.read_exact(6, 31))
        if typ != want:
            raise HPError(f"reply type {typ:#x}, expected {want:#x}")
        return status, ln

    def negotiate(self):
        link = self.link
        # A1 hello
        self._entry(1, 0, b"SVIM" + struct.pack("<H", 100))
        st, ln = self._read_reply_entry(0x8001)
        if st == 1:
            d = link.read_exact(6, 31)
            if struct.unpack_from("<H", d, 4)[0] != 100:
                raise HPError("F011h")
        elif st in (2, 3):
            if st == 3:
                link.read_exact(ln, 31)
            raise HPError("F011h: interactive mode not supported")
        elif st != 0:
            link.read_exact(ln, 31)
            raise HPError("F001h")
        # A2 idle timeout
        self._entry(2, 0, struct.pack("<H", self.idle_s))
        st, ln = self._read_reply_entry(0x8002)
        if st == 1:
            self.idle_s = struct.unpack("<H", link.read_exact(2, 31))[0]
        elif st != 0:
            raise HPError("F001h idle")
        # A3 max message size
        self._entry(3, 0, struct.pack("<I", self.maxmsgsize))
        st, ln = self._read_reply_entry(0x8003)
        if st == 1:
            self.maxmsgsize = struct.unpack("<I", link.read_exact(4, 31))[0]
        elif st != 0:
            raise HPError("F001h size")
        self._entry(8, 0)
        # phase B
        done = False
        while not done:
            n = link.read_exact(2, 31)[1]
            for _ in range(n):
                typ, st, ln = struct.unpack("<HHH", link.read_exact(6, 31))
                if typ == 1:
                    link.read_exact(6, 31)
                    self._entry(0x8001, 8)
                elif typ == 2:
                    v = struct.unpack("<H", link.read_exact(2, 31))[0]
                    if v <= self.idle_s:
                        self.idle_s = v
                        self._entry(0x8002, 0)
                    else:
                        self._entry(0x8002, 1, struct.pack("<H", self.idle_s))
                elif typ == 3:
                    v = struct.unpack("<I", link.read_exact(4, 31))[0]
                    self._entry(0x8003, 0) if v <= self.maxmsgsize else self._entry(0x8003, 1, struct.pack("<I", self.maxmsgsize))
                elif typ == 8:
                    self._entry(9, 0)
                    done = True
                elif typ == 9:
                    done = True
                elif typ == 10:
                    raise HPError("aborted (type 10)")
                else:
                    if ln:
                        link.read_exact(ln, 31)
                    self._entry(typ | 0x8000, 7)

    # ----- link: data records -----

    def send_record(self, block):
        self.link.write(b"\x00" + struct.pack("<H", len(block)) + block)

    def recv_record(self, size=V.BLOCK_MAX):
        """Skip bytes other than 00/01, skip control records, F004h when too long."""
        link = self.link
        while True:
            b = link.read_exact(1, 31)[0]
            if b == 0x01:
                _t, n = struct.unpack("<HH", link.read_exact(4, 31))
                if n:
                    link.read_exact(n, 31)
                continue
            if b != 0x00:
                continue
            n = struct.unpack("<H", link.read_exact(2, 31))[0]
            data = link.read_exact(n, 31)
            if n > size:
                raise HPError("F004h: reply longer than the buffer")
            return data

    def call(self, proc, req, args, rep, sizes=None, desc_size=None, ok=(0,)):
        block = V.build(req, proc, *args)
        self.send_record(block)
        reply = self.recv_record()
        self.log.append((block, reply))
        vals = V.break_reply(rep, reply, sizes=sizes, desc_size=desc_size)
        if vals[0] not in ok:
            raise VimFailed(proc, vals[0])
        return vals

    def ping(self):
        self.send_record(PING)
        reply = self.recv_record(12)              # 12-byte buffer, content never read
        self.log.append((PING, reply))

    def disconnect(self):
        """Control record type 2, 00; read the answer; hang up."""
        link = self.link
        link.write(b"\x01" + struct.pack("<HH", 2, 1) + b"\x00")
        if link.read_exact(1, 31)[0] != 0x01:
            raise HPError("no control record answer")
        typ, ln = struct.unpack("<HH", link.read_exact(4, 31))
        data = link.read_exact(ln, 31)
        if typ == 2 and data[:1] != b"\x00":
            raise HPError("disconnect answer not 00")
        try:
            link.drain(5)
        except LinkTimeout:
            pass
        return typ, data

    # ----- calls: §5.10 session -----

    def open_session(self, user, password, host="cc:Mail"):
        self.session = self.call(0x0003, "fzzzds", [host.encode(), user.encode("cp850"),
                                 password.encode("cp850"), 100, S["CP850"]], "th")[1]
        self.container = self.call(0x0200, "fhz", [self.session, None], "th")[1]
        self.views = {}

    def close_session(self):
        self.call(0x0208, "fh", [self.container], "t")
        self.call(0x0005, "fh", [self.session], "t")
        return self.disconnect()

    # ----- §5.11 inbox -----

    def counts(self, sel=S["NO_FILTER"], data=None, flags=0):
        """Unread then total; position zeroed, skip 1, 0 attributes, count FFFFh."""
        unread = self.call(0x0201, "fhEiSpda", [self.container, 0, 1, sel, data, flags | 1, (0xFFFF, [])],
                           "tEbA")[3][0]
        total = self.call(0x0201, "fhEiSpda", [self.container, 0, 1, sel, data, flags, (0xFFFF, [])],
                          "tEbA")[3][0]
        return unread, total

    def page(self, view, n, sel=S["NO_FILTER"], data=None, flags=0, attrs=INBOX_PAGE):
        """A page, then a move of the other edge: n >= 0 pages down (skip -1 from the bottom
        edge), n < 0 pages up (skip +1 from the top edge). Returns the rows in display order (top first)."""
        v = self.views.setdefault(view, {"posA": 0, "posB": 0, "fresh": True, "rows": []})
        down = n >= 0
        pos, skip, count = (v["posB"], -1, n) if down else (v["posA"], 1, -n)
        vals = self.call(0x0201, "fhEiSpda", [self.container, pos, skip, sel, data, flags, (count, attrs)],
                         "tEbA", sizes=[s for _, s in attrs])
        newpos, more, (got, entries) = vals[1], vals[2], vals[3]
        rows = []
        for k in range(got):
            row = {}
            for attr, size, d in entries:
                row[attr] = d[k * size:(k + 1) * size]
            rows.append(row)
        if not down:
            rows.reverse()                       # inserted at slot 0 one by one
        # the move of the other edge; fresh = skip -1 from 0, count 1
        other = "posA" if down else "posB"
        if v["fresh"]:
            v[other] = 0
        mcount = 1 if v["fresh"] else got
        if got:
            mv = self.call(0x0201, "fhEiSpda", [self.container, v[other], skip, sel, data, flags, (mcount, [])],
                           "tEbA")
            v[other] = mv[1]
        v["posB" if down else "posA"] = newpos
        v["fresh"] = False
        v["more"] = more
        v["rows"] = rows
        return rows

    def all_refs(self, sel=S["NO_FILTER"], data=None, flags=0):
        """Position zeroed once, skip -1, batches of 20, 2 attributes, until the total."""
        _u, total = self.counts(sel, data, flags)
        pos, refs = 0, []
        while len(refs) < total:
            vals = self.call(0x0201, "fhEiSpda", [self.container, pos, -1, sel, data, flags,
                             (20, [(S["REF"], 8), (S["UNREAD_MAIL"], 2)])], "tEbA", sizes=[8, 2])
            pos, (got, entries) = vals[1], vals[3]
            if not got:
                break
            refs += [entries[0][2][k * 8:(k + 1) * 8] for k in range(got)]
        return refs

    def query_new(self):
        return self.call(0x0204, "fh", [self.container], "tb")[1]

    def read_message(self, ref, unread=True):
        """Open, note part, header, recipients, mark read, close."""
        h = self.call(0x0300, "fhRz", [self.container, ref, None], "th")[1]
        notes = self.items(h, S["NOTE_PART"], limit=20)
        text = b""
        if notes:
            it = notes[0]
            size = min(max(it["size"] + 0x800, 0x800), 0x5000)
            ih = self.call(0x0306, "fhRzd", [h, it["ref"], None, 0], "th")[1]
            text = self.call(0x0307, "fhc", [ih, (0, size)], "tdC", desc_size=size)[2]
            self.call(0x0308, "fh", [ih], "t")
        hdr = self.call(0x0302, "fha", [h, (1, HEADER)], "tA", sizes=[s for _, s in HEADER])[1][1]
        header = {a: d for a, _s, d in hdr}
        rcpts = {}
        for cls in (S["TO"], S["CC"], S["BCC"]):
            pos, names = 0, []
            while True:
                vals = self.call(0x0309, "fhSEia", [h, cls, pos, 1, (1, [(S["RECIPIENT"], 0x90C)])], "tEbA",
                                 sizes=[0x90C])
                pos, (got, ents) = vals[1], vals[3]
                if not got:
                    break
                names.append(ents[0][2]["value"])
                if len(names) > 1000:
                    raise HPError("recipient loop")
            rcpts[cls] = names
        attachments = self.items(h, S["ATTACH"], limit=20)
        if unread:
            self.call(0x0301, "fhR", [self.container, ref], "t")
        return dict(handle=h, text=text, header=header, recipients=rcpts, attachments=attachments)

    def close_message(self, h):
        self.call(0x0106, "fh", [h], "t")

    TRANSFER_HEADER = [(S["TYPE"], 0x20), (S["FROM"], 0x90C), (S["SUBJECT"], 0x3C), (S["DATE"], 0x0C),
                       (S["PRIORITY"], 2)]

    def transfer(self, ref):
        """VimTransferMessage, copy to a local folder: the wire calls only."""
        h = self.call(0x0300, "fhRz", [self.container, ref, None], "th")[1]
        hdr = self.call(0x0302, "fha", [h, (1, self.TRANSFER_HEADER)], "tA",
                        sizes=[s for _, s in self.TRANSFER_HEADER])[1][1]
        rcpts = {}
        for cls in (S["TO"], S["CC"], S["BCC"]):
            pos, names = 0, []
            while True:
                vals = self.call(0x0309, "fhSEia", [h, cls, pos, 1, (2, [(S["NAME"], 0x100)])], "tEbA",
                                 sizes=[0x100])
                pos, (got, ents) = vals[1], vals[3]
                if not got:
                    break
                names += [ents[0][2][k * 0x100:(k + 1) * 0x100].split(b"\0", 1)[0].decode("cp850")
                          for k in range(got)]
            rcpts[cls] = names
        items = []
        for cls in (S["NOTE_PART"], S["ATTACH"]):
            pos = 0
            while True:
                vals = self.call(0x0304, "fhEiwSp", [h, pos, 1, 2, S["CLASS"], struct.pack("<I", cls)], "tEbwD")
                pos, got = vals[1], vals[4]
                if not got:
                    break
                for it in got:
                    ih = self.call(0x0306, "fhRzd", [h, it["ref"], b"VIM_TEXT", S["NATIVE"]], "th")[1]
                    n = max(it["size"], 1)
                    data = self.call(0x0307, "fhc", [ih, (0, n)], "tdC", desc_size=n)[2]
                    self.call(0x0308, "fh", [ih], "t")
                    items.append((it, data))
        self.call(0x0106, "fh", [h], "t")
        return dict(header={a: d for a, _s, d in hdr}, recipients=rcpts, items=items)

    def items(self, h, cls, limit=20):
        out, pos = [], 0
        for _ in range(limit):
            vals = self.call(0x0304, "fhEiwSp", [h, pos, 1, 1, S["CLASS"], struct.pack("<I", cls)], "tEbwD")
            pos, items = vals[1], vals[4]
            if not items:
                break
            out += items
        return out

    def detach(self, h, item):
        """Open NATIVE, reads of min(rest, 1000h) at a running offset."""
        ih = self.call(0x0306, "fhRzd", [h, item["ref"], None, S["NATIVE"]], "th")[1]
        data, off = b"", 0
        while off < item["size"]:
            n = min(item["size"] - off, 0x1000)
            chunk = self.call(0x0307, "fhc", [ih, (off, n)], "tdC", desc_size=n)[2]
            if not chunk:
                break
            data += chunk
            off += len(chunk)
        self.call(0x0308, "fh", [ih], "t")
        return data

    def delete(self, ref, folder=None):
        if folder is None:
            return self.call(0x0203, "fhR", [self.container, ref], "t")
        return self.call(0x0602, "fhRz", [self.container, ref, folder.encode("cp850")], "t")

    def file(self, ref, folder, move_from=None):
        self.call(0x0601, "fhRz", [self.container, ref, folder.encode("cp850")], "t")
        if move_from:
            self.call(0x0602, "fhRz", [self.container, ref, move_from.encode("cp850")], "t")

    def folders(self):
        """A count (entry size 0, count FFFFh), then pages of 20 names of 50h (skip +1)."""
        cnt = self.call(0x0202, "fhSEiww", [self.container, S["CATEGORY"], 0, 1, 0, 0xFFFF], "tEbwp")
        total = cnt[3]
        names, pos = [], 0
        while len(names) < total:
            vals = self.call(0x0202, "fhSEiww", [self.container, S["CATEGORY"], pos, 1, 0x50, 20], "tEbwp")
            pos, got, data = vals[1], vals[3], vals[4]
            if len(data) > got * 0x50 or len(data) > 0x640:
                raise HPError("folder names overflow the 640h-byte buffer")
            if not got:
                break
            names += [data[i * 0x50:(i + 1) * 0x50].split(b"\x00", 1)[0].decode("cp850") for i in range(got)]
        return names

    def folder_count(self, folder):
        return self.call(0x0201, "fhEiSpda", [self.container, 0, 1, S["CATEGORY"], folder.encode("cp850"), 0,
                         (0xFFFF, [])], "tEbA")[3][0]

    # ----- §5.12 sending -----

    def send(self, to=(), cc=(), bcc=(), subject="", text="", attachments=(), flags=1, derive=None):
        """Flags bit 0 = send, bit 1 = SAVE/DRAFT. derive = (ref, REPLY/FORWARD, flags)."""
        if derive:
            ref, sel, dflags = derive
            orig = self.call(0x0300, "fhRz", [self.container, ref, None], "th")[1]
            m = self.call(0x0101, "fhSd", [orig, sel, dflags], "th")[1]
            self.call(0x0106, "fh", [orig], "t")
        else:
            m = self.call(0x0100, "fhz", [self.session, b"VIM_MAIL"], "th")[1]
        try:
            s = subject.encode("cp850") + b"\x00"
            self.call(0x0102, "fhSp", [m, S["SUBJECT"], s], "t")
            if flags & 2:
                self.call(0x0102, "fhSp", [m, S["SAVE"] if flags & 1 else S["DRAFT"], struct.pack("<H", 1)], "t")
            missing = []
            for cls, names in ((S["TO"], to), (S["CC"], cc), (S["BCC"], bcc)):
                for name in names:
                    r = V.recipient(name, S["UNKNOWN_RECIP_TYPE"])
                    st = self.call(0x0103, "fhSN", [m, cls, r], "t", ok=(0, 15))[0]
                    if st == 15:
                        missing.append(name)
            if text:
                t = text.replace("\r\n", "\n").replace("\n", "\r\n").encode("cp850")
                self.call(0x0104, "fhSzSzC", [m, S["NOTE_PART"], b"VIM_UNWRAPPED_TEXT", S["NATIVE"], None,
                                              (len(t), t, 0, None)], "t")
            for fname in attachments:
                self.call(0x0104, "fhSzSzC", [m, S["ATTACH"], None, S["NATIVE"], fname.encode("cp850"),
                                              (0, None, 0, fname.encode("cp850"))], "t")
            if flags & 1:
                self.call(0x0105, "fh", [m], "t")
            else:
                self.call(0x0106, "fh", [m], "t")
            return missing
        except VimFailed:
            # the client's cleanup: close, find the half-made message, remove it
            self.call(0x0106, "fh", [m], "t", ok=range(0, 1 << 32))
            vals = self.call(0x0201, "fhEiSpda", [self.container, 0, 1, S["SENT"] if flags & 1 else S["DRAFT"],
                             None, 1, (1, [(S["REF"], 8)])], "tEbA", sizes=[8])
            if vals[3][0]:
                self.call(0x0203, "fhR", [self.container, vals[3][1][0][2][:8]], "t")
            raise

    # ----- §5.13 address books -----

    def open_book(self, name):
        return self.call(0x0401, "fhz", [self.session, name], "th")[1]

    def book_entries(self, book):
        """A count, then pages of 20 with skip +1."""
        total = self.call(0x0404, "fhRzEiSpa", [book, bytes(8), None, 0, 1, S["NO_FILTER"], None, (0xFFFF, [])],
                          "tEbA")[3][0]
        out, pos = [], 0
        while len(out) < total:
            vals = self.call(0x0404, "fhRzEiSpa", [book, bytes(8), None, pos, 1, S["NO_FILTER"], None,
                             (20, AB_BROWSE)], "tEbA", sizes=[s for _, s in AB_BROWSE])
            pos, (got, ents) = vals[1], vals[3]
            if not got:
                break
            for k in range(got):
                out.append(dict(ref=ents[0][2][k * 8:k * 8 + 8],
                                name=ents[1][2][k * 0x7F:(k + 1) * 0x7F].split(b"\x00", 1)[0].decode("cp850"),
                                type=struct.unpack_from("<I", ents[2][2], k * 4)[0]))
        return out

    def match(self, book, name, how=S["FULL"]):
        vals = self.call(0x0406, "fhRzSpSR", [book, bytes(8), None, S["RDN"], name.encode("cp850"), how, bytes(8)],
                         "tRh", ok=(0, 19))
        return None if vals[0] else vals[1]

    def entry(self, book, ref):
        vals = self.call(0x0407, "fhRza", [book, ref, None, (1, AB_ENTRY)], "tA", sizes=[s for _, s in AB_ENTRY])
        a = {attr: d for attr, _s, d in vals[1][1]}
        return dict(name=a[S["RDN"]].split(b"\x00", 1)[0].decode("cp850"),
                    address=a[S["ADDRESS"]][4:].split(b"\x00", 1)[0].decode("cp850"),
                    addr_type=struct.unpack_from("<I", a[S["ADDRESS"]])[0],
                    type=struct.unpack_from("<I", a[S["TYPE"]])[0])

    def close_book(self, book):
        self.call(0x0410, "fh", [book], "t")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("address")
    ap.add_argument("user")
    ap.add_argument("password")
    ap.add_argument("--po", default="MYPOST")
    ap.add_argument("--lsec", action="store_true")
    a = ap.parse_args()
    host, port = a.address.rsplit(":", 1)
    hp = HP(socket.create_connection((host, int(port))), mode=LSEC if a.lsec else HSEC)
    hp.connect(a.user, a.password, a.po)
    hp.open_session(a.user, a.password)
    print("unread/total:", hp.counts())
    for row in hp.page(0, 20):
        print(row[S["REF"]].hex(), "unread" if row[S["UNREAD_MAIL"]] != b"\0\0" else "      ",
              row[S["FROM_NAME"]].split(b"\0")[0].decode("cp850"), "|",
              row[S["SUBJECT"]].split(b"\0")[0].decode("cp850"))
    print("folders:", hp.folders())
    print(hp.close_session())


if __name__ == "__main__":
    main()
