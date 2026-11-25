# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""cc:Mail message records as sent on the wire (spec/session-layer.md section 4).

A message = header record + body.
- Header record = part 1 (word[8] bytes: 32-byte fixed part + tag-06/13 descriptors)
  followed by the addressing part (dword[0] - dword[4] bytes of TLVs).
- Body = dword[4] - word[8] bytes: item data at the offsets given by the tag-06 descriptors
  (offsets relative to the start of the message file, whose body starts at word[8]).
Integers are little-endian. TLV: tag(1) len(1, signed) data[len]; strings include the NUL.
Text items are stored in cc:Mail's column-transposed form (transpose / untranspose).
"""
import datetime
import re
import struct

FIXED_LEN = 0x20
DESC_LEN = 0x12

TAG_FROM, TAG_FORWARDED_BY, TAG_TO, TAG_SENT_TO, TAG_SUBJECT, TAG_ITEM = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
TAG_END7, TAG_TO_FOLDER, TAG_TO_LIST, TAG_CC, TAG_CC_SENT, TAG_CC_LIST = 0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D
TAG_RECEIPT, TAG_PATH, TAG_UNKNOWN_RCPT, TAG_BCC, TAG_BCC_SENT = 0x0E, 0x0F, 0x10, 0x11, 0x12
TAG_EMBEDDED, TAG_ALIAS, TAG_RECEIPT_TOKEN, TAG_PRIORITY, TAG_FOLDER = 0x13, 0x14, 0x15, 0x16, 0x1B

ITEM_TYPES = {1: "text", 2: "graphics", 3: "file", 4: "fax", 5: "update", 6: "other"}
PRIORITIES = {0: "normal", 1: "low", 2: "urgent"}

# ----- stored-text transposition (column order of the stored form) -----

_COLUMNS = bytes([0x09, 0x04, 0x05, 0x0D, 0x0C, 0x0B, 0x01, 0x07, 0x0A, 0x03, 0x02, 0x10, 0x08, 0x0F, 0x00, 0x0E, 0x06])


def _order(n):
    return [i for c in _COLUMNS for i in range(c, n, 17)]


def transpose(plain: bytes) -> bytes:
    out = bytearray()
    for pos in range(0, len(plain), 0x200):
        chunk = plain[pos:pos + 0x200]
        out.extend(chunk[i] for i in _order(len(chunk)))
    return bytes(out)


def untranspose(stored: bytes) -> bytes:
    out = bytearray()
    for pos in range(0, len(stored), 0x200):
        chunk = stored[pos:pos + 0x200]
        plain = bytearray(len(chunk))
        for k, i in enumerate(_order(len(chunk))):
            plain[i] = chunk[k]
        out.extend(plain)
    return bytes(out)


# ----- TLVs -----

def parse_tlvs(data: bytes, start: int):
    out = []
    pos = start
    while pos < len(data):
        if pos + 2 > len(data):
            raise ValueError(f"truncated TLV at {pos}")
        tag, ln = data[pos], data[pos + 1]
        if ln >= 0x80:
            raise ValueError(f"negative TLV length at {pos}")
        out.append([tag, bytes(data[pos + 2:pos + 2 + ln])])
        pos += 2 + ln
    if pos != len(data):
        raise ValueError("TLVs do not end at the record end")
    return out


def build_tlvs(tlvs) -> bytes:
    return b"".join(bytes([t, len(d)]) + d for t, d in tlvs)


_DATE_STAMP = re.compile(r"\s+\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}\s+\d{1,2}:\d{2}(\s*[AP]M)?\s*$", re.I)


def strip_date_stamp(title: str) -> str:
    """Remove the trailing "m/d/yy h:mmPM" date stamp clients append to file item titles
    (file-items.md 3)."""
    return _DATE_STAMP.sub("", title).strip()


def dos_name(name: str) -> str:
    """8.3 file name for a DOS client: a detached file is named after the first word of the title as the
    file name, so no spaces and DOS characters only."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    stem, dot, ext = base.rpartition(".")
    if not dot:
        stem, ext = base, ""
    clean = lambda s, n: (re.sub(r"[^A-Za-z0-9_$~!#%&'(){}^@`-]", "", s).upper() or "FILE")[:n]  # noqa: E731
    return clean(stem, 8) + ("." + clean(ext, 3) if ext else "")


def cstr(s: str, cp: int = 850) -> bytes:
    """Header string in code page cp (CCINTL.TB tables when loaded), NUL-terminated."""
    from .codepage import tables
    return tables().encode(s, cp) + b"\x00" if s else b""


def text(d: bytes) -> str:
    return d.split(b"\x00", 1)[0].decode("cp850", "replace")


class Message:
    """Header record + body, with the fixed fields decoded."""

    def __init__(self, record: bytes, body: bytes):
        self.record = bytes(record)
        self.body = bytes(body)
        (self.total, self.addr_off, self.part1_len, self.magic, self.copies, self.f0e,
         self.date, self.time, self.headings, self.items, self.last_item) = struct.unpack_from(
            "<IIHHHIIIHHH", self.record, 0)
        if len(self.record) != self.part1_len + self.total - self.addr_off:
            raise ValueError("header record length does not match its size fields")
        if len(self.body) != self.addr_off - self.part1_len:
            raise ValueError("body length does not match the header")
        self.part1_tlvs = parse_tlvs(self.record[:self.part1_len], FIXED_LEN)
        self.addr_tlvs = parse_tlvs(self.record[self.part1_len:], 0)

    @classmethod
    def from_file(cls, data: bytes):
        """Stored form used by this server: record length word + record + body."""
        n = struct.unpack_from("<H", data, 0)[0]
        record = data[2:2 + n]
        part1, total, addr = struct.unpack_from("<H", record, 8)[0], *struct.unpack_from("<II", record, 0)
        return cls(record, data[2 + n:2 + n + addr - part1])

    def to_file(self) -> bytes:
        return struct.pack("<H", len(self.record)) + self.record + self.body

    @property
    def tlvs(self):
        return self.part1_tlvs + self.addr_tlvs

    def names(self, tag):
        return [text(d) for t, d in self.addr_tlvs if t == tag]

    def entries(self, tags):
        """[(tag, name, [post office path])]: a name entry followed by its tag-0F path entries,
        i.e. cc:Mail's "name at PO" (session-layer.md 4.3: routing uses the last 0F)."""
        out = []
        for t, d in self.addr_tlvs:
            if t == TAG_PATH and out:
                out[-1][2].append(text(d))
            elif t in tags:
                out.append((t, text(d), []))
            elif t != TAG_ALIAS:
                out.append((None, "", []))          # a non-name entry ends the previous path
        return [e for e in out if e[0] is not None]

    @property
    def author(self):
        n = self.names(TAG_FROM)
        return n[0] if n else ""

    @property
    def subject(self):
        # some clients write the subject in part 1 (with the 06 descriptors), others and the
        # post office in the addressing part (with 06/13/07): look in both.
        for t, d in self.tlvs:
            if t == TAG_SUBJECT:
                return text(d)
        return ""

    @property
    def when(self):
        d, mo, y = self.date & 0xFF, (self.date >> 8) & 0xFF, (self.date >> 16) + 1900
        s, mi, h = self.time & 0xFF, (self.time >> 8) & 0xFF, (self.time >> 16) & 0xFF
        try:
            return datetime.datetime(y, mo, d, h, mi, s)
        except ValueError:
            return None

    @property
    def priority(self):
        for t, d in self.addr_tlvs:
            if t == TAG_PRIORITY and d:
                return PRIORITIES.get(d[0], str(d[0]))
        return "normal"

    def descriptors(self):
        """Tag-06 descriptors: dicts with index (+2, logical item), type, number, w8, wa, length,
        offset (spec/file-items.md 1)."""
        out = []
        for t, d in self.part1_tlvs:
            if t == TAG_ITEM and len(d) >= DESC_LEN:
                idx, typ, num, w8, wa, length, offset = struct.unpack_from("<HHHHHII", d, 0)
                out.append(dict(index=idx, type=typ, number=num, w8=w8, wa=wa, length=length, offset=offset))
        return out

    def _stored(self, desc):
        a = desc["offset"] - self.part1_len
        return self.body[a:a + desc["length"]]

    def titles(self):
        """Tag 07 = title of item i, in index order (file-items.md 1)."""
        return [text(d) for t, d in self.addr_tlvs if t == TAG_END7]

    def logical_items(self):
        """Logical items (file-items.md 7.2): dicts with index, type (name), title, data, and for
        Mac files rsrc/info. Text: the characters part, untransposed. File: +A 0 part untransposed
        (Mac when a +A 2 info part exists). Fax: 0x80 header block, then 512-byte blocks."""
        titles = self.titles()
        by_index = {}
        for d in self.descriptors():
            by_index.setdefault(d["index"], []).append(d)
        out = []
        for i in sorted(by_index):
            parts = by_index[i]
            typ = parts[0]["type"]
            title = strip_date_stamp(titles[i]) if i < len(titles) else ""
            item = dict(index=i, type=ITEM_TYPES.get(typ, f"type{typ}"), title=title, data=b"")
            if typ == 1:
                chars = [p for p in parts if p["wa"] == 0]
                item["data"] = untranspose(self._stored(chars[0])) if chars else b""
            elif typ == 3:
                wa = {p["wa"]: p for p in parts}
                item["data"] = untranspose(self._stored(wa[0])) if 0 in wa else b""
                if 2 in wa:                                     # Mac file (file-items.md 2.2)
                    info = self._stored(wa[2])
                    item["info"] = untranspose(info[:0x100]) + untranspose(info[0x100:0x16C])
                    item["rsrc"] = untranspose(self._stored(wa[1])) if 1 in wa else b""
                    item["type"] = "macfile"
            elif typ == 4:                                      # fax (file-items.md 4.1, 7.2)
                raw = self._stored(parts[0])
                item["data"] = untranspose(raw[:0x80]) + untranspose(raw[0x80:])
            else:
                item["data"] = self._stored(parts[0])
            out.append(item)
        return out

    def item_list(self):
        """(type, index, data) per logical item, data untransposed (kept for older callers)."""
        return [(it["type"], it["index"], it["data"]) for it in self.logical_items()]

    def recipients_to(self):
        """Names of the tag-03 entries, in order: the receiver answers one verdict byte per entry."""
        return [text(d) for t, d in self.addr_tlvs if t == TAG_TO]

    def for_recipient(self, name: str) -> "Message":
        """Copy to deliver to one mailbox: that name stays the single 03 entry, other pending
        To entries become 04 (sent to), other people's bcc entries are dropped."""
        tlvs, seen, skip_path = [], False, False
        for t, d in self.addr_tlvs:
            if skip_path and t in (TAG_PATH, TAG_ALIAS):
                continue
            skip_path = False
            if t == TAG_TO:
                if not seen and text(d).lower() == name.lower():
                    seen = True
                else:
                    t = TAG_SENT_TO
            elif t in (TAG_BCC, TAG_BCC_SENT) and text(d).lower() != name.lower():
                skip_path = True
                continue
            tlvs.append([t, d])
        if not seen:
            # the recipient was only cc/bcc or not listed: append a 03 entry for it, as a post
            # office does before sending, so the client answers 82 instead of 83/89
            tlvs.append([TAG_TO, cstr(name)])
        addr = build_tlvs(tlvs)
        part1 = bytearray(self.record[:self.part1_len])
        struct.pack_into("<I", part1, 0, self.addr_off + len(addr))   # total size
        struct.pack_into("<H", part1, 0x0C, 1)                        # copies still to send
        return Message(bytes(part1) + addr, self.body)

    # ----- code pages (spec/codepages.md 1, 5) -----
    # tag 31 = code page of the names, 20 = of the subject, 21 = of text items (2-byte LE each)

    NAME_TAGS = (TAG_FROM, TAG_FORWARDED_BY, TAG_TO, TAG_SENT_TO, 0x08, 0x0A, TAG_CC, TAG_CC_SENT,
                 0x0D, TAG_PATH, 0x10, TAG_BCC, TAG_BCC_SENT, TAG_ALIAS, TAG_FOLDER)

    def codepages(self, default):
        """(names, subject, text) code pages from tags 31/20/21; text falls back to the first 21,
        then 31, then `default` (codepages.md 5.2)."""
        found = {}
        for t, d in self.tlvs:
            if t in (0x31, 0x20, 0x21) and len(d) >= 2 and t not in found:
                found[t] = struct.unpack_from("<H", d)[0]
        names = found.get(0x31, default)
        return names, found.get(0x20, names), found.get(0x21, names)

    def with_codepage(self, cp, convert_from=None):
        """Copy with tags 31/20/21 = cp. With convert_from=(names, subject, text) code pages, the
        names, subject and text items are converted to cp first with the CCINTL.TB tables (single
        byte code pages keep every length, so sizes and offsets stay valid)."""
        from .codepage import tables
        tb = tables()

        def conv(data, src):
            if not convert_from or not src or src == cp:
                return data
            raw = data.split(b"\x00", 1)[0]
            return tb.convert(raw, src, cp) + data[len(raw):]

        src_names, src_subject, src_text = convert_from or (None, None, None)
        tag = struct.pack("<H", cp)
        cp_tags = (0x31, 0x20, 0x21)

        def fix(t, d, src):
            if t in cp_tags and len(d) >= 2:
                return tag + d[2:]                     # rewrite in place, same length
            return conv(d, src)

        # part 1 keeps its size: tags there are rewritten in place, never added or removed
        p1 = [[t, fix(t, d, src_subject if t == TAG_SUBJECT else None)] for t, d in self.part1_tlvs]
        ad = [[t, fix(t, d, src_names if t in self.NAME_TAGS else src_subject if t == TAG_SUBJECT else None)]
              for t, d in self.addr_tlvs]
        present = {t for t, _ in p1 + ad}
        missing = [[t, tag] for t in cp_tags if t not in present]
        end = [x for x in ad if x[0] == TAG_END7]
        ad = [x for x in ad if x[0] != TAG_END7] + missing + end
        body = bytearray(self.body)
        if convert_from and src_text and src_text != cp:
            for t, d in p1:
                if t == TAG_ITEM and len(d) >= DESC_LEN:
                    _lvl, typ, _n, _w8, wa, length, offset = struct.unpack_from("<HHHHHII", d, 0)
                    if typ == 1 and wa == 0 and length:
                        a = offset - self.part1_len
                        plain = untranspose(bytes(body[a:a + length]))
                        body[a:a + length] = transpose(tb.convert(plain, src_text, cp))
        part1 = bytearray(self.record[:FIXED_LEN] + build_tlvs(p1))
        if len(part1) != self.part1_len:
            raise ValueError("part 1 changed size")
        addr = build_tlvs(ad)
        struct.pack_into("<I", part1, 0, self.addr_off + len(addr))
        return Message(bytes(part1) + addr, bytes(body))

    def for_post_office(self, dest: str, own: str):
        """Outgoing copy for post office `dest` (spec/router-to-router.md 3.3):
        pending 03/0B/11 entries whose 0F run names dest are kept, other pending entries become
        04/0C/12 in this copy; kept cc/bcc get an appended 03 copy (no 0F run); 03 followed by
        0F <own> becomes 04; the author gets 0F <own> if it has no path (replies route back, 7.4).
        Returns None when nothing is pending for dest."""
        pend = {TAG_TO: TAG_SENT_TO, TAG_CC: TAG_CC_SENT, TAG_BCC: TAG_BCC_SENT}
        tl = [list(x) for x in self.addr_tlvs]

        def run(i):                      # 0F names right after entry i
            out, j = [], i + 1
            while j < len(tl) and tl[j][0] in (TAG_PATH, TAG_ALIAS):
                if tl[j][0] == TAG_PATH:
                    out.append(text(tl[j][1]).lower())
                j += 1
            return out

        kept, copies = 0, []
        for i, (t, d) in enumerate(tl):
            if t not in pend:
                continue
            path = run(i)
            if dest.lower() not in path:
                tl[i][0] = pend[t]
                continue
            if path and path[0] == own.lower() and t == TAG_TO:
                tl[i][0] = TAG_SENT_TO
                continue
            kept += 1
            if t in (TAG_CC, TAG_BCC):
                copies.append([TAG_TO, d])
        if not kept:
            return None
        for i, (t, d) in enumerate(tl):
            if t == TAG_FROM and not run(i):
                tl.insert(i + 1, [TAG_PATH, cstr(own)])
                break
        # the empty 07 entry stays last
        end = [x for x in tl if x[0] == TAG_END7]
        tl = [x for x in tl if x[0] != TAG_END7] + copies + end
        addr = build_tlvs(tl)
        part1 = bytearray(self.record[:self.part1_len])
        struct.pack_into("<I", part1, 0, self.addr_off + len(addr))
        struct.pack_into("<H", part1, 0x0C, 1)
        return Message(bytes(part1) + addr, self.body)

    def mark_refused(self, verdicts) -> "Message":
        """Copy in which the i-th 03 entry becomes tag 10 (unknown recipient) when the i-th
        verdict is 83 (DB6 post offices mark only 83; DB8 ones any verdict != 82)."""
        tlvs, i = [], 0
        for t, d in self.addr_tlvs:
            if t == TAG_TO:
                if i < len(verdicts) and verdicts[i] == 0x83:
                    t = TAG_UNKNOWN_RCPT
                i += 1
            tlvs.append([t, d])
        return Message(self.record[:self.part1_len] + build_tlvs(tlvs), self.body)

    def to_text(self) -> str:
        lines = [f"From: {self.author}"]
        for label, tag in (("To", TAG_TO), ("Sent-To", TAG_SENT_TO), ("Cc", TAG_CC), ("Cc", TAG_CC_SENT),
                           ("Bcc", TAG_BCC), ("Bcc", TAG_BCC_SENT), ("To-Folder", TAG_TO_FOLDER),
                           ("Folder", TAG_FOLDER), ("Forwarded-By", TAG_FORWARDED_BY)):
            for n in self.names(tag):
                lines.append(f"{label}: {n}")
        lines.append(f"Subject: {self.subject}")
        lines.append(f"Date: {self.when}")
        lines.append(f"Priority: {self.priority}")
        other = sorted({t for t, _ in self.tlvs} - {1, 2, 3, 4, 5, 6, 0x0B, 0x0C, 0x11, 0x12, 0x08, 0x1B, 0x16})
        if other:
            lines.append("Other-Tags: " + " ".join(f"{t:02x}" for t in other))
        for typ, num, data in self.item_list():
            lines.append(f"\n--- item {num}: {typ}, {len(data)} bytes ---")
            lines.append(data.decode("cp850", "replace") if typ == "text" else data[:64].hex(" "))
        return "\n".join(lines) + "\n"


# ----- non-delivery report (spec/router-to-router.md 3.5; DB6 post office) -----

ADMINISTRATOR = "Administrator"
NDR_SUBJECT = "Message not deliverable"
# from the first 01 on, every entry with another tag is deleted
NDR_KEEP = (0x06, 0x07, 0x05, 0x13, 0x20, 0x21, 0x23, 0x16, 0x1D)
RETURNED = 2            # tag 13 +0A: 2 = returned message


def _flat(record):
    """The header record as one TLV run from offset 32 (part 1 + addressing)."""
    return [list(x) for x in parse_tlvs(record, FIXED_LEN)]


def _author_index(tl):
    """The author: the last 02 (forwarded by), else the first 01."""
    fwd = [i for i, (t, _) in enumerate(tl) if t == TAG_FORWARDED_BY]
    if fwd:
        return fwd[-1]
    return next((i for i, (t, _) in enumerate(tl) if t == TAG_FROM), None)


def report_address(sent: Message, own: str, post_office, user, cp=850):
    """To entries of the report and where it goes. post_office(name) -> canonical name of a known
    post office or None; user(name) -> canonical local user or None.
    Returns (to_tlvs, target, routed) with target ("route", po) or ("local", user), or None when
    the sender is not in the mail directory and no report is built."""
    tl = _flat(sent.record)
    a = _author_index(tl)
    if a is None:
        return None
    # the 0F run after the author, up to a 0F naming this post office;
    # the last entry of it that is a known post office, stepping back past unknown ones
    run, j = [], a + 1
    while j < len(tl) and tl[j][0] == TAG_PATH and text(tl[j][1]).strip().lower() != own.lower():
        run.append(j)
        j += 1
    if run:
        for k in reversed(run):
            po = post_office(text(tl[k][1]))
            if po:
                # the author entry and its 0F entries before the found one, as 03,
                # then 0F <that post office> (+ its next hops: none here)
                to = [[TAG_TO, tl[a][1]]] + [list(tl[i]) for i in range(a + 1, k)] + [[TAG_PATH, cstr(po, cp)]]
                return to, ("route", po), True
        return None                 # a path to no known post office: no report
    name = user(text(tl[a][1]))     # directory lookup
    if not name:
        return None
    # 03 <directory name> (+ next hops: none for a local user), then 0F <own>
    return [[TAG_TO, cstr(name, cp)], [TAG_PATH, cstr(own, cp)]], ("local", name), False


def embedded_header(record: bytes) -> bytes:
    """The original header record as embedded in a report: magic word
    0A := 0x46 'F' (addressing directly after part 1), then the fixed part, the rest of part 1 and
    the addressing part, each in stored (transposed) form from its own first byte. Clients read it
    back untransposing each part."""
    r = bytearray(record)
    struct.pack_into("<H", r, 0x0A, 0x46)
    p1 = struct.unpack_from("<H", r, 8)[0]
    return transpose(bytes(r[:FIXED_LEN])) + transpose(bytes(r[FIXED_LEN:p1])) + transpose(bytes(r[p1:]))


def read_embedded(data: bytes) -> bytes:
    """Inverse of embedded_header, the way clients read a header at a file offset:
    32 bytes, then word[8] - 32, then (magic 'F') dword[0] - dword[4] bytes from offset word[8]."""
    fixed = untranspose(data[:FIXED_LEN])
    total, addr_off, p1 = struct.unpack_from("<IIH", fixed, 0)
    part1 = untranspose(data[FIXED_LEN:p1])
    addr = untranspose(data[p1:p1 + total - addr_off])
    return fixed + part1 + addr


def non_delivery(sent: Message, stored: Message, refused_by: str, to_tlvs, own: str, cp: int,
                 routed=False, cc_tlvs=(), targets=1, when=None) -> Message:
    """The post office's non-delivery report (DB6 form).
    sent = the outgoing copy with the refused 03 entries turned into tag 10; stored = the message as stored (its header record is embedded); refused_by =
    the name of the post office or user whose queue held the message;
    to_tlvs = report_address()[0]; cp = the post office code page for tag 20."""
    rec = sent.record
    n06 = struct.unpack_from("<H", rec, 0x1C)[0]
    tl = _flat(rec)

    # every tag-10 entry with the 0F entries and then the 14 entries after it
    runs, i = [], 0
    while i < len(tl):
        if tl[i][0] != TAG_UNKNOWN_RCPT:
            i += 1
            continue
        j = i + 1
        while j < len(tl) and tl[j][0] == TAG_PATH:
            j += 1
        while j < len(tl) and tl[j][0] == TAG_ALIAS:
            j += 1
        runs += [list(x) for x in tl[i:j]]
        i = j

    # a 20-byte slot opens at 32 + 20 * word[1C];
    # it becomes 13 12, +0A word = 2, +0C dword = length of the stored record, +10 dword = 0
    pos, k = FIXED_LEN, 0
    while pos < FIXED_LEN + 20 * n06 and k < len(tl):
        pos += 2 + len(tl[k][1])
        k += 1
    if pos != FIXED_LEN + 20 * n06:
        raise ValueError("the item descriptors do not end at 32 + 20 * word[1C]")
    slot = [TAG_EMBEDDED, bytes(8) + struct.pack("<HII", RETURNED, len(stored.record), 0)]
    tl.insert(k, slot)
    # from the first 01 on, only NDR_KEEP tags stay
    first = next((i for i, (t, _) in enumerate(tl) if t == TAG_FROM), 0)
    tl = tl[:first] + [x for x in tl[first:] if x[0] in NDR_KEEP]
    # every 05 and every 20 removed
    tl = [x for x in tl if x[0] not in (TAG_SUBJECT, 0x20)]
    # then 01 Administrator, 0F <refused_by>, 05 "Message not deliverable", 20 <cp>
    tl += [[TAG_FROM, cstr(ADMINISTRATOR, cp)], [TAG_PATH, cstr(refused_by, cp)]]
    if routed and refused_by.strip().lower() != own.lower():
        # the author's (now Administrator's)
        # 0F run must end with this post office, else 0F <own> is inserted after it
        tl.append([TAG_PATH, cstr(own, cp)])
    tl += [[TAG_SUBJECT, cstr(NDR_SUBJECT, cp)], [0x20, struct.pack("<H", cp)]]
    # the saved tag-10 runs; To = the author; cc
    tl += runs + [list(x) for x in to_tlvs] + [list(x) for x in cc_tlvs]

    # storing: word[8] = offset of the first 01; items renumbered 1..n and laid out
    # from word[8] on; then each tag 13 gets its +10;
    # word[1E] = word[1C]; dword[4] = end of the data, dword[0] = dword[4] + addressing length
    offs, pos = [], FIXED_LEN
    for t, d in tl:
        offs.append(pos)
        pos += 2 + len(d)
    word8 = next(o for o, (t, _) in zip(offs, tl) if t == TAG_FROM)
    v7 = word8
    body = bytearray()

    def old_data(off, length):
        if length and not off:
            raise ValueError("item data kept outside the message (SEG file) is not supported")
        a = off - stored.part1_len
        return stored.body[a:a + length]

    n = 0
    for e in tl:
        if e[0] != TAG_ITEM or n >= n06:
            continue
        d = bytearray(e[1])
        length, off = struct.unpack_from("<II", d, 10)
        body += old_data(off, length)
        n += 1
        struct.pack_into("<H", d, 4, n)                 # +6 item number
        struct.pack_into("<I", d, 14, v7)               # +10 offset
        v7 += length
        e[1] = bytes(d)
    for e in tl:
        if e[0] != TAG_EMBEDDED:
            continue
        d = bytearray(e[1])
        length, off = struct.unpack_from("<II", d, 10)
        # the new slot (old +10 = 0) re-reads the stored record from the
        # message start; older embedded headers are re-read at their old offsets
        data = embedded_header(stored.record) if e is slot else old_data(off, length)
        body += data
        struct.pack_into("<I", d, 14, v7)
        v7 += length
        e[1] = bytes(d)

    hdr = bytearray(rec[:FIXED_LEN]) + build_tlvs(tl)
    when = when or datetime.datetime.now()
    # header reset: word 0A = 'M', word 0C = 0, dword 0E = 0, new date and time; word 8,
    # dword 4, dword 0 := 0 (set again above); words 1A/1C/1E are left alone.
    # When queued: word 0C = number of targets, dword 0E = ++post office serial
    # (this server keeps no serial: 0)
    struct.pack_into("<IIHHHIII", hdr, 0, v7 + len(hdr) - word8, v7, word8, 0x4D, targets, 0,
                     when.day | when.month << 8 | (when.year - 1900) << 16,
                     when.second | when.minute << 8 | when.hour << 16)
    struct.pack_into("<H", hdr, 0x1E, n06)
    return Message(bytes(hdr), bytes(body))


DEFAULT_ATTRIBUTE = 0x17   # the usual default video attribute of a text item


def compose(author: str, recipients, subject: str, body_text: str, when=None, priority=0, folder=None,
            author_po=None, extra=(), receipt=False, codepage=850, attachments=None) -> Message:
    """codepage = the code page the reader's client shows (the recipient's configured code page);
    names, subject and text are encoded in it and tagged 31/20/21 (codepages.md 5)."""
    from .codepage import tables

    def cstr(s, _cp=codepage):          # noqa: F811 - compose encodes in the target code page
        return tables().encode(s, _cp) + b"\x00" if s else b""
    """Build a message with one text body in the form clients write (spec/items.md):
    item 1 = attribute layer (+A=1, +8 = default attribute, length 0),
    item 2 = characters (+A=0, +8 = number of CR LF), text ending in CR LF
    (clients check for the item end only after a CR LF)."""
    from . import limits as L
    when = when or datetime.datetime.now()
    subject = L.clip(subject, L.SUBJECT_MAX)
    author = L.clip(author, L.HEADER_STRING_MAX)
    text = L.wrap_lines(body_text.replace("\r\n", "\n"))
    text_crlf = text.replace("\n", "\r\n")
    if not text_crlf.endswith("\r\n"):
        text_crlf += "\r\n"
    plain = tables().encode(text_crlf, codepage)
    attachments = list(attachments or [])
    chunks = L.split_text(plain)
    if len(chunks) > 1:
        # one text item must fit a client's 0x5000-cell limit (limits.md): the full text
        # goes as a file item and the body keeps its start
        attachments.insert(0, ("MESSAGE.TXT", plain))
        plain = chunks[0] + b"[the full text is attached as MESSAGE.TXT]\r\n"
    attachments = attachments[:L.ITEMS_MAX - 1]
    # item 0 = text: attribute part + characters part (items.md); item i>0 = file, one type-3 part
    # (file-items.md 7.1). Each item's data is transposed from its own first byte.
    n_desc = 2 + len(attachments)
    part1_len = FIXED_LEN + n_desc * (2 + DESC_LEN)
    text_stored = transpose(plain)
    descs = [struct.pack("<HHHHHII", 0, 1, 1, DEFAULT_ATTRIBUTE, 1, 0, part1_len),
             struct.pack("<HHHHHII", 0, 1, 2, plain.count(b"\r\n"), 0, len(text_stored), part1_len)]
    body = bytearray(text_stored)
    titles = [b""]
    for i, (fname, data) in enumerate(attachments, start=1):
        descs.append(struct.pack("<HHHHHII", i, 3, 2 + i, 0, 0, len(data), part1_len + len(body)))
        body += transpose(bytes(data))
        titles.append(cstr(dos_name(fname)))     # title = the DOS name; no date stamp (7.1 step 5)
    body = bytes(body)
    tlvs = [[TAG_FROM, cstr(author)]]
    if author_po:                       # "author at PO", e.g. "bob@example.com at INTERNET"
        tlvs.append([TAG_PATH, cstr(author_po)])
    for r in recipients:                        # "name at PO" -> 03 name + 0F PO
        name, _, rpo = r.partition(" at ")
        tlvs.append([TAG_TO, cstr(name.strip())])
        if rpo.strip():
            tlvs.append([TAG_PATH, cstr(rpo.strip())])
    for tag, name, po in extra:                 # e.g. (TAG_SENT_TO, "x@y.com", "INTERNET")
        tlvs.append([tag, cstr(name)])
        if po:
            tlvs.append([TAG_PATH, cstr(po)])
    if receipt:
        tlvs.append([TAG_RECEIPT, b""])
    tlvs.append([TAG_SUBJECT, cstr(subject)])
    if priority:
        tlvs.append([TAG_PRIORITY, bytes([priority, 0])])
    if folder:
        tlvs.append([TAG_FOLDER, cstr(folder)])
    for t in titles:                      # tag 07 = title of item i, in index order (file-items.md 1)
        tlvs.append([TAG_END7, t])
    addr = build_tlvs(tlvs)
    addr_off = part1_len + len(body)
    date = when.day | when.month << 8 | (when.year - 1900) << 16
    tim = when.second | when.minute << 8 | when.hour << 16
    # word[1A] = logical items, word[1C] = descriptors, word[1E] = last part number (file-items.md 7.1)
    fixed = struct.pack("<IIHHHIIIHHH", addr_off + len(addr), addr_off, part1_len, 0x4D, 1, 0, date, tim,
                        1 + len(attachments), n_desc, n_desc)
    record = fixed + b"".join(bytes([TAG_ITEM, DESC_LEN]) + d for d in descs) + addr
    return Message(record, body).with_codepage(codepage)
