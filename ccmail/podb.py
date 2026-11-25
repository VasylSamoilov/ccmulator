# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""cc:Mail DB 8.x post office files (CCDATA): reader and writer. Format: spec/podb.md.

Keys and passwords use the collation and normalization tables of CCINTL.TB.
Section numbers (§) are spec/podb.md.

Reader:  PostOffice(po_dir)            -- every file decrypted, records, indexes, messages
Writer:  deliver(po_dir, message, recipients), add_user(po_dir, name, password, comments),
         mark_read(po_dir, user, message_number),
         delete_message(po_dir, user, message_number | pointer_id), purge_folder(po_dir, user)
         Each change of a file is one transaction (§8, §12): lock bytes 0..511, re-read the file,
         change records/indexes in memory, write the changed pages with page 0 last, unlock.
Check:   verify(po_dir) -> list of problems (page/record CRCs, indexes rebuilt from the records,
         counters). Used by the tests and `tools/ccpodb.py PO check`.
"""
import errno
import fcntl
import os
import random
import struct
import time as _time
import zlib

from .message import Message, untranspose, transpose, parse_tlvs, build_tlvs

PAGE = 512          # physical page
LPAGE = 504         # logical page = page minus 8-byte header
FIXED_KEY = bytes.fromhex(              # 66-byte fixed key (§1.3), + 30 zero bytes
    "0140c65421e3c609782642de6be37da2d446ec80617b184f1ec4ec561e214399"
    "51f0dfe0a923da88170cd57ec15636f8dd2b0e0417d46c59987f984133c4fb64"
    "56dc") + bytes(30)

KIND_DD, KIND_DS, KIND_MBOX, KIND_MI, KIND_MS = 0x01000000, 0x02000000, 0x03000000, 0x04000000, 0x05000000

# record tags (§3)
T_FILE_ROOT, T_INDEX_ROOT, T_UNIV_INDEX, T_EXTENSION = 0x01, 0x3C, 0x46, 0x28
T_DIR_ROOT, T_DIR_ENTRY, T_DIR_MEMBER = 0xC8, 0xD2, 0x104
T_MSG_INDEX_ROOT, T_MESSAGE_FILE, T_MESSAGE_INDEX, T_FREE_SPACE = 0x12C, 0x136, 0x140, 0x154
T_MAILBOX_ROOT, T_FOLDER, T_POINTER = 0x190, 0x1B8, 0x1C2
ID_INDEX, TRANSACTION_INDEX = 3, 0x1F
F_DELETED, F_NEW, F_CHANGED = 1, 2, 4            # low flag byte (§2)
INBOX, FOLDER_ROOT = 0x2B, 0x2A


class PODBError(Exception):
    pass


# ---------------------------------------------------------------- CRC
def _crc_table():
    t = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) if c & 0x8000 else c << 1
        t.append(c & 0xFFFF)
    return t


_CRC = _crc_table()


def crc16(data, c=0xFFFF, backwards=False):
    for x in (reversed(data) if backwards else data):
        c = ((c << 8) & 0xFFFF) ^ _CRC[(c >> 8) ^ x]
    return c


def page_ok(p):                        # CRC over the whole 512-byte page
    return crc16(p, backwards=True) == 0x1D0F


def set_page_crc(p):                   # ~CRC16 over bytes 511..2
    struct.pack_into("<H", p, 0, crc16(bytes(p[2:]), backwards=True) ^ 0xFFFF)


def record_crc(data):                  # ~CRC forward, stored LE after the record
    return crc16(data) ^ 0xFFFF


def crc32_reg(data, init=0xFFFFFFFF):  # CRC-32 register, no final xor
    return zlib.crc32(data, init ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


def univ_object_id(time_dw, date_dw, rec_no, file_id):   # §7
    return crc32_reg(struct.pack("<IIII", time_dw, date_dw, rec_no, file_id))


def now_date_time(t=None):             # byte 3 = 0
    lt = _time.localtime(t)
    return (lt.tm_mday | lt.tm_mon << 8 | (lt.tm_year - 1900) << 16,
            lt.tm_sec | lt.tm_min << 8 | lt.tm_hour << 16)


# ---------------------------------------------------------------- cipher (§1.3)
def key_setup(k):
    s = bytearray(96)
    s[0], s[1], s[2] = k[0], k[1], 0
    v = (k[0x37] * k[0x18]) & 0xFFFFFFFF
    for i in range(88, -1, -1):
        v = (v * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        s[3 + i] = v >> 24
    for j in range(64):
        s[3 + j] ^= k[2 + j]
    for j in range(64):
        s[28 + j] ^= k[2 + j]
    di, si = 89, 38
    for _ in range(7921):                                   # 7921 mixing steps, lags 89 and 38
        s[2 + di] = (s[2 + di] + s[2 + si] + 1) & 0xFF
        di = di - 1 or 89
        si = si - 1 or 89
    return s


def _keystream(seed, off, n):
    s = bytearray(90)
    v = ((off >> 9) * 0xC49D + 1) & 0xFFFF
    for i in range(45):
        struct.pack_into("<H", s, 2 * i, struct.unpack_from("<H", seed, 2 * i)[0] ^ v)
    j = (((off >> 16) ^ v) & 0xFFFF) % 89 + 1
    k = j - 51
    if k <= 0:
        k += 89
    t = bytearray(256)
    for i in range(256):
        s[j] = (s[j] + s[k]) & 0xFF
        t[i] = s[j]
        j = j - 1 or 89
        k = k - 1 or 89
    last = t[255]
    out = bytearray(n)
    for i in range(n):
        idx = last
        last = t[idx]
        s[j] = (s[j] + s[k]) & 0xFF
        t[idx] = s[j]
        j = j - 1 or 89
        k = k - 1 or 89
        out[i] = last
    return out


def _rot2(x):
    x &= 0xFF
    return ((x << 2) | (x >> 6)) & 0xFF


def _f(a, kw):
    a0, a1, a2, a3 = a
    f1 = a1 ^ (kw & 0xFF) ^ a0
    f2 = a2 ^ (kw >> 8) ^ a3
    f1 = _rot2(f1 + f2 + 1)
    f2 = _rot2(f2 + f1)
    return bytes((_rot2(a0 + f1), f1, f2, _rot2(a3 + f2 + 1)))


def _x(a, b):
    return bytes(p ^ q for p, q in zip(a, b))


def _feal_dec(blk, k):
    kw = struct.unpack_from("<8H", k, 0)
    left, right = _x(blk[:4], k[24:28]), _x(blk[4:8], k[28:32])
    right = _x(right, left)
    for r in range(7, -1, -1):
        left, right = right, _x(left, _f(right, kw[r]))
    left = _x(left, right)
    return _x(right, k[16:20]) + _x(left, k[20:24])


def _feal_enc(blk, k):
    kw = struct.unpack_from("<8H", k, 0)
    left, right = _x(blk[:4], k[16:20]), _x(blk[4:8], k[20:24])
    right = _x(right, left)
    for r in range(8):
        left, right = right, _x(left, _f(right, kw[r]))
    left = _x(left, right)
    return _x(right, k[24:28]) + _x(left, k[28:32])


def decrypt(state, data, off):
    """Per 512-byte chunk, FEAL decrypt (mode 2) then keystream (mode 1, 2)."""
    out = bytearray(data)
    for p in range(0, len(out), 512):
        n = min(512, len(out) - p)
        chunk = bytearray(out[p:p + n])
        if state[0] == 2:
            for b in range(0, n - n % 8, 8):
                chunk[b:b + 8] = _feal_dec(bytes(chunk[b:b + 8]), state[2:34])
        if state[0] in (1, 2):
            ks = _keystream(state[2:92], off + p, n)
            chunk = bytearray(c ^ e for c, e in zip(chunk, ks))
        out[p:p + n] = chunk
    return bytes(out)


def encrypt(state, data, off):
    """Per 512-byte chunk, keystream, then FEAL encrypt (mode 2)."""
    out = bytearray(data)
    for p in range(0, len(out), 512):
        n = min(512, len(out) - p)
        chunk = bytearray(out[p:p + n])
        if state[0] in (1, 2):
            ks = _keystream(state[2:92], off + p, n)
            chunk = bytearray(c ^ e for c, e in zip(chunk, ks))
        if state[0] == 2:
            for b in range(0, n - n % 8, 8):
                chunk[b:b + 8] = _feal_enc(bytes(chunk[b:b + 8]), state[2:34])
        out[p:p + n] = chunk
    return bytes(out)


def mode2(state):
    s = bytearray(key_setup(state))
    s[0] = 2
    return s


def _password_ks(n):                   # keystream of setup(FIXED) at offset 0
    return _keystream(key_setup(FIXED_KEY)[2:92], 0, n)


def decode_password(blob):
    """Mailbox_Password (0x191): (norm(pw) + NUL + rand fill to 64) XOR KS (§10)."""
    if not blob:
        return None
    plain = bytes(a ^ b for a, b in zip(blob, _password_ks(len(blob))))
    return plain.split(b"\0", 1)[0].decode("cp850", "replace") if b"\0" in plain else None


# ---------------------------------------------------------------- CCINTL
class Intl:
    """The CCINTL.TB rules the database needs for keys and passwords: string compare,
    normalize, normalize for hashing, highest character, split length.
    Single-byte code pages and 1200 only.
    The PO code page and language come from the CCPODD header (header
    field 0xED, 0xEF; default 437 / "EN"), and the sort flag = header byte 19 bit 0x10."""

    def __init__(self, path, cp=437, lang=b"en", sort_flag=0):
        from .codepage import Tables
        self.tb = Tables(path)
        data = _read(path)
        self.cp, self.lang, self.sort_flag = cp, lang.lower(), sort_flag
        fo, fs = struct.unpack_from("<II", data, 0x14)           # 806-byte fold table
        self.fold = struct.unpack_from(f"<{fs // 2}H", data, fo)
        self.fold_count = fs // 2                                # number of fold entries (403)
        lo, ls = struct.unpack_from("<II", data, 0x0C)           # locale directory, 32-byte entries
        self.locales = {}
        for k in range(ls // 32):
            typ, wo, ws = struct.unpack_from("<HII", data, lo + 32 * k)
            lng, fl = data[lo + 32 * k + 10:lo + 32 * k + 12].lower(), struct.unpack_from("<H", data, lo + 32 * k + 12)[0]
            xo, xs, co, cs = struct.unpack_from("<IIII", data, lo + 32 * k + 16)
            if typ == 0x8003 and (lng, fl & 3) not in self.locales:
                self.locales[(lng, fl & 3)] = (struct.unpack_from(f"<{ws // 2}H", data, wo), xo, co)

    def _weights(self, flags):         # language + (flags & 3)
        try:
            return self.locales[(self.lang, flags & 3)]
        except KeyError:
            raise PODBError(f"CCINTL.TB has no locale {self.lang!r} variant {flags & 3}")

    def _dec(self, cp):
        if cp not in self.tb.dec:
            raise PODBError(f"CCINTL.TB has no table {cp}->1200")
        return self.tb.dec[cp]

    def _enc(self, cp, u):             # direct byte for U+00xx, else bsearch pairs, '?'
        if u < 0x100:
            return self.tb.enc_direct[cp][u]
        keys, vals = self.tb.enc_pairs[cp]
        import bisect
        i = bisect.bisect_left(keys, u)
        return vals[i] if i < len(keys) and keys[i] == u else 0x3F

    def to_unicode(self, data, cp):    # cp -> 1200 for single-byte cp
        t = self._dec(cp)
        return b"".join(struct.pack("<H", t[b]) for b in data)

    def normalize(self, data, cp):
        """Normalize, single-byte code page: U = table[b]; if U < 403: V = fold[U], byte = enc(V)
        unless that is '?' for V != '?'."""
        t, out = self._dec(cp), bytearray(data)
        for i, b in enumerate(data):
            u = t[b]
            if u < self.fold_count:
                v = self.fold[u]
                e = self._enc(cp, v)
                if e != 0x3F or v == 0x3F:
                    out[i] = e
        return bytes(out)

    def normalize_hash(self, data, cp):
        """Normalize for hashing: like normalize, but V = the byte itself when U >= 403."""
        t, out = self._dec(cp), bytearray(data)
        for i, b in enumerate(data):
            u, v = t[b], b
            if u < self.fold_count:
                v = self.fold[u]
            e = self._enc(cp, v)
            if e != 0x3F or v == 0x3F:
                out[i] = e
        return bytes(out)

    def strcmp(self, a, b, cp, flags):
        """Collating compare(a, b) -> 1 if a > b, -1 if a < b, 0 if equal. Single weights only: an entry
        with bit 0x8000 (expansion 0xC000 / contraction 0xA000) is refused (the 'en' tables of the
        sample CCINTL.TB have none)."""
        W, _, _ = self._weights(flags)
        n = len(W)
        step = 2 if cp == 1200 else 1
        t = None if cp == 1200 else self._dec(cp)
        i = j = 0
        while i < len(a):
            if j >= len(b):
                if not flags & 0x10 and any(a[i:]):
                    return 1
                return 0
            c1 = struct.unpack_from("<H", a, i)[0] if cp == 1200 else t[a[i]]
            c2 = struct.unpack_from("<H", b, j)[0] if cp == 1200 else t[b[j]]
            w1 = W[c1] if c1 < n else 4095
            w2 = W[c2] if c2 < n else 4095
            if (w1 | w2) & 0x8000:
                raise PODBError("collation expansion/contraction not implemented")
            if w2 < w1:
                return 1
            if w2 > w1:
                return -1
            if (w1 == 4095 or w2 == 4095) and c1 != c2:
                return 1 if c2 < c1 else -1
            i += step
            j += step
        if not flags & 0x20 and any(b[j:]):
            return -1
        return 0

    def highest_char(self, cp, flags):
        """Highest character: 0xFF for 1200; else the byte 0x80..0xFF with the highest weight."""
        if cp == 1200:
            return 0xFF
        W, _, _ = self._weights(flags)
        n, t = len(W), self._dec(cp)
        best, w_best, u_best = 0xFF, 0, n
        for c in range(128, 256):
            u = t[c]
            if u < n:
                w = W[u]
                if w_best > w or w & 0x8000:
                    continue
                w_best, u_best, best = w, u, c
            elif u_best <= u:
                w_best, u_best, best = 4095, u, c
        return best

    def split_len(self, cp, n):
        """Split length for a non-multi-byte code page: n, even for 1200; a locale with
        contraction tables would cut further and is refused."""
        _, _, co = self._weights(0)
        if co:
            raise PODBError("ccIntlSplitStr with contractions not implemented")
        return n & ~1 if cp == 1200 else n


def encode_password(intl, pw):
    """strlen+1 <= 64 (else error 33459), then normalized in the PO code page.
    Returns (enc_pw for the key mask, 64-byte Mailbox_Password blob)."""
    raw = pw.encode("cp437") if isinstance(pw, str) else pw
    raw += b"\0"
    if len(raw) > 0x40:
        raise PODBError("password too long (33459): at most 63 bytes")
    norm = intl.normalize(raw, intl.cp)
    ks = _password_ks(64)
    mask = bytes(a ^ b for a, b in zip(norm[:-1], ks))
    blob = bytearray(norm) + bytes(random.getrandbits(8) for _ in range(64 - len(norm)))
    return mask, bytes(a ^ b for a, b in zip(blob, ks))


# ---------------------------------------------------------------- files
def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def find_file(po_dir, base):
    """Case-insensitive lookup; generation .00 .. .99 tried in order."""
    names = {n.upper(): n for n in os.listdir(po_dir)}
    cand = [base] if "." in base else [f"{base}.{g:02d}" for g in range(100)]
    for c in cand:
        if c.upper() in names:
            return os.path.join(po_dir, names[c.upper()])
    return None


def file_name(fid, gen=0):             # 'U' + _ltoa(n, 16) (lower case), zero-padded to 7
    kind, num = fid & 0x7F000000, fid & 0xFFFFFF
    if kind == KIND_MBOX:
        return "CCPOMBOX.00" if num == 0 else f"U{num:07x}.{gen:02d}"
    return {KIND_DD: "CCPODD", KIND_DS: "CCPODS", KIND_MI: "CCPOMI", KIND_MS: "CCPOMS"}[kind] + f".{gen:02d}"


class Record:
    """An F001 record. `chunks` = [(offset, slot count)] of the record and its Extension_Field
    continuations; `slots` = [[tag, value]] over all chunks, without the 0x28 link slots."""

    def __init__(self, f, off, tag, rid, flags, chunks, slots, crc_ok):
        self.file, self.off, self.tag, self.id, self.flags = f, off, tag, rid, flags
        self.chunks, self.slots, self.crc_ok = chunks, slots, crc_ok

    @property
    def fields(self):
        return [tuple(s) for s in self.slots]

    def get(self, tag, default=None):
        for t, v in self.slots:
            if t == tag:
                return v
        return default

    def has(self, tag):
        return any(t == tag for t, _ in self.slots)

    def all(self, tag):
        return [v for t, v in self.slots if t == tag]

    def str(self, tag):
        b = self.file.data_at(self.get(tag, 0))
        return b.split(b"\0", 1)[0].decode("cp850", "replace") if b is not None else None

    def nslots(self):
        return sum(n for _, n in self.chunks)


class DBFile:
    """One record file: offset 0..511 random/lock region, header page at 512, pages from 1024.
    `pages[n]` = plain page n (512 bytes incl. the 8-byte page header); logical address L is in
    page L // 504 at byte 8 + L % 504 (§1.2)."""

    def __init__(self, path, header_state, raw=None, po=None):
        self.path, self.po = path, po
        if raw is None:
            raw = _read(path)
        self.raw_len = len(raw)
        self.header_state = header_state
        self.header = bytearray(decrypt(header_state, raw[512:1024], 512))
        if not page_ok(self.header):
            raise PODBError(f"{path}: bad header page CRC (wrong key?)")
        p = self.header[510] + 158                         # key copy (b), the one that decrypts the file
        self.key = bytes(self.header[p + i] ^ FIXED_KEY[66 - i] for i in range(66))
        self.state = key_setup(self.key)
        self.pages = [bytearray(decrypt(self.state, raw[o:o + 512], o)) for o in range(1024, len(raw) - 511, 512)]
        self.bad_pages = [n for n, pg in enumerate(self.pages) if not page_ok(pg)]
        self.dirty = set()
        self.header_dirty = False
        self.log = []                                      # what the writer did (dry-run report)
        self._index_defs = None

    # --- logical bytes
    @property
    def L(self):
        return b"".join(bytes(pg[8:]) for pg in self.pages)

    def read(self, off, n):
        out = bytearray()
        while n > 0:
            pg, o = divmod(off, LPAGE)
            k = min(n, LPAGE - o)
            out += self.pages[pg][8 + o:8 + o + k]
            off, n = off + k, n - k
        return bytes(out)

    def write(self, off, data):
        pos = 0
        while pos < len(data):
            pg, o = divmod(off + pos, LPAGE)
            k = min(len(data) - pos, LPAGE - o)
            self.pages[pg][8 + o:8 + o + k] = data[pos:pos + k]
            self.dirty.add(pg)
            pos += k

    def u16(self, off):
        return struct.unpack("<H", self.read(off, 2))[0]

    def u32(self, off):
        return struct.unpack("<I", self.read(off, 4))[0]

    def page_type(self, n):
        return struct.unpack_from("<H", self.pages[n], 2)[0]

    # --- records
    def record_at(self, off):
        """F001 record and its continuations: a last field 0x28 (Extension_Field) holds the offset
        of another F001 record whose fields continue this one."""
        t, ln = struct.unpack("<HH", self.read(off, 4))
        if t != 0xF001:
            raise PODBError(f"{self.path}: no F001 record at {off:#x}")
        rec_tag, rec_id, flags = struct.unpack("<HII", self.read(off + 4, 10))
        crc_ok = self.u16(off + 4 + ln) == record_crc(self.read(off, 4 + ln))
        chunks, slots, cur = [], [], off
        while True:
            ln = self.u16(cur + 2)
            n = (ln - 10) // 6
            fl = [list(struct.unpack("<HI", self.read(cur + 14 + 6 * i, 6))) for i in range(n)]
            if fl and fl[-1][0] == T_EXTENSION and fl[-1][1]:
                chunks.append((cur, n - 1))
                slots += fl[:-1]
                cur = fl[-1][1]
                continue
            chunks.append((cur, n))
            slots += fl
            break
        return Record(self, off, rec_tag, rec_id, flags, chunks, slots, crc_ok)

    @property
    def root(self):
        return self.record_at(0)

    def data_at(self, off):
        """F007 (word length) / F00F (dword length) data record: the bytes (§2)."""
        if not off:
            return None
        t = self.u16(off)
        if t == 0xF007:
            return self.read(off + 4, self.u16(off + 2))
        if t == 0xF00F:
            return self.read(off + 6, self.u32(off + 2))
        return None

    string_at = data_at

    def write_record(self, r):
        """Rewrite the flags, all slots and the CRC trailer of each chunk."""
        self.write(r.off + 10, struct.pack("<I", r.flags))
        i = 0
        for k, (cur, n) in enumerate(r.chunks):
            for s in range(n):
                self.write(cur + 14 + 6 * s, struct.pack("<HI", *r.slots[i]))
                i += 1
            ln = self.u16(cur + 2)
            self.write(cur + 4 + ln, struct.pack("<H", record_crc(self.read(cur, 4 + ln))))

    # --- File_Root (§2)
    def root_get(self, tag):
        return self.root.get(tag)

    def root_add(self, tag, delta):    # field += delta, written back; returns the new value
        r = self.root
        for s in r.slots:
            if s[0] == tag:
                s[1] = (s[1] + delta) & 0xFFFFFFFF
                self.write_record(r)
                return s[1]
        raise PODBError(f"File_Root has no field {tag:#x}")

    def root_set(self, tag, value):
        r = self.root
        for s in r.slots:
            if s[0] == tag:
                s[1] = value
                self.write_record(r)
                return
        raise PODBError(f"File_Root has no field {tag:#x}")

    def page_count(self):              # max(ceil(R/504), X/504)
        R, X = self.root_get(6), self.root_get(7)
        return max((R + LPAGE - 1) // LPAGE, X // LPAGE)

    def alloc(self, n, kind, internal=False):
        """Space allocator. kind 'field' = F001, 'data' = F007/F00F, 'index'
        = an index page. Returns the logical offset (a page boundary for 'index')."""
        R, X = self.root_get(6), self.root_get(7)
        old_count = self.page_count()
        fresh = False
        if kind == "index":
            if X < R:
                p = R if R % LPAGE == 0 else R + LPAGE - R % LPAGE
            else:
                p = X
            self.root_set(7, p + n)                        # Next_Index_Offset
        else:
            r = R % LPAGE
            p = R
            if kind == "field":
                if X > R:
                    if not r or r + n > LPAGE:
                        fresh = True
                        p = (LPAGE - 14) % 6 + X
                elif r + n - 2 > LPAGE:
                    left = LPAGE - r
                    if left < 14:
                        p += left
                        r = 0
                    if r + n - 2 > LPAGE:
                        p += (LPAGE - r - 14) % 6
                        if not r:
                            fresh = True
            elif kind == "data":
                if r:
                    if r + n > LPAGE and X > R:
                        p = X
                elif X > R:
                    p = X
            else:
                raise ValueError(kind)
            self.root_set(6, p + n)                        # Next_Record_Offset
        if kind != "index" and p % LPAGE and not fresh and p // LPAGE < old_count:
            o = p % LPAGE                                  # zero the slot
            k = n if o + n <= LPAGE else LPAGE - o
            self.write(p, bytes(k))
        new_count = self.page_count()
        page0_dw4 = struct.unpack_from("<I", self.pages[0], 4)[0]
        for pg in range(old_count, new_count):             # new pages
            buf = bytearray(PAGE)
            typ = 1 if kind != "index" else (2 if internal else 6)
            struct.pack_into("<HI", buf, 2, typ, page0_dw4)
            if pg < len(self.pages):
                self.pages[pg] = buf
            else:
                while len(self.pages) < pg:
                    raise PODBError("page gap")
                self.pages.append(buf)
            self.dirty.add(pg)
        return p

    def new_record(self, tag, nslots, flags=F_NEW):
        """id = ++File_Root.ID_Count, size 6n+16, flags 2 (new)."""
        nslots = max(nslots, 2)
        rid = self.root_add(2, 1)
        off = self.alloc(6 * nslots + 16, "field")
        self.write(off, struct.pack("<HHHII", 0xF001, 6 * nslots + 10, tag, rid, flags) + bytes(6 * nslots + 2))
        r = Record(self, off, tag, rid, flags, [(off, nslots)], [[0, 0] for _ in range(nslots)], True)
        self.write_record(r)
        self.log.append(("new", tag, rid, off))
        return r

    def new_data(self, data, long=False):
        """F007 (len word) or F00F (len dword), padded to even, CRC."""
        hdr = struct.pack("<HI", 0xF00F, len(data)) if long else struct.pack("<HH", 0xF007, len(data))
        body = hdr + data + (b"\0" if len(data) & 1 else b"")
        off = self.alloc(len(body) + 2, "data")
        self.write(off, body + struct.pack("<H", record_crc(body)))
        return off

    def find_record(self, rid):
        idx = self.index(ID_INDEX)
        for key, i, off in self.btree_entries(idx):
            if i == rid:
                return self.record_at(off)
        return None

    # --- indexes (§4)
    def index_root(self):
        return self.record_at(self.root_get(0x3C))

    def indexes(self):
        """Index_Root (record at File_Root field 0x3C): {index id: [root page, entry count]}."""
        out, cur = {}, None
        for tag, v in self.index_root().slots:
            if tag == 0x3D:
                cur = v
            elif tag == 0x3E and cur is not None:
                out[cur] = [v, 0]
            elif tag == 0x3F and cur in out:
                out[cur][1] = v
        return out

    def _index_root_set(self, iid, tag, value=None, delta=None):
        r = self.index_root()
        cur = None
        for s in r.slots:
            if s[0] == 0x3D:
                cur = s[1]
            elif s[0] == tag and cur == iid:
                s[1] = value if delta is None else (s[1] + delta) & 0xFFFFFFFF
                self.write_record(r)
                return
        raise PODBError(f"Index_Root has no index {iid:#x} (33497)")

    def index_defs(self):
        if self._index_defs is None:
            order = list(self.indexes())
            defs = {}
            for r in self._all_records():
                if r.tag == T_UNIV_INDEX and not r.flags & F_DELETED:
                    defs[r.id] = IndexDef(self, r)
            self._index_defs = [defs[i] for i in order if i in defs]
        return self._index_defs

    def index(self, iid):
        for d in self.index_defs():
            if d.id == iid:
                return d
        raise PODBError(f"no index {iid:#x}")

    def _all_records(self):
        """F001 records found by walking ID_INDEX directly (bootstrap, keys are plain dwords)."""
        root = self.indexes()[ID_INDEX][0]
        out = []

        def walk(pg):
            page = self.pages[pg]
            typ, n = struct.unpack_from("<HH", page, 2)[0], struct.unpack_from("<H", page, 8)[0]
            for k in range(n):
                if typ & 4:
                    rid, off = struct.unpack_from("<II", page, 10 + 12 * k + 4)
                    if rid:
                        out.append(self.record_at(off))
                else:
                    walk(struct.unpack_from("<I", page, 10 + 8 * k + 4)[0])
        if root:
            walk(root)
        return out

    def live_records(self):
        """All records listed in ID_INDEX, deleted ones skipped (flag bit 0)."""
        return [r for r in self._all_records() if not r.flags & F_DELETED]

    def node(self, pg, d):
        page = self.pages[pg]
        typ, n = struct.unpack_from("<H", page, 2)[0], struct.unpack_from("<H", page, 8)[0]
        leaf = bool(typ & 4)
        esz = d.klen + (8 if leaf else 4)
        ents = []
        for k in range(n):
            e = bytes(page[10 + esz * k:10 + esz * (k + 1)])
            if leaf:
                ents.append((e[:d.klen], *struct.unpack_from("<II", e, d.klen)))
            else:
                ents.append((e[:d.klen], struct.unpack_from("<I", e, d.klen)[0]))
        return leaf, ents

    def put_node(self, pg, d, leaf, ents):
        page = self.pages[pg]
        esz = d.klen + (8 if leaf else 4)
        if esz * len(ents) > LPAGE - 2:
            raise PODBError("node overflow")
        body = b"".join(e[0] + (struct.pack("<II", e[1], e[2]) if leaf else struct.pack("<I", e[1])) for e in ents)
        page[8:] = struct.pack("<H", len(ents)) + body + bytes(LPAGE - 2 - len(body))
        self.dirty.add(pg)

    def btree_entries(self, d, pg=None):
        """(key, rec_id, offset) of every leaf entry in order, sentinel excluded."""
        if pg is None:
            pg = self.indexes()[d.id][0]
            if not pg:
                return
        leaf, ents = self.node(pg, d)
        for e in ents:
            if leaf:
                if not (e[1] == 0 and e[2] == 0xFFFFFFFF):
                    yield e
            else:
                yield from self.btree_entries(d, e[1])

    def btree(self, root_page, key_len):   # reader API kept from tools/ccpodb.py
        class _D:
            klen = key_len
        if not root_page:
            return
        leaf, ents = self.node(root_page, _D)
        for e in ents:
            if leaf:
                if e[0] != b"\xff" * key_len:
                    yield e
            else:
                yield from self.btree(e[1], key_len)


class IndexPart:
    def __init__(self):
        self.field, self.flags, self.dtype, self.length = 0, 0, 0, 0
        self.alt_field, self.alt_dtype = 0, 0


def _dtype_class(t):
    """Index part class of a data type (class -> type:
    1 -> ULong, 2 -> Charstr, 3 -> Binstr, 4 -> Comp_Unicode, 5 -> Unicode)."""
    if t in (3, 4, 5, 6, 7, 8):
        return 1
    return {0xC: 2, 0xD: 2, 0xE: 3, 0xF: 3, 0x12: 4, 0x13: 4, 0x10: 5, 0x11: 5}.get(t) or \
        (_ for _ in ()).throw(PODBError(f"index part data type {t:#x} not supported"))


class IndexDef:
    """Univ_Index record (§4): fields 0x47 name, 0x48 container, 0x4A record tags, 0x49 Idx_Values,
    then per part 0x4B field, 0x4D flags, 0x8D type, 0x8E length, 0x4C alt field, 0x4E alt type."""

    def __init__(self, f, r):
        self.file, self.id, self.flags = f, r.id, r.flags
        self.name = r.str(0x47)
        self.container = r.get(0x48)
        self.records = r.all(0x4A)
        self.values = r.get(0x49)
        self.parts = []
        for t, v in r.slots:
            if t == 0x4B:
                p = IndexPart()
                p.field = v
                self.parts.append(p)
            elif self.parts:
                p = self.parts[-1]
                if t == 0x4D:
                    p.flags = v
                elif t == 0x8D:
                    p.dtype = v
                elif t == 0x8E:
                    p.length = v
                elif t == 0x4C:
                    p.alt_field = v
                elif t == 0x4E:
                    p.alt_dtype = v
        for p in self.parts:
            p.cls = 1 if p.flags & 0x10 else _dtype_class(p.dtype)
            p.alt_cls = _dtype_class(p.alt_dtype) if p.flags & 8 else 0
            p.klen = 4 if p.cls == 1 else p.length
        self.klen = sum(p.klen for p in self.parts)
        self.dup = bool(self.flags & 0x800)                 # Duplicate_Keys

    def __repr__(self):
        return f"<Index {self.id:#x} {self.name}>"


# ---------------------------------------------------------------- index engine
class Indexer:
    """Keys, comparison and B-tree changes for one file, in the order the format requires."""

    def __init__(self, f, intl, po_cp=437):
        self.f, self.intl, self.cp = f, intl, po_cp

    # --- the values of a record for an index; None = not in this index (error 33490)
    def values(self, d, r):
        out = []
        for p in d.parts:
            if p.field == 3:
                out.append(r.id)
                continue
            use_alt = False
            if not r.has(p.field):
                if not p.flags & 8:
                    return None
                if not r.has(p.alt_field):
                    return None
                use_alt = True
            v = r.get(p.alt_field if use_alt else p.field)
            cls = p.alt_cls if use_alt else p.cls
            if p.flags & 0x10:                              # hash
                data = self.f.data_at(v) if v else None
                if not data:
                    return None
                out.append(self.hash(data))
                continue
            if cls == 1:
                out.append(v)
                continue
            data = self.f.data_at(v) if v else None
            if not data:
                return None
            if use_alt:                                     # Charstr -> Unicode (1200)
                if not (p.alt_cls == 2 and p.cls in (4, 5)):
                    raise PODBError("alternate field combination 33480")
                data = self.intl.to_unicode(data, self.cp)
            elif cls == 4:
                raise PODBError("Comp_Unicode key fields not supported")
            out.append(data)
        return out

    def hash(self, data):              # rotation, NormalizeHashStr, CRC-32 register
        z = data.find(b"\0")
        if 0 <= z < len(data) - 1:
            n = z + 1
            data = data[n:n + len(data) - n - 1] + b" " + data[:n]
        return crc32_reg(self.intl.normalize_hash(data, self.cp))

    def condition(self, d, r):         # Idx_Values program (§10)
        if not d.values:
            return True
        prog = self.f.read(d.values, 4 + self.f.u16(d.values + 2))
        return run_idx_values(prog, r)

    def key(self, d, vals):
        out = b""
        for p, v in zip(d.parts, vals):
            if p.cls == 1:
                out += struct.pack("<I", v & 0xFFFFFFFF)
                continue
            L, n = p.length, len(v)
            if p.cls == 2 and n == L and v[L - 1] == 0:
                n -= 1
            elif p.cls in (4, 5):
                m = L if L & 1 else L - 1
                if m + 1 == n and v[m - 1:m + 1] == b"\0\0":
                    n -= 2
            if n < L:
                out += bytes([n]) + v[:n] + bytes(L - n - 1)
            else:
                k = L - 1
                if p.flags & 4:
                    k = self.intl.split_len(self.cp if p.cls == 2 else 1200, k)
                out += bytes([k | 0x80]) + v[:k] + bytes(L - k - 1)
        return out

    def sentinel(self, d):             # highest key for ascending parts, zeros for descending
        out = b""
        for p in d.parts:
            if p.flags & 1:
                if p.cls == 1:
                    out += b"\xff" * 4
                else:
                    fill = self.intl.highest_char(self.cp if p.cls == 2 else 1200, 2) if p.flags & 4 else 0xFF
                    out += bytes([p.length - 1]) + bytes([fill]) * (p.length - 1)
            else:
                out += bytes(p.klen)
        return out

    # --- search values vs a stored key; >0 = search is greater
    def compare(self, d, vals, key, entry_off=None):
        pos = 0
        for i, p in enumerate(d.parts):
            kb = key[pos:pos + p.klen]
            pos += p.klen
            if p.cls == 1:
                s, e = vals[i] & 0xFFFFFFFF, struct.unpack("<I", kb)[0]
                r = 1 if s > e else -1 if s < e else 0
            else:
                n, trunc = kb[0] & 0x7F, kb[0] & 0x80
                r = self._cmp_str(p, vals[i], kb[1:1 + n], 0x30 if trunc else 0)
                if trunc and r == 0 and entry_off is not None:
                    full = self.values(d, self.f.record_at(entry_off))   # truncated: compare the full value
                    r = self._cmp_str(p, vals[i], full[i], 0)
            if not p.flags & 1:
                r = -r
            if r:
                return r
        return 0

    def _cmp_str(self, p, a, b, flags):
        if p.flags & 4:
            cp = self.cp if p.cls == 2 else 1200
            return self.intl.strcmp(a, b, cp, flags | (2 if self.intl.sort_flag else 0))
        n = min(len(a), len(b))
        r = (a[:n] > b[:n]) - (a[:n] < b[:n])
        if not flags & 0x30 and r == 0:
            if len(b) < len(a) and any(a[n:]):
                return 1
            if len(a) < len(b) and any(b[n:]):
                return -1
        return r

    # --- tree walking
    def _descend(self, d, vals, root):
        """Per level the first entry with search <= key (else the last)."""
        path, pg = [], root
        while True:
            leaf, ents = self.f.node(pg, d)
            pos = len(ents) - 1
            for k, e in enumerate(ents):
                if self.compare(d, vals, e[0], e[2] if leaf else None) <= 0:
                    pos = k
                    break
            path.append([pg, pos])
            if leaf:
                return path
            pg = ents[pos][1]

    def _advance(self, d, path):       # next leaf entry, across leaves
        lvl = len(path) - 1
        while lvl >= 0:
            pg, pos = path[lvl]
            _, ents = self.f.node(pg, d)
            if pos + 1 < len(ents):
                path[lvl][1] = pos + 1
                break
            lvl -= 1
        else:
            raise PODBError("B-tree walk past the sentinel")
        for k in range(lvl + 1, len(path)):
            pg, pos = path[k - 1]
            leaf, ents = self.f.node(pg, d)
            path[k] = [ents[pos][1], 0]

    def _entry(self, d, path):
        pg, pos = path[-1]
        return self.f.node(pg, d)[1][pos]

    def find_insert(self, d, vals, rec_id):
        """Position for an insert: lower bound, then (Duplicate_Keys) equal keys ordered by record id."""
        root = self.f.indexes()[d.id][0]
        path = self._descend(d, vals, root)
        while True:
            key, eid, eoff = self._entry(d, path)
            if eid == 0:                                    # sentinel
                return path
            r = self.compare(d, vals, key, eoff)
            if r > 0:
                self._advance(d, path)
                continue
            if d.dup:
                if r != 0 or rec_id < eid:
                    return path
                if rec_id == eid:
                    raise PODBError(f"record {rec_id:#x} already in index {d.name}")
                self._advance(d, path)
                continue
            if r == 0:
                raise PODBError(f"duplicate key in {d.name} (33482)")
            return path

    def find_entry(self, d, vals, rec_id):
        root = self.f.indexes()[d.id][0]
        if not root:
            return None
        path = self._descend(d, vals, root)
        while True:
            key, eid, eoff = self._entry(d, path)
            if eid == 0:
                return None
            r = self.compare(d, vals, key, eoff)
            if r < 0:
                return None
            if r == 0 and eid == rec_id:
                return path
            self._advance(d, path)

    def insert(self, d, r):
        vals = self.values(d, r)
        if vals is None:
            return False
        if not self.indexes_root(d):
            self._first_insert(d)
        path = self.find_insert(d, vals, r.id)
        entry = (self.key(d, vals), r.id, r.off)
        self._node_insert(d, path, len(path) - 1, entry)
        self.f._index_root_set(d.id, 0x3F, delta=1)         # entry count + 1
        self.f.log.append(("index+", d.name, r.id))
        return True

    def indexes_root(self, d):
        return self.f.indexes()[d.id][0]

    def _new_index_page(self, d, internal):   # page header dword +4 = index id
        off = self.f.alloc(LPAGE, "index", internal)
        pg = off // LPAGE
        struct.pack_into("<I", self.f.pages[pg], 4, d.id)
        self.f.dirty.add(pg)
        return pg

    def _first_insert(self, d):        # leaf with the sentinel, then the internal root
        s = self.sentinel(d)
        leaf = self._new_index_page(d, False)
        self.f.put_node(leaf, d, True, [(s, 0, 0xFFFFFFFF)])
        root = self._new_index_page(d, True)
        self.f.put_node(root, d, False, [(s, leaf)])
        self.f._index_root_set(d.id, 0x3E, value=root)    # root page

    def _node_insert(self, d, path, lvl, entry):
        pg, pos = path[lvl]
        leaf, ents = self.f.node(pg, d)
        esz = d.klen + (8 if leaf else 4)
        if esz * (len(ents) + 1) > 0x1F6:                    # node full
            return self._split(d, path, lvl, entry)
        ents.insert(pos, entry)
        self.f.put_node(pg, d, leaf, ents)

    def _split(self, d, path, lvl, entry):             # split into two new pages
        if len(path) >= 10:
            raise PODBError("B-tree depth 10 (33494)")
        pg, p = path[lvl]
        leaf, ents = self.f.node(pg, d)
        n = len(ents)
        left_pg = self._new_index_page(d, not leaf)
        right_pg = self._new_index_page(d, not leaf)
        rn = 1 if p == n - 1 else n >> 1
        ln_ = n - rn
        left, right = ents[:ln_], ents[ln_:]
        if ln_ <= p:
            right.insert(p - ln_, entry)
        else:
            left.insert(p, entry)
        self.f.put_node(left_pg, d, leaf, left)
        self.f.put_node(right_pg, d, leaf, right)
        lk, rk = left[-1][0], right[-1][0]
        self.f.log.append(("split", d.name, pg, left_pg, right_pg))
        if lvl == 0:                                        # root: 2-entry internal node in place
            self.f.put_node(pg, d, False, [(lk, left_pg), (rk, right_pg)])
            return
        ppg, ppos = path[lvl - 1]
        pleaf, pents = self.f.node(ppg, d)
        pents[ppos] = (rk, right_pg)
        self.f.put_node(ppg, d, False, pents)
        self.f.root_add(0x0F, 512)                          # old page -> Deleted_Space
        self._node_insert(d, path, lvl - 1, (lk, left_pg))

    def delete(self, d, r, vals=None):
        vals = self.values(d, r) if vals is None else vals
        if vals is None:
            return False
        path = self.find_entry(d, vals, r.id)
        if path is None:
            raise PODBError(f"record {r.id:#x} not found in {d.name}")
        self._node_delete(d, path, len(path) - 1)
        self.f._index_root_set(d.id, 0x3F, delta=-1)
        self.f.log.append(("index-", d.name, r.id))
        return True

    def _node_delete(self, d, path, lvl):
        pg, pos = path[lvl]
        leaf, ents = self.f.node(pg, d)
        del ents[pos]
        # the entries after pos move down by one (memcpy); the last entry's old bytes
        # stay behind the new end (not cleared), count -1
        esz = d.klen + (8 if leaf else 4)
        page = self.f.pages[pg]
        a = 10 + esz * pos
        b = 10 + esz * (len(ents) + 1)
        page[a:b - esz] = page[a + esz:b]
        struct.pack_into("<H", page, 8, len(ents))
        self.f.dirty.add(pg)
        if ents or lvl == 0:
            return
        self.f.root_add(0x0F, 512)                          # empty page -> Deleted_Space
        self._node_delete(d, path, lvl - 1)

    # --- record level (commit, update, delete)
    def covers(self, d, tag):
        return d.id == ID_INDEX or (tag in d.records and d.id != TRANSACTION_INDEX)

    def commit_new(self, r):           # commit of a new record
        r.flags &= ~(F_NEW | F_CHANGED)
        self.f.write_record(r)
        for d in self.f.index_defs():
            if not self.covers(d, r.tag) or len(d.parts) >= 10:
                continue
            if d.id != ID_INDEX and not self.condition(d, r):
                continue
            self.insert(d, r)

    def update(self, r, changes):
        """Update of an existing record: set fields (an absent field takes a free slot, tag 0),
        re-key the indexes whose key changed, flag 4 when an index changed."""
        before = {}
        if not r.flags & F_NEW:
            for d in self.f.index_defs():
                if d.id in (ID_INDEX, TRANSACTION_INDEX) or r.tag not in d.records:
                    continue
                before[d.id] = (self.values(d, r) if self.condition(d, r) else None)
        for tag, value in changes:
            for s in r.slots:
                if s[0] == tag:
                    s[1] = value
                    break
            else:
                for s in r.slots:
                    if s[0] == 0:
                        s[0], s[1] = tag, value
                        break
                else:
                    raise PODBError(f"record {r.id:#x}: no free slot for field {tag:#x} "
                                    "(an Extension_Field continuation would be needed)")
        changed = False
        for d in self.f.index_defs():
            if d.id not in before:
                continue
            new = self.values(d, r) if self.condition(d, r) else None
            if new != before[d.id]:
                if before[d.id] is not None:
                    self.delete(d, r, before[d.id])
                if new is not None:
                    self.insert(d, r)
                changed = True
        if changed:
            r.flags |= F_CHANGED
        self.f.write_record(r)
        return r

    def delete_record(self, r):
        r.flags |= F_DELETED
        self.f.write_record(r)
        self.f.root_add(0x0F, 6 * r.nslots() + 16)         # record size -> Deleted_Space
        for d in self.f.index_defs():
            if d.id in (ID_INDEX, TRANSACTION_INDEX) or r.tag not in d.records:
                continue
            if self.condition(d, r):
                self.delete(d, r)


def run_idx_values(prog, r):
    """Idx_Values bytecode, a stack of (value, valid). Program = F007 data record."""
    if struct.unpack_from("<H", prog, 0)[0] != 0xF007:
        raise PODBError("Idx_Values is not an F007 record")
    end = 4 + (struct.unpack_from("<H", prog, 2)[0] & ~1)
    pc, st = 4, []
    cmp_ops = {0x10A: lambda a, b: a < b, 0x10B: lambda a, b: a <= b, 0x10C: lambda a, b: a > b,
               0x10D: lambda a, b: a >= b, 0x10E: lambda a, b: a == b, 0x10F: lambda a, b: a != b,
               0x113: lambda a, b: bool(a and b), 0x114: lambda a, b: bool(a or b)}
    while pc < end:
        op = struct.unpack_from("<H", prog, pc)[0]
        if op in cmp_ops:                                   # invalid operand -> 0, valid
            (b, vb), (a, va) = st.pop(), st.pop()
            st.append((int(cmp_ops[op](a, b)), 1) if va and vb else (0, 1))
        elif op in (0x110, 0x112):
            (b, vb), (a, va) = st.pop(), st.pop()
            st.append(((a & b) if op == 0x110 else (a | b), int(bool(va and vb))))
        elif op == 0x101:
            a, va = st.pop()
            st.append((0 if a else 1, 1) if va else (0, 1))
        elif op == 0x115:
            st.append((struct.unpack_from("<I", prog, pc + 2)[0], 1))
            pc += 4
        elif op == 0x116:
            tag = struct.unpack_from("<H", prog, pc + 2)[0]
            st.append((r.get(tag), 1) if r.has(tag) else (0, 0))
            pc += 2
        elif op == 0x117:
            st.append((r.tag, 1))
        elif op == 0x118:
            st.append((r.flags, 1))
        else:
            raise PODBError(f"Idx_Values opcode {op:#x} (33404)")
        pc += 2
    return bool(st[0][0]) if st else True


# ---------------------------------------------------------------- post office (reader)
class PostOffice:
    def __init__(self, po_dir):
        self.dir = po_dir
        fixed = mode2(FIXED_KEY)
        self.dd = DBFile(find_file(po_dir, "CCPODD"), fixed, po=self)
        self.s_dd = self.dd.state                          # kept for U headers and CCPOMS
        self.ds = DBFile(find_file(po_dir, "CCPODS"), fixed, po=self)
        self.mi = DBFile(find_file(po_dir, "CCPOMI"), fixed, po=self)
        self.fields, self.values = {}, {}
        for r in self.dd.live_records():
            if r.tag == 0x8C:                              # Record_Defn
                self.fields[r.get(0x68)] = (r.str(0x8F), r.get(0x8D), r.get(0x8E))
            elif r.tag == 0xA0:                            # Value_Defn
                self.values.setdefault(r.get(0x68), {})[r.get(0xA1)] = r.str(0x8F)
        self._ms = {}
        self._intl = None

    @property
    def intl(self):
        """DB code page/language from the CCPODD header."""
        if self._intl is None:
            h = self.dd.header
            cp, lang, flag = 437, b"en", 0
            if struct.unpack_from("<H", h, 28)[0] == 0xED and struct.unpack_from("<H", h, 34)[0] == 0xEF:
                cp, lang, flag = struct.unpack_from("<H", h, 30)[0], bytes(h[36:38]), h[19] & 0x10
            path = find_file(self.dir, "CCINTL.TB")
            if not path:
                raise PODBError("CCINTL.TB missing (needed for keys and passwords)")
            self._intl = Intl(path, cp, lang, flag)
        return self._intl

    def name(self, tag):
        return self.fields.get(tag, (f"tag{tag:x}",))[0]

    def flag_names(self, rec_tag, flags):
        names = [n for v, n in sorted(self.values.get(rec_tag, {}).items()) if v and flags & v == v]
        if flags & 1:
            names.append("DELETED")
        if flags & 2:
            names.append("UNCOMMITTED")
        return names

    def mailbox_file(self, fid):
        path = find_file(self.dir, file_name(fid)[:-3])
        return DBFile(path, mode2(self.s_dd), po=self) if path else None

    def directory(self):
        out = []
        for r in self.ds.live_records():
            if r.tag != T_DIR_ENTRY:
                continue
            out.append(dict(id=r.id, name=r.str(0xD7), type=self.values.get(0xD8, {}).get(r.get(0xD8), r.get(0xD8)),
                            dir_type=r.get(0xD8), comments=r.str(0xD9), address=r.str(0xDD), mailbox=r.get(0xCA),
                            home_post=r.get(0xD5), flags=self.flag_names(0xD2, r.flags), raw_flags=r.flags))
        return out

    def ms_pages(self, po_file_number):
        """CCPOMS data: key = S_dd itself with mode byte 2, no header read; pages
        carry no CRC."""
        if po_file_number not in self._ms:
            num = po_file_number & 0xFF                    # assumption: CCPOMS.0n = Message_File 0x190+n
            path = find_file(self.dir, f"CCPOMS.{num:02d}")
            raw = _read(path)
            st = ms_state(self.s_dd)
            self._ms[po_file_number] = [decrypt(st, raw[o:o + 512], o) for o in range(1024, len(raw) - 511, 512)]
        return self._ms[po_file_number]

    def message_index(self):
        return {r.get(0x12E): r for r in self.mi.live_records() if r.tag == T_MESSAGE_INDEX}

    def read_message(self, mi):
        """Message_Index -> CCPOMS: 6-byte prefix (word, dword offset), then the message file
        with [0,32), [32,part1), [addr_off,total) transposed (same as on the wire)."""
        pages = self.ms_pages(mi.get(0x66))
        off, ln, num = mi.get(0x141), mi.get(0x142), mi.get(0x12E)
        first = off // LPAGE
        data = b""
        for n in range(first, (off + ln + LPAGE - 1) // LPAGE):
            pg = pages[n]
            if struct.unpack_from("<I", pg, 4)[0] != num:  # page header dword = Message_Number
                raise PODBError(f"message {num}: page {n} belongs to {struct.unpack_from('<I', pg, 4)[0]}")
            data += pg[8:]
        s = data[off - first * LPAGE:off - first * LPAGE + ln]
        tag, start = struct.unpack_from("<HI", s, 0)
        r = s[6:]
        fixed = untranspose(r[:32])
        total, addr_off, part1 = struct.unpack_from("<IIH", fixed, 0)
        part1_rec = fixed + untranspose(r[32:part1])
        return Message(part1_rec + untranspose(r[addr_off:total]), r[part1:addr_off]), (tag, start)

    def mailbox_password(self, mb):
        root = next(r for r in mb.live_records() if r.tag == T_MAILBOX_ROOT)
        return decode_password(mb.data_at(root.get(0x191, 0)))

    def check_password(self, user, password):
        """Login check (§10): unmask header key copy (a) with enc_pw and test
        the CRC of page 0 with setup(K)."""
        e = self.entry(user)
        mb = self.mailbox_file(e["mailbox"])
        k = bytearray(mb.header[62:128])
        if struct.unpack_from("<I", mb.header, 0x12)[0] & 0x100:
            mask, _ = encode_password(self.intl, password)
            for i, b in enumerate(mask):
                k[2 + i] ^= b
        raw = _read(mb.path)[:PAGE * 3]
        return page_ok(decrypt(key_setup(k), raw[1024:1536], 1024))

    def entry(self, name):
        want = name.lower()
        for e in self.directory():
            if e["name"] and e["name"].lower() == want:
                return e
        raise PODBError(f"no directory entry {name!r}")


def ms_state(s_dd):                    # CCPOMS key: S_dd copied as is, S[0] = 2
    st = bytearray(s_dd)
    st[0] = 2
    return st


# ---------------------------------------------------------------- locking and transactions (§8)
LOCK_RETRY, LOCK_TIMEOUT = 0.2, 60.0   # every 200 ms for 60 s, then error 33300


class Txn:
    """One locked change of one file: exclusive fcntl byte-range lock on bytes 0..511 (the region
    DOS/Windows programs lock with LockFileEx), fresh read, changes, commit = dirty pages, page 0 last,
    fsync, unlock. Linux fcntl locks are not LockFileEx locks: a DOS/Windows program on another
    machine (Samba, DOSBox mount) may not see them (§8, UNKNOWN). dry=True: nothing is written."""

    def __init__(self, path, header_state, dry=False, po=None, cache=None):
        self.path, self.hs, self.dry, self.po, self.cache = path, header_state, dry, po, cache
        self.fd = None

    def __enter__(self):
        if self.dry:
            if self.path not in self.cache:
                self.cache[self.path] = DBFile(self.path, self.hs, po=self.po)
            self.f = self.cache[self.path]
            return self.f
        self.fd = os.open(self.path, os.O_RDWR)
        deadline = _time.monotonic() + LOCK_TIMEOUT
        while True:
            try:
                fcntl.lockf(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB, PAGE, 0, os.SEEK_SET)
                break
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EAGAIN) or _time.monotonic() > deadline:
                    os.close(self.fd)
                    raise PODBError(f"{self.path}: cannot lock (33300)")
                _time.sleep(LOCK_RETRY)
        size = os.fstat(self.fd).st_size
        raw = os.pread(self.fd, size, 0)
        self.f = DBFile(self.path, self.hs, raw=raw, po=self.po)
        return self.f

    def __exit__(self, et, ev, tb):
        try:
            if et is None:
                self.commit()
        finally:
            if self.fd is not None:
                try:
                    fcntl.lockf(self.fd, fcntl.LOCK_UN, PAGE, 0, os.SEEK_SET)
                finally:
                    os.close(self.fd)
        return False

    def commit(self):
        f = self.f
        if self.cache is not None:
            self.cache.setdefault("_report", []).append((os.path.basename(self.path), sorted(f.dirty), list(f.log)))
        if self.dry:
            f.log = []
            return
        if f.header_dirty:
            set_page_crc(f.header)
            os.pwrite(self.fd, encrypt(f.header_state, bytes(f.header), PAGE), PAGE)
        for pg in sorted(f.dirty - {0}) + ([0] if 0 in f.dirty else []):
            set_page_crc(f.pages[pg])
            off = (pg + 2) * PAGE
            os.pwrite(self.fd, encrypt(f.state, bytes(f.pages[pg]), off), off)
        os.fsync(self.fd)
        f.dirty.clear()
        f.log = []


class Writer:
    """Changes to a post office. dry=True keeps every change in memory and reports it."""

    def __init__(self, po_dir, dry=False):
        if find_file(po_dir, "CCPODOWN"):
            raise PODBError("CCPODOWN present: the post office is shut down (33463)")
        self.dir, self.dry = po_dir, dry
        self.po = PostOffice(po_dir)
        self.cache = {}
        self.ms_writes = []

    def report(self):
        return self.cache.get("_report", [])

    def txn(self, path, header_state):
        return Txn(path, header_state, self.dry, self.po, self.cache)

    def fixed(self, base):
        return self.txn(find_file(self.dir, base), mode2(FIXED_KEY))

    def mbox(self, fid):
        path = find_file(self.dir, file_name(fid)[:-3])
        if not path:
            raise PODBError(f"mailbox file {file_name(fid)} missing")
        return self.txn(path, mode2(self.po.s_dd))

    def ix(self, f):
        return Indexer(f, self.po.intl, self.po.intl.cp)

    def _ds_read(self):
        if self.dry and find_file(self.dir, "CCPODS") in self.cache:
            return self.cache[find_file(self.dir, "CCPODS")]
        return DBFile(find_file(self.dir, "CCPODS"), mode2(FIXED_KEY), po=self.po)

    def _lookup(self, ds, name):
        want = name.lower()
        for r in ds.live_records():
            if r.tag == T_DIR_ENTRY and (r.str(0xD7) or "").lower() == want:
                return r
        return None

    def _name_eq(self, a, b, n):
        """Collating compare over n bytes of each, flags 4 (+2 with the sort
        flag, 0 in the samples), PO code page."""
        if n <= 0:
            return False
        flags = 4 | (2 if self.po.intl.sort_flag else 0)
        return self.po.intl.strcmp(bytes(a[:n]), bytes(b[:n]), self.po.intl.cp, flags) == 0

    def _author_is(self, ds, msg, e):
        """Author check (DB8): is the message's author the Dir_Entry e?
        Author = the last 02 item, else the first 01 item (both from offset 32 of the
        header record). "Administrator" never matches. The item's length byte
        must equal the Dir_Name length (stored bytes with the NUL, plus a
        leading '#' for types 4/5), then the names are compared, also with the halves of a
        'Last\\0First' name swapped."""
        tl = msg.tlvs
        item = None
        for t, d in tl:
            if t == 0x02:
                item = d
        if item is None:
            item = next((d for t, d in tl if t == 0x01), None)
        if item is None:
            return False
        text = item.split(b"\0", 1)[0]
        adm = b"Administrator"
        if self.po.intl.strcmp(text + b"\0", adm + b"\0", self.po.intl.cp,
                               4 | (2 if self.po.intl.sort_flag else 0)) == 0:
            return False
        name = ds.data_at(e.get(0xD7))
        if e.get(0xD8) in (4, 5):
            name = b"#" + name
        n = len(item)
        if n != len(name):
            return False
        a1, a2 = item, name
        if self._name_eq(a1, a2, n):
            return True
        k = len(a2.split(b"\0", 1)[0]) + 1                 # strlen(a2) + 1
        if k < n and self._name_eq(a1[n - k:], a2, k) and self._name_eq(a1, a2[k:], n - k - 1):
            return True
        k = len(a1.split(b"\0", 1)[0]) + 1                 # strlen(a1) + 1
        if k < n and self._name_eq(a2[n - k:], a1, k) and self._name_eq(a2, a1[k:], n - k - 1):
            return True
        return False

    @staticmethod
    def _dir_attr_remote(e, local_po):
        """The entry counts as remote when Home_Post_ID (213) is not the local PO, or record flag 0x200
        (field 199), or Aliased_Entry_ID (212) present, or Dir_Type 2 (|= 3)."""
        return (e.get(0xD5) != local_po or bool(e.flags & 0x200) or e.get(0xD4) is not None
                or e.get(0xD8) == 2)

    # ------------------------------------------------------------ deliver (§12.1)
    def deliver(self, message: Message, recipients, flags=0, add_univ_tag=False):
        """Store `message` once and put a Message_Pointer into each recipient's Inbox.
        Returns the Message_Number. flags = Message_Pointer flags (0 = new/unread)."""
        po = self.po
        ds = self._ds_read()
        rcpt = []
        for name in recipients:
            e = self._lookup(ds, name)
            if e is None or not e.get(0xCA):
                raise PODBError(f"{name!r}: no local mailbox")
            if e.get(0xD8) not in (1, 2):
                raise PODBError(f"{name!r}: Dir_Type {e.get(0xD8)} (bulletin boards need the "
                                "Shared_Folder_Entry update, not implemented)")
            rcpt.append(e)
        if not rcpt:
            raise PODBError("no recipients")

        # copies 0 -> 1; tag 0x22 gives Univ_Post_ID / Univ_Object_ID
        rec = bytearray(message.record)
        if struct.unpack_from("<H", rec, 12)[0] == 0:
            struct.pack_into("<H", rec, 12, 1)
        msg = Message(bytes(rec), message.body)
        if any(t == 0x32 for t, d in msg.tlvs):
            # with a tag 0x32 the post office takes Message_Seen and the folder from it
            # (folder id or a UNIV_OBJECT lookup) instead of the author rule; not ported
            raise PODBError("message has tag 0x32 (folder placement not implemented)")
        tag22 = next((d for t, d in msg.tlvs if t == 0x22 and len(d) == 8), None)
        upid, uoid = struct.unpack("<II", tag22) if tag22 else (0, 0)
        if tag22 is None and add_univ_tag:                 # append an empty tag 0x22
            addr = msg.record[msg.part1_len:] + b"\x22\x08" + bytes(8)
            p1 = bytearray(msg.record[:msg.part1_len])
            struct.pack_into("<I", p1, 0, msg.total + 10)
            msg = Message(bytes(p1) + addr, msg.body)
        total = msg.total
        need = -(-(total + 8) // LPAGE) * LPAGE           # whole 504-byte units

        # 1. CCPOMI: space, Message_Count, Message_Index
        with self.fixed("CCPOMI") as mi:
            ix = self.ix(mi)
            offset = self._ms_space(mi, ix, need)
            mir = mi.find_record(0x28)
            number = mir.get(0x12D) + 1
            ix.update(mir, [(0x12D, number)])
            if not upid:
                upid = mir.get(0x131)                      # Msg_Index_Root field 305
            date, tim = now_date_time()
            n = len(rcpt)
            r = mi.new_record(T_MESSAGE_INDEX, 9 + n + n)  # 9 fixed slots + 2 per recipient
            if not uoid:
                uoid = univ_object_id(tim, date, r.id, KIND_MI)
            vals = [(0x12E, number), (0x66, KIND_MS), (0x141, offset), (0x142, need), (0x145, date),
                    (0x146, tim), (0x143, 1), (0x131, upid), (0x1C4, uoid)] + [(0x147, e.id) for e in rcpt]
            for i, (t, v) in enumerate(vals):
                r.slots[i] = [t, v]
            mi.write_record(r)
            ix.commit_new(r)

        rec = bytearray(msg.record)
        struct.pack_into("<I", rec, 14, uoid)              # header dword +14 = Univ_Object_ID
        if tag22 is None and add_univ_tag:                 # fill the appended tag
            struct.pack_into("<II", rec, len(rec) - 8, upid, uoid)
        msg = Message(bytes(rec), msg.body)

        # 2. CCPOMS: no lock of its own, after the CCPOMI commit
        stored = struct.pack("<HI", 1, offset) + transpose(msg.record[:32]) + \
            transpose(msg.record[32:msg.part1_len]) + msg.body + transpose(msg.record[msg.part1_len:])
        self._ms_write(offset, need, number, stored)

        # 3. each recipient's mailbox; the pointer flags per recipient
        local_po = ds.find_record(0x28).get(0xCC)          # the local post office's id
        for e in rcpt:
            f = flags
            if self._author_is(ds, msg, e) and not self._dir_attr_remote(e, local_po):
                f = (f | 0x100) & ~0x400                   # Message_Seen, no receipt
            with self.mbox(e.get(0xCA)) as mb:
                self._add_pointer(mb, INBOX, number, need, f, upid, uoid)

        # 4. CCPOMI: Message_Index flags |= 0x300
        with self.fixed("CCPOMI") as mi:
            r = self._find_mi(mi, number)
            r.flags |= 0x300
            mi.write_record(r)
        return number

    def _find_mi(self, mi, number):
        d = mi.index(0x15)                                 # MESSAGE_NUMBER_INDEX
        for key, rid, off in mi.btree_entries(d):
            if struct.unpack_from("<I", key)[0] == number:
                return mi.record_at(off)
        raise PODBError(f"message {number} not in CCPOMI")

    def _ms_space(self, mi, ix, need):
        """A Free_Space record (FREE_LENGTH_INDEX: first with PO_File_Number 0x5000000
        and Free_Length >= need) is used first, else Message_File.Next_Msg_Offset."""
        mf = mi.find_record(0x190)                         # Message_File CCPOMS.00
        free = None
        d = mi.index(0x19)
        if ix.indexes_root(d):
            for key, rid, off in mi.btree_entries(d):
                fileno, flen = struct.unpack_from("<II", key)
                if fileno == KIND_MS and flen >= need:
                    free = mi.record_at(off)
                    break
        used_free = False
        if free is not None:
            offset = free.get(0x155)
            rest = free.get(0x156) - need
            if rest:
                ix.update(free, [(0x156, rest), (0x155, offset + need)])
            else:
                ix.delete_record(free)
                used_free = True
            changes = [(0x138, mf.get(0x138) + 1), (0x139, mf.get(0x139) + need),
                       (0x13A, mf.get(0x13A, 0) - int(used_free)), (0x13B, mf.get(0x13B, 0) - need)]
        else:
            offset = mf.get(0x137)
            changes = [(0x138, mf.get(0x138) + 1), (0x139, mf.get(0x139) + need), (0x137, offset + need)]
        ix.update(mf, changes)
        return offset

    def _ms_write(self, offset, need, number, stored):
        """504-byte units, page header (0, 0, Message_Number), zero padding, no CRC,
        encrypted with S_dd mode 2, written at (unit + 2) * 512."""
        path = find_file(self.dir, "CCPOMS.00")
        st = ms_state(self.po.s_dd)
        data = stored + bytes(need - len(stored))
        writes = []
        for k in range(0, need, LPAGE):
            unit = (offset + k) // LPAGE
            pg = struct.pack("<HHI", 0, 0, number) + data[k:k + LPAGE]
            writes.append(((unit + 2) * PAGE, encrypt(st, pg, (unit + 2) * PAGE)))
        self.ms_writes.append((number, [w[0] for w in writes]))
        if self.dry:
            self.cache.setdefault("_report", []).append(("CCPOMS.00", [w[0] // PAGE - 2 for w in writes], [("message", number)]))
            return
        fd = os.open(path, os.O_RDWR)
        try:
            for off, b in writes:
                os.pwrite(fd, b, off)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _add_pointer(self, mb, folder_id, number, length, flags, upid, uoid):
        ix = self.ix(mb)
        folder = mb.find_record(folder_id)
        entry_no = self._folder_counts(mb, ix, folder, +1, length, flags)
        p = mb.new_record(T_POINTER, 10)                   # 10 slots
        for i, (t, v) in enumerate([(4, folder_id), (0x1C3, entry_no), (0x12E, number), (0x142, length),
                                    (0x131, upid), (0x1C4, uoid)]):
            p.slots[i] = [t, v]
        p.flags |= flags & ~0xFF
        mb.write_record(p)
        ix.commit_new(p)
        return p

    def _folder_counts(self, mb, ix, folder, n, size, flags, top=True):
        """Entry_Count/Number_Msgs/Size_Msgs (+New unless Message_Seen) on the folder,
        the Hier counters on it and its parents until Parent_ID 0x2A (only non-zero deltas are added)."""
        ch = []
        entry_no = None

        def add(tag, d):
            nonlocal ch
            if d:
                ch.append((tag, (folder.get(tag, 0) + d) & 0xFFFFFFFF))
        if top:
            if n > 0:
                entry_no = folder.get(0x1BA, 0) + 1
                add(0x1BA, 1)
            add(0x138, n)
            add(0x139, size * n)
            if not flags & 0x100:
                add(0x1BB, n)
                add(0x1BC, size * n)
        add(0x1BD, n)
        add(0x1BE, size * n)
        if not flags & 0x100:
            add(0x1BF, n)
            add(0x1C0, size * n)
        ix.update(folder, ch)
        parent = folder.get(4)
        if parent and parent != FOLDER_ROOT:
            self._folder_counts(mb, ix, mb.find_record(parent), n, size, flags, top=False)
        return entry_no

    # ------------------------------------------------------------ mark read
    def mark_read(self, user, number):
        """Set Message_Seen (0x100) on the user's pointer to `number` and take it out of the New
        counters. Derived from the folder counter rule (§6); how the clients themselves mark a
        message read is not known."""
        e = self._lookup(self._ds_read(), user)
        with self.mbox(e.get(0xCA)) as mb:
            ix = self.ix(mb)
            for p in mb.live_records():
                if p.tag == T_POINTER and p.get(0x12E) == number:
                    if p.flags & 0x100:
                        return False
                    p.flags |= 0x100
                    mb.write_record(p)
                    folder = mb.find_record(p.get(4))
                    size = p.get(0x142)
                    ch = [(0x1BB, folder.get(0x1BB) - 1), (0x1BC, folder.get(0x1BC) - size),
                          (0x1BF, folder.get(0x1BF) - 1), (0x1C0, folder.get(0x1C0) - size)]
                    ix.update(folder, ch)
                    par = folder.get(4)
                    while par and par != FOLDER_ROOT:
                        f2 = mb.find_record(par)
                        ix.update(f2, [(0x1BF, f2.get(0x1BF) - 1), (0x1C0, f2.get(0x1C0) - size)])
                        par = f2.get(4)
                    return True
        raise PODBError(f"{user}: no message {number}")

    # ------------------------------------------------------------ delete (§12.3)
    def delete_message(self, user, number=None, pointer_id=None):
        """Delete one Message_Pointer from `user`'s mailbox, then drop
        the mailbox's reference in CCPOMI; the message itself is freed only when no
        Mailbox_ID_Number is left. Give the Message_Number, the pointer's record
        id, or both. Returns {"pointer": id, "unref": bool, "freed": bool}; None if the pointer
        is already deleted."""
        ds = self._ds_read()
        e = self._lookup(ds, user)
        if e is None or not e.get(0xCA):
            raise PODBError(f"{user!r}: no local mailbox")
        if e.get(0xD8) == 4:
            # a Message_Propagated pointer of a bulletin board leaves a Shadow record
            # (fields 4/451/455/305/452/491), and Shared_Folder_Entry records are updated. Not ported.
            raise PODBError(f"{user!r} is a bulletin board (Shadow / Shared_Folder_Entry not implemented)")
        if number is None and pointer_id is None:
            raise PODBError("give a Message_Number or a pointer id")
        with self.mbox(e.get(0xCA)) as mb:
            ix = self.ix(mb)
            if pointer_id is not None:
                p = mb.find_record(pointer_id)
                if p is None or p.tag != T_POINTER or (number is not None and p.get(0x12E) != number):
                    raise PODBError(f"{user}: no pointer {pointer_id:#x}" + (f" to message {number}" if number else ""))
            else:
                ps = [x for x in mb.live_records() if x.tag == T_POINTER and x.get(0x12E) == number]
                if not ps:
                    raise PODBError(f"{user}: no message {number}")
                if len(ps) > 1:
                    raise PODBError(f"{user}: message {number} has pointers {[hex(x.id) for x in ps]}; "
                                    "give pointer_id")
                p = ps[0]
            if p.flags & F_DELETED:                        # already deleted, nothing done
                return None
            folder = mb.find_record(p.get(4))
            if folder.flags & 0x100:                       # Shared_Folder -> Shared_Folder_Entry
                raise PODBError(f"{user}: folder {folder.str(0x1B9)!r} is shared (not implemented)")
            number = p.get(0x12E)
            size, seen = p.get(0x142), bool(p.flags & 0x100)
            upid, uoid = p.get(0x131), p.get(0x1C4)
            ix.delete_record(p)
            self._folder_uncount(mb, ix, folder, size, seen, top=True)
            unref = True
            if p.flags & 0x100000:                         # Message_Copied
                # search UNIV_OBJECT (index 0x1C) for (Univ_Post_ID, Univ_Object_ID) with the
                # filter: record tag == 0x1C2 and Message_Number == n
                d = mb.index(0x1C)
                copies = []
                for key, rid, off in mb.btree_entries(d):
                    if struct.unpack_from("<II", key) == (upid, uoid):
                        r = mb.record_at(off)
                        if r.tag == T_POINTER and r.get(0x12E) == number and not r.flags & F_DELETED:
                            copies.append(r)
                if copies and copies[0].get(0x12E):        # another copy keeps the reference
                    unref = False
                    if len(copies) == 1:                   # the last copy loses the flag
                        copies[0].flags &= ~0x100000
                        mb.write_record(copies[0])
        freed = False
        if unref:                                          # CCPOMI after the U commit
            with self.fixed("CCPOMI") as mi:
                freed = self._unref(mi, self.ix(mi), number, e.id)
        return {"pointer": p.id, "unref": unref, "freed": freed}

    def purge_folder(self, user, folder_id=INBOX):
        """Every pointer of a folder, in FOLDER_MSGS order, through delete_message (one U and
        one CCPOMI transaction each). Returns the results of delete_message."""
        e = self._lookup(self._ds_read(), user)
        if e is None or not e.get(0xCA):
            raise PODBError(f"{user!r}: no local mailbox")
        path = find_file(self.dir, file_name(e.get(0xCA))[:-3])
        mb = self.cache.get(path) if self.dry else None
        if mb is None:
            mb = DBFile(path, mode2(self.po.s_dd), po=self.po)
        d = mb.index(0x1B)
        ids = [rid for key, rid, off in mb.btree_entries(d) if struct.unpack_from("<I", key)[0] == folder_id]
        return [self.delete_message(user, pointer_id=rid) for rid in ids]

    def _folder_uncount(self, mb, ix, folder, size, seen, top):
        """top: Number_Msgs/Size_Msgs and,
        unless seen, Number_New/Size_New; always the Hier counters (and the New Hier ones unless
        seen); the folder is committed; then the parent without top while Parent_ID != 0x2A.
        Entry_Count is not changed. Every field is set, not only non-zero deltas."""
        ch = []

        def sub(tag, d):
            ch.append((tag, (folder.get(tag, 0) - d) & 0xFFFFFFFF))
        if top:
            sub(0x138, 1)
            sub(0x139, size)
            if not seen:
                sub(0x1BB, 1)
                sub(0x1BC, size)
        sub(0x1BD, 1)
        sub(0x1BE, size)
        if not seen:
            sub(0x1BF, 1)
            sub(0x1C0, size)
        ix.update(folder, ch)
        parent = folder.get(4)
        if parent and parent != FOLDER_ROOT:               # a folder always has a parent
            self._folder_uncount(mb, ix, mb.find_record(parent), size, seen, top=False)

    def _unref(self, mi, ix, number, holder):
        """Drop the reference of mailbox `holder`, under the CCPOMI lock. The first
        Mailbox_ID_Number (327) slot with this value becomes Mailbox_ID_Deleted (328), same value,
        written in place (no index change). While another 327 is left the record is only
        rewritten. Otherwise the Message_Index is deleted and its CCPOMS span
        freed. CCPOMS itself is not touched. Returns True when the message was freed."""
        r = self._find_mi(mi, number)                      # MESSAGE_NUMBER_INDEX
        k = next((i for i, (t, v) in enumerate(r.slots) if t == 0x147 and v == holder), None)
        if k is None:
            raise PODBError(f"message {number}: no Mailbox_ID_Number {holder:#x} (33472)")
        rest = [v for i, (t, v) in enumerate(r.slots) if t == 0x147 and i != k]
        if not rest and r.flags & 0x800:
            # Message_Translated: the records found by (Univ_Post_ID,
            # Univ_Object_ID) through an index of CCPOMI must go too; not implemented
            raise PODBError(f"message {number}: Message_Translated cleanup not implemented")
        r.slots[k][0] = 0x148                              # Mailbox_ID_Deleted
        mi.write_record(r)
        if rest:
            return False
        fileno, length, offset = r.get(0x66), r.get(0x142), r.get(0x141)
        ix.delete_record(r)
        self._ms_free(mi, ix, fileno, length, offset)
        return True

    def _ms_free(self, mi, ix, fileno, length, offset):
        """Give a CCPOMS span back.
        - successor: FREE_OFFSET_INDEX entry with key (file, offset + length) (an equal
          search); predecessor: the entry before it, or with no successor the last
          entry with file == file and Free_Offset < offset (a less-than search); it merges only
          if it ends at `offset`.
        - The merged span reaching Next_Msg_Offset: Next_Msg_Offset shrinks, no Free_Space
          record, merged neighbours deleted.
        - Else with a neighbour: the predecessor (else the successor) is re-set to the merged
          span (Free_Length, Free_Offset), the other neighbour is deleted.
        - Else a new Free_Space (3 slots Free_Length, Free_Offset, PO_File_Number =
          0x5000000).
        - Message_File 0x190: Number_Free_Space, Size_Free_Space, Next_Msg_Offset,
          Size_Msgs - length, Number_Msgs - 1; then the merged neighbours are deleted."""
        d = mi.index(0x18)
        ents = []
        if ix.indexes_root(d):
            ents = [(struct.unpack_from("<II", key), off) for key, rid, off in mi.btree_entries(d)]
        end = offset + length
        succ = pred = None
        si = next((i for i, (k, off) in enumerate(ents) if k == (fileno, end)), None)
        if si is not None:
            succ = mi.record_at(ents[si][1])
            if si > 0:
                pred = mi.record_at(ents[si - 1][1])
        else:
            cand = [off for k, off in ents if k[0] == fileno and k[1] < offset]
            if cand:
                pred = mi.record_at(cand[-1])
        new_len, new_off = length, offset
        if succ is not None:
            new_len += succ.get(0x156)
        if pred is not None and pred.get(0x156) + pred.get(0x155) == offset:
            new_off = pred.get(0x155)
            new_len += pred.get(0x156)
        else:
            pred = None
        mf = mi.find_record(0x190)                          # Message_File
        nfree, sfree = mf.get(0x13A, 0), mf.get(0x13B, 0)
        nmo, smsgs, nmsgs = mf.get(0x137), mf.get(0x139), mf.get(0x138)
        if new_off > nmo:
            raise PODBError("freed span past Next_Msg_Offset (33478)")
        gone = []
        if new_off + new_len == nmo:                       # back to the end of the store
            nmo -= new_len
            sfree -= new_len
            gone = [x for x in (pred, succ) if x is not None]
        elif pred is not None or succ is not None:         # merge into a neighbour
            keep = pred if pred is not None else succ
            ix.update(keep, [(0x156, new_len), (0x155, new_off)])
            gone = [succ] if keep is pred and succ is not None else []
        else:                                              # new Free_Space
            fs = mi.new_record(T_FREE_SPACE, 3)
            for i, (t, v) in enumerate([(0x156, new_len), (0x155, new_off), (0x66, KIND_MS)]):
                fs.slots[i] = [t, v]
            mi.write_record(fs)
            ix.commit_new(fs)
            nfree += 1
        nfree -= len(gone)
        ix.update(mf, [(0x13A, nfree), (0x13B, (sfree + length) & 0xFFFFFFFF), (0x137, nmo),
                       (0x139, smsgs - length), (0x138, nmsgs - 1)])
        for x in gone:                                     # predecessor first, then successor
            ix.delete_record(mi.record_at(x.off))

    # ------------------------------------------------------------ add user (§12.2)
    def add_user(self, name, password, comments=""):
        """Add a directory entry and mailbox for a local user, then set the password.
        Returns (Dir_Entry id, mailbox file id)."""
        po = self.po
        bname = name.encode("cp437")
        if not name or len(bname) + 1 > 0x7F or "," in name:
            raise PODBError("name: 1..126 bytes, no comma (comma names are stored as "
                            "Last\\0First, not done here)")
        bcom = comments.encode("cp437") if comments else b""
        if len(bcom) + 1 > 0x7F:
            raise PODBError("comments: at most 126 bytes")
        if password:
            encode_password(po.intl, password)            # length check before any change
        dpath = find_file(self.dir, "CCPODS")
        with self.txn(dpath, mode2(FIXED_KEY)) as ds:      # CCPODS locked throughout
            ix = self.ix(ds)
            if self._lookup(ds, name):
                raise PODBError(f"{name!r} exists (MEW -37)")
            d = ds.index(0xA)                              # DIRECTORY_NAME (collation equal = taken)
            for key, rid, off in ds.btree_entries(d):
                r0 = ds.record_at(off)
                if not r0.flags & F_DELETED and r0.get(0xD8) != 3:
                    if ix._cmp_str(d.parts[0], bname + b"\0", ds.data_at(r0.get(0xD7)), 0) == 0:
                        raise PODBError(f"{name!r} collates equal to {r0.str(0xD7)!r}")
            droot = ds.find_record(0x28)
            local_po = droot.get(0xCC)                     # Local_Post_ID_Number
            ix.update(droot, [(0xCB, droot.get(0xCB, 0) + 1)])     # Number_Local_Users
            ent = ds.new_record(T_DIR_ENTRY, 6)
            fields = [(0xD7, ds.new_data(bname + b"\0")), (0xD8, 1), (0xD5, local_po)]
            if bcom:
                fields.append((0xD9, ds.new_data(bcom + b"\0")))   # strlen + 1
            for i, (t, v) in enumerate(fields):
                ent.slots[i] = [t, v]
            ds.write_record(ent)
            fid = self._create_mailbox(ds, ix, droot, ent.id, password)
            k = len(fields)
            ent.slots[k] = [0xCA, fid]                     # Mailbox_Number
            ent.slots[k + 1] = [0xDC, 0]                   # Mailbox_Version
            ds.write_record(ent)
            ix.commit_new(ent)
            pent = ds.find_record(local_po)
            mem = ds.new_record(T_DIR_MEMBER, 8)
            for i, (t, v) in enumerate([(0x105, 1), (0x108, ds.new_data(bname + b"\0")), (5, ent.id), (0x109, 1),
                                        (0x106, ds.new_data(ds.data_at(pent.get(0xD7)))), (4, local_po),
                                        (0x107, pent.get(0xD8))]):
                mem.slots[i] = [t, v]
            ds.write_record(mem)
            ix.commit_new(mem)
            # the address/Unicode uniqueness records are not needed for a plain user: skipped
        return ent.id, fid

    def _create_mailbox(self, ds, ix, droot, owner_id, password):
        po = self.po
        count = droot.get(0xC9) or 100                     # Mailbox_Count, 100 when unset
        fid = count + 1
        ix.update(droot, [(0xC9, fid)])
        upid = droot.get(0x131)
        path = os.path.join(self.dir, file_name(fid))
        if find_file(self.dir, file_name(fid)):
            raise PODBError(f"{file_name(fid)} already exists")
        tpath = find_file(self.dir, "CCPOMBOX.00")
        traw = _read(tpath)
        thdr = decrypt(mode2(FIXED_KEY), traw[512:1024], 512)          # key copy (a)
        if not page_ok(thdr):
            raise PODBError("CCPOMBOX.00: bad header")
        tstate = key_setup(thdr[62:128])
        # rand at 0, K_file = setup(S_dd)[0:66] with K[36], K[65] random
        kst = bytearray(key_setup(po.s_dd))
        kst[2 + 34] = random.getrandbits(8)
        kst[2 + 63] = random.getrandbits(8)
        K = bytes(kst[:66])
        hdr = bytearray(random.getrandbits(8) for _ in range(512))
        struct.pack_into("<HI", hdr, 2, 0, 0)
        struct.pack_into("<HHHIIHI", hdr, 8, 0, 4, 0xF001, 0, 0, 31, 0)
        hdr[62:128] = K
        p = hdr[510] + 158
        hdr[p:p + 66] = bytes(K[j] ^ FIXED_KEY[66 - j] for j in range(66))
        dstate = key_setup(K)
        out = bytearray(random.getrandbits(8) for _ in range(512))
        hstate = mode2(po.s_dd)
        set_page_crc(hdr)
        out += encrypt(hstate, bytes(hdr), 512)
        for o in range(1024, len(traw) - 511, 512):        # decrypt template, encrypt new
            out += encrypt(dstate, decrypt(tstate, traw[o:o + 512], o), o)
        if self.dry:
            self.cache[path] = DBFile(path, hstate, raw=bytes(out), po=po)
            self.cache.setdefault("_report", []).append((file_name(fid), "created", [("mailbox", fid)]))
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                os.write(fd, bytes(out))
                os.fsync(fd)
            finally:
                os.close(fd)
        with self.txn(path, hstate) as mb:
            mix = self.ix(mb)
            date, tim = now_date_time()
            fr = mb.root
            mix.update(fr, [(9, date), (10, tim)])         # creation date and time
            mroot = mb.find_record(0x28)
            mix.update(mroot, [(0x131, upid), (0x147, owner_id)])
            fx = mb.index(0x1D)                            # FOLDER_INDEX, Parent_ID == 0x2A
            for key, rid, off in list(mb.btree_entries(fx)):
                if struct.unpack_from("<I", key)[0] != FOLDER_ROOT:
                    continue
                fr2 = mb.record_at(off)
                mix.update(fr2, [(0x1C4, univ_object_id(tim, date, fr2.id, fid))])
                mix.update(fr2, [(0x131, upid)])
            if password:
                self._set_password(mb, mix, password)
        return fid

    def _set_password(self, mb, mix, password):
        """Set the password of a mailbox without one: header flags: clear 0x200, set 0x100; key
        copy (a) bytes 2.. ^= enc_pw; Mailbox_Password = new blob (fresh F007); 0x193 = today;
        header rewritten."""
        mask, blob = encode_password(self.po.intl, password)
        h = mb.header
        fl = struct.unpack_from("<I", h, 18)[0]
        struct.pack_into("<I", h, 18, (fl & ~0x200) | 0x100)
        for i, b in enumerate(mask):
            h[62 + 2 + i] ^= b
        mroot = mb.find_record(0x28)
        mix.update(mroot, [(0x191, mb.new_data(blob)), (0x193, now_date_time()[0])])
        mb.header_dirty = True


def deliver(po_dir, message, recipients, dry=False, **kw):
    w = Writer(po_dir, dry)
    return w.deliver(message, recipients, **kw), w


def add_user(po_dir, name, password, comments="", dry=False):
    w = Writer(po_dir, dry)
    return w.add_user(name, password, comments), w


def mark_read(po_dir, user, number, dry=False):
    w = Writer(po_dir, dry)
    return w.mark_read(user, number), w


def delete_message(po_dir, user, number=None, pointer_id=None, dry=False):
    w = Writer(po_dir, dry)
    return w.delete_message(user, number, pointer_id), w


def purge_folder(po_dir, user, folder_id=INBOX, dry=False):
    w = Writer(po_dir, dry)
    return w.purge_folder(user, folder_id), w


# ---------------------------------------------------------------- verification
def scan_records(f):
    """Every F001 record in the record stream (data pages only), in order."""
    out, pos = [], 0
    R = f.root_get(6)
    while pos + 4 <= R:
        pg = pos // LPAGE
        if not f.page_type(pg) & 1:
            pos = (pg + 1) * LPAGE
            continue
        t, ln = struct.unpack("<HH", f.read(pos, 4))
        if t == 0:
            pos += 2
            continue
        if t == 0xF001:
            out.append(pos)
            pos += 4 + ln + 2
        elif t == 0xF007:
            pos += 4 + ln + (ln & 1) + 2
        elif t == 0xF00F:
            n = f.u32(pos + 2)
            pos += 6 + n + (n & 1) + 2
        else:
            pos += 2
    return out


def verify_file(f, intl, cp=437, label=None):
    """Page CRCs, record CRCs, every index rebuilt from the records and compared with the tree
    (entries, collation order, keys, counts, structure)."""
    label = label or os.path.basename(f.path)
    errs = []
    if f.bad_pages:
        errs.append(f"{label}: bad page CRCs {f.bad_pages}")
    if f.page_count() != len(f.pages):
        errs.append(f"{label}: {len(f.pages)} pages, File_Root says {f.page_count()}")
    offs = scan_records(f)
    recs = [f.record_at(o) for o in offs]
    for r in recs:
        for cur, n in r.chunks:
            ln = f.u16(cur + 2)
            if f.u16(cur + 4 + ln) != record_crc(f.read(cur, 4 + ln)):
                errs.append(f"{label}: record at {cur:#x} bad CRC")
        if r.flags & F_NEW:
            errs.append(f"{label}: record {r.id:#x} still flagged new")
        if r.tag != T_EXTENSION:
            for t, v in r.slots:
                if v and t and f.po and f.po.fields.get(t, (0, 0))[1] in (0xC, 0xD, 0xE, 0xF, 0x10, 0x11, 0x12, 0x13, 0xB):
                    tt = f.u16(v)
                    ln = f.u16(v + 2) if tt == 0xF007 else f.u32(v + 2)
                    hl = 4 if tt == 0xF007 else 6
                    n = hl + ln + (ln & 1)
                    if tt not in (0xF007, 0xF00F) or f.u16(v + n) != record_crc(f.read(v, n)):
                        errs.append(f"{label}: data record {v:#x} of {r.id:#x} field {t:#x} bad")
    base = [r for r in recs if r.tag != T_EXTENSION]
    ids = {}
    for r in base:
        if r.id in ids:
            errs.append(f"{label}: duplicate id {r.id:#x}")
        ids[r.id] = r
    if base and max(r.id for r in base) > f.root_get(2):
        errs.append(f"{label}: ID_Count below a record id")
    ix = Indexer(f, intl, cp)
    roots = f.indexes()
    for d in f.index_defs():
        root, count = roots[d.id]
        exp = []
        for r in base:
            if not ix.covers(d, r.tag) or d.id == TRANSACTION_INDEX:
                continue
            if d.id != ID_INDEX and (r.flags & F_DELETED or not ix.condition(d, r)):
                continue
            vals = ix.values(d, r)
            if vals is not None:
                exp.append((ix.key(d, vals), r.id, r.off))
        got = list(f.btree_entries(d)) if root else []
        if sorted(got) != sorted(exp):
            errs.append(f"{label}: index {d.name}: tree {len(got)} entries, records give {len(exp)}; "
                        f"missing {[hex(e[1]) for e in set(exp) - set(got)]}, extra {[hex(e[1]) for e in set(got) - set(exp)]}")
        if count != len(got):
            errs.append(f"{label}: index {d.name}: Index_Entry_Count {count}, tree {len(got)}")
        for a, b in zip(got, got[1:]):                     # order by the collating compare
            vb = ix.values(d, f.record_at(b[2]))
            r = ix.compare(d, vb, a[0], a[2])
            if r < 0 or (r == 0 and (not d.dup or b[1] <= a[1])):
                errs.append(f"{label}: index {d.name}: {b[1]:#x} sorts before {a[1]:#x}")
        if root:
            errs += _verify_tree(f, d, root, ix, label)
    return errs


def _verify_tree(f, d, root, ix, label):
    errs = []
    sent = ix.sentinel(d)

    def walk(pg, depth, last):
        typ = f.page_type(pg)
        if struct.unpack_from("<I", f.pages[pg], 4)[0] != d.id:
            errs.append(f"{label}: {d.name} page {pg} has index id {struct.unpack_from('<I', f.pages[pg], 4)[0]:#x}")
        leaf, ents = f.node(pg, d)
        if typ not in (2, 6) or (leaf != (typ == 6)):
            errs.append(f"{label}: {d.name} page {pg} type {typ}")
        if depth == 0 and leaf:
            errs.append(f"{label}: {d.name} root page {pg} is a leaf")
        if leaf:
            if last and (not ents or ents[-1][1:] != (0, 0xFFFFFFFF) or ents[-1][0] != sent):
                errs.append(f"{label}: {d.name} last leaf {pg} has no sentinel")
            return ents[-1] if ents else None
        for k, e in enumerate(ents):
            mx = walk(e[1], depth + 1, last and k == len(ents) - 1)
            if mx is None or mx[0] == e[0]:
                continue
            # an internal key is the child's last key at insert/split time; a removal
            # does not lower it, so after deletes it may be larger than the child's last key
            if mx[1] == 0 or ix.compare(d, ix.values(d, f.record_at(mx[2])), e[0], None) > 0:
                errs.append(f"{label}: {d.name} page {pg} key of child {e[1]} is below its last key")
        return mx if ents else None
    walk(root, 0, True)
    return errs


def verify(po_dir):
    """Every check over a whole post office. Returns a list of problems (empty = consistent)."""
    po = PostOffice(po_dir)
    intl, cp = po.intl, po.intl.cp
    errs = []
    for f in (po.dd, po.ds, po.mi):
        errs += verify_file(f, intl, cp)
    mis = po.message_index()
    holders = {}
    ds_recs = po.ds.live_records()
    droot = next(r for r in ds_recs if r.tag == T_DIR_ROOT)
    entries = [r for r in ds_recs if r.tag == T_DIR_ENTRY]
    mboxes = [r.get(0xCA) for r in entries if r.get(0xCA)]
    if mboxes and droot.get(0xC9) < max(mboxes):
        errs.append("Dir_Root.Mailbox_Count below a mailbox number")
    for r in entries:
        if not r.get(0xCA) or r.flags & F_DELETED:
            continue
        mb = po.mailbox_file(r.get(0xCA))
        if mb is None:
            errs.append(f"{r.str(0xD7)}: mailbox file missing")
            continue
        label = os.path.basename(mb.path)
        errs += verify_file(mb, intl, cp, label)
        recs = mb.live_records()
        mroot = next(x for x in recs if x.tag == T_MAILBOX_ROOT)
        if mroot.get(0x147) != r.id:
            errs.append(f"{label}: Mailbox_ID_Number {mroot.get(0x147):#x} != owner {r.id:#x}")
        folders = {x.id: x for x in recs if x.tag == T_FOLDER}
        ptrs = [x for x in recs if x.tag == T_POINTER]
        cnt = {fid: [0] * 8 for fid in folders}
        copied = set()
        for p in ptrs:
            # Message_Copied (0x100000) pointers of one message in one mailbox share one
            # Mailbox_ID_Number: deleting drops it only with the last copy
            if not p.flags & 0x100000 or p.get(0x12E) not in copied:
                holders.setdefault(p.get(0x12E), []).append(r.id)
            if p.flags & 0x100000:
                copied.add(p.get(0x12E))
            fid, size, new = p.get(4), p.get(0x142), not p.flags & 0x100
            c = cnt[fid]
            c[0] += 1; c[1] += size; c[2] += new; c[3] += size * new
            q = fid
            while q in folders:
                cq = cnt[q]
                cq[4] += 1; cq[5] += size; cq[6] += new; cq[7] += size * new
                q = folders[q].get(4)
                if q == FOLDER_ROOT:
                    break
            if p.get(0x12E) not in mis:
                errs.append(f"{label}: pointer to missing message {p.get(0x12E)}")
            elif size > mis[p.get(0x12E)].get(0x142):
                # delivery stores the unit length; ADE notices from the post office (ade2 run) carry the
                # message's own total instead (the writing path is UNKNOWN): only a larger one is wrong
                errs.append(f"{label}: pointer length above Message_Index length")
        for fid, fo in folders.items():
            have = [fo.get(t, 0) for t in (0x138, 0x139, 0x1BB, 0x1BC, 0x1BD, 0x1BE, 0x1BF, 0x1C0)]
            if have != cnt[fid]:
                errs.append(f"{label}: folder {fo.str(0x1B9)} counters {have} != pointers {cnt[fid]}")
            nums = sorted(p.get(0x1C3) for p in ptrs if p.get(4) == fid)
            if nums and (len(set(nums)) != len(nums) or max(nums) > fo.get(0x1BA, 0)):
                errs.append(f"{label}: folder {fo.str(0x1B9)} Entry_Count {fo.get(0x1BA)} vs entries {nums}")
    mf = next(x for x in po.mi.live_records() if x.tag == T_MESSAGE_FILE and x.id == 0x190)
    mir = next(x for x in po.mi.live_records() if x.tag == T_MSG_INDEX_ROOT)
    if mf.get(0x138) != len(mis):
        errs.append(f"Message_File Number_Msgs {mf.get(0x138)} != {len(mis)} Message_Index records")
    if mf.get(0x139) != sum(m.get(0x142) for m in mis.values()):
        errs.append("Message_File Size_Msgs != sum of Message_Length")
    if mis and mir.get(0x12D) < max(mis):
        errs.append("Msg_Index_Root.Message_Count below a Message_Number")
    spans = sorted((m.get(0x141), m.get(0x141) + m.get(0x142)) for m in mis.values())
    for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
        if b0 < a1:
            errs.append(f"CCPOMS spans overlap at {b0:#x}")
    if spans and spans[-1][1] > mf.get(0x137):
        errs.append("a message lies past Next_Msg_Offset")
    # free space bookkeeping (§12.3)
    frees = [x for x in po.mi.live_records() if x.tag == T_FREE_SPACE]
    if mf.get(0x13A, 0) != len(frees):
        errs.append(f"Message_File Number_Free_Space {mf.get(0x13A, 0)} != {len(frees)} Free_Space records")
    if mf.get(0x13B, 0) != sum(x.get(0x156) for x in frees):
        errs.append("Message_File Size_Free_Space != sum of Free_Length")
    if mf.get(0x139) + mf.get(0x13B, 0) != mf.get(0x137):
        errs.append(f"Size_Msgs {mf.get(0x139):#x} + Size_Free_Space {mf.get(0x13B, 0):#x} != "
                    f"Next_Msg_Offset {mf.get(0x137):#x}")
    fspans = sorted((x.get(0x155), x.get(0x155) + x.get(0x156)) for x in frees)
    allsp = sorted([(a, b, "msg") for a, b in spans] + [(a, b, "free") for a, b in fspans])
    for (a0, a1, ka), (b0, b1, kb) in zip(allsp, allsp[1:]):
        if b0 < a1:
            errs.append(f"CCPOMS {ka} and {kb} spans overlap at {b0:#x}")
        elif b0 == a1 and ka == kb == "free":
            errs.append(f"Free_Space at {a0:#x} and {b0:#x} adjacent (they should have been merged)")
    for a, b in fspans:
        if b > mf.get(0x137):
            errs.append(f"Free_Space at {a:#x} past Next_Msg_Offset")
        elif b == mf.get(0x137):
            errs.append(f"Free_Space at {a:#x} ends at Next_Msg_Offset (the store should have been shrunk instead)")
    for x in frees:
        if x.get(0x66) != KIND_MS:
            errs.append(f"Free_Space {x.id:#x} PO_File_Number {x.get(0x66):#x}")
    for n, m in mis.items():
        if not m.flags & 0x300:
            # flags 0x300 are set only after the local deliveries; a real post office left
            # two records without them (ade2 run: holders but no pointers, one not parseable).
            # Their cause (an interrupted store is one guess) and cleanup are UNKNOWN: skipped.
            continue
        if not m.all(0x147):
            errs.append(f"message {n}: live Message_Index without a Mailbox_ID_Number (it should have been deleted)")
        if sorted(m.all(0x147)) != sorted(holders.get(n, [])):
            errs.append(f"message {n}: holders {[hex(x) for x in m.all(0x147)]} != pointers {[hex(x) for x in holders.get(n, [])]}")
        try:
            got, _ = po.read_message(m)
            if struct.unpack_from("<I", got.record, 14)[0] != m.get(0x1C4):
                # such a message is reported unreadable and removed by the maintenance tools (§14)
                errs.append(f"message {n}: header dword +14 is not its Univ_Object_ID")
        except Exception as e:                              # noqa: BLE001
            errs.append(f"message {n}: {e}")
    return errs


# ---------------------------------------------------------------- structural diff
def snapshot(po_dir):
    """{file: {"records": {id: (tag, flags, fields)}, "indexes": {name: count}, "pages": n}}."""
    po = PostOffice(po_dir)
    out = {}
    files = [po.dd, po.ds, po.mi]
    for e in po.directory():
        if e["mailbox"]:
            mb = po.mailbox_file(e["mailbox"])
            if mb:
                files.append(mb)
    for f in files:
        roots = f.indexes()
        out[os.path.basename(f.path).upper()] = dict(
            records={r.id: (r.tag, r.flags, tuple(r.fields)) for r in f._all_records()},
            indexes={d.name: roots[d.id][1] for d in f.index_defs()},
            pages=len(f.pages))
    ms = find_file(po_dir, "CCPOMS.00")
    out["CCPOMS.00"] = dict(records={}, indexes={}, pages=(os.path.getsize(ms) - 1024) // PAGE)
    return out


def diff(a, b, po=None):
    """Kinds of change between two snapshots: [(file, kind, detail)]."""
    nm = (lambda t: po.name(t)) if po else (lambda t: f"{t:#x}")
    out = []
    for fn in sorted(set(a) | set(b)):
        A, B = a.get(fn), b.get(fn)
        if A is None:
            out.append((fn, "file added", f"{len(B['records'])} records"))
            continue
        if B is None:
            out.append((fn, "file removed", ""))
            continue
        for rid in sorted(set(B["records"]) - set(A["records"])):
            out.append((fn, "record added", f"{nm(B['records'][rid][0])} {rid:#x}"))
        for rid in sorted(set(A["records"]) & set(B["records"])):
            ta, fa, xa = A["records"][rid]
            tb, fb, xb = B["records"][rid]
            if fa != fb:
                out.append((fn, "flags changed", f"{nm(ta)} {rid:#x} {fa:#x}->{fb:#x}"))
            if xa != xb:
                da, db = dict(), dict()
                for t, v in xa:
                    da.setdefault(t, v)
                for t, v in xb:
                    db.setdefault(t, v)
                ch = sorted(t for t in set(da) | set(db) if da.get(t) != db.get(t))
                out.append((fn, "fields changed", f"{nm(ta)} {rid:#x}: {', '.join(nm(t) for t in ch)}"))
        for name in sorted(B["indexes"]):
            if A["indexes"].get(name) != B["indexes"][name]:
                out.append((fn, "index count", f"{name} {A['indexes'].get(name)}->{B['indexes'][name]}"))
        if A["pages"] != B["pages"]:
            out.append((fn, "pages", f"{A['pages']}->{B['pages']}"))
    return out
