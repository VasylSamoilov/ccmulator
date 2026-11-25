# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Code page conversion with the tables from a CCINTL.TB file (spec/codepages.md section 3).

Translation directory at 0x84: 64 entries of type(2) offset(4) size(4) from_cp(2) to_cp(2).
Type 1 (cp -> 1200 Unicode): 256 little-endian words. Type 3 (1200 -> cp): 256 direct bytes for
U+0000..00FF, then sorted (word Unicode, word byte) pairs. Best-fit table at header +0x1C/+0x20
(231 x (word Unicode, word replacement)); only the low byte of the replacement is used.
Unmappable -> best fit -> '?'.
Without CCINTL.TB, Python codecs stand in (exact only for 437/850/852/860-863/865/866).
"""
import bisect
import struct

UNICODE = 1200

# Code pages CCINTL.TB does not contain, taken from open-source tables (not invented here):
# - 1125 (IBM CP1125 / RUSCII, Ukrainian DOS: Ґ ґ Є є І і Ї ї): CPython's Lib/encodings/cp1125.py
#   (Python Software Foundation License), the IBM code page definition as Python ships it. Cyrillic
#   DOS users in Ukraine used it instead of 866, which has no і/ї/є/ґ. cc:Mail clients have no
#   table for it and treat such text as 437 or 850; with "codepage": 1125
#   set for a user, this server converts it correctly to and from other code pages and Unicode.
EXTRA = {1125: "cp1125"}

PYTHON = {**EXTRA, 437: "cp437", 850: "cp850", 852: "cp852", 857: "cp857", 860: "cp860", 861: "cp861",
          862: "cp862", 863: "cp863", 865: "cp865", 866: "cp866", 1250: "cp1250", 1251: "cp1251",
          1252: "cp1252", 1253: "cp1253", 1254: "cp1254", 1255: "cp1255", 1256: "cp1256",
          32768: "mac_roman", 34374: "ascii", **{34193 + i: f"iso8859_{i + 1}" for i in range(9)}}
INTERNET = {437: 34193, 850: 34193, 851: 34193, 860: 34193, 861: 34193, 863: 34193, 1252: 34193,
            32768: 34193, 852: 34194, 1250: 34194, 865: 34196, 866: 34197, 1251: 34197, 1256: 34198,
            1253: 34199, 862: 34200, 1255: 34200, 857: 34201, 1254: 34201,   # spec 3.4
            1125: 34197}   # ours: like 866 -> ISO-8859-5 (that loses і/ї/є/ґ; UTF-8 is preferred)
MIME_NAME = {34374: "us-ascii", **{34193 + i: f"iso-8859-{i + 1}" for i in range(9)}}


ALIASES = {"866u": 1125, "cp866u": 1125, "ruscii": 1125, "cp866nav": 1125, "rst2018-91": 1125,
           "dos": 437, "latin1": 34193, "iso-8859-1": 34193, "windows-1251": 1251, "windows-1252": 1252}


def parse(value) -> int:
    """Code page from po.json: a number or a name like "866u" (= CP1125, RUSCII: the Ukrainian
    standard RST 2018-91 registered by IBM as code page 1125)."""
    if isinstance(value, int):
        return value
    s = str(value).strip().lower()
    if s in ALIASES:
        return ALIASES[s]
    return int(s.removeprefix("cp"))


class Tables:
    def __init__(self, path=None):
        self.dec, self.enc_direct, self.enc_pairs = {}, {}, {}
        self.bestfit_keys, self.bestfit_vals = [], []
        if path:
            self._load(path)

    def _load(self, path):
        data = open(path, "rb").read()
        major, minor, d_off, d_size = struct.unpack_from("<HHII", data, 0)
        bf_off, bf_size = struct.unpack_from("<II", data, 0x1C)
        if major != 3:
            raise ValueError("CCINTL.TB major version is not 3")
        for k in range(d_size // 14):
            typ, off, size, frm, to = struct.unpack_from("<HIIHH", data, d_off + 14 * k)
            if typ == 1 and to == UNICODE:
                self.dec[frm] = struct.unpack_from("<256H", data, off)
            elif typ == 3 and frm == UNICODE:
                self.enc_direct[to] = data[off:off + 256]
                n = (size - 256) // 4
                pairs = [struct.unpack_from("<HH", data, off + 256 + 4 * i) for i in range(n)]
                self.enc_pairs[to] = ([p[0] for p in pairs], [p[1] for p in pairs])
        for i in range(bf_size // 4):
            u, r = struct.unpack_from("<HH", data, bf_off + 4 * i)
            self.bestfit_keys.append(u)
            self.bestfit_vals.append(r)

    def has(self, cp):
        return cp in self.dec or cp in PYTHON

    def decode(self, b: bytes, cp: int) -> str:
        if cp in self.dec:
            t = self.dec[cp]
            return "".join(chr(t[x]) for x in b)
        return b.decode(PYTHON.get(cp, "cp437"), "replace")

    def _enc_char(self, u: int, cp: int) -> int:
        if cp in self.enc_direct:
            if u < 0x100:
                v = self.enc_direct[cp][u]
            else:
                keys, vals = self.enc_pairs[cp]
                i = bisect.bisect_left(keys, u)
                v = vals[i] if i < len(keys) and keys[i] == u else 0x3F
        else:
            try:
                v = chr(u).encode(PYTHON.get(cp, "cp437"))[0]
            except UnicodeEncodeError:
                v = 0x3F
        if v == 0x3F and u != 0x3F:
            i = bisect.bisect_left(self.bestfit_keys, u)
            if i < len(self.bestfit_keys) and self.bestfit_keys[i] == u:
                return self.bestfit_vals[i] & 0xFF          # low byte only
        return v

    def encode(self, s: str, cp: int) -> bytes:
        return bytes(self._enc_char(ord(c) if ord(c) < 0x10000 else 0xFFFD, cp) for c in s)

    def convert(self, b: bytes, src: int, dst: int) -> bytes:
        if not src or not dst or src == dst:
            return b
        return self.encode(self.decode(b, src), dst)


_tables = Tables()


def tables():
    return _tables


def load(path):
    global _tables
    _tables = Tables(path)
    return _tables
