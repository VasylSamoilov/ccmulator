#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Parse a proxy binary log (logfile.bin) into cc:Mail link frames per direction.

Usage: frames.py capture.log.bin
Reassembles each direction's byte stream, finds frames (02 len ctl p0 hcrc [data dcrc]),
checks both CRCs and prints each frame in time order. Bytes outside valid frames are
printed as "junk" so nothing is silently skipped.
"""
import struct
import sys


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ 0xFFFF


def chunks(path):
    with open(path, "rb") as f:
        raw = f.read()
    i = 0
    while i < len(raw):
        d, t, n = struct.unpack_from("<BQI", raw, i)
        i += 13
        yield d, t / 1e6, raw[i:i + n]
        i += n


def parse(stream):
    """stream: list of (time, byte). Yields (time, kind, info)."""
    i = 0
    junk = []
    while i < len(stream):
        t, b = stream[i]
        found = None
        if b == 0x02:
            # HSEC header: 2-byte length; LSEC header: 1-byte length.
            for lenbytes in (2, 1):
                hl = lenbytes + 2
                if i + 1 + hl + 2 > len(stream):
                    continue
                hdr = bytes(x for _, x in stream[i + 1:i + 1 + hl])
                hcrc = bytes(x for _, x in stream[i + 1 + hl:i + 3 + hl])
                if crc16(hdr).to_bytes(2, "big") == hcrc:
                    found = (lenbytes, hdr)
                    break
        if found:
            lenbytes, hdr = found
            n = hdr[0] | (hdr[1] << 8 if lenbytes == 2 else 0)
            ctl, p0 = hdr[lenbytes], hdr[lenbytes + 1]
            start = i + 3 + lenbytes + 2
            end = start
            data = b""
            ok = True
            if n > 1:
                if start + (n - 1) + 2 > len(stream):
                    ok = False
                else:
                    data = bytes(x for _, x in stream[start:start + n - 1])
                    dcrc = bytes(x for _, x in stream[start + n - 1:start + n + 1])
                    ok = crc16(data).to_bytes(2, "big") == dcrc
                    end = start + n + 1
            if junk:
                yield junk[0][0], "junk", bytes(x for _, x in junk)
                junk = []
            yield t, "frame", (n, ctl, p0, data, ok, "H" if lenbytes == 2 else "L")
            i = end
            continue
        junk.append((t, b))
        i += 1
    if junk:
        yield junk[0][0], "junk", bytes(x for _, x in junk)


def show(n, ctl, p0, data):
    kind = "ACK " if ctl & 0x40 else "DATA"
    flag = " F80" if ctl & 0x80 else ""
    seq_hi, seq_lo = (ctl >> 3) & 7, ctl & 7
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{kind}{flag} ctl={ctl:02x} hi={seq_hi} lo={seq_lo} n={n:4d} p0={p0:02x} {data[:48].hex(' ')} |{text[:48]}|"


def main():
    streams = {0: [], 1: []}
    for d, t, data in chunks(sys.argv[1]):
        streams[d].extend((t, b) for b in data)
    events = []
    for d, s in streams.items():
        for t, kind, info in parse(s):
            events.append((t, d, kind, info))
    events.sort(key=lambda e: e[0])
    for t, d, kind, info in events:
        tag = "R>" if d == 0 else "<P"
        if kind == "frame":
            n, ctl, p0, data, ok, mode = info
            print(f"{t:9.3f} {tag} {mode} {show(n, ctl, p0, data)}{'' if ok else '  BAD DCRC'}")
        else:
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in info)
            print(f"{t:9.3f} {tag} junk {len(info)} {info[:48].hex(' ')} |{text[:48]}|")


main()
