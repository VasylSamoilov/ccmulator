#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Scripted newer-client call over raw TCP (spec/newer-client-check.md items 12, 27):
B0 80 -> 81, name, 8B -> password, 82 + PO name -> 82, A5 (address book sync) and A2 (mailbox
sync) requests, 88, then accept every message offered until the post office's 88.

Usage: mobileclient.py HOST PORT USER PASSWORD
"""
import socket
import struct
import sys

host, port, user, pw = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
s = socket.create_connection((host, port), timeout=30)
buf = b""


def read(n):
    global buf
    while len(buf) < n:
        d = s.recv(65536)
        if not d:
            raise SystemExit(f"closed, wanted {n} bytes, have {buf.hex(' ')}")
        buf += d
    out, buf = buf[:n], buf[n:]
    return out


def code():
    while True:
        c = read(1)[0]
        if c != 0x91:
            return c


def say(what, b):
    print(f"us>  {what}: {b.hex(' ')}")
    s.sendall(b)


say("B0 80", b"\xb0\x80")
c = code()
print(f"po>  {c:02x}  (81 = old login)")
say("name", bytes([len(user) + 1]) + user.encode() + b"\0")
c = code()
print(f"po>  {c:02x}  (8B = password please)")
say("password", bytes([len(pw) + 1]) + pw.encode() + b"\0")
c = code()
n = read(1)[0]
name = read(n)
print(f"po>  {c:02x} + post office {name!r}")
say("82 (right post office)", b"\x82")
say("A5 address book sync", b"\xa5")
print(f"po>  {code():02x}  (83 expected: refused)")
say("A2 mailbox sync", b"\xa2")
print(f"po>  {code():02x}  (A7 expected: not available)")
say("88 (nothing to send)", b"\x88")
got = 0
while True:
    c = code()
    if c != 0x84:
        print(f"po>  {c:02x}  (end of the post office's turn)")
        break
    say("85", b"\x85")
    hl = struct.unpack("<H", read(2))[0]
    rec = read(hl)
    total, addr_off, part1 = struct.unpack_from("<IIH", rec, 0)
    n03 = 0
    pos = part1
    while pos + 2 <= len(rec):
        n03 += rec[pos] == 3
        pos += 2 + rec[pos + 1]
    say(f"{n03} verdict(s) 82 + 86", b"\x82" * n03 + b"\x86")
    body = read(addr_off - part1)
    got += 1
    print(f"po>  message {got}: header {hl} bytes, body {len(body)} bytes")
    say("87", b"\x87")
print(f"done: {got} message(s) received")
s.close()
