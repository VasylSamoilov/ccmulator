# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Directory updates for client users (spec/directory-updates.md).

One format serves the desktop and the palmtop clients (§5): a message with exactly one logical
item, a type-3 (file) item titled "CCMUPDAT mm/dd/<year-1900> h:mm"; a client applies attachments
named CCMUPDAT* as directory updates.
The item text is CR LF lines:
    Name: <name>   Locn: L | P | DL | DP   Addr: <post office>   Cmts: <comment>   Chng: <new name>
"""
import datetime
import struct

from .message import (Message, FIXED_LEN, DESC_LEN, TAG_FROM, TAG_PATH, TAG_TO, TAG_SUBJECT, TAG_END7,
                      build_tlvs, transpose, untranspose)

SUBJECT = "ADE update message"          # as a post office sends it (spec/router-to-router.md 4.2)
TAG_DIR_REQUEST = 0x18                  # the client's request carries an empty tag 18


def item_text(entries, enc=lambda s: s.encode("cp850", "replace")) -> bytes:
    """entries: dicts with name, kind 'L' (user) or 'P' (post office), and optional addr, cmts,
    chng (rename), delete. Post offices go before the users that point at them (§6)."""
    out = bytearray()
    for e in sorted(entries, key=lambda e: e.get("kind") != "P"):
        out += b"Name: " + enc(e["name"]) + b"\r\n"
        if e.get("delete"):
            out += b"Locn: D" + e["kind"].encode() + b"\r\n"      # no Addr: on deletes (§6)
            continue
        out += b"Locn: " + e["kind"].encode() + b"\r\n"
        if e.get("chng"):
            out += b"Chng: " + enc(e["chng"]) + b"\r\n"
        if e.get("addr"):
            out += b"Addr: " + enc(e["addr"]) + b"\r\n"
        if e.get("cmts"):
            out += b"Cmts: " + enc(e["cmts"]) + b"\r\n"
    if len(out) % 2048 == 0:
        # the HP 200LX client hangs on a file whose size is a multiple of 2048; blank lines are
        # skipped by every reader (§4.4)
        out += b"\r\n"
    return bytes(out)


def title(when: datetime.datetime) -> str:
    """Tag 07, as the client reads it: mm/dd/(year-1900) h:mm, no ".n" sequence number (§5)."""
    return f"CCMUPDAT {when.month:02d}/{when.day:02d}/{when.year - 1900} {when.hour}:{when.minute:02d}"


def update_message(own_po: str, recipient: str, entries, when=None, cp=850) -> Message:
    """The §5 message: 01 Administrator + 0F own PO, 03 recipient, 05, one type-3 item, 07 title.
    cp = the recipient's code page (names are written as its client shows them)."""
    from .codepage import tables
    when = (when or datetime.datetime.now()).replace(microsecond=0)

    def enc(s):
        return tables().encode(s, cp)

    def cstr(s):
        return enc(s) + b"\x00"

    data = item_text(entries, enc=enc)
    part1_len = FIXED_LEN + 2 + DESC_LEN
    desc = struct.pack("<HHHHHII", 0, 3, 1, 0, 0, len(data), part1_len)
    body = transpose(data)
    addr = build_tlvs([[TAG_FROM, cstr("Administrator")], [TAG_PATH, cstr(own_po)],
                       [TAG_TO, cstr(recipient)], [TAG_SUBJECT, cstr(SUBJECT)],
                       [TAG_END7, cstr(title(when))]])
    addr_off = part1_len + len(body)
    date = when.day | when.month << 8 | (when.year - 1900) << 16
    tim = when.second | when.minute << 8 | when.hour << 16
    fixed = struct.pack("<IIHHHIIIHHH", addr_off + len(addr), addr_off, part1_len, 0x4D, 1, 0, date, tim,
                        1, 1, 1)
    record = fixed + bytes([0x06, DESC_LEN]) + desc + addr
    return Message(record, body)


def directory_entries(po):
    """Our whole directory as update records: other post offices (P) and the gateway's, then the
    users (L) with Addr = their post office. The own post office is not sent (it is the client's home)."""
    entries = []
    for name in po._cfg.get("post_offices", {}):
        entries.append({"name": name, "kind": "P", "addr": po.name})
    gw = getattr(po, "gateway", None)
    if gw is not None and getattr(gw, "enabled", False) and not po.post_office(gw.gw_po):
        entries.append({"name": gw.gw_po, "kind": "P", "addr": po.name})
    for canon, _ in po.users.values():
        e = {"name": canon, "kind": "L", "addr": po.name}
        cfg = po._cfg["users"][canon]
        if isinstance(cfg, dict) and cfg.get("comments"):
            e["cmts"] = cfg["comments"]
        entries.append(e)
    # entries learned from other post offices by ADE (ade.py): their post offices first
    from . import ade
    learned = ade.entries(po)
    known = {e["name"].lower() for e in entries} | {po.name.lower()}
    pos = [e for e in learned if e.get("locn") == "P"]
    for e in learned:
        a = (e.get("addr") or e.get("via") or "").split(" ")[0]
        if e.get("locn") != "P" and a and a.lower() not in known and not any(
                p["name"].lower() == a.lower() for p in pos):
            pos.append({"name": a, "locn": "P"})
    for e in pos + [e for e in learned if e.get("locn") != "P"]:
        if e["name"].lower() in known:
            continue
        known.add(e["name"].lower())
        entries.append(ade._remote_entry(e, po.name))
    return entries


def request_after(msg: Message):
    """The client's "Directory update request" (tag 18, one type-6 item of 20 bytes, §1.2): the
    "After date and time" the user entered, or None if this is not such a request."""
    if not any(t == TAG_DIR_REQUEST for t, _ in msg.tlvs):
        return None
    for d in msg.descriptors():
        if d["type"] == 6 and d["length"] >= 0x14:
            raw = untranspose(msg.body[d["offset"] - msg.part1_len:][:d["length"]])
            day, month, year = raw[0x0C], raw[0x0D], raw[0x0E]
            sec, minute, hour = raw[0x10], raw[0x11], raw[0x12]
            try:
                return datetime.datetime(1900 + year, month, day, hour, minute, min(sec, 59))
            except ValueError:
                return datetime.datetime(1900, 1, 1)
    return datetime.datetime(1900, 1, 1)
