# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Directory exchange (ADE) with peer post offices, compatible with cc:Mail Router 6.10
(spec/router-to-router.md section 4).

An ADE message is ordinary mail between post offices: 01 Administrator + 0F <origin>,
03 Administrator + 0F <partner>, 05 subject, 07 "CCMUPDAT|CCMSYNCH|CCMSYNCH.REQ <date time>",
one level-0 type-3 (file) item with CR LF lines, 21 code page, 1C 0002.

Item lines:
    Synch: /postofc=<PO> | /directory | ...       synch and synch request header
    Name: <name>   Locn: [D]L|R|A|P|M|B|C [prop]   Addr:   Achng:   Cmts:   Chng:   ...

What is learned from partners is kept in <data>/ade.json:
    {"entries": {"<name lower>": {"name", "locn", "addr", "cmts", "via", "prop"}}}
Users there are addressable ("name" routes to the post office in addr, else via) and are
part of the directory our client users get (directory.directory_entries).

po.json, per partner post office: "ade": true, or "ade": {"prop": "0xD3"} (the partner's
ADE_Update_Flags for that entry; default DEFAULT_PROP).
"""
import datetime
import fcntl
import json
import logging
import os
import struct

from .message import (Message, FIXED_LEN, DESC_LEN, TAG_FROM, TAG_FORWARDED_BY, TAG_PATH, TAG_TO,
                      TAG_SUBJECT, TAG_END7, TAG_EMBEDDED, build_tlvs, transpose, untranspose, text)

log = logging.getLogger("ccmail.ade")

# ADE_Update_Flags (entry attribute E4h / post office defaults E6h, E7h): bit names from the
# post office's own data dictionary CCPODD (Value_Defn records of tag E4h)
SEND_UPDATE, SEND_LOCAL, SEND_REMOTE, SEND_OTHER = 0x1, 0x2, 0x4, 0x8
RECV_UPDATE, RECV_LOCAL, RECV_REMOTE, RECV_OTHER = 0x10, 0x20, 0x40, 0x80
SEND_ALIASES, SEND_SECONDARY, SEND_MLISTS, SEND_BBOARDS = 0x100, 0x200, 0x400, 0x800
DOMAIN, ENTERPRISE, RECV_MLISTS, RECV_BBOARDS = 0x1000, 0x2000, 0x4000, 0x8000
NO_PROP = 17                       # no flags stored -> 0011h
CAN_UPDATE = 0xC0E0                # author's post office may update us
REQUEST_MASK = 0x0D0E              # what a synch request may ask for
# our default for a partner: send our users, take its users and the entries it knows of
DEFAULT_PROP = SEND_UPDATE | SEND_LOCAL | RECV_UPDATE | RECV_REMOTE | RECV_OTHER

UPDATE, SYNCH, REQUEST, INFO = 1, 2, 3, 4
NAMES = {UPDATE: "CCMUPDAT", SYNCH: "CCMSYNCH", REQUEST: "CCMSYNCH.REQ"}
SUBJECTS = {UPDATE: "ADE update message", SYNCH: "ADE synchronization message",
            REQUEST: "ADE synchronization request message"}
ADMIN = "Administrator"
TAG_KIND, TAG_CODEPAGE = 0x1C, 0x21

# returned-message subjects
REJECTED_AUTHOR, DELETED_FORMAT, REJECTED_FORMAT, DELETED_UPDATES, CANNOT_APPLY, SYNCH_CANNOT_APPLY = range(6)
RETURN_SUBJECTS = [
    "ADE message rejected (author cannot update directory)",
    "ADE message deleted (message incorrectly formatted)",
    "ADE message rejected (message incorrectly formatted)",
    "ADE message deleted (attached updates incorrectly formatted)",
    "ADE message received (attached updates cannot be applied)",
    "ADE synch message rejected (attached updates cannot be applied)",
]
# record error codes, written as "Error: /code=%d /text=%s"
ERRORS = {1: "Name field missing", 2: "Update field too long", 3: "Update field may not be empty",
          4: "Duplicate update field", 5: "Invalid location status", 6: "Invalid propagation field",
          7: "Invalid update format", 8: "Location not specified", 9: "Maximum directory entries exceeded",
          10: "Maximum local users exceeded", 11: "Invalid location change",
          12: "Administrator may not be deleted", 13: "Changed name already in directory",
          14: "Update not allowed", 15: "Entry locked", 16: "Duplicate names not allowed",
          17: "Maximum call entries exceeded", 18: "Extended fields not allowed", 19: "",
          20: "Invalid address"}
LETTERS = "LRAPMBC"


# ----- partners -----

def partner_prop(po, name):
    """The prop word of an ADE partner, or None when that post office does not exchange."""
    cfg = po.post_office_cfg(name)
    a = cfg.get("ade")
    if not a:
        return None
    if isinstance(a, dict) and "prop" in a:
        p = a["prop"]
        return int(p, 0) if isinstance(p, str) else int(p)
    return DEFAULT_PROP


def partners(po):
    return [n for n in po._cfg.get("post_offices", {}) if partner_prop(po, n) is not None]


# ----- text: date stamp, records -----

def title(kind, when):
    """sprintf("%s %y"), where %y is the date, a space and the time. With the US settings
    (iDate 0, iTime 0) the date is M/D/YY and the time H:MM plus AM/PM (no space).
    The receiver compares only the name prefix."""
    h = when.hour % 12 or 12
    return (f"{NAMES[kind]} {when.month}/{when.day}/{when.year % 100:02d} "
            f"{h}:{when.minute:02d}{'PM' if when.hour >= 12 else 'AM'}")


def prop_text(p):
    """4 hex digits, least significant nibble first."""
    return "".join("0123456789ABCDEF"[(p >> (4 * i)) & 15] for i in range(4))


def parse_prop(s):
    """Hex digits, least significant nibble first."""
    v = 0
    for i, c in enumerate(s.strip()[:4]):
        v |= int(c, 16) << (4 * i)
    return v


def record_text(r):
    """One record as a post office writes it: Name, Locn, Addr (not for a post office), Achng,
    Cmts (always). Our addition for renames: Chng (which the peer post office reads)."""
    out = [f"Name: {r['name']}"]
    if r.get("chng"):
        out.append(f"Chng: {r['chng']}")
    locn = ("D" if r.get("delete") else "") + r["locn"]
    if r.get("prop") is not None:
        locn += " " + prop_text(r["prop"])
    out.append(f"Locn: {locn}")
    if r["locn"] != "P" and r.get("addr") is not None:
        out.append(f"Addr: {r['addr']}")
    if r.get("achng"):
        out.append(f"Achng: {r['achng']}")
    out.append(f"Cmts: {r.get('cmts') or ''}")
    return "".join(x + "\r\n" for x in out)


_FIELDS = [("NAME:", "name", 126, False), ("LOCN:", "locn", 126, False), ("ADDR:", "addr", 383, True),
           ("CMTS:", "cmts", 126, True), ("CHNG:", "chng", 126, False), ("ACHNG:", "achng", 383, True),
           ("PSWD:", "pswd", 10, False), ("LOCK:", "lock", 126, False)]


def lines(data: bytes, cp=437):
    """Split at LF, CR dropped, ^Z and trailing blanks cut, leading blanks skipped,
    REM lines skipped."""
    from .codepage import tables
    tb = tables()
    for raw in data.split(b"\n"):
        raw = raw.replace(b"\r", b"")
        if b"\x1a" in raw:
            raw = raw.split(b"\x1a", 1)[0]
        s = tb.decode(raw[:527], cp).strip()
        if not s or s[:4].upper() in ("REM:", "REM "):
            continue
        yield s


def parse(data: bytes, kind=UPDATE, cp=437):
    """(header lines, records). A record is a dict of the fields given plus 'text' (its lines)
    and 'error' (code, 0 = none) as the receiving post office checks them."""
    header, records, cur = [], [], None
    for s in lines(data, cp):
        u = s.upper()
        if u.startswith("NAME:"):
            cur = {"text": [], "error": 0, "seen": set()}
            records.append(cur)
        elif cur is None:
            if u.startswith("SYNCH:") or u.startswith("FORMAT:") or u.startswith("STAT:"):
                header.append(s)
            else:
                # a line before any Name: that is not Synch:/Format: -> code 1
                cur = {"text": [], "error": 1, "seen": set()}
                records.append(cur)
            if cur is None:
                continue
        cur["text"].append(s)
        if cur["error"]:
            continue
        for kw, key, limit, empty in _FIELDS:
            if u.startswith(kw):
                if key == "chng" and kind == SYNCH:
                    break                                   # not read in a synch
                v = s[len(kw):].strip()
                if key in cur["seen"]:
                    cur["error"] = 4
                elif len(v) > limit:
                    cur["error"] = 2
                elif not v and not empty:
                    cur["error"] = 3
                else:
                    cur["seen"].add(key)
                    cur[key] = v
                    if key == "locn":
                        _parse_locn(cur, v)
                break
        else:
            if u.startswith("SYNCH:") or u.startswith("FORMAT:"):
                header.append(s)                            # allowed between records
    for r in records:
        r.pop("seen", None)
        if not r["error"] and "name" not in r:
            r["error"] = 1
    return header, records


def _parse_locn(r, v):
    first = v[:1].upper()
    if first not in LETTERS and first != "D":
        r["error"] = 5
        return
    r["delete"] = first == "D"
    letter = v[1:2].upper() if r["delete"] else first
    r["letter"] = letter if letter in LETTERS else ""
    rest = v[2 if r["delete"] else 1:].strip()
    if rest and not rest.startswith("<"):
        try:
            r["prop"] = parse_prop(rest.split()[0])
        except ValueError:
            r["error"] = 6


def synch_scope(header, own, sender):
    """The scope bits of the Synch: lines: /directory E0h, /postofc=<receiver> 20h, =<sender> 40h,
    =<other> 80h, -/postofc= clears it, /mlist 4000h, /bboard 8000h."""
    bits = 0
    for h in header:
        if not h.upper().startswith("SYNCH:"):
            continue
        v = h[6:].strip()
        lv = v.lower()
        if lv.startswith("/directory"):
            bits |= 0xE0
        elif lv.startswith("/mlist"):
            bits |= 0x4000
        elif lv.startswith("/bboard"):
            bits |= 0x8000
        elif lv.startswith("/postofc=") or lv.startswith("-/postofc="):
            name = v.split("=", 1)[1].strip().lower()
            b = 0x20 if name == own.lower() else 0x40 if name == sender.lower() else 0x80
            bits = bits | b if lv.startswith("/") else bits & ~b
        elif lv.startswith("/domain"):
            bits |= 0x1000
        elif lv.startswith("/enterprise"):
            bits |= 0x2000
    return bits


def swap_nibbles(v):
    """A synch request names receive bits; the answering post office turns them into send bits."""
    return ((v << 4) & 0xF0F0) | ((v >> 4) & 0x0F0F)


# ----- messages -----

def build(po, partner, kind, data: bytes, when=None):
    """An ADE message for a directly reached partner. The From always carries 0F <own>
    because the receiver authorises by it."""
    from .codepage import tables
    when = (when or datetime.datetime.now()).replace(microsecond=0)
    cp = po.codepage

    def cstr(s):
        return tables().encode(s, cp) + b"\x00"

    part1_len = FIXED_LEN + 2 + DESC_LEN
    desc = struct.pack("<HHHHHII", 0, 3, 1, 0, 0, len(data), part1_len)
    body = transpose(data)
    addr = build_tlvs([[TAG_FROM, cstr(ADMIN)], [TAG_PATH, cstr(po.name)],
                       [TAG_TO, cstr(ADMIN)], [TAG_PATH, cstr(partner)],
                       [TAG_SUBJECT, cstr(SUBJECTS[kind])],
                       [TAG_CODEPAGE, struct.pack("<H", cp)], [TAG_KIND, struct.pack("<H", 2)],
                       [TAG_END7, cstr(title(kind, when))]])
    addr_off = part1_len + len(body)
    date = when.day | when.month << 8 | (when.year - 1900) << 16
    tim = when.second | when.minute << 8 | when.hour << 16
    fixed = struct.pack("<IIHHHIIIHHH", addr_off + len(addr), addr_off, part1_len, 0x4D, 1, 0, date, tim,
                        1, 1, 1)
    return Message(fixed + bytes([0x06, DESC_LEN]) + desc + addr, body)


def classify(msg: Message):
    """0 = not ADE, else UPDATE / SYNCH / REQUEST / INFO."""
    if any(t == TAG_EMBEDDED for t, _ in msg.tlvs):
        return 0
    descs = msg.descriptors()
    if any(d["index"] == 0 and d["type"] == 5 for d in descs):
        return UPDATE
    if msg.headings != 1 or not any(d["index"] == 0 and d["type"] == 3 for d in descs):
        return 0
    titles = [text(d) for t, d in msg.tlvs if t == TAG_END7]
    name = titles[0].upper() if titles else ""
    if not name or name.startswith("CCMUPDAT.UND") or name.startswith("CCMUPDAT.RTE"):
        return 0
    for prefix, kind in (("CCMUPDAT", UPDATE), ("CCMSYNCH.REQ", REQUEST), ("CCMSYNCH", SYNCH),
                         ("CCMINFO.REQ", INFO)):
        if name.startswith(prefix):
            return kind
    return 0


def item_data(msg: Message):
    """The first level-0 item of any type, through the block transform."""
    for d in msg.descriptors():
        if d["index"] == 0:
            return untranspose(msg.body[d["offset"] - msg.part1_len:][:d["length"]])
    return b""


def origin(msg: Message):
    """The author is the last 01/02; the entry right after it must be 0F <PO>."""
    tl = msg.addr_tlvs
    idx = [i for i, (t, _) in enumerate(tl) if t in (TAG_FROM, TAG_FORWARDED_BY)]
    if not idx:
        return None, None
    i = idx[-1]
    author = text(tl[i][1])
    if i + 1 < len(tl) and tl[i + 1][0] == TAG_PATH:
        return author, text(tl[i + 1][1])
    return author, None


def is_ade(po, caller_po, msg):
    """Whether mail for 03 Administrator is taken as ADE: known post-office caller,
    ADE class, ADE exchange configured with that caller (the ADE policy)."""
    return bool(caller_po) and partner_prop(po, caller_po) is not None and classify(msg) != 0


# ----- learned directory store -----

def _path(po):
    return os.path.join(po.root, "ade.json")


def load(po):
    try:
        with open(_path(po), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"entries": {}}


def update(po, change):
    """Read ade.json, change(state), write it back atomically under a lock (like
    PostOffice.update). Returns what change returned."""
    path = _path(po)
    with open(path + ".lock", "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        state = load(po)
        result = change(state)
        tmp = path + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, path)
        return result


def entries(po):
    return list(load(po)["entries"].values())


def lookup(po, name):
    return load(po)["entries"].get(name.strip().lower())


def route_for(po, name):
    """The configured post office that mail for a learned user goes to: its address when that
    is a configured post office, else through a learned post office entry, else the partner
    that told us about it."""
    first = e = lookup(po, name)
    seen = set()
    while e and e["name"].lower() not in seen:
        seen.add(e["name"].lower())
        addr = (e.get("addr") or "").split(" ")[0]
        if addr and po.post_office(addr):
            return po.post_office(addr)
        e = lookup(po, addr) if addr else None
        if e is not None and e.get("locn") != "P":
            break
    return po.post_office(first["via"]) if first and first.get("via") else None


def po_route(po, name):
    """Route of a learned post office entry (not configured here) or None."""
    e = lookup(po, name)
    if not e or e.get("locn") != "P" or po.post_office(name):
        return None
    return route_for(po, name)


def add_routes(po, msg: Message):
    """Route completion for names known through ADE: a pending 03/0B/11 entry that is a
    learned user without a 0F run gets `0F <its PO> [0F <next hop>]`; one whose 0F run ends at a
    learned (not configured) post office gets `0F <next hop>`. Then the per-destination copy
    (for_post_office) keeps it. Messages without such entries are returned unchanged."""
    state = load(po)["entries"]
    if not state:
        return msg
    tl = [list(x) for x in msg.addr_tlvs]
    out, i, changed = [], 0, False
    while i < len(tl):
        t, d = tl[i]
        out.append([t, d])
        i += 1
        if t not in (TAG_TO, 0x0B, 0x11):
            continue
        run = []
        while i < len(tl) and tl[i][0] == TAG_PATH:
            run.append(text(tl[i][1]))
            out.append(tl[i])
            i += 1
        name = text(d)
        add = []
        if not run and not po.user(name) and user_route(po, name):
            e = lookup(po, name)
            home = (e.get("addr") or "").split(" ")[0]
            if home and home.lower() != po.name.lower():
                add.append(home)
            hop = user_route(po, name)
            if hop and hop.lower() != home.lower():
                add.append(hop)
        elif run and not any(po.post_office(p) or p.lower() == po.name.lower() for p in run):
            hop = po_route(po, run[-1])
            if hop:
                add.append(hop)
        for p in add:
            out.append([TAG_PATH, p.encode("cp850", "replace") + b"\x00"])
            changed = True
    if not changed:
        return msg
    addr = build_tlvs(out)
    p1 = bytearray(msg.record[:msg.part1_len])
    struct.pack_into("<I", p1, 0, msg.addr_off + len(addr))
    return Message(bytes(p1) + addr, msg.body)


def user_route(po, name):
    """Route of a learned user (not a post office entry) or None."""
    e = lookup(po, name)
    if not e or e.get("locn") == "P":
        return None
    return route_for(po, name)


# ----- applying received records -----

def _allowed(rec, prop, own, sender):
    """The filter for a received record: the record's own prop bits F0E0h must be within ours; then
    P -> Recv_Other, M -> Recv_Mlists, B -> Recv_Bboards, Addr = receiver -> Recv_Local,
    Addr = sender -> Recv_Remote, else Recv_Other (domain/enterprise routing not modelled)."""
    if rec.get("prop") is not None and (~prop & rec["prop"] & 0xF0E0):
        return False
    letter = rec.get("letter", "")
    if letter == "M":
        return bool(prop & RECV_MLISTS)
    if letter == "B":
        return bool(prop & RECV_BBOARDS)
    if letter != "P":
        a = (rec.get("addr") or "").strip().lower()
        if a and a == own.lower():
            return bool(prop & RECV_LOCAL)
        if a and a == sender.lower():
            return bool(prop & RECV_REMOTE)
    return bool(prop & RECV_OTHER)


def _ours(po, name):
    """Names this post office owns: its users, its configured post offices, itself."""
    return po.user(name) or po.post_office(name) or (name.lower() == po.name.lower() and po.name)


def apply_record(po, state, rec, prop, sender):
    """One update record. Returns (changed entry list for our users, error code). Changes go into
    state["entries"]. Error 14 for names we own (a local entry needs Recv_Local, which we
    never take: partners do not change po.json)."""
    E = state["entries"]
    name = rec["name"]
    letter = rec.get("letter", "")
    if letter in ("M", "B", "C"):
        return [], 0                                        # lists, boards, call entries: not kept here
    if not _allowed(rec, prop, po.name, sender):
        return [], 14
    if name.lower() == po.name.lower():
        return [], 0 if letter == "P" else 14
    if po.user(name) or (po.post_office(name) and letter != "P"):
        return [], 14
    if po.post_office(name):
        return [], 0                                        # a configured partner: no change
    key = name.lower()
    cur = E.get(key)
    if cur is None and rec.get("chng") and E.get(rec["chng"].lower()):
        key, cur = rec["chng"].lower(), E[rec["chng"].lower()]   # already renamed
    addr = rec.get("achng") if rec.get("achng") is not None else rec.get("addr")
    if rec.get("delete"):
        if cur is None:
            return [], 0
        if letter in ("L", "l") and cur.get("locn") == "P":
            return [], 5
        del E[key]
        return [{"name": cur["name"], "kind": "P" if cur.get("locn") == "P" else "L", "delete": True}], 0
    if not letter:
        return [], 8
    if letter == "A":
        letter = "R"                                        # an alias is taken as remote
    if cur is not None and (cur.get("locn") == "P") != (letter == "P"):
        return [], 11
    if cur is None:
        if letter == "P" and not addr:
            addr = sender                                   # reached through the sender
        new = {"name": rec.get("chng") or name, "locn": letter, "addr": addr or "",
               "cmts": rec.get("cmts") or "", "via": sender}
        if rec.get("prop") is not None:
            new["prop"] = rec["prop"]
        if new["name"].lower() != key and (E.get(new["name"].lower()) or _ours(po, new["name"])):
            return [], 13
        E[new["name"].lower()] = new
        out = [_remote_entry(new, po.name)]
        home = (new["addr"] or "").split(" ")[0]
        if letter != "P" and home and not _ours(po, home) and home.lower() not in E:
            # an unknown home post office becomes a P entry reached through the sender
            E[home.lower()] = {"name": home, "locn": "P", "addr": sender, "cmts": "", "via": sender}
            out.insert(0, _remote_entry(E[home.lower()], po.name))
        return out, 0
    changed = dict(cur)
    out = []
    if rec.get("chng") and rec["chng"].lower() != key:
        if E.get(rec["chng"].lower()) or _ours(po, rec["chng"]):
            return [], 13
        changed["name"] = rec["chng"]
    elif rec.get("chng"):
        changed["name"] = rec["chng"]
    changed["locn"] = letter
    if addr is not None and not (letter == "P" and not addr):
        changed["addr"] = addr
    if rec.get("cmts") is not None:
        changed["cmts"] = rec["cmts"]
    if rec.get("prop") is not None:
        changed["prop"] = rec["prop"]
    changed["via"] = sender
    if changed == cur:
        return [], 0
    del E[key]
    E[changed["name"].lower()] = changed
    r = _remote_entry(changed, po.name)
    if changed["name"] != cur["name"]:
        r = dict(r, name=cur["name"], chng=changed["name"])
    out.append(r)
    return out, 0


def _remote_entry(e, own=None):
    """The entry as a client directory update record (directory.item_text). A post office gets
    Addr = our name, as directory_entries() writes the configured ones."""
    if e.get("locn") == "P":
        return {"name": e["name"], "kind": "P", "addr": own or e.get("addr") or ""}
    r = {"name": e["name"], "kind": "L", "addr": e.get("addr") or e.get("via") or ""}
    if e.get("cmts"):
        r["cmts"] = e["cmts"]
    return r


def synch_deletes(state, records, scope, sender):
    """The synch merge: learned entries inside the synch's scope that no record names are
    deleted. Scope 40h = entries whose address is the sender, 80h = other entries the sender
    told us about; our own entries (20h) are never touched."""
    named = {r["name"].lower() for r in records if r.get("name")}
    out = []
    for key, e in state["entries"].items():
        if key in named or (e.get("via") or "").lower() != sender.lower():
            continue
        at_sender = (e.get("addr") or "").lower() == sender.lower() and e.get("locn") != "P"
        if (scope & 0x40 and at_sender) or (scope & 0x80 and not at_sender):
            out.append({"name": e["name"], "locn": e.get("locn") or "L", "letter": e.get("locn") or "L",
                        "delete": True, "addr": e.get("addr"), "error": 0, "text": []})
    return out


def handle(po, caller_po, msg):
    """Process an ADE message received from post office caller_po.
    Returns a short result string for the log."""
    kind = classify(msg)
    author, from_po = origin(msg)
    src = po.post_office(from_po) if from_po else None
    prop = partner_prop(po, src) if src else None
    if src is None or prop is None:
        _return(po, caller_po, msg, REJECTED_AUTHOR)
        return f"rejected: author {author!r} at {from_po!r} cannot update the directory"
    if kind in (UPDATE, SYNCH) and not prop & CAN_UPDATE:
        _return(po, src, msg, REJECTED_AUTHOR)
        return f"rejected: prop {prop:04X}h of {src} has no C0E0h bits"
    data = item_data(msg)
    if kind == REQUEST:
        header, _ = parse(data, REQUEST, po.codepage)
        want = swap_nibbles(synch_scope(header, po.name, src))
        if want and want & ~prop & REQUEST_MASK:
            _return(po, src, msg, REJECTED_AUTHOR)
            return f"synch request from {src} for {want:04X}h refused (prop {prop:04X}h)"
        if src != caller_po:
            return f"synch request from {src} via {caller_po}: not ours to answer"
        queue_synch(po, src)
        return f"synch request from {src}: synch queued"
    if kind == INFO:
        return "information request: not answered (format UNKNOWN)"
    header, records = parse(data, kind, po.codepage)
    if kind == SYNCH and any(r["error"] for r in records):
        # a synch with disallowed records is not applied at all
        return f"synch from {src}: {sum(1 for r in records if r['error'])} bad record(s), not applied"
    changes, rejected, applied = [], [], []

    def change(state):
        todo = list(records)
        if kind == SYNCH:
            todo += synch_deletes(state, records, synch_scope(header, po.name, src) & prop, src)
        for r in todo:
            if r["error"]:
                rejected.append(r)
                continue
            out, err = apply_record(po, state, r, prop, src)
            if err:
                r["error"] = err
                rejected.append(r)
            if out:
                applied.append(r)
            changes.extend(out)
    update(po, change)
    if changes:
        _notify_users(po, changes)
        forward(po, applied, src)       # what changed here, synch deletes included
    if rejected:
        _return(po, src, msg, SYNCH_CANNOT_APPLY if kind == SYNCH else CANNOT_APPLY, rejected)
    return (f"{'synch' if kind == SYNCH else 'update'} from {src}: {len(records)} record(s), "
            f"{len(changes)} change(s), {len(rejected)} not applied")


def _notify_users(po, changes):
    """Our client users get the learned changes as a directory update (directory-updates.md)."""
    from . import directory
    for canon, _ in sorted(po.users.values()):
        po.deposit(canon, directory.update_message(po.name, canon, changes, cp=po.user_codepage(canon)))


def _return(po, dest, msg, code, rejected=()):
    """The returned message: from "ROUTER" to Administrator at the origin, subject from
    RETURN_SUBJECTS; codes >= 3 attach "CCMUPDAT.UND %y" with the records and their Error: lines.
    The protocol also allows the original as a returned heading; we send the subject and the UND
    file only (the original is kept in received/)."""
    if not dest or not po.post_office(dest):
        log.info("ADE: cannot return %r (no route)", RETURN_SUBJECTS[code])
        return None
    und = b""
    for r in rejected:
        und += "".join(s + "\r\n" for s in r.get("text", [])).encode("cp850", "replace")
        und += f"Error: /code={r['error']} /text={ERRORS.get(r['error'], '')}\r\n".encode()
    from .message import compose
    note = f"{RETURN_SUBJECTS[code]}\r\nOriginal: {msg.subject} ({(msg.titles() or [''])[0]})\r\n"
    atts = [("CCMUPDAT.UND", und)] if code >= 3 and und else []
    out = compose("ROUTER", [f"{ADMIN} at {dest}"], RETURN_SUBJECTS[code], note, author_po=po.name,
                  attachments=atts)
    log.info("ADE: returned to %s: %s", dest, RETURN_SUBJECTS[code])
    return po.route(dest, out)


# ----- sending -----

def _send_ok(rec, prop, own, partner):
    """P -> Send_Other; Addr = own -> Send_Local; Addr = partner -> Send_Remote;
    else Send_Other. Aliases need Send_Aliases."""
    if rec.get("letter") == "A" and not prop & SEND_ALIASES:
        return False
    if rec.get("locn") == "P" or rec.get("letter") == "P":
        return bool(prop & SEND_OTHER)
    a = (rec.get("addr") or "").lower()
    if a == own.lower():
        return bool(prop & SEND_LOCAL)
    if a == partner.lower():
        return bool(prop & SEND_REMOTE)
    return bool(prop & SEND_OTHER)


def local_records(po):
    """Our users as a post office writes its local users in a synch: Locn L, Addr = home post office."""
    out = []
    for canon, _ in po.users.values():
        cfg = po._cfg["users"][canon]
        cmts = cfg.get("comments", "") if isinstance(cfg, dict) else ""
        out.append({"name": canon, "locn": "L", "letter": "L", "addr": po.name, "cmts": cmts})
    return sorted(out, key=lambda r: r["name"].lower())


def queue_update(po, records, exclude=None, only=None):
    """An update to every ADE partner (or `only` that one), each filtered by what that partner
    is sent; never back to the post office the records came from. Returns
    [(partner, id)]."""
    out = []
    for p in partners(po):
        if (exclude and p.lower() == exclude.lower()) or (only and p.lower() != only.lower()):
            continue
        prop = partner_prop(po, p)
        keep = [r for r in records if _send_ok(r, prop, po.name, p)]
        if not keep:
            continue
        out.append((p, po.route(p, build(po, p, UPDATE, _enc(po, keep)))))
    return out


def _enc(po, records, header=()):
    from .codepage import tables
    s = "".join(h + "\r\n" for h in header) + "".join(record_text(r) for r in records)
    return tables().encode(s, po.codepage)


def forward(po, records, src):
    """Accepted records go on to the other partners."""
    fwd = []
    for r in records:
        r = {k: v for k, v in r.items() if k not in ("text", "error")}
        if r.get("letter") in ("M", "B", "C"):
            continue
        r["locn"] = r.get("letter") or r.get("locn")
        fwd.append(r)
    return queue_update(po, fwd, exclude=src) if fwd else []


def queue_synch(po, partner):
    """Full synch: "Synch: /postofc=<own>" (what a post office sends a Send_Local partner),
    then our users in name order (the receiver merges in its own name order)."""
    prop = partner_prop(po, partner) or DEFAULT_PROP
    recs = [r for r in local_records(po) if _send_ok(r, prop, po.name, partner)]
    msg = build(po, partner, SYNCH, _enc(po, recs, [f"Synch: /postofc={po.name}"]))
    return po.route(partner, msg)


def queue_request(po, partner, everything=False):
    """Synch request: header lines only. /postofc=<partner> asks for its own users and
    needs only Send_Local in its prop for us; /directory asks for all (needs 0Eh)."""
    line = "Synch: /directory" if everything else f"Synch: /postofc={partner}"
    return po.route(partner, build(po, partner, REQUEST, _enc(po, [], [line])))
