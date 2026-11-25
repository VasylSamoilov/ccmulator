#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""cc:Mail DB8 post office (CCDATA directory) tool, spec/podb.md. Library: ccmail/podb.py.

    python3 tools/ccpodb.py PO_DIR dir                 # directory entries (CCPODS)
    python3 tools/ccpodb.py PO_DIR mailboxes           # mailbox files, folders, message pointers
    python3 tools/ccpodb.py PO_DIR messages USER [--out DIR]   # every message of USER's mailbox
    python3 tools/ccpodb.py PO_DIR records FILE        # every live record of one file, by ID_INDEX
    python3 tools/ccpodb.py PO_DIR check               # CRCs, indexes rebuilt from records, counters

  Writing (dry run unless --write is given; a dry run prints what would change):
    python3 tools/ccpodb.py PO_DIR deliver --from A --to B [--to C ...] --subject S --text T
                                           [--file MSG] [--univ-tag] [--write]
    python3 tools/ccpodb.py PO_DIR adduser NAME PASSWORD [--comments C] [--write]
    python3 tools/ccpodb.py PO_DIR markread USER MESSAGE_NUMBER [--write]
    python3 tools/ccpodb.py PO_DIR delete USER MESSAGE_NUMBER [--pointer ID] [--write]
    python3 tools/ccpodb.py PO_DIR purge USER [--folder ID] [--write]   # every message of a folder (Inbox 0x2b)

Never run --write against a post office whose programs run on another machine: the fcntl lock
on bytes 0..511 is not guaranteed to be seen by LockFileEx there (spec/podb.md §8).
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from ccmail import podb  # noqa: E402
from ccmail.message import Message, compose  # noqa: E402
from ccmail.podb import (FIXED_KEY, DBFile, PostOffice, decode_password, file_name,  # noqa: E402
                         find_file, mode2)


def _fmt_date(v):
    return f"{(v >> 16) + 1900:04d}-{(v >> 8) & 0xFF:02d}-{v & 0xFF:02d}" if v else "-"


def cmd_dir(po):
    print(f"{'id':>6} {'type':<10} {'name':<22} {'mailbox':<10} flags / comments")
    for e in po.directory():
        mb = file_name(e["mailbox"])[:-3] if e["mailbox"] else ""
        extra = " ".join(e["flags"])
        if e["comments"]:
            extra += f" comments={e['comments']!r}"
        if e["address"]:
            extra += f" address={e['address']!r}"
        print(f"{e['id']:>6x} {e['type']!s:<10} {e['name']!s:<22} {mb:<10} {extra}")


def _mailbox_owner(po):
    return {e["mailbox"]: e for e in po.directory() if e["mailbox"]}


def cmd_mailboxes(po):
    mis = po.message_index()
    for fid, e in sorted(_mailbox_owner(po).items()):
        mb = po.mailbox_file(fid)
        if not mb:
            print(f"{file_name(fid)}: {e['name']} (no file)")
            continue
        root = next(r for r in mb.live_records() if r.tag == 0x190)
        pw = mb.string_at(root.get(0x191, 0))
        print(f"{os.path.basename(mb.path)}: owner {e['name']!r} (Mailbox_ID_Number {root.get(0x147):#x}), "
              f"password {decode_password(pw)!r} (blob {pw[:8].hex() + '..' if pw else '-'}), "
              f"header flags {struct.unpack_from('<I', mb.header, 0x12)[0]:#x}, last access {_fmt_date(root.get(0x199, 0))}"
              f"{' bad pages ' + str(mb.bad_pages) if mb.bad_pages else ''}")
        recs = list(mb.live_records())
        folders = {r.id: r for r in recs if r.tag == 0x1B8}
        for f in folders.values():
            print(f"   folder {f.id:#x} {f.str(0x1B9)!r} msgs={f.get(0x138)} size={f.get(0x139)} "
                  f"new={f.get(0x1BB)} {' '.join(po.flag_names(0x1B8, f.flags))}")
        for p in sorted((r for r in recs if r.tag == 0x1C2), key=lambda r: (r.get(4), r.get(0x1C3))):
            mi = mis.get(p.get(0x12E))
            folder = folders.get(p.get(4))
            print(f"   msg #{p.get(0x1C3)} in {folder.str(0x1B9) if folder else hex(p.get(4))!r}: Message_Number "
                  f"{p.get(0x12E)} len {p.get(0x142):#x} {' '.join(po.flag_names(0x1C2, p.flags))}"
                  f"{'' if mi else ' (no Message_Index!)'}")


def cmd_messages(po, user, out_dir=None):
    mis = po.message_index()
    owner = {e["name"].lower(): e for e in po.directory() if e["mailbox"]}
    e = owner[user.lower()]
    mb = po.mailbox_file(e["mailbox"])
    recs = list(mb.live_records())
    folders = {r.id: r.str(0x1B9) for r in recs if r.tag == 0x1B8}
    ptrs = sorted((r for r in recs if r.tag == 0x1C2), key=lambda r: (r.get(4), r.get(0x1C3)))
    for p in ptrs:
        mi = mis[p.get(0x12E)]
        msg, (tag, start) = po.read_message(mi)
        print(f"=== {user} / {folders.get(p.get(4))} #{p.get(0x1C3)}  Message_Number {p.get(0x12E)}  "
              f"CCPOMS offset {mi.get(0x141):#x} (prefix {tag}, {start:#x})  stored {_fmt_date(mi.get(0x145))}  "
              f"holders {[hex(x) for x in mi.all(0x147)]}  flags {' '.join(po.flag_names(0x1C2, p.flags))}")
        print(msg.to_text())
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, f"{user}-{p.get(0x12E)}.msg"), "wb") as fh:
                fh.write(msg.to_file())


def cmd_records(po, name):
    path = find_file(po.dir, name)
    hdr = mode2(po.s_dd) if os.path.basename(path).upper().startswith("U") else mode2(FIXED_KEY)
    f = DBFile(path, hdr, po=po)
    for r in [f.root] + list(f.live_records())[1:]:
        vals = []
        for t, v in r.fields:
            nm, typ, _ = po.fields.get(t, (f"tag{t:x}", None, None))
            if typ == 12 and v:
                s = f.string_at(v)
                txt = s.split(b"\0", 1)[0].decode("cp850", "replace") if s else None
                vals.append(f"{nm}={txt!r}" if s else f"{nm}={v:#x}")
            elif typ in (14, 18) and v:
                s = f.string_at(v)
                vals.append(f"{nm}=<{s.hex() if s else hex(v)}>")
            elif t in po.values and v in po.values[t]:
                vals.append(f"{nm}={po.values[t][v]}")
            else:
                vals.append(f"{nm}={v:#x}")
        print(f"{r.off:06x} {po.name(r.tag)} id={r.id:#x} flags={r.flags:#x}"
              f"[{' '.join(po.flag_names(r.tag, r.flags))}]{'' if r.crc_ok else ' BAD-CRC'}: {', '.join(vals)}")


def _report(w, write):
    print("written:" if write else "dry run, nothing written; would change:")
    for fn, pages, log in w.report():
        print(f"  {fn}: {'created' if pages == 'created' else 'pages ' + str(pages)}")
        for item in log:
            if item[0] == "new":
                print(f"     new {w.po.name(item[1])} id {item[2]:#x} at {item[3]:#x}")
            elif item[0] == "split":
                print(f"     split {item[1]}: page {item[2]} -> {item[3]} + {item[4]}")
            elif item[0] in ("index+", "index-"):
                print(f"     {item[1]} {'+' if item[0] == 'index+' else '-'} {item[2]:#x}")
            else:
                print(f"     {item}")


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    po_dir, cmd = argv[1], argv[2]
    if cmd in ("deliver", "adduser", "markread", "delete", "purge"):
        ap = argparse.ArgumentParser(prog=f"ccpodb.py PO_DIR {cmd}")
        ap.add_argument("--write", action="store_true")
        if cmd == "deliver":
            ap.add_argument("--from", dest="author", required=True)
            ap.add_argument("--to", action="append", required=True)
            ap.add_argument("--subject", default="")
            ap.add_argument("--text", default="")
            ap.add_argument("--file", help="a .msg file (ccmail.message to_file form) instead of --subject/--text")
            ap.add_argument("--univ-tag", action="store_true", help="append tag 0x22 like the Router's a8==0 path")
            a = ap.parse_args(argv[3:])
            msg = Message.from_file(open(a.file, "rb").read()) if a.file else \
                compose(a.author, a.to, a.subject, a.text, codepage=437)
            w = podb.Writer(po_dir, dry=not a.write)
            n = w.deliver(msg, a.to, add_univ_tag=a.univ_tag)
            print(f"Message_Number {n} -> {', '.join(a.to)}")
        elif cmd == "adduser":
            ap.add_argument("name")
            ap.add_argument("password")
            ap.add_argument("--comments", default="")
            a = ap.parse_args(argv[3:])
            w = podb.Writer(po_dir, dry=not a.write)
            rid, fid = w.add_user(a.name, a.password, a.comments)
            print(f"Dir_Entry {rid:#x}, mailbox {file_name(fid)}")
        elif cmd == "delete":
            ap.add_argument("user")
            ap.add_argument("number", type=int)
            ap.add_argument("--pointer", type=lambda s: int(s, 0), help="Message_Pointer record id")
            a = ap.parse_args(argv[3:])
            w = podb.Writer(po_dir, dry=not a.write)
            res = w.delete_message(a.user, a.number, a.pointer)
            print("already deleted" if res is None else
                  f"pointer {res['pointer']:#x} deleted; reference {'dropped' if res['unref'] else 'kept (copy)'}"
                  f"; message {'freed' if res['freed'] else 'kept'}")
        elif cmd == "purge":
            ap.add_argument("user")
            ap.add_argument("--folder", type=lambda s: int(s, 0), default=podb.INBOX)
            a = ap.parse_args(argv[3:])
            w = podb.Writer(po_dir, dry=not a.write)
            res = w.purge_folder(a.user, a.folder)
            print(f"{len(res)} pointers deleted, {sum(1 for r in res if r and r['freed'])} messages freed")
        else:
            ap.add_argument("user")
            ap.add_argument("number", type=int)
            a = ap.parse_args(argv[3:])
            w = podb.Writer(po_dir, dry=not a.write)
            print("marked" if w.mark_read(a.user, a.number) else "already read")
        _report(w, a.write)
        if a.write:
            errs = podb.verify(po_dir)
            print("check:", "ok" if not errs else f"{len(errs)} problems")
            for e in errs:
                print("  ", e)
        return 0
    if cmd == "check":
        errs = podb.verify(po_dir)
        for e in errs:
            print(e)
        print("ok" if not errs else f"{len(errs)} problems")
        return 1 if errs else 0
    po = PostOffice(po_dir)
    if cmd == "dir":
        cmd_dir(po)
    elif cmd == "mailboxes":
        cmd_mailboxes(po)
    elif cmd == "messages":
        out = argv[argv.index("--out") + 1] if "--out" in argv else None
        cmd_messages(po, argv[3], out)
    elif cmd == "records":
        cmd_records(po, argv[3])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
