# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""cc:Mail post office for remote clients.

    python3 -m ccmail.server serve --data DIR [--port 5003]     answer calls arriving over TCP
    python3 -m ccmail.server send --data DIR --from A --to B --subject S [--file F | --text T]
    python3 -m ccmail.server show FILE.msg
    python3 -m ccmail.server user add|set|passwd|rename|del|list --data DIR [NAME [NEW]] [...]
    python3 -m ccmail.server po add|set|del|list --data DIR [NAME] [...]
    python3 -m ccmail.server fetch --data DIR [USER]              fetch internet mail accounts now

TCP is what the DOSBox-X modem (and later a modem bridge) delivers after CONNECT; the
connection carries the raw serial bytes.
"""
import argparse
import logging
import os
import socket
import sys
import threading

from .gateway import Gateway
from .link import Link, LinkClosed, LinkTimeout
from .message import Message, compose
from .session import Call, Refused
from .store import PostOffice

log = logging.getLogger("ccmail")


def handle(conn, addr, po, n, line_bps=None):
    name = f"call{n}"
    link = Link(conn, name, speed=line_bps)
    log.info("%s: connection from %s:%d", name, *addr)
    try:
        Call(link, po, name).run()
    except (LinkClosed, LinkTimeout, Refused) as e:
        log.info("%s: ended: %s", name, e)
    except Exception:
        log.exception("%s: failed", name)
    finally:
        log.info("%s: link stats %s", name, link.stats)
        conn.close()


def serve(args):
    from .fetch import Fetcher
    po = PostOffice(args.data)
    po.gateway = Gateway(po)
    po.fetcher = Fetcher(po, po.gateway)
    if po.gateway.enabled:
        if po.gateway.listen:
            threading.Thread(target=po.gateway.serve_smtp, daemon=True).start()
        log.info("internet gateway: post office %s, domain %s", po.gateway.gw_po, po.gateway.domain)
        for err in po.gateway.config_errors():
            log.error("config: %s", err)
    # always running, cheap when idle: per-user smtp/fetch settings may be added while we run
    threading.Thread(target=po.gateway.run_sender, daemon=True).start()
    threading.Thread(target=po.fetcher.run, daemon=True).start()
    counter = iter(range(1, 1 << 30))

    def listen(port):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, port))
        srv.listen(4)
        log.info("post office %s, %d users, listening on %s:%d", po.name, len(po.users), args.host, port)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr, po, next(counter), args.line_bps),
                             daemon=True).start()

    if args.serial:
        # a client on a serial port that expects a Hayes modem (ccmail/modem.py)
        from .modem import Modem, open_port
        ser = open_port(args.serial, args.baud, rtscts=args.rtscts)
        modem = Modem(ser, args.capture, name="serial")
        bps = args.line_bps or args.baud

        def serial_call(sock):
            handle(sock, (args.serial, args.baud), po, next(counter), bps)

        threading.Thread(target=modem.serve, args=(serial_call,), daemon=True).start()
        if args.serial_only:
            threading.Event().wait()

    # 3264 (0CC0h) is the port newer clients and peer post offices use over TCP/IP, raw session
    # bytes (newer-client-check.md item 12, router-to-router.md 1.2)
    ports = args.port or [5003, 3264]
    for p in ports[1:]:
        threading.Thread(target=listen, args=(p,), daemon=True).start()
    listen(ports[0])


def send(args):
    from . import ade
    po = PostOffice(args.data)
    text = open(args.file, encoding="utf-8").read() if args.file else args.text
    # a user learned by ADE is addressed at its post office
    args.to = [f"{ade.lookup(po, r)['name']} at {ade.user_route(po, r)}"
               if " at " not in r and not po.user(r) and ade.user_route(po, r) else r for r in args.to]
    for r in args.to:
        name, _, rpo = r.partition(" at ")
        if rpo and not po.post_office(rpo):
            sys.exit(f"unknown post office {rpo}")
        if not rpo and not po.user(r):
            sys.exit(f"unknown user {r}")
    author_po = po.name if any(" at " in r for r in args.to) else None
    attachments = [(os.path.basename(p), open(p, "rb").read()) for p in (args.attach or [])]
    msg = compose(args.author, args.to, args.subject, text, priority=args.priority, folder=args.folder,
                  author_po=author_po, attachments=attachments)
    routed = set()
    for r in args.to:
        name, _, rpo = r.partition(" at ")
        if rpo:
            # one queued copy per post office: it carries every recipient there
            if po.post_office(rpo) not in routed:
                routed.add(po.post_office(rpo))
                print(po.route(po.post_office(rpo), msg), "-> post office", po.post_office(rpo))
        else:
            print(po.deposit(po.user(r), msg), "->", po.user(r))


def call(args):
    """Call another post office now (router-to-router.md 7.2)."""
    from .link import LSEC, HSEC, RAW
    from .session import call_post_office
    po = PostOffice(args.data)
    dest = po.post_office(args.po)
    if not dest:
        sys.exit(f"post office {args.po} is not configured in po.json")
    cfg = po.post_office_cfg(dest)
    host, port = cfg["connect"].rsplit(":", 1)
    mode = {"LSEC": LSEC, "HSEC": HSEC, "RAW": RAW}[cfg.get("mode", "HSEC").upper()]
    sock = socket.create_connection((host, int(port)), timeout=30)
    sock.settimeout(None)
    try:
        call_post_office(po, dest, sock, mode, f"call-{dest}")
    except (LinkClosed, LinkTimeout, Refused) as e:
        log.info("call to %s ended: %s", dest, e)
    finally:
        sock.close()


def directory_cmd(args):
    """Queue a directory update (spec/directory-updates.md §5) for users: their clients apply it
    to their copy of the directory."""
    from . import directory
    po = PostOffice(args.data)
    po.gateway = Gateway(po)
    entries = directory.directory_entries(po)
    for name in args.delete or []:
        entries.append({"name": name, "kind": "L", "delete": True})
    for r in args.to:
        user = po.user(r)
        if not user:
            sys.exit(f"unknown user {r}")
        msg = directory.update_message(po.name, user, entries, cp=po.user_codepage(user))
        print(po.deposit(user, msg), "->", user, f"({len(entries)} entries)")


def ade_cmd(args):
    """Directory exchange with another post office (ade.py): queue a full synch, a synch request
    or an update with all our users; list what was learned. Sent at the next call."""
    from . import ade
    po = _admin_po(args)
    if args.action == "list":
        for e in sorted(ade.entries(po), key=lambda e: e["name"].lower()):
            print(f"{e['name']:30} {e.get('locn', ''):2} {e.get('addr', ''):14} via {e.get('via', ''):10} "
                  f"{e.get('cmts', '')}")
        return
    dest = po.post_office(args.po or "")
    if not dest or ade.partner_prop(po, dest) is None:
        sys.exit(f"{args.po} is not a post office with \"ade\" set in po.json")
    if args.action == "sync":
        print(ade.queue_synch(po, dest), "-> synch for", dest)
    elif args.action == "request":
        print(ade.queue_request(po, dest, everything=args.all), "-> synch request for", dest)
    elif args.action == "update":
        q = ade.queue_update(po, ade.local_records(po), only=dest)
        print("\n".join(f"{mid} -> update for {p}" for p, mid in q) or "nothing to send")


def _admin_po(args):
    po = PostOffice(args.data)
    po.gateway = Gateway(po)
    return po


def _report(queued, notify):
    if queued:
        print(f"directory update queued for {len(queued)} user(s): " + ", ".join(u for u, _ in queued))
    elif notify:
        print("no directory update needed")


def user_cmd(args):
    """Address book: users (po.json). Each change queues a directory update for the users."""
    from . import admin
    po = _admin_po(args)
    notify = not args.no_update
    try:
        if args.action == "list":
            for name, cmts, cp, waiting, locked in admin.list_users(po):
                flags = (" locked" if locked else "") + (f" cp{cp}" if cp else "")
                print(f"{name:30} {waiting:4} waiting{flags}  {cmts}")
            return
        if not args.name:
            sys.exit(f"{args.action} needs a name")
        if args.action == "add":
            if not args.password:
                sys.exit("--password is required")
            q = admin.add_user(po, args.name, args.password, args.comments, args.codepage, notify)
        elif args.action == "set":
            q = admin.set_user(po, args.name, args.comments, args.codepage, notify, email=args.email)
        elif args.action == "passwd":
            if not args.password:
                sys.exit("--password is required")
            admin.set_password(po, args.name, args.password)
            print(f"password of {po.user(args.name)} changed")
            return
        elif args.action == "rename":
            if not args.new:
                sys.exit("rename needs the new name")
            q = admin.rename_user(po, args.name, args.new, notify)
        elif args.action == "del":
            canon, lines = admin.user_state(po, args.name)
            print(f"Deleting user {canon} removes:")
            for line in lines or ["(no mail or other state)"]:
                print("  - " + line)
            print("Its files are moved to deleted/ in the data directory, not destroyed.")
            if not (args.yes or args.force):
                if not sys.stdin.isatty():
                    sys.exit("not deleted: confirm with --yes")
                if input(f"Delete {canon}? [y/N] ").strip().lower() not in ("y", "yes"):
                    sys.exit("not deleted")
            q = admin.delete_user(po, canon, True, notify)
    except admin.AdminError as e:
        sys.exit(str(e))
    print(f"{args.action}: done")
    _report(q, notify)


def po_cmd(args):
    """Address book: other post offices (po.json post_offices)."""
    from . import admin
    po = _admin_po(args)
    notify = not args.no_update
    try:
        if args.action == "list":
            for name, connect, mode, waiting in admin.list_post_offices(po):
                print(f"{name:20} {connect:22} {mode:5} {waiting:4} waiting")
            return
        if not args.name:
            sys.exit(f"{args.action} needs a name")
        if args.action == "add":
            q = admin.add_post_office(po, args.name, args.password, args.call_password, args.connect,
                                      args.mode, notify)
        elif args.action == "set":
            admin.set_post_office(po, args.name, password=args.password, call_password=args.call_password,
                                  connect=args.connect, mode=args.mode)
            q = []
            notify = False
        elif args.action == "del":
            q = admin.delete_post_office(po, args.name, args.force, notify)
    except admin.AdminError as e:
        sys.exit(str(e))
    print(f"{args.action}: done")
    _report(q, notify)


def fetch_cmd(args):
    """Fetch the users' internet mail accounts now (ccmail/fetch.py); print what was taken."""
    import imaplib
    import poplib
    import ssl
    from .fetch import Fetcher, FetchError
    from .gateway import ConfigError
    po = _admin_po(args)
    fetcher = Fetcher(po, po.gateway)
    users = [args.user] if args.user else fetcher.users()
    if args.user and not po.user(args.user):
        sys.exit(f"unknown user {args.user}")
    if not users:
        sys.exit('no user has a "fetch" entry in po.json')
    failed = False
    for user in users:
        user = po.user(user)
        try:
            taken = fetcher.fetch_user(user)
        except ConfigError as e:
            print(f"{user}: configuration: {e}")
            failed = True
            continue
        except (FetchError, OSError, poplib.error_proto, imaplib.IMAP4.error, ssl.SSLError) as e:
            print(f"{user}: failed: {type(e).__name__}: {e}")
            failed = True
            continue
        print(f"{user}: {len(taken)} new message(s)")
        for t in taken:
            print(f"  from {t['author']}: {t['subject']!r}")
    if failed:
        sys.exit(1)


def unlock(args):
    po = PostOffice(args.data)
    user = po.user(args.user)
    if not user:
        sys.exit(f"unknown user {args.user}")
    po.unlock(user)
    print(f"{user} unlocked")


def show(args):
    with open(args.file, "rb") as f:
        print(Message.from_file(f.read()).to_text())


def main():
    p = argparse.ArgumentParser(prog="ccmail.server")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--data", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, action="append",
                   help="TCP port to listen on (repeatable; default 5003 and 3264)")
    s.add_argument("--line-bps", type=int,
                   help="speed of the line behind the connection (e.g. a modem or serial bridge); "
                        "times retransmissions from when a frame has left the line")
    s.add_argument("--serial", help="serial device with a client that expects a Hayes modem "
                                    "(e.g. /dev/ttyUSB0); answers AT commands, CONNECT on dial")
    s.add_argument("--baud", type=int, default=9600, help="serial speed (the client's INI speed)")
    s.add_argument("--rtscts", action="store_true", help="hardware flow control on the serial port")
    s.add_argument("--capture", help="record every serial byte (tools/proxy.py .bin format)")
    s.add_argument("--serial-only", action="store_true", help="do not listen on TCP")
    s.set_defaults(func=serve)
    s = sub.add_parser("send")
    s.add_argument("--data", required=True)
    s.add_argument("--from", dest="author", required=True)
    s.add_argument("--to", action="append", required=True)
    s.add_argument("--subject", required=True)
    s.add_argument("--text", default="")
    s.add_argument("--file")
    s.add_argument("--priority", type=int, default=0, choices=(0, 1, 2))
    s.add_argument("--folder")
    s.add_argument("--attach", action="append", help="file to attach (repeatable)")
    s.set_defaults(func=send)
    s = sub.add_parser("call")
    s.add_argument("--data", required=True)
    s.add_argument("po", help="post office to call (configured in po.json post_offices)")
    s.set_defaults(func=call)
    s = sub.add_parser("directory", help="send the directory to users as a CCMUPDAT update")
    s.add_argument("--data", required=True)
    s.add_argument("--to", action="append", required=True)
    s.add_argument("--delete", action="append", help="also remove this entry from their directory")
    s.set_defaults(func=directory_cmd)
    s = sub.add_parser("user", help="address book: add, set, passwd, rename, del, list users")
    s.add_argument("--data", required=True)
    s.add_argument("action", choices=("add", "set", "passwd", "rename", "del", "list"))
    s.add_argument("name", nargs="?")
    s.add_argument("new", nargs="?", help="rename: the new name")
    s.add_argument("--password")
    s.add_argument("--comments", help="directory comment (empty string clears it here)")
    s.add_argument("--codepage", help="DOS code page of the user's PC (e.g. 866); empty clears it")
    s.add_argument("--email", help="set: the user's own internet address (From, inbound); empty clears it")
    s.add_argument("--force", action="store_true", help="del: same as --yes (kept for scripts)")
    s.add_argument("--yes", action="store_true", help="del: do not ask for confirmation")
    s.add_argument("--no-update", action="store_true", help="do not queue directory updates")
    s.set_defaults(func=user_cmd)
    s = sub.add_parser("po", help="address book: add, set, del, list other post offices")
    s.add_argument("--data", required=True)
    s.add_argument("action", choices=("add", "set", "del", "list"))
    s.add_argument("name", nargs="?")
    s.add_argument("--password", help="what that post office sends us")
    s.add_argument("--call-password", help="what we send when we call it")
    s.add_argument("--connect", help="host:port to call it at")
    s.add_argument("--mode", choices=("LSEC", "HSEC", "RAW"))
    s.add_argument("--force", action="store_true", help="del: even with mail waiting for it")
    s.add_argument("--no-update", action="store_true", help="do not queue directory updates")
    s.set_defaults(func=po_cmd)
    s = sub.add_parser("ade", help="directory exchange with another post office: sync, request, update, list")
    s.add_argument("--data", required=True)
    s.add_argument("action", choices=("sync", "request", "update", "list"))
    s.add_argument("po", nargs="?")
    s.add_argument("--all", action="store_true", help="request: ask for its whole directory (/directory)")
    s.set_defaults(func=ade_cmd)
    s = sub.add_parser("fetch", help="fetch the users' POP3/IMAP accounts now (po.json \"fetch\")")
    s.add_argument("--data", required=True)
    s.add_argument("user", nargs="?", help="only this user (default: every user with \"fetch\")")
    s.set_defaults(func=fetch_cmd)
    s = sub.add_parser("unlock")
    s.add_argument("--data", required=True)
    s.add_argument("user")
    s.set_defaults(func=unlock)
    s = sub.add_parser("show")
    s.add_argument("file")
    s.set_defaults(func=show)
    args = p.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(message)s")
    args.func(args)


if __name__ == "__main__":
    main()
