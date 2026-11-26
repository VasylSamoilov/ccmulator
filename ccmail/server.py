# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""cc:Mail post office for remote clients.

    python3 -m ccmail.server serve --data DIR [--port 5003]     answer calls arriving over TCP
    python3 -m ccmail.server send --data DIR --from A --to B --subject S [--file F | --text T]
    python3 -m ccmail.server show FILE.msg
    python3 -m ccmail.server user add|set|passwd|rename|del|list --data DIR [NAME [NEW]] [...]
    python3 -m ccmail.server po add|set|del|list --data DIR [NAME] [...]
    python3 -m ccmail.server fetch --data DIR [USER]              fetch internet mail accounts now

Connections (README.md, Connections): TCP ports carry raw session bytes (an emulator's modem,
newer clients on 3264) or Telnet (--telnet-port, ccmail/telnet.py); --serial DEV|URL is a serial
port (ccmail/serialport.py) with a client that expects a modem (ccmail/modem.py) or, with
--modem, our own modem (ccmail/hayes.py), which `call` also uses for po.json "dial" entries.
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
    err = check_serve_options(args)
    if err:
        sys.exit(err)
    po = PostOffice(args.data)
    counter = iter(range(1, 1 << 30))
    # the serial port first: a wrong setting or a busy port stops us before anything listens
    serial_start = start_serial(args, po, counter) if args.serial else None
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

    def listen(srv, port, telnet):
        log.info("post office %s, %d users, listening on %s:%d%s", po.name, len(po.users), args.host,
                 port, " (Telnet)" if telnet else "")
        while True:
            conn, addr = srv.accept()
            if telnet:
                from .telnet import serve_connection

                def tcall(sock, conn=conn, addr=addr):
                    handle(sock, addr, po, next(counter), args.line_bps)
                threading.Thread(target=serve_connection, args=(conn, tcall, f"telnet {addr[0]}:{addr[1]}"),
                                 daemon=True).start()
            else:
                threading.Thread(target=handle, args=(conn, addr, po, next(counter), args.line_bps),
                                 daemon=True).start()

    if serial_start:
        serial_start()

    # 3264 (0CC0h) is the port newer clients and peer post offices use over TCP/IP, raw session
    # bytes (newer-client-check.md item 12, router-to-router.md 1.2)
    listeners = []
    if not args.serial_only:
        listeners += [(p, bool(args.telnet)) for p in (args.port or [5003, 3264])]
    listeners += [(p, True) for p in (args.telnet_port or [])]
    if not listeners:
        threading.Event().wait()
    socks = []
    for p, telnet in listeners:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, p))
        srv.listen(4)
        socks.append((srv, p, telnet))
    for srv, p, telnet in socks[1:]:
        threading.Thread(target=listen, args=(srv, p, telnet), daemon=True).start()
    listen(*socks[0])


def check_serve_options(args):
    """Options that need --serial or --modem; returns an error text or None."""
    if not args.serial:
        given = [o for o, v in (("--baud", args.baud), ("--framing", args.framing), ("--flow", args.flow),
                                ("--rtscts", args.rtscts), ("--capture", args.capture),
                                ("--modem", args.modem), ("--serial-only", args.serial_only))
                 if v]
        if given:
            return f"only with --serial: {', '.join(given)}"
    if not args.modem:
        given = [o for o, v in (("--modem-init", args.modem_init),
                                ("--modem-autoanswer", args.modem_autoanswer is not None)) if v]
        if given:
            return f"only with --modem: {', '.join(given)}"
    if args.serial_only and args.telnet_port:
        return "--serial-only listens on no TCP port; leave out --telnet-port or --serial-only"
    if args.rtscts and args.flow and args.flow != "rtscts":
        return f"--rtscts contradicts --flow {args.flow}"
    return None


def start_serial(args, po, counter):
    """--serial: the modem emulator for a client on a cable, or (--modem) our own modem."""
    from .serialport import SettingsError, check_settings, describe, open_port, physical, Port, Capture
    flow = args.flow or ("rtscts" if args.rtscts else None)
    try:
        settings, warnings = check_settings(args.serial, args.baud, args.framing, flow,
                                            role="modem" if args.modem else "line")
        if args.modem:
            from .hayes import HayesModem, parse_init
            init = parse_init(args.modem_init)
    except SettingsError as e:
        sys.exit(f"--serial {args.serial}: {e}")
    for w in warnings:
        log.warning("%s: %s", args.serial, w)
    try:
        ser = open_port(args.serial, settings)
    except SettingsError as e:
        sys.exit(str(e))
    log.info("serial %s: %s", args.serial, describe(settings))
    if args.modem:
        port = Port(ser, Capture(args.capture), name="modem")
        try:
            modem = HayesModem(port, init, autoanswer=args.modem_autoanswer, name="modem")
        except SettingsError as e:
            sys.exit(f"--modem: {e}")

        def modem_call(sock, speed):
            bps = args.line_bps or speed
            if speed and speed == settings.get("baudrate") and not args.line_bps:
                log.warning("modem: CONNECT %d = the port speed: the modem may report its DTE speed, "
                            "not the line's (set it to report the carrier speed, e.g. ATW2 or S95, "
                            "or give --line-bps)", speed)
            if args.line_bps and speed and speed != args.line_bps:
                log.info("modem: CONNECT %s, link timed for --line-bps %d", speed, args.line_bps)
            handle(sock, (args.serial, speed or 0), po, next(counter), bps)

        target = (modem.serve, (modem_call,))
    else:
        from .modem import Modem
        speed = settings.get("baudrate") if physical(args.serial) else (args.line_bps or 9600)
        modem = Modem(ser, args.capture, name="serial", connect_speed=speed)
        bps = args.line_bps or speed

        def serial_call(sock):
            handle(sock, (args.serial, speed), po, next(counter), bps)

        target = (modem.serve, (serial_call,))
    return threading.Thread(target=target[0], args=target[1], daemon=True).start


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
    mode = {"LSEC": LSEC, "HSEC": HSEC, "RAW": RAW}[cfg.get("mode", "HSEC").upper()]
    if cfg.get("dial"):
        failed = call_by_modem(po, dest, capture=args.capture)
        if failed:
            sys.exit(f"call to {dest} failed: {failed}")
        return
    if not cfg.get("connect"):
        sys.exit(f'post office {dest} has neither "connect" (host:port) nor "dial" in po.json')
    host, port = cfg["connect"].rsplit(":", 1)
    sock = socket.create_connection((host, int(port)), timeout=30)
    sock.settimeout(None)
    try:
        call_post_office(po, dest, sock, mode, f"call-{dest}")
    except (LinkClosed, LinkTimeout, Refused) as e:
        log.info("call to %s ended: %s", dest, e)
    finally:
        sock.close()


def call_by_modem(po, dest, capture=None):
    """Call post office `dest` through a modem: po.json entry "dial" (e.g. "ATDT5551234"),
    "modem" (device or rfc2217:// URL), optional "baud", "framing", "flow" (the port to the
    modem), "modem_init" ("ATZ;AT E0 V1 Q0 &C1 &D2 S0=0" or a list). The call owns the port: a
    running `serve --modem` on the same device must be stopped first (a local device is opened
    exclusively, so the second opener fails). Returns None on success, else what failed."""
    from .hayes import DialFailed, HayesModem, ModemError, check_command, parse_init
    from .link import HSEC, LSEC, RAW
    from .serialport import Capture, Port, PortClosed, SettingsError, check_settings, open_port
    from .session import call_post_office
    cfg = po.post_office_cfg(dest)
    mode = {"LSEC": LSEC, "HSEC": HSEC, "RAW": RAW}[cfg.get("mode", "HSEC").upper()]
    url = cfg.get("modem")
    if not url:
        return f'po.json {dest}: "dial" needs "modem" (the device or rfc2217:// URL of our modem)'
    try:
        settings, warnings = check_settings(url, cfg.get("baud"), cfg.get("framing"), cfg.get("flow"),
                                            role="modem")
        init = parse_init(cfg.get("modem_init"))
        check_command(cfg["dial"], "dial string")
    except SettingsError as e:
        return f"po.json {dest}: {e}"
    for w in warnings:
        log.warning("%s: %s", url, w)
    try:
        ser = open_port(url, settings)
    except SettingsError as e:
        return f"{e} (the call needs the modem port to itself: is serve --modem using it?)"
    port = Port(ser, Capture(capture), name=f"modem-{dest}")
    modem = HayesModem(port, init, name=f"modem-{dest}")
    failed = None

    def run(sock, speed):
        try:
            call_post_office(po, dest, sock, mode, f"call-{dest}", line_bps=speed)
        except (LinkClosed, LinkTimeout, Refused) as e:
            log.info("call to %s ended: %s", dest, e)
        except Exception:
            log.exception("call to %s failed", dest)
        finally:
            sock.close()

    try:
        modem.init()
        speed, first = modem.dial(cfg["dial"])
        modem.run_call(run, speed, first)      # the session's own outcome is in the log
    except DialFailed as e:
        failed = f"{cfg['dial']}: {e.result}"
    except (ModemError, PortClosed) as e:
        failed = str(e)
    finally:
        try:
            modem.hangup()
        except Exception as e:
            log.info("hang-up: %s", e)
        port.close()
    return failed


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
    s = sub.add_parser("serve", formatter_class=argparse.RawDescriptionHelpFormatter,
                       description="Answer calls: TCP (raw bytes or Telnet) and/or a serial port "
                                   "(a client on a cable that expects a modem, or our own modem).",
                       epilog="examples:\n"
                              "  serve --data D                                   raw TCP on 5003 and 3264\n"
                              "  serve --data D --telnet-port 2323                + a Telnet port (tcpser, terminal servers)\n"
                              "  serve --data D --serial /dev/ttyUSB0 --baud 2400 --serial-only\n"
                              "                                                   HP 200LX on a cable (modem emulation)\n"
                              "  serve --data D --serial rfc2217://ts:7001 --baud 9600 --framing 8N1\n"
                              "  serve --data D --serial /dev/ttyS0 --modem --baud 38400 --flow rtscts\n"
                              "                                                   our own modem answers RING\n"
                              "See README.md, Connections.")
    s.add_argument("--data", required=True)
    s.add_argument("--host", default="127.0.0.1", help="address the TCP ports listen on")
    s.add_argument("--port", type=int, action="append",
                   help="TCP port carrying raw session bytes (repeatable; default 5003 and 3264)")
    s.add_argument("--telnet", action="store_true",
                   help="the --port ports (or 5003 and 3264) speak Telnet instead of raw bytes")
    s.add_argument("--telnet-port", type=int, action="append",
                   help="an extra TCP port that speaks Telnet (RFC 854/855; BINARY, SGA, RFC 2217 "
                        "COM-PORT-OPTION acknowledged); repeatable")
    s.add_argument("--line-bps", type=int,
                   help="speed of the line behind the connection (e.g. a modem or serial bridge); "
                        "times retransmissions from when a frame has left the line. "
                        "With --modem it overrides the CONNECT speed")
    g = s.add_argument_group("serial port (only with --serial)")
    g.add_argument("--serial", metavar="DEV|URL",
                   help="serial port: a device (/dev/ttyUSB0) or a pyserial URL (rfc2217://host:port, "
                        "socket://host:port, loop://). Without --modem: a client on it expects a "
                        "Hayes modem; we answer its AT commands and say CONNECT <port speed> on dial")
    g.add_argument("--baud", type=int,
                   help="port speed (default 9600); a rate the port takes (300..115200 typical). "
                        "Not for socket:// and loop:// (no physical port)")
    g.add_argument("--framing", metavar="8N1",
                   help="data bits 7/8, parity N/E/O/M/S, stop bits 1/2 (default 8N1); 7 bits = the "
                        "protocol's ASCII mode only")
    g.add_argument("--flow", choices=("none", "rtscts", "xonxoff", "dsrdtr"),
                   help="flow control (default none); xonxoff = ASCII mode only")
    g.add_argument("--rtscts", action="store_true", help="same as --flow rtscts (kept for scripts)")
    g.add_argument("--capture", help="record every serial byte (tools/proxy.py .bin format)")
    g.add_argument("--serial-only", action="store_true", help="do not listen on TCP at all")
    g = s.add_argument_group("our own modem on --serial (answer mode)")
    g.add_argument("--modem", action="store_true",
                   help="a real Hayes modem is on --serial: init it, answer RING with ATA, take the "
                        "line speed from CONNECT, hang up (DTR drop, +++ ATH0) after each call")
    g.add_argument("--modem-init", metavar='"ATZ;AT..."',
                   help='init commands separated by ";" (default "ATZ;AT E0 V1 Q0 &C1 &D2 S0=0"); '
                        "each must answer OK, at most 40 characters after AT")
    g.add_argument("--modem-autoanswer", type=int, metavar="N",
                   help="let the modem answer after N rings (adds ATS0=N) instead of ATA on RING")
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
    s = sub.add_parser("call", help="call another post office now: TCP (\"connect\") or a modem (\"dial\")")
    s.add_argument("--data", required=True)
    s.add_argument("po", help='post office to call (po.json post_offices: "connect": "host:port", or '
                              '"dial": "ATDT..." with "modem": DEV|rfc2217://..., optional "baud", '
                              '"framing", "flow", "modem_init"; the call needs the modem port to itself)')
    s.add_argument("--capture", help="with \"dial\": record every byte on the modem port")
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
