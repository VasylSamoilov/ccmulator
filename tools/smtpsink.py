#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Test SMTP server that stores every message as <dir>/<n>.eml (stand-in for the internet).

Usage: smtpsink.py PORT DIR
"""
import os
import socket
import sys
import threading

port, outdir = int(sys.argv[1]), sys.argv[2]
os.makedirs(outdir, exist_ok=True)
lock = threading.Lock()


def session(conn):
    f = conn.makefile("rb")
    send = lambda s: conn.sendall(s.encode() + b"\r\n")  # noqa: E731
    send("220 sink ESMTP")
    env = {"from": None, "rcpt": []}
    while True:
        line = f.readline()
        if not line:
            break
        cmd = line.decode("latin-1").strip()
        verb = cmd[:4].upper()
        if verb == "DATA":
            send("354 go ahead")
            data = bytearray()
            while True:
                ln = f.readline()
                if not ln or ln in (b".\r\n", b".\n"):
                    break
                data += ln[1:] if ln.startswith(b"..") else ln
            with lock:
                n = len([x for x in os.listdir(outdir) if x.endswith(".eml")]) + 1
                path = os.path.join(outdir, f"{n:04d}.eml")
                with open(path, "wb") as out:
                    out.write(f"X-Envelope-From: {env['from']}\r\nX-Envelope-To: {', '.join(env['rcpt'])}\r\n".encode())
                    out.write(data)
            print("stored", path, "for", env["rcpt"], flush=True)
            send("250 stored")
        elif verb == "MAIL":
            env = {"from": cmd[10:].strip(), "rcpt": []}
            send("250 OK")
        elif verb == "RCPT":
            env["rcpt"].append(cmd[8:].strip())
            send("250 OK")
        elif verb == "QUIT":
            send("221 bye")
            break
        else:
            send("250 OK")
    conn.close()


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(4)
print("sink on", port, flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=session, args=(c,), daemon=True).start()
