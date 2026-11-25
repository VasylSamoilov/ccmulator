#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Recording proxy between a cc:Mail client and a post office (both behind DOSBox-X modems).

Usage: proxy.py listen_port router_port logfile
The client's modem dials listen_port; the proxy connects to the post office's modem port
router_port (which rings the post office) and relays both ways, logging each chunk with time,
direction, hex and printable text. "R>" = client to post office, "<P" = post office to client.
A raw binary log is also written (logfile.bin): per chunk 1 byte direction (0=R>, 1=<P),
8 bytes little-endian microseconds, 4 bytes length, data.
"""
import select
import socket
import struct
import sys
import time

listen_port, router_port, logpath = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", listen_port))
srv.listen(1)
print(f"proxy {listen_port} -> {router_port}, log {logpath}", flush=True)

while True:
    remote, _ = srv.accept()
    router = socket.create_connection(("127.0.0.1", router_port))
    t0 = time.monotonic()
    txt = open(logpath, "a")
    binlog = open(logpath + ".bin", "ab")
    txt.write(f"---- call {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    peers = {remote: (router, "R>", 0), router: (remote, "<P", 1)}
    open_socks = [remote, router]
    while open_socks:
        r, _, _ = select.select(open_socks, [], [], 1.0)
        for s in r:
            data = s.recv(65536)
            other, tag, code = peers[s]
            t = time.monotonic() - t0
            if not data:
                txt.write(f"{t:9.3f} {tag} closed\n")
                open_socks = []
                break
            other.sendall(data)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            txt.write(f"{t:9.3f} {tag} {len(data):5d} {data.hex(' ')} |{text}|\n")
            txt.flush()
            binlog.write(struct.pack("<BQI", code, int(t * 1e6), len(data)) + data)
            binlog.flush()
    remote.close()
    router.close()
    txt.close()
    binlog.close()
