#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Line simulator between a client (DOSBox modem) and the server: a real link's speed and noise.

Usage: linesim.py LISTEN_PORT SERVER_PORT LOG [--bps N] [--ber P] [--drop P] [--burst P] [--seed S]

- --bps N    throttle each direction to N bits/s (10 bits per byte, like 8N1 async)
- --ber P    probability per BIT of flipping it (e.g. 1e-4 = about one error per 1000 bytes)
- --drop P   probability per BYTE of losing it
- --burst P  probability per byte of starting a noise burst (8..64 bytes of random garbage
             replacing the line, like a click on an analog line)
Every injected error is logged with its position, so failures can be traced to the frame they hit.
"""
import argparse
import random
import select
import socket
import struct
import time

ap = argparse.ArgumentParser()
ap.add_argument("listen", type=int)
ap.add_argument("server", type=int)
ap.add_argument("log")
ap.add_argument("--bps", type=int, default=0)
ap.add_argument("--ber", type=float, default=0.0)
ap.add_argument("--drop", type=float, default=0.0)
ap.add_argument("--burst", type=float, default=0.0)
ap.add_argument("--seed", type=int, default=1)
a = ap.parse_args()
rng = random.Random(a.seed)
logf = open(a.log, "a")


def log(msg):
    logf.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    logf.flush()


def damage(data, tag, counters):
    out = bytearray()
    burst = 0
    for b in data:
        counters["bytes"] += 1
        if burst:
            out.append(rng.randrange(256))
            burst -= 1
            continue
        if a.burst and rng.random() < a.burst:
            burst = rng.randrange(8, 65)
            counters["bursts"] += 1
            log(f"{tag} burst of {burst} bytes at byte {counters['bytes']}")
            out.append(rng.randrange(256))
            continue
        if a.drop and rng.random() < a.drop:
            counters["drops"] += 1
            log(f"{tag} dropped byte {counters['bytes']} ({b:02x})")
            continue
        if a.ber:
            for bit in range(8):
                if rng.random() < a.ber:
                    b ^= 1 << bit
                    counters["flips"] += 1
                    log(f"{tag} bit flip at byte {counters['bytes']} bit {bit}")
        out.append(b)
    return bytes(out)


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", a.listen))
srv.listen(1)
log(f"line {a.listen} -> {a.server}: bps={a.bps} ber={a.ber} drop={a.drop} burst={a.burst} seed={a.seed}")
while True:
    client, _ = srv.accept()
    server = socket.create_connection(("127.0.0.1", a.server))
    peers = {client: (server, "C>"), server: (client, "<S")}
    queues = {client: bytearray(), server: bytearray()}     # bytes waiting to go out to that socket
    stats = {"C>": dict(bytes=0, flips=0, drops=0, bursts=0), "<S": dict(bytes=0, flips=0, drops=0, bursts=0)}
    next_send = {client: 0.0, server: 0.0}
    byte_time = 10.0 / a.bps if a.bps else 0.0
    open_ = True
    t0 = time.monotonic()
    binlog = open(a.log + ".bin", "ab")
    log("call start")
    while open_:
        r, _, _ = select.select([client, server], [], [], 0.002)
        for s in r:
            data = s.recv(4096)
            if not data:
                open_ = False
                break
            other, tag = peers[s]
            damaged = damage(data, tag, stats[tag])
            queues[other] += damaged
            # what the far side actually receives, in tools/proxy.py's binary format
            # (direction 0 = client -> server, 1 = server -> client), for tools/frames.py
            binlog.write(struct.pack("<BQI", 0 if tag == "C>" else 1,
                                     int((time.monotonic() - t0) * 1e6), len(damaged)) + damaged)
            binlog.flush()
        now = time.monotonic()
        for s in (client, server):
            q = queues[s]
            if not q:
                continue
            if not byte_time:
                s.sendall(bytes(q))
                q.clear()
                continue
            # pace the line: send as many bytes as the elapsed time allows
            if next_send[s] < now - 0.05:
                next_send[s] = now
            n = 0
            while q and next_send[s] <= now:
                n += 1
                next_send[s] += byte_time
                if n > len(q):
                    break
            if n:
                s.sendall(bytes(q[:n]))
                del q[:n]
    client.close()
    server.close()
    log(f"call end: {stats}")
