# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Shared helpers for the transport tests (serial emulation, serial URLs, real-modem driver,
Telnet): a post office copy in the scratch directory, line ends with expect(), a raw-mode client
login."""
import json
import os
import select
import shutil
import socket
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(os.environ.get("CCMAIL_TEST_DIR") or os.path.join(tempfile.gettempdir(), "ccmulator-tests"),
                    "transport-tests")


def make_po(name):
    from ccmail.store import PostOffice
    root = os.path.join(WORK, name)
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    with open(os.path.join(HERE, "data-test", "po.json"), encoding="utf-8") as f:
        conf = json.load(f)
    conf.pop("gateway", None)
    conf.pop("failed_attempts", None)
    with open(os.path.join(root, "po.json"), "w", encoding="utf-8") as f:
        json.dump(conf, f)
    return root, PostOffice(root)


class Line:
    """One end of a byte line (socket or pty fd) with a buffer: sendall, read(n), expect(text)."""

    def __init__(self, sock=None, fd=None):
        self.sock = sock
        self.fd = fd
        self.buf = b""

    def fileno(self):
        return self.sock.fileno() if self.sock else self.fd

    def sendall(self, data):
        if self.sock:
            self.sock.sendall(data)
        else:
            os.write(self.fd, data)

    def _more(self, timeout):
        r, _, _ = select.select([self], [], [], timeout)
        if not r:
            return False
        try:
            d = self.sock.recv(65536) if self.sock else os.read(self.fd, 65536)
        except OSError:
            d = b""
        if not d:
            raise EOFError(f"line closed, have {self.buf!r}")
        self.buf += d
        return True

    def expect(self, text, timeout=10):
        """Wait until `text` (bytes) is in the buffer; return everything up to and including it."""
        end = time.monotonic() + timeout
        while text not in self.buf:
            left = end - time.monotonic()
            if left <= 0:
                raise AssertionError(f"no {text!r} within {timeout} s, have {self.buf!r}")
            self._more(left)
        k = self.buf.index(text) + len(text)
        out, self.buf = self.buf[:k], self.buf[k:]
        return out

    def read(self, n, timeout=10):
        end = time.monotonic() + timeout
        while len(self.buf) < n:
            left = end - time.monotonic()
            if left <= 0:
                raise AssertionError(f"wanted {n} bytes, have {self.buf!r}")
            self._more(left)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def quiet(self, seconds):
        """Collect what arrives within `seconds` (no error on silence); returns it."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                self._more(max(0.0, end - time.monotonic()))
            except EOFError:
                break
        out, self.buf = self.buf, b""
        return out

    def close(self):
        if self.sock:
            self.sock.close()
        elif self.fd is not None:
            os.close(self.fd)


def lstring(s):
    b = s.encode("cp850") + b"\x00"
    return bytes([len(b)]) + b


def code(line, timeout=10):
    while True:
        c = line.read(1, timeout)[0]
        if c != 0x91:
            return c


def raw_login(line, user="user1", pw="123", first=b"\x80"):
    """Raw-mode (no packets) client login: 80 -> 81, name, 8B, password -> 82 + PO name; we 82.
    Returns the post office name the server sent."""
    line.sendall(first)
    assert code(line) == 0x81
    line.sendall(lstring(user))
    assert code(line) == 0x8B
    line.sendall(lstring(pw))
    c = code(line)
    assert c == 0x82, hex(c)
    n = line.read(1)[0]
    name = line.read(n)
    line.sendall(b"\x82")
    return name.split(b"\x00", 1)[0].decode("cp850")


def call_handler(po, calls, bps_seen=None):
    """A handler(sock[, line_bps]) running the real Call; records the line speeds it was given."""
    from ccmail.server import handle

    def h(sock, line_bps=None):
        if bps_seen is not None:
            bps_seen.append(line_bps)
        handle(sock, ("test", 0), po, next(calls), line_bps)
    return h


def counter():
    return iter(range(1, 1 << 30))


def tcp_server():
    """A listening socket on 127.0.0.1, port chosen by the system."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    return srv, srv.getsockname()[1]


def thread(target, *args):
    t = threading.Thread(target=target, args=args, daemon=True)
    t.start()
    return t


class SerialLike:
    """Settings and modem lines of a pyserial port as plain attributes; every setting change is
    recorded in .changes (what PortManager applied from the RFC 2217 client)."""
    RECORDED = ("baudrate", "bytesize", "parity", "stopbits", "xonxoff", "rtscts", "dtr", "rts")

    def __init__(self):
        self.__dict__["changes"] = []
        self.baudrate, self.bytesize, self.parity, self.stopbits = 9600, 8, "N", 1
        self.xonxoff = self.rtscts = False
        self.break_condition = False
        self.dtr = self.rts = False
        self.cts = self.dsr = True
        self.ri = False
        self.timeout = 0.2
        self.port = "fake"
        self.changes.clear()

    def __setattr__(self, k, v):
        if k in self.RECORDED:
            self.changes.append((k, v))
        object.__setattr__(self, k, v)

    def reset_input_buffer(self):
        pass

    def reset_output_buffer(self):
        pass


class CableDev(SerialLike):
    """A serial port whose other end of the cable is `far` (a Line): what we write arrives
    there and the reverse. DCD is always on (a null-modem cable from DTR)."""

    def __init__(self):
        super().__init__()
        a, b = socket.socketpair()
        self.wire = a
        self.far = Line(sock=b)
        self.cd = True
        self.closed = False

    @property
    def in_waiting(self):
        return 0

    def read(self, n=1):
        r, _, _ = select.select([self.wire], [], [], self.timeout)
        if not r:
            return b""
        d = self.wire.recv(max(n, 4096))
        if not d:
            raise OSError("cable closed")
        return d

    def write(self, data):
        self.wire.sendall(data)
        return len(data)

    def flush(self):
        pass

    def close(self):
        self.closed = True


class Rfc2217Server:
    """A one-connection RFC 2217 server (pyserial's PortManager) in front of `dev`, a
    pyserial-shaped object; settings and DTR/RTS the client sends land in dev.changes, its CD
    goes back as modem state notifications."""

    def __init__(self, dev):
        import serial.rfc2217
        self.dev = dev
        self.srv, self.port = tcp_server()
        self.stop = False
        self.rfc2217 = serial.rfc2217
        thread(self._run)

    def _run(self):
        conn, _ = self.srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        lock = threading.Lock()

        class W:
            def write(_, data):
                with lock:
                    conn.sendall(data)
        pm = self.rfc2217.PortManager(self.dev, W())

        def net_to_dev():
            while not self.stop:
                try:
                    d = conn.recv(4096)
                except OSError:
                    break
                if not d:
                    break
                out = b"".join(pm.filter(d))
                if out:
                    self.dev.write(out)
        thread(net_to_dev)
        while not self.stop:
            try:
                pm.check_modem_lines()
                d = self.dev.read(self.dev.in_waiting or 1)
                if d:
                    with lock:
                        conn.sendall(b"".join(pm.escape(d)))
            except OSError:
                break
        conn.close()

    def close(self):
        self.stop = True
        self.srv.close()


class DevSocketServer:
    """`dev` behind a plain TCP port (for socket://): no settings, no modem lines."""

    def __init__(self, dev):
        self.dev = dev
        self.srv, self.port = tcp_server()
        self.stop = False
        thread(self._run)

    def _run(self):
        conn, _ = self.srv.accept()

        def net_to_dev():
            while not self.stop:
                try:
                    d = conn.recv(4096)
                except OSError:
                    break
                if not d:
                    break
                self.dev.write(d)
        thread(net_to_dev)
        while not self.stop:
            try:
                d = self.dev.read(self.dev.in_waiting or 1)
                if d:
                    conn.sendall(d)
            except OSError:
                break
        conn.close()

    def close(self):
        self.stop = True
        self.srv.close()
