# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Serial ports for the server: local devices and pyserial URLs, their settings, and a port
object that works the same for every kind.

    /dev/ttyS0, /dev/ttyUSB0       a local device (opened exclusively)
    rfc2217://host:port            a network serial server (ser2net, terminal servers); pyserial's
                                   RFC 2217 client forwards speed, framing, flow control, DTR, RTS
                                   and reads DCD from the server's modem state notifications.
                                   Options: ?ign_set_control (servers that do not acknowledge
                                   SET-CONTROL, e.g. sredird), ?poll_modem (ask for the modem
                                   state when DCD is read), ?timeout=N (network timeout, s)
    socket://host:port             raw bytes over TCP: no physical port, no settings
    loop://                        loopback (tests): no physical port, no settings

Port settings (speed, framing, flow) are checked against what the port and the cc:Mail link can
do (check_settings) and applied only where there is a physical port (device, rfc2217://); for
socket:// and loop:// giving them is an error (there is nothing to set).

Port reads every byte of the pyserial object in a thread into a socket pair, so the modem loops
can select() on it whatever the port is (an RFC 2217 or loop port has no file descriptor).
"""
import logging
import re
import select
import socket
import struct
import threading
import time

log = logging.getLogger("ccmail.serial")

VIRTUAL = ("socket", "loop")            # URL schemes with no physical port behind them
FLOWS = ("none", "rtscts", "xonxoff", "dsrdtr")
# Speeds the clients know: the DOS client's CONNECT table, 300 and 1200..115200 (spec/link-layer.md
# §8: 1152, 576, 384, 192, 96, 48, 24, 12 x 100); the HP 200LX client's settings take 300..19200
# (spec/hp200lx-check.md §4).
REMOTE_SPEEDS = (300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200)
HP_SPEEDS = (300, 1200, 2400, 4800, 9600, 19200)


class SettingsError(ValueError):
    pass


def kind(url):
    """'device' for a path, else the URL scheme (rfc2217, socket, loop, spy, ...)."""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", url or "")
    return m.group(1).lower() if m else "device"


def physical(url):
    return kind(url) not in VIRTUAL


def parse_framing(text):
    """'8N1' -> (8, 'N', 1); '7E1', '8N2', '5N1.5' ... Data bits 5-8, parity N E O M S, stop
    bits 1, 1.5, 2. Raises SettingsError for anything else."""
    m = re.fullmatch(r"([5-8])([NEOMS])(1|1\.5|2)", (text or "").strip().upper())
    if not m:
        raise SettingsError(f"framing {text!r}: give data bits 5-8, parity N/E/O/M/S and stop bits "
                            f"1/1.5/2, e.g. 8N1, 7E1, 8N2")
    stop = float(m.group(3))
    return int(m.group(1)), m.group(2), (1.5 if stop == 1.5 else int(stop))


def check_settings(url, baud, framing, flow, role="line"):
    """Check the port settings given on the command line or in po.json; returns (settings,
    warnings). settings = dict for open_port (empty for socket:// and loop://).
    role = "line": the port is the cc:Mail line (emulation, null modem): its speed is the line
    speed. role = "modem": the port goes to our own modem (DTE speed; the line speed comes from
    CONNECT). Raises SettingsError with what is wrong."""
    import serial
    warnings = []
    if not physical(url):
        given = [n for n, v in (("--baud", baud), ("--framing", framing), ("--flow", flow)) if v]
        if given:
            raise SettingsError(f"{kind(url)}:// has no physical port; {', '.join(given)} "
                                f"cannot be applied (use --line-bps for the link timers)")
        return {}, warnings
    baud = 9600 if baud is None else baud
    rates = serial.Serial.BAUDRATES
    if baud not in rates:
        raise SettingsError(f"speed {baud}: not a rate the port takes; valid: "
                            + ", ".join(str(r) for r in rates))
    bits, parity, stop = parse_framing(framing or "8N1")
    if bits < 7:
        raise SettingsError(f"framing {framing}: {bits} data bits cannot carry cc:Mail (even its "
                            f"ASCII packets use characters 20h-6Fh, 7 bits); use 8N1 or 7E1/7O1/7N1")
    if stop == 1.5:
        raise SettingsError(f"framing {framing}: 1.5 stop bits exist only with 5 data bits (UART), "
                            f"and 5 data bits cannot carry cc:Mail; use 1 or 2 stop bits")
    flow = (flow or "none").lower()
    if flow not in FLOWS:
        raise SettingsError(f"flow {flow!r}: one of {', '.join(FLOWS)}")
    if bits == 7:
        warnings.append(f"framing {bits}{parity}{stop}: 7 data bits carry only the ASCII packet mode "
                        f"(the client must use it: Remote COMM/ASCII, the HP 200LX AsciiMode); binary "
                        f"packets and raw mode need 8 data bits (spec/link-layer.md §3.1)")
    if flow == "xonxoff":
        warnings.append("flow xonxoff: binary frames contain 11h/13h, so only the ASCII packet mode "
                        "works (Remote COMM/ASCII; spec/link-layer.md §3.1); the port's driver "
                        "takes XON/XOFF out of the data")
    if role == "line":
        if baud not in REMOTE_SPEEDS:
            warnings.append(f"speed {baud}: not a speed the cc:Mail clients know (Remote: 300, "
                            f"1200-115200; HP 200LX: 300-19200). Remote counts an unknown CONNECT "
                            f"speed as its configured one and uses its 70h-tick (6.2 s) timer set; "
                            f"our link uses 6.2 s timers at every speed and a line clock "
                            f"of {baud} bps")
        elif baud not in HP_SPEEDS:
            warnings.append(f"speed {baud}: the HP 200LX takes 300-19200 bps only (its INI); "
                            f"Remote knows it (70h-tick, 6.2 s timer set above 2400 bps)")
    settings = {"baudrate": baud, "bytesize": bits, "parity": parity,
                "stopbits": stop, "flow": flow}
    return settings, warnings


def describe(settings):
    if not settings:
        return "no port settings"
    s = settings
    stop = s["stopbits"]
    return f"{s['baudrate']} bps {s['bytesize']}{s['parity']}{stop} flow {s['flow']}"


_PARITY = {"N": "N", "E": "E", "O": "O", "M": "M", "S": "S"}


def open_port(url, settings=None, timeout=0.2):
    """Open a device or URL with checked settings (check_settings). DTR and RTS are raised
    (unless the flow control drives them), where the port has them."""
    import serial
    settings = dict(settings or {})
    kw = {"timeout": timeout}
    if settings:
        flow = settings.pop("flow", "none")
        kw.update(baudrate=settings["baudrate"], bytesize=settings["bytesize"],
                  parity=_PARITY[settings["parity"]], stopbits=settings["stopbits"],
                  rtscts=flow == "rtscts", xonxoff=flow == "xonxoff", dsrdtr=flow == "dsrdtr")
    else:
        flow = "none"
    if kind(url) == "device":
        kw["exclusive"] = True
    try:
        ser = serial.serial_for_url(url, **kw)
    except ValueError as e:
        raise SettingsError(f"{url}: the port refused the settings: {e}") from e
    except serial.SerialException as e:
        raise SettingsError(f"{url}: cannot open: {e}") from e
    if physical(url):
        lines = []
        if flow != "dsrdtr":
            lines.append("dtr")
        if flow != "rtscts":
            lines.append("rts")
        for line in lines:
            try:
                setattr(ser, line, True)
            except Exception as e:           # a pty (tests) has no modem lines
                log.info("%s: cannot set %s: %s", url, line.upper(), e)
    return ser


class Capture:
    """--capture: every chunk in tools/proxy.py's binary form (1 byte direction: 0 = from the
    port, 1 = to the port; 8 bytes microseconds; 4 bytes length; data)."""

    def __init__(self, path):
        self.f = open(path, "ab") if path else None
        self.t0 = time.monotonic()
        self.lock = threading.Lock()

    def write(self, direction, data):
        if self.f and data:
            t = int((time.monotonic() - self.t0) * 1e6)
            with self.lock:
                self.f.write(struct.pack("<BQI", direction, t, len(data)) + data)
                self.f.flush()


class PortClosed(Exception):
    pass


class Port:
    """A pyserial port read by a thread: select() on it (fileno), read(timeout), write().
    The reader stops when the port fails or is closed; then read() raises PortClosed."""

    def __init__(self, ser, capture=None, name="port"):
        self.ser = ser
        self.name = name
        self.capture = capture if capture is not None else Capture(None)
        self._rx, self._feed = socket.socketpair()
        self._stop = False
        self._warned = set()
        self._wlock = threading.Lock()
        self._thread = threading.Thread(target=self._reader, name=f"{name}-reader", daemon=True)
        self._thread.start()

    @property
    def port(self):
        return getattr(self.ser, "port", None) or getattr(self.ser, "portstr", "?")

    def _reader(self):
        try:
            while not self._stop:
                data = self.ser.read(self.ser.in_waiting or 1)
                if data:
                    self.capture.write(0, data)
                    self._feed.sendall(data)
        except Exception as e:
            if not self._stop:
                log.warning("%s: port read failed: %s", self.name, e)
        finally:
            try:
                self._feed.close()
            except OSError:
                pass

    def fileno(self):
        return self._rx.fileno()

    def read(self, timeout=0.0):
        """What has arrived (waiting up to `timeout` s for something); b"" if nothing."""
        r, _, _ = select.select([self._rx], [], [], timeout)
        if not r:
            return b""
        data = self._rx.recv(65536)
        if not data:
            raise PortClosed(f"{self.name}: port closed")
        return data

    def write(self, data):
        if not data:
            return
        with self._wlock:
            self.capture.write(1, data)
            self.ser.write(data)
            try:
                self.ser.flush()
            except Exception:
                pass

    def set_line(self, line, value):
        """Set DTR or RTS where the port has it; a failure is logged once per line."""
        try:
            setattr(self.ser, line, value)
            return True
        except Exception as e:
            if line not in self._warned:
                self._warned.add(line)
                log.info("%s: cannot set %s (%s); not used", self.name, line.upper(), e)
            return False

    def carrier(self):
        """DCD: True/False, or None where it cannot be read."""
        try:
            return bool(self.ser.cd)
        except Exception:
            return None

    def close(self):
        self._stop = True
        try:
            self.ser.close()
        except Exception:
            pass
        self._thread.join(2)
        self._rx.close()
