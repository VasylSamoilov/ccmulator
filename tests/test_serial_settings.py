# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Serial port settings (ccmail/serialport.py) and the serve options that need a port: parsing
of --framing, the limits (speeds the port takes, 5/6 data bits and 1.5 stop bits refused,
flow), the warnings (7 bits, XON/XOFF, speeds the clients do not know), no settings for
socket:// and loop://, and the settings reaching the pyserial object. Needs pyserial (skipped
without it)."""
import argparse
import unittest

try:
    import serial
except ImportError:
    raise unittest.SkipTest("needs pyserial")

from ccmail import server
from ccmail.serialport import (SettingsError, check_settings, kind, open_port, parse_framing,
                               physical)


class FramingTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_framing("8N1"), (8, "N", 1))
        self.assertEqual(parse_framing("7e1"), (7, "E", 1))
        self.assertEqual(parse_framing("8O2"), (8, "O", 2))
        self.assertEqual(parse_framing("7M1"), (7, "M", 1))
        self.assertEqual(parse_framing("5N1.5"), (5, "N", 1.5))
        for bad in ("9N1", "8X1", "8N3", "8N", "N81", "", "8N1.0"):
            with self.assertRaises(SettingsError, msg=bad):
                parse_framing(bad)


class LimitsTest(unittest.TestCase):
    dev = "/dev/ttyS9"          # never opened here

    def check(self, *a, **kw):
        return check_settings(self.dev, *a, **kw)

    def test_defaults(self):
        s, w = self.check(None, None, None)
        self.assertEqual(s, {"baudrate": 9600, "bytesize": 8, "parity": "N", "stopbits": 1, "flow": "none"})
        self.assertEqual(w, [])

    def test_speed_must_be_a_port_rate(self):
        with self.assertRaises(SettingsError) as e:
            self.check(2500, None, None)
        self.assertIn("2500", str(e.exception))
        self.assertIn("115200", str(e.exception))        # the valid list is given

    def test_five_six_bits_refused(self):
        for f in ("5N1", "6E1", "6N2"):
            with self.assertRaises(SettingsError) as e:
                self.check(2400, f, None)
            self.assertIn("cannot carry cc:Mail", str(e.exception))

    def test_one_and_a_half_stop_refused(self):
        for f in ("8N1.5", "7E1.5"):
            with self.assertRaises(SettingsError) as e:
                self.check(2400, f, None)
            self.assertIn("1.5 stop bits", str(e.exception))

    def test_flow(self):
        with self.assertRaises(SettingsError):
            self.check(2400, None, "hardware")
        for f in ("none", "rtscts", "dsrdtr"):
            self.assertEqual(self.check(2400, None, f)[1], [])

    def test_ascii_only_warnings(self):
        s, w = self.check(2400, "7E1", None)
        self.assertEqual((s["bytesize"], s["parity"]), (7, "E"))
        self.assertEqual(len(w), 1)
        self.assertIn("ASCII packet mode", w[0])
        s, w = self.check(2400, "8N1", "xonxoff")
        self.assertEqual(len(w), 1)
        self.assertIn("11h/13h", w[0])

    def test_speed_warnings(self):
        self.assertEqual(self.check(19200, None, None)[1], [])
        w = self.check(38400, None, None)[1]
        self.assertEqual(len(w), 1)
        self.assertIn("HP 200LX takes 300-19200", w[0])
        w = self.check(600, None, None)[1]
        self.assertIn("not a speed the cc:Mail clients know", w[0])
        self.assertIn("6.2 s", w[0])
        # the port to our own modem: DTE speed, the line speed comes from CONNECT
        self.assertEqual(self.check(115200, None, None, role="modem")[1], [])
        self.assertEqual(self.check(600, None, None, role="modem")[1], [])

    def test_rfc2217_same_limits(self):
        with self.assertRaises(SettingsError):
            check_settings("rfc2217://h:1", 1234, None, None)
        s, _ = check_settings("rfc2217://h:1", 2400, "8E1", "rtscts")
        self.assertEqual(s["parity"], "E")


class VirtualPortTest(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(kind("/dev/ttyUSB0"), "device")
        self.assertEqual(kind("rfc2217://h:1"), "rfc2217")
        self.assertEqual(kind("socket://h:1"), "socket")
        self.assertFalse(physical("loop://"))
        self.assertTrue(physical("rfc2217://h:1"))

    def test_no_settings_for_socket_and_loop(self):
        self.assertEqual(check_settings("loop://", None, None, None), ({}, []))
        for url in ("loop://", "socket://127.0.0.1:1"):
            with self.assertRaises(SettingsError) as e:
                check_settings(url, 2400, None, None)
            self.assertIn("no physical port", str(e.exception))
            self.assertIn("--baud", str(e.exception))
            with self.assertRaises(SettingsError):
                check_settings(url, None, "7E1", "xonxoff")

    def test_loop_port_opens(self):
        ser = open_port("loop://")
        ser.write(b"abc")
        self.assertEqual(ser.read(3), b"abc")
        ser.close()


class ApplyTest(unittest.TestCase):
    """The checked settings reach the pyserial object (here a loop:// object configured by
    hand, since loop:// itself takes none; RFC 2217 is in test_modem_emulation/test_hayes)."""

    def test_kwargs(self):
        captured = {}
        real = serial.serial_for_url

        def fake(url, **kw):
            captured.update(kw)
            return real("loop://", do_not_open=False)
        serial.serial_for_url = fake
        try:
            s, _ = check_settings("/dev/ttyS9", 4800, "7O2", "xonxoff")
            open_port("/dev/ttyS9", s).close()
        finally:
            serial.serial_for_url = real
        self.assertEqual((captured["baudrate"], captured["bytesize"], captured["parity"],
                          captured["stopbits"]), (4800, 7, "O", 2))
        self.assertEqual((captured["xonxoff"], captured["rtscts"], captured["dsrdtr"]), (True, False, False))
        self.assertTrue(captured["exclusive"])


class ServeOptionsTest(unittest.TestCase):
    def args(self, **kw):
        base = dict(serial=None, baud=None, framing=None, flow=None, rtscts=False, capture=None,
                    modem=False, serial_only=False, modem_init=None, modem_autoanswer=None,
                    telnet_port=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_port_options_need_serial(self):
        self.assertIn("--baud", server.check_serve_options(self.args(baud=2400)))
        self.assertIn("--modem", server.check_serve_options(self.args(modem=True)))
        self.assertIn("--framing", server.check_serve_options(self.args(framing="8N1")))
        self.assertIsNone(server.check_serve_options(self.args()))
        self.assertIsNone(server.check_serve_options(self.args(serial="/dev/x", baud=2400)))

    def test_modem_options_need_modem(self):
        self.assertIn("--modem-init", server.check_serve_options(self.args(serial="/dev/x", modem_init="ATZ")))
        self.assertIn("--modem-autoanswer",
                      server.check_serve_options(self.args(serial="/dev/x", modem_autoanswer=2)))
        self.assertIsNone(server.check_serve_options(self.args(serial="/dev/x", modem=True, modem_autoanswer=2)))

    def test_contradictions(self):
        self.assertIn("--rtscts", server.check_serve_options(self.args(serial="/dev/x", rtscts=True, flow="xonxoff")))
        self.assertIn("--serial-only", server.check_serve_options(
            self.args(serial="/dev/x", serial_only=True, telnet_port=[2323])))


if __name__ == "__main__":
    unittest.main()
