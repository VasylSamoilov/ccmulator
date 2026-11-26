# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Our own Hayes modem (ccmail/hayes.py) against a scripted fake modem (tests/fakemodem.py):
init with OK and retries, RING -> ATA -> CONNECT and the speed taken from it (CONNECT 2400,
CONNECT 14400/ARQ, bare CONNECT, CARRIER before CONNECT), auto answer, a real Call over the line,
hang-up by DTR drop (and +++ ATH0 where DTR does nothing), re-init, carrier loss by DCD and by
NO CARRIER, NO CARRIER inside data, and dial-out to another post office (BUSY and success).
The fake modem is used directly, behind rfc2217:// (PortManager) and behind socket://.
Needs pyserial (skipped without it)."""
import json
import os
import shutil
import socket
import time
import unittest

try:
    import serial  # noqa: F401
except ImportError:
    raise unittest.SkipTest("needs pyserial")

from ccmail import hayes, server
from ccmail.hayes import HayesModem, connect_speed, DialFailed
from ccmail.serialport import Port, SettingsError, open_port
from ccmail.store import PostOffice
from fakemodem import FakeModem
from linekit import (CableDev, DevSocketServer, Rfc2217Server, WORK, call_handler, counter, raw_login,
                     thread)

FAST = dict(ok_timeout=0.6, atz_pause=0.05, guard=0.5, dtr_drop=0.2, drain_pause=0.1, silence=0.3,
            dcd_poll=0.1, reinit_wait=0.2, answer_timeout=5, dial_timeout=5)


def fast(m):
    for k, v in FAST.items():
        setattr(m, k, v)
    return m


def wait_for(cond, timeout=10, what="condition"):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


class SpeedParseTest(unittest.TestCase):
    def test_connect_lines(self):
        self.assertEqual(connect_speed("CONNECT"), 300)
        self.assertEqual(connect_speed("CONNECT 2400"), 2400)
        self.assertEqual(connect_speed("CONNECT 14400/ARQ"), 14400)
        self.assertEqual(connect_speed("CONNECT 9600/V42BIS"), 9600)
        self.assertIsNone(connect_speed("CONNECT FAST"))

    def test_init_strings(self):
        self.assertEqual(hayes.parse_init(None), hayes.DEFAULT_INIT)
        self.assertEqual(hayes.parse_init("ATZ; AT&F E0 ;"), ("ATZ", "AT&F E0"))
        for bad, why in (("ATZ\r", "printable"), ("ATZ;XYZ", "start with AT"),
                         ("AT" + "S0=0" * 11, "at most 40"), ("AT\x1bZ", "printable")):
            with self.assertRaises(SettingsError) as e:
                hayes.parse_init(bad)
            self.assertIn(why, str(e.exception))
        with self.assertRaises(SettingsError):
            hayes.check_command("ATDT555\n1234", "dial string")
        with self.assertRaises(SettingsError):
            HayesModem(None, autoanswer=0)


class AnswerCase:
    """A post office answering through HayesModem.serve() on a fake modem."""
    connect = "CONNECT 2400"
    pre_connect = ()
    autoanswer = None
    has_dcd = True

    def make_port(self, fake):
        return Port(fake, name="modem")

    def setUp(self):
        name = "hayes-" + self.id().rsplit(".", 2)[-2] + "-" + self.id().rsplit(".", 1)[-1]
        from linekit import make_po
        self.root, self.po = make_po(name)
        self.fake = FakeModem(self.connect, has_dcd=self.has_dcd, pre_connect=self.pre_connect)
        self.port = self.make_port(self.fake)
        self.m = fast(HayesModem(self.port, autoanswer=self.autoanswer))
        self.bps = []
        self.ends = []
        orig = self.m.run_call

        def run_call(*a):
            why = orig(*a)
            self.ends.append(why)
            return why
        self.m.run_call = run_call
        self.t = thread(self.m.serve, call_handler(self.po, counter(), self.bps), 2)

    def tearDown(self):
        self.port.close()
        self.fake.close()

    def initialised(self, n=1):
        wait_for(lambda: self.fake.commands.count(hayes.DEFAULT_INIT[1]) >= n, what=f"init {n}")
        time.sleep(0.1)

    def call(self):
        self.fake.ring()
        wait_for(lambda: self.fake.far_line is not None and self.fake.online, what="CONNECT")
        far = self.fake.far_line
        self.assertEqual(raw_login(far), "MYPOST")
        return far


class AnswerDirectTest(AnswerCase, unittest.TestCase):
    def test_answer_call_hangup_reinit(self):
        self.initialised()
        self.assertEqual(self.fake.commands[:2], ["ATZ", "AT E0 V1 Q0 &C1 &D2 S0=0"])
        far = self.call()
        self.assertIn("ATA", self.fake.commands)
        far.sendall(b"\x88")                      # nothing to upload: server's turn, its 88
        far.expect(b"\x88")
        wait_for(lambda: self.ends, what="call end")
        self.assertEqual(self.ends[0], "session ended")
        self.assertEqual(self.bps, [2400])
        wait_for(lambda: ("hangup", "dtr") in self.fake.events, what="DTR hang-up")
        self.assertIn(("dtr", False), self.fake.events)
        self.initialised(2)                       # re-init after the call
        i = self.fake.commands.index("ATA")
        self.assertIn("ATH0", self.fake.commands[i:])
        self.assertIn("ATZ", self.fake.commands[i:])

    def test_carrier_lost_dcd(self):
        self.initialised()
        far = self.call()
        self.fake.drop()                          # far end hangs up mid-call
        wait_for(lambda: self.ends, what="call end")
        self.assertEqual(self.ends[0], "carrier lost (DCD)")
        self.initialised(2)


class NoDcdTest(AnswerCase, unittest.TestCase):
    has_dcd = False                               # cable without DCD: only NO CARRIER tells

    def test_no_carrier_result(self):
        self.initialised()
        self.call()
        self.fake.drop()
        wait_for(lambda: self.ends, what="call end")
        self.assertEqual(self.ends[0], "NO CARRIER")
        self.initialised(2)


class Connect14400Test(AnswerCase, unittest.TestCase):
    connect = "CONNECT 14400/ARQ"

    def test_speed(self):
        self.initialised()
        far = self.call()
        self.assertEqual(self.bps, [14400])
        far.close()


class BareConnectTest(AnswerCase, unittest.TestCase):
    connect = "CONNECT"

    def test_speed(self):
        self.initialised()
        far = self.call()
        self.assertEqual(self.bps, [300])
        far.close()


class CarrierLineTest(AnswerCase, unittest.TestCase):
    connect = "CONNECT 38400"                     # DTE speed; CARRIER is the line
    pre_connect = ("CARRIER 9600", "PROTOCOL: LAPM")

    def test_speed(self):
        self.initialised()
        far = self.call()
        self.assertEqual(self.bps, [9600])
        far.close()


class AutoAnswerTest(AnswerCase, unittest.TestCase):
    autoanswer = 2

    def test_s0(self):
        wait_for(lambda: "ATS0=2" in self.fake.commands, what="ATS0=2")
        time.sleep(0.1)
        self.fake.ring()
        time.sleep(0.2)
        self.assertFalse(self.fake.online)
        self.fake.ring()                          # the modem answers by itself
        wait_for(lambda: self.fake.online and self.bps, what="auto answer")
        self.assertNotIn("ATA", self.fake.commands)
        self.assertEqual(raw_login(self.fake.far_line), "MYPOST")
        self.assertEqual(self.bps, [2400])


class Rfc2217ModemTest(AnswerCase, unittest.TestCase):
    """The fake modem behind an RFC 2217 server: settings, DTR and DCD go over the network."""

    def make_port(self, fake):
        from ccmail.serialport import check_settings
        self.server = Rfc2217Server(fake)
        settings, _ = check_settings("rfc2217://x", 38400, "8N1", "rtscts", role="modem")
        ser = open_port(f"rfc2217://127.0.0.1:{self.server.port}", settings)
        return Port(ser, name="modem")

    def tearDown(self):
        super().tearDown()
        self.server.close()

    def test_answer_dcd_dtr(self):
        self.assertIn(("baudrate", 38400), self.fake.changes)
        self.assertIn(("rtscts", True), self.fake.changes)
        self.initialised()
        self.call()
        self.fake.drop()
        wait_for(lambda: self.ends, what="call end")
        self.assertEqual(self.ends[0], "carrier lost (DCD)")
        wait_for(lambda: ("dtr", False) in self.fake.events, what="DTR drop over RFC 2217")
        self.initialised(2)


class SocketModemTest(AnswerCase, unittest.TestCase):
    """socket://: no DTR, no DCD. The hang-up needs +++ and ATH0."""

    def make_port(self, fake):
        self.server = DevSocketServer(fake)
        ser = open_port(f"socket://127.0.0.1:{self.server.port}")
        return Port(ser, name="modem")

    def tearDown(self):
        super().tearDown()
        self.server.close()

    def test_hangup_by_escape(self):
        self.initialised()
        far = self.call()
        far.sendall(b"\x88")
        far.expect(b"\x88")
        wait_for(lambda: ("hangup", "ATH") in self.fake.events, timeout=15, what="ATH0 hang-up")
        self.assertIn(("escape",), self.fake.events)
        self.assertNotIn(("hangup", "dtr"), self.fake.events)
        self.initialised(2)


class DataModeTest(unittest.TestCase):
    """data_mode() on its own: the far end's +++ and the text NO CARRIER are data."""

    def test_no_carrier_inside_data(self):
        dev = CableDev()
        port = Port(dev)
        m = fast(HayesModem(port))
        ours, theirs = socket.socketpair()
        out = {}
        t = thread(lambda: out.setdefault("why", m.data_mode(ours)))
        dev.far.sendall(b"text\r\nNO CARRIER\r\nmore")
        time.sleep(0.6)
        dev.far.sendall(b"\r\nNO CARRIER\r\n")
        time.sleep(0.1)
        dev.far.sendall(b"x+++y")                  # within the silence: still data
        time.sleep(0.6)
        self.assertNotIn("why", out)
        got = b""
        theirs.settimeout(1)
        while b"x+++y" not in got:
            got += theirs.recv(100)
        self.assertEqual(got, b"text\r\nNO CARRIER\r\nmore\r\nNO CARRIER\r\nx+++y")
        dev.far.sendall(b"\r\nNO CARRIER\r\n")    # at the end, then quiet: carrier lost
        t.join(3)
        self.assertEqual(out["why"], "NO CARRIER")
        port.close()
        ours.close()
        theirs.close()


class StrayBytesTest(unittest.TestCase):
    """The session closes at once while the far end keeps sending: the next call is answered."""

    def test_next_call_answered(self):
        fake = FakeModem()
        port = Port(fake)
        m = fast(HayesModem(port))
        seen = []

        def handler(sock, bps):
            seen.append(bps)
            sock.close()
        thread(m.serve, handler, 2)

        def flood(far):
            try:
                for _ in range(500):
                    far.sendall(b"x" * 200)
                    time.sleep(0.002)
            except OSError:
                pass
        for n in (1, 2):
            wait_for(lambda: fake.commands.count(hayes.DEFAULT_INIT[1]) >= n, what=f"init {n}")
            time.sleep(0.1)
            fake.ring()
            wait_for(lambda: fake.online, what="CONNECT")
            thread(flood, fake.far_line)
            wait_for(lambda: len(seen) >= n, what=f"call {n}")
            wait_for(lambda: fake.events.count(("hangup", "dtr")) >= n, what=f"hang-up {n}")
        self.assertEqual(seen, [2400, 2400])
        port.close()


class InitTest(unittest.TestCase):
    def test_retry_after_silence(self):
        fake = FakeModem(silent_rounds=1)          # the first ATZ gets no answer
        port = Port(fake)
        m = fast(HayesModem(port))
        m.init()
        self.assertEqual(fake.commands, ["ATZ", "ATZ", "AT E0 V1 Q0 &C1 &D2 S0=0"])
        self.assertIn(("dtr", False), fake.events)  # DTR toggled between the rounds
        port.close()

    def test_no_answer_fails(self):
        fake = FakeModem(silent_rounds=99)
        port = Port(fake)
        m = fast(HayesModem(port))
        m.retries = 2
        with self.assertRaises(hayes.ModemError):
            m.init()
        self.assertEqual(fake.commands, ["ATZ", "ATZ"])
        port.close()


class DialOutTest(unittest.TestCase):
    """`call` with "dial": OURPO dials MYPOST through the fake modem; the far end of the line is
    our own answering server for MYPOST, so the routed message must arrive there."""

    def setUp(self):
        self.root = os.path.join(WORK, "hayes-dialout")
        shutil.rmtree(self.root, ignore_errors=True)
        self.a_dir = os.path.join(self.root, "ourpo")
        self.b_dir = os.path.join(self.root, "mypost")
        os.makedirs(self.a_dir)
        os.makedirs(self.b_dir)
        self.fake = FakeModem(dial_results={"5551234": "CONNECT 9600", "5550000": "BUSY"})
        self.server = Rfc2217Server(self.fake)
        url = f"rfc2217://127.0.0.1:{self.server.port}"
        with open(os.path.join(self.a_dir, "po.json"), "w") as f:
            json.dump({"post_office": "OURPO", "users": {"bob": "1"},
                       "post_offices": {"MYPOST": {"password": "p1", "call_password": "p2", "mode": "LSEC",
                                                   "dial": "ATDT5551234", "modem": url, "baud": 19200,
                                                   "framing": "8N1", "flow": "rtscts"},
                                        "BUSYPO": {"password": "x", "dial": "ATDT5550000", "modem": url}}}, f)
        with open(os.path.join(self.b_dir, "po.json"), "w") as f:
            json.dump({"post_office": "MYPOST", "users": {"user": "123"},
                       "post_offices": {"OURPO": {"password": "p2"}}}, f)
        self.a = PostOffice(self.a_dir)
        self.b = PostOffice(self.b_dir)
        self.saved = {k: getattr(HayesModem, k) for k in FAST}
        for k, v in FAST.items():
            setattr(HayesModem, k, v)

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(HayesModem, k, v)
        self.server.close()
        self.fake.close()

    def test_busy(self):
        failed = server.call_by_modem(self.a, "BUSYPO")
        self.assertEqual(failed, "ATDT5550000: BUSY")
        self.assertIn(("dial", "5550000"), self.fake.events)

    def test_dial_and_deliver(self):
        from ccmail.message import compose, Message
        msg = compose("bob", ["user at MYPOST"], "over the phone", "hello by modem\r\n+++ATH0\r\nNO CARRIER\r\n",
                      attachments=[("all.bin", bytes(range(256)) * 4)])
        self.a.route("MYPOST", msg)
        answered = []

        def far_end():
            wait_for(lambda: self.fake.far_line is not None, what="dial CONNECT")
            sock = self.fake.far_line.sock
            answered.append(True)
            server.handle(sock, ("line", 0), self.b, 1, 9600)
        thread(far_end)
        failed = server.call_by_modem(self.a, "MYPOST")
        self.assertIsNone(failed)
        self.assertTrue(answered)
        self.assertIn(("baudrate", 19200), self.fake.changes)
        self.assertIn(("rtscts", True), self.fake.changes)
        self.assertIn("ATDT5551234", self.fake.commands)
        box = os.path.join(self.b_dir, "mail", "user")
        wait_for(lambda: os.path.isdir(box) and any(n.endswith(".msg") for n in os.listdir(box)),
                 what="delivered message")
        text = "".join(open(os.path.join(box, n), encoding="latin-1").read()
                       for n in os.listdir(box) if n.endswith(".txt"))
        self.assertIn("over the phone", text)
        got = [Message.from_file(open(os.path.join(box, n), "rb").read())
               for n in os.listdir(box) if n.endswith(".msg")]
        self.assertEqual(got[0].body, msg.body)
        self.assertIn(("dtr", False), self.fake.events)   # hung up afterwards


if __name__ == "__main__":
    unittest.main()
