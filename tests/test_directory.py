# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Directory update messages against the examples of spec/directory-updates.md §5."""
import datetime
import struct
import unittest

from ccmail.directory import update_message, item_text, request_after
from ccmail.message import Message, transpose, build_tlvs, FIXED_LEN, DESC_LEN

WHEN = datetime.datetime(2026, 11, 25, 10, 30)

HEADER_5A = bytes.fromhex("""
26 01 00 00 d5 00 00 00 34 00 4d 00 01 00 00 00
00 00 19 0b 7e 00 00 1e 0a 00 01 00 01 00 01 00
06 12 00 00 03 00 01 00 00 00 00 00 a1 00 00 00
34 00 00 00 01 0e 41 64 6d 69 6e 69 73 74 72 61
74 6f 72 00 0f 03 48 51 00 03 0a 44 6f 65 2c 20
4a 61 6e 65 00 05 13 41 44 45 20 75 70 64 61 74
65 20 6d 65 73 73 61 67 65 00 07 19 43 43 4d 55
50 44 41 54 20 31 31 2f 32 35 2f 31 32 36 20 31
30 3a 33 30 00""")

BODY_5A = bytes.fromhex("""
4e 72 68 0a 44 4c 3a 6e 48 3a 0d 20 6e 61 6f 0a
0d 42 65 20 0a 53 3a 6d 63 4e 0a 52 73 0a 51 6f
72 20 64 6f 0d 6d 0d 48 4a 64 2c 41 72 4c 43 48
20 20 64 65 0a 42 20 0a 61 3a 6d 4c 0d 0d 48 42
72 53 52 64 69 4c 3a 3a 6d 6f 4e 0a 43 3a 2c 41
6f 0d 20 3a 0d 65 50 3a 63 4e 4c 0d 62 20 6c 6d
20 65 6f 0a 0a 51 6f 3a 61 63 4e 0d 48 6e 3a 2c
64 3a 41 64 74 0d 20 20 65 63 43 6f 0a 6e 20 61
72 6e 41 73 4e 6e 61 0a 51 65 20 20 64 20 4c 0d
68 3a 4a 64 77 0a 74 42 41 6d 20 65 6e 61 4c 41
0d""")

TEXT_5B = bytes.fromhex("""
4e 61 6d 65 3a 20 42 72 6f 77 6e 2c 20 42 6f 62 0d 0a
4c 6f 63 6e 3a 20 4c 0d 0a
41 64 64 72 3a 20 42 52 41 4e 43 48 0d 0a
4e 61 6d 65 3a 20 4f 6c 64 2c 20 46 72 65 64 0d 0a
4c 6f 63 6e 3a 20 44 4c 0d 0a""")


class DirectoryTest(unittest.TestCase):
    def test_example_5a(self):
        entries = [{"name": "Smith, John", "kind": "L", "addr": "HQ"},
                   {"name": "Doe, Jane", "kind": "L", "addr": "HQ"},
                   {"name": "Brown, Bob", "kind": "L", "addr": "BRANCH", "cmts": "Sales"},
                   {"name": "BRANCH", "kind": "P", "addr": "HQ"}]
        msg = update_message("HQ", "Doe, Jane", entries, WHEN)
        self.assertEqual(msg.record, HEADER_5A)
        self.assertEqual(msg.body, BODY_5A)

    def test_example_5b_text(self):
        entries = [{"name": "Brown, Bob", "kind": "L", "addr": "BRANCH"},
                   {"name": "Old, Fred", "kind": "L", "delete": True}]
        self.assertEqual(item_text(entries), TEXT_5B)

    def test_2048_guard(self):
        name = "x" * (2048 - len("Name: \r\nLocn: L\r\n"))
        self.assertEqual(len(item_text([{"name": name, "kind": "L"}])) % 2048, 2)

    def test_request_date(self):
        # the client's request item (spec §1.2): 14 00 00 00 01 00 01 00 00 00 00 00, date, time
        data = bytes.fromhex("14000000 0100 0100 00000000") + bytes([24, 11, 126, 0, 0, 15, 9, 0])
        part1 = FIXED_LEN + 2 + DESC_LEN
        body = transpose(data)
        addr = build_tlvs([[0x01, b"user\0"], [0x03, b"Administrator\0"], [0x18, b""]])
        fixed = struct.pack("<IIHHHIIIHHH", part1 + len(body) + len(addr), part1 + len(body), part1, 0x4D, 1, 0,
                            0, 0, 1, 1, 1)
        record = fixed + bytes([6, DESC_LEN]) + struct.pack("<HHHHHII", 0, 6, 1, 0, 0, len(data), part1) + addr
        self.assertEqual(request_after(Message(record, body)), datetime.datetime(2026, 11, 24, 9, 15))


if __name__ == "__main__":
    unittest.main()
