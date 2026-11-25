# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""cc:Mail limits the server applies to what it creates (spec/limits.md).

Accept what real clients and post offices send; emit only what every client can take.
"""

NAME_MAX = 126            # user / post office names, chars
LIST_NAME_MAX = 125       # mailing lists, bulletin boards
HEADER_STRING_MAX = 126   # any header TLV string: length byte is read as signed, 127 bytes incl. NUL
SUBJECT_MAX = 60          # subject length every client and gateway accepts
PASSWORD_MAX = 63         # DB 8.x post offices refuse >= 64 bytes; clients send at most 10
WIRE_FIELD_MAX = 0x80     # login name/password length byte
HEADER_PART_MAX = 0x1000  # clients take a header only if word[8] <= 0x1000 and the
                          # addressing part <= 0x1000 - word[8]
ROUTER_HEADER_BUF = 8192  # largest received header a post office takes
RECIPIENTS_MAX = 1000     # the post office checks the count before each entry and answers 83 when
                          # it is already >= 1000: 1000 accepted, the rest 83
ITEMS_MAX = 20            # items per message
TEXT_ITEM_CELLS = 0x5000  # largest text item a client can read
LINE_MAX = 80             # text line, 80 columns


def wrap_lines(text: str, width: int = LINE_MAX - 1) -> str:
    """Break lines longer than `width` at spaces where possible (clients edit in 80 columns;
    how they show longer received lines is UNKNOWN in limits.md, so do not send them)."""
    out = []
    for line in text.split("\n"):
        while len(line) > width:
            cut = line.rfind(" ", 0, width + 1)
            if cut <= 0:
                cut = width
            out.append(line[:cut].rstrip())
            line = line[cut:].lstrip(" ")
        out.append(line)
    return "\n".join(out)


def split_text(text_crlf: bytes, max_items: int = ITEMS_MAX - 1):
    """Split CR LF text into chunks that each fit a client's text item limit: len - lines + 0x51
    + rows must stay under 0x5000; cut at line ends, keep CR LF endings."""
    budget = TEXT_ITEM_CELLS - 0x51 - 0x100
    chunks, cur = [], b""
    for line in text_crlf.split(b"\r\n")[:-1] if text_crlf.endswith(b"\r\n") else text_crlf.split(b"\r\n"):
        piece = line + b"\r\n"
        if cur and len(cur) + len(piece) > budget:
            chunks.append(cur)
            cur = b""
        cur += piece
    if cur or not chunks:
        chunks.append(cur)
    if len(chunks) > max_items:
        chunks = chunks[:max_items - 1] + [b"[text cut: more than fits in a cc:Mail message]\r\n"]
    return chunks


def clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "~"
