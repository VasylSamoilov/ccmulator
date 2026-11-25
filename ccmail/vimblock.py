# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2026 Vasyl Samoilov
"""Data blocks of the remote VIM calls (spec/hp200lx-check.md §5.9).

One remote call = one request block (client -> server) and one reply block (server -> client),
each carried in one interactive data record. The encoding is the one of spec §5.9:

- build(fmt, *args)          = a request as the client encodes it. Used by the simulated client
                               (tools/hpclient.py) and the tests.
- parse_request(fmt, block)  = the server's reading of such a block.
- build_reply(fmt, *args)    = the server's reply, laid out so that the client can decode it.
- break_reply(fmt, block)    = how the client decodes a reply, with its size checks.

Little-endian. Letters:
  f w b          u16
  h i d s S t    u32 (t = status; decoding stops at a non-zero status)
  E              u32: the low dword of a vimEnumRef (reply: stored, high dword set to 0)
  R              8 bytes vimRef
  z              u32 offset (0 = NULL); the string with its NUL is placed after the rest of the
                 format (the rest is encoded first, then the string, and the block ends)
  p / P          u16 / u32 length + u32 offset, data placed like z (offset 0 = NULL pointer)
  a / A          u16 count, u16 n, count x {Attr u32, Size u32, DataOffset u32}; A then holds
                 Size*n data bytes per entry at DataOffset
  c              u32 Offset, u32 Size of a vimBuffFileDesc (request of ReadMessageItem)
  C              request: the 16-byte vimBuffFileDesc {Size, BufferOffset, Offset, FileNameOffset},
                 the rest of the format, then Size data bytes.
                 reply: no descriptor; the data bytes follow at once and their count is the
                 preceding d
  N              u32 offset of a 24-byte vimRecipient {Type, DName.Type, off AddressBook,
                 off DName.Value, Address.Type, off Address.Value} that follows at once, then the
                 rest of the format, then the non-empty strings
  D              reply only: count = the preceding w; count x 28 bytes {Class, off Type, off Name,
                 off Path, Size, Ref(8)}; strings by offset
All offsets count from the start of the block.
"""
import struct

BLOCK_MAX = 0x5400          # the client's block size limit: one record at most, both ways

# a decoded vimRecipient (attribute 4Bh alone, n = 1): 90Ch bytes
RECIP_SIZE = 0x90C          # Type 4 + DName (4 + 256 + 1024) + Address (4 + 1024)
DNAME_SIZE = 0x504          # vimDistinguishedName
ADDRESS_SIZE = 0x404        # vimAddress
ITEMDESC_SIZE = 0x250       # decoded vimItemDesc; the client needs this much room per D entry


class BlockError(ValueError):
    pass


# ----- recipients and names in their in-memory (VIM.H) form -----

def recipient(value="", rtype=0, dname_type=0, book="", addr_type=0, addr=""):
    return dict(type=rtype, dname_type=dname_type, book=book, value=value, addr_type=addr_type, addr=addr)


def _cstr(s, enc="cp850"):
    return s.encode(enc, "replace") if isinstance(s, str) else bytes(s)


def _fixed(b: bytes, size: int) -> bytes:
    """A C string in a fixed field: cut to size-1 bytes, NUL padded."""
    b = b[:max(size - 1, 0)]
    return b + b"\x00" * (size - len(b))


def recipient_struct(r, enc="cp850") -> bytes:
    """The 90Ch-byte vimRecipient (VIM.H layout): what a reply carries for an attribute of that
    size that is not the lone 4Bh case (e.g. 22h FROM in GetMessageHeader)."""
    return (struct.pack("<II", r["type"], r["dname_type"]) + _fixed(_cstr(r["book"], enc), 256)
            + _fixed(_cstr(r["value"], enc), 1024) + struct.pack("<I", r["addr_type"])
            + _fixed(_cstr(r["addr"], enc), 1024))


def dname_struct(value, book="", dtype=0, enc="cp850") -> bytes:
    """vimDistinguishedName, 504h bytes."""
    return struct.pack("<I", dtype) + _fixed(_cstr(book, enc), 256) + _fixed(_cstr(value, enc), 1024)


def address_struct(value, atype=0, enc="cp850") -> bytes:
    """vimAddress, 404h bytes."""
    return struct.pack("<I", atype) + _fixed(_cstr(value, enc), 1024)


def parse_recipient_struct(b: bytes, enc="cp850"):
    def s(x):
        return x.split(b"\x00", 1)[0].decode(enc, "replace")
    t, dt = struct.unpack_from("<II", b, 0)
    at = struct.unpack_from("<I", b, 0x508)[0]
    return recipient(s(b[0x108:0x508]), t, dt, s(b[8:0x108]), at, s(b[0x50C:0x90C]))


# ----- the client's request encoding -----

def build(fmt: str, *args) -> bytes:
    """Request block exactly as the client lays it out. Arguments per letter:
    f w b h i d s S t E: int; R: 8 bytes; z: bytes or None; p/P: bytes or None (length = len),
    or (length, bytes or None); a/A: (n, [(attr, size[, data])]);
    c: (offset, size); C: (size, buffer bytes or None, offset, filename bytes or None);
    N: a recipient() dict."""
    buf = bytearray(BLOCK_MAX)
    n = _build(fmt, list(args), buf, 0, BLOCK_MAX)
    return bytes(buf[:n])


def _build(fmt, args, buf, off, room):
    start = off
    i = 0
    while i < len(fmt):
        ch = fmt[i]
        i += 1
        if ch in "fwb":
            v = args.pop(0)
            if room < 2:
                raise BlockError("block full")
            struct.pack_into("<H", buf, off, v & 0xFFFF)
            off += 2
            room -= 2
        elif ch in "hidsSt":
            v = args.pop(0)
            if room < 4:
                raise BlockError("block full")
            struct.pack_into("<I", buf, off, v & 0xFFFFFFFF)
            off += 4
            room -= 4
        elif ch == "E":                       # low dword of the vimEnumRef
            v = args.pop(0)
            struct.pack_into("<I", buf, off, v & 0xFFFFFFFF)
            off += 4
            room -= 4
        elif ch == "R":
            v = bytes(args.pop(0))
            if len(v) != 8:
                raise BlockError("vimRef must be 8 bytes")
            buf[off:off + 8] = v
            off += 8
            room -= 8
        elif ch == "z":
            v = args.pop(0)
            if v is None:
                struct.pack_into("<I", buf, off, 0)
                off += 4
                room -= 4
                continue
            v = bytes(v)
            n = _build(fmt[i:], args, buf, off + 4, room - 4)   # the rest first
            struct.pack_into("<I", buf, off, off + 4 + n)
            off += 4 + n
            room -= 4 + n
            if len(v) + 1 > room:
                raise BlockError("block full")
            buf[off:off + len(v) + 1] = v + b"\x00"
            return off + len(v) + 1 - start                       # stop: the rest is done
        elif ch in "pP":
            v = args.pop(0)
            if isinstance(v, tuple):
                length, data = v
            else:
                data = v
                length = len(v) if v is not None else 0
            if ch == "P":
                struct.pack_into("<I", buf, off, length)
                off += 4
                room -= 4
            else:
                struct.pack_into("<H", buf, off, length & 0xFFFF)
                off += 2
                room -= 2
            if data is None:
                struct.pack_into("<I", buf, off, 0)
                off += 4
                room -= 4
                continue
            data = bytes(data)[:length & 0xFFFF].ljust(length & 0xFFFF, b"\x00")
            n = _build(fmt[i:], args, buf, off + 4, room - 4)
            struct.pack_into("<I", buf, off, off + 4 + n)
            off += 4 + n
            room -= 4 + n
            if len(data) > room:
                raise BlockError("block full")
            buf[off:off + len(data)] = data
            return off + len(data) - start
        elif ch in "aA":
            nn, entries = args.pop(0)
            if len(entries) * 12 + 4 > room:
                raise BlockError("block full")
            struct.pack_into("<HH", buf, off, len(entries), nn & 0xFFFF)
            off += 4
            room -= 4
            table = off
            for e in entries:
                struct.pack_into("<III", buf, off, e[0], e[1], 0)
                off += 12
                room -= 12
            if ch == "A":
                # the rest of the format first, then each entry's Size*n bytes;
                # the encoding would then go on with the rest again: A is always last in practice
                n = _build(fmt[i:], args, buf, off, room)
                off += n
                room -= n
                for k, e in enumerate(entries):
                    size = (e[1] * nn) & 0xFFFF
                    data = bytes(e[2] if len(e) > 2 and e[2] is not None else b"")[:size].ljust(size, b"\x00")
                    struct.pack_into("<I", buf, table + 12 * k + 8, off)
                    buf[off:off + size] = data
                    off += size
                    room -= size
                return off - start
        elif ch == "c":
            offset, size = args.pop(0)
            struct.pack_into("<II", buf, off, offset, size)
            off += 8
            room -= 8
        elif ch == "C":
            size, buffer, offset, filename = args.pop(0)
            if size + 16 > room:
                raise BlockError("block full")
            desc = off
            struct.pack_into("<IIII", buf, off, size, 1 if buffer is not None else 0, offset,
                             1 if filename is not None else 0)
            off += 16
            room -= 16
            n = _build(fmt[i:], args, buf, off, room)
            off += n
            room -= n
            src = buffer if buffer is not None else (filename or b"")
            data = bytes(src)[:size].ljust(size, b"\x00")
            if buffer is not None:                # Buffer field = data offset, FileName = 0
                struct.pack_into("<I", buf, desc + 4, off)
                struct.pack_into("<I", buf, desc + 12, 0)
            else:                                 # Buffer = 0, FileName field = data offset
                struct.pack_into("<I", buf, desc + 4, 0)
                struct.pack_into("<I", buf, desc + 12, off)
            buf[off:off + size] = data
            off += size
            return off - start
        elif ch == "N":
            r = args.pop(0)
            if room < 0x18:
                raise BlockError("block full")
            struct.pack_into("<I", buf, off, off + 4)
            off += 4
            st = off
            buf[st:st + 0x18] = bytes(0x18)
            struct.pack_into("<II", buf, st, r["type"], r["dname_type"])
            struct.pack_into("<I", buf, st + 0x10, r["addr_type"])
            off += 0x18
            room -= 0x18
            n = _build(fmt[i:], args, buf, off, room)
            off += n
            for field, key in ((8, "book"), (0x0C, "value"), (0x14, "addr")):
                s = _cstr(r[key])
                if s:
                    struct.pack_into("<I", buf, st + field, off)
                    buf[off:off + len(s) + 1] = s + b"\x00"
                    off += len(s) + 1
            return off - start
        else:
            raise BlockError(f"letter {ch!r} not in the builder")
    return off - start


# ----- the server's reading of a request -----

def _str_at(block, off):
    if off == 0:
        return None
    if off >= len(block):
        raise BlockError(f"string offset {off} outside the {len(block)}-byte block")
    end = block.find(b"\x00", off)
    return bytes(block[off:end if end >= 0 else len(block)])


def parse_request(fmt: str, block: bytes):
    """Fields of a request block, in format order. z -> bytes or None; p/P -> bytes or None
    (exactly `length` bytes, no NUL); a -> (n, [(attr, size)]); A -> (n, [(attr, size, data)]);
    c -> (offset, size); C -> dict(size, offset, data, by_name); N -> recipient dict."""
    out = []
    pos = 0

    def need(k):
        if pos + k > len(block):
            raise BlockError(f"block ends at {len(block)}, field needs {pos}+{k} ({fmt})")

    for ch in fmt:
        if ch in "fwb":
            need(2)
            out.append(struct.unpack_from("<H", block, pos)[0])
            pos += 2
        elif ch in "hidsStE":
            need(4)
            v = struct.unpack_from("<I", block, pos)[0]
            pos += 4
            out.append(v - (1 << 32) if ch == "i" and v & 0x80000000 else v)
        elif ch == "R":
            need(8)
            out.append(bytes(block[pos:pos + 8]))
            pos += 8
        elif ch == "z":
            need(4)
            out.append(_str_at(block, struct.unpack_from("<I", block, pos)[0]))
            pos += 4
        elif ch in "pP":
            k = 4 if ch == "P" else 2
            need(k + 4)
            length = struct.unpack_from("<I" if ch == "P" else "<H", block, pos)[0]
            off = struct.unpack_from("<I", block, pos + k)[0]
            pos += k + 4
            if off == 0:
                out.append(None)
            else:
                if off + length > len(block):
                    raise BlockError("p data outside the block")
                out.append(bytes(block[off:off + length]))
        elif ch in "aA":
            need(4)
            count, n = struct.unpack_from("<HH", block, pos)
            pos += 4
            need(12 * count)
            entries = []
            for k in range(count):
                attr, size, doff = struct.unpack_from("<III", block, pos + 12 * k)
                if ch == "A":
                    entries.append((attr, size, bytes(block[doff:doff + size * n]) if doff else None))
                else:
                    entries.append((attr, size))
            pos += 12 * count
            out.append((n, entries))
        elif ch == "c":
            need(8)
            out.append(struct.unpack_from("<II", block, pos))
            pos += 8
        elif ch == "C":
            need(16)
            size, boff, offset, foff = struct.unpack_from("<IIII", block, pos)
            pos += 16
            doff = boff or foff
            data = bytes(block[doff:doff + size]) if doff and size else b""
            if len(data) != size:
                raise BlockError("C data outside the block")
            out.append(dict(size=size, offset=offset, data=data, by_name=not boff))
        elif ch == "N":
            need(4)
            st = struct.unpack_from("<I", block, pos)[0]
            pos += 4
            if st == 0 or st + 0x18 > len(block):
                raise BlockError("N outside the block")
            t, dt, ob, ov, at, oa = struct.unpack_from("<IIIIII", block, st)

            def s(o):
                v = _str_at(block, o)
                return v.decode("cp850", "replace") if v else ""
            out.append(recipient(s(ov), t, dt, s(ob), at, s(oa)))
            if pos == st:                       # the struct follows the offset field
                pos = st + 0x18
        else:
            raise BlockError(f"letter {ch!r} not expected in a request")
    return out


# ----- the server's reply -----

def build_reply(fmt: str, *args) -> bytes:
    """Reply block for the client. Arguments: t h d i s S b w f: int; E: int; R: 8 bytes;
    z: bytes or None; p/P: bytes; A: (n, [(attr, size, data)]) with data = Size*n bytes;
    D: [dict(cls, type, name, path, size, ref)] (count = the preceding w); C: bytes (count = the
    preceding d). With a non-zero t first, only the status is sent (decoding stops there)."""
    args = list(args)
    fixed = bytearray()
    later = []          # (patch position, bytes): data placed after all fixed fields

    for ch in fmt:
        if ch == "t":
            v = args.pop(0)
            fixed += struct.pack("<I", v)
            if v:
                return bytes(fixed)
        elif ch in "fwb":
            fixed += struct.pack("<H", args.pop(0) & 0xFFFF)
        elif ch in "hidsSE":
            fixed += struct.pack("<I", args.pop(0) & 0xFFFFFFFF)
        elif ch == "R":
            v = bytes(args.pop(0))
            assert len(v) == 8
            fixed += v
        elif ch == "z":
            v = args.pop(0)
            if v is None:
                fixed += bytes(4)
            else:
                later.append((len(fixed), bytes(v) + b"\x00"))
                fixed += bytes(4)
        elif ch in "pP":
            v = bytes(args.pop(0) or b"")
            fixed += struct.pack("<I" if ch == "P" else "<H", len(v))
            if v:
                later.append((len(fixed), v))
            fixed += bytes(4)
        elif ch == "A":
            n, entries = args.pop(0)
            fixed += struct.pack("<HH", len(entries), n)
            for attr, size, data in entries:
                fixed += struct.pack("<II", attr, size)
                if data:
                    later.append((len(fixed), bytes(data)))
                fixed += bytes(4)
        elif ch == "D":
            items = args.pop(0)
            for it in items:
                fixed += struct.pack("<I", it["cls"])
                for key in ("type", "name", "path"):
                    # always a string, also an empty one: with offset 0 the client would keep
                    # whatever its field held before
                    later.append((len(fixed), _cstr(it.get(key) or b"") + b"\x00"))
                    fixed += bytes(4)
                fixed += struct.pack("<I", it["size"]) + bytes(it["ref"])
        elif ch == "C":
            fixed += bytes(args.pop(0))        # inline, count = the preceding d
        else:
            raise BlockError(f"letter {ch!r} not expected in a reply")
    out = bytearray(fixed)
    for at, data in later:
        struct.pack_into("<I", out, at, len(out))
        out += data
    if len(out) > BLOCK_MAX:
        raise BlockError(f"reply of {len(out)} bytes exceeds the HP's {BLOCK_MAX}-byte block")
    return bytes(out)


def recipient_compact(r, enc="cp850"):
    """(24-byte struct, strings) for the lone 4Bh RECIPIENT attribute: the struct is read at
    DataOffset and the strings at offsets from the block start.
    Returned as a callable that lays it out at a given block offset."""
    def place(at):
        strings = bytearray()
        offs = []
        for key in ("book", "value", "addr"):
            # every string placed, also empty ones: an empty string and offset 0 decode the
            # same, and placing them all is the safe form
            offs.append(at + 0x18 + len(strings))
            strings += _cstr(r[key], enc) + b"\x00"
        return struct.pack("<IIIIII", r["type"], r["dname_type"], offs[0], offs[1], r["addr_type"],
                           offs[2]) + bytes(strings)
    return place


def build_reply_recipient(n_more, pos, r, size=RECIP_SIZE):
    """'tEbA' reply of EnumerateMessageRecipients with one 4Bh attribute and one recipient."""
    head = struct.pack("<IIH", 0, pos, n_more) + struct.pack("<HH", 1, 1)
    entry_at = len(head)
    data_at = entry_at + 12
    body = recipient_compact(r)(data_at)
    return head + struct.pack("<III", 0x4B, size, data_at) + body


# ----- the client's decoding of a reply -----

def break_reply(fmt: str, block: bytes, sizes=None, room=BLOCK_MAX, desc_size=None):
    """Read a reply as the client does. Returns the list of values (status first). For A, `sizes`
    = the Size of each requested attribute: the client takes wire Size*n bytes into a buffer
    of requested Size*n, so a larger wire Size would overflow it - raised here.
    `room` = the room available for decoding (the block size 5400h).
    desc_size = the caller's vimBuffFileDesc.Size for C (data count must not exceed it)."""
    out = []
    pos = 0
    left = room
    last_word = last_dword = None

    def rd(fmtc, k):
        nonlocal pos, left
        if left < k:
            raise BlockError("breaker: not enough room")
        if pos + k > len(block):
            raise BlockError(f"reply ends at {len(block)}, the HP reads {pos}+{k}")
        v = struct.unpack_from(fmtc, block, pos)[0]
        pos += k
        left -= k
        return v

    def cstr_at(o):
        end = block.find(b"\x00", o)
        if end < 0:
            raise BlockError("unterminated string in reply")
        return bytes(block[o:end])

    for ch in fmt:
        if ch in "fwb":
            last_word = rd("<H", 2)
            out.append(last_word)
        elif ch in "hidsS":
            last_dword = rd("<I", 4)
            out.append(last_dword)
        elif ch == "t":
            v = rd("<I", 4)
            out.append(v)
            if v:
                break
        elif ch == "E":
            out.append(rd("<I", 4))
        elif ch == "R":
            if pos + 8 > len(block):
                raise BlockError("reply too short for R")
            out.append(bytes(block[pos:pos + 8]))
            pos += 8
            left -= 8
        elif ch == "z":
            o = rd("<I", 4)
            out.append(cstr_at(o))
        elif ch in "pP":
            length = rd("<I" if ch == "P" else "<H", 4 if ch == "P" else 2)
            o = rd("<I", 4)
            if o + length > len(block):
                raise BlockError("p data outside the reply")
            out.append(bytes(block[o:o + length]))
        elif ch == "A":
            count = rd("<H", 2)
            n = rd("<H", 2)
            vals = []
            if count:
                table = pos
                if table + 12 * count > len(block):
                    raise BlockError("A table outside the reply")
                pos += 4                      # the client moves on by 4 only
                for k in range(count):
                    attr, size, doff = struct.unpack_from("<III", block, table + 12 * k)
                    want = sizes[k] if sizes and k < len(sizes) else None
                    if attr == 0x4B and count == 1 and n == 1:
                        # compact vimRecipient at DataOffset
                        t, dt, ob, ov, at, oa = struct.unpack_from("<IIIIII", block, doff)
                        s = lambda o: cstr_at(o).decode("cp850", "replace") if o else ""  # noqa: E731
                        vals.append((attr, RECIP_SIZE, recipient(s(ov), t, dt, s(ob), at, s(oa))))
                        continue
                    if want is not None and size > want:
                        raise BlockError(f"attribute {attr:#x}: wire Size {size:#x} > buffer {want:#x}")
                    data = bytes(block[doff:doff + size * n]) if doff else None
                    if doff and len(data) != size * n:
                        raise BlockError(f"attribute {attr:#x}: data outside the reply")
                    vals.append((attr, size, data))
            out.append((n, vals))
        elif ch == "D":
            count = last_word or 0
            items = []
            for k in range(count):
                if left < ITEMDESC_SIZE:
                    raise BlockError("breaker: D needs 250h bytes of room per entry")
                base = pos + 0x1C * k
                cls, ot, on, op, size = struct.unpack_from("<IIIII", block, base)
                ref = bytes(block[base + 0x14:base + 0x1C])
                g = lambda o: cstr_at(o).decode("cp850", "replace") if o else ""  # noqa: E731
                items.append(dict(cls=cls, type=g(ot), name=g(on), path=g(op), size=size, ref=ref))
                left -= 0x1C
            out.append(items)
        elif ch == "C":
            count = last_dword or 0
            if count > left or (desc_size is not None and count > desc_size):
                raise BlockError("breaker: C count larger than the room or the buffer")
            out.append(bytes(block[pos:pos + count]))
            pos += count
            left -= count
        else:
            raise BlockError(f"letter {ch!r} not in the breaker")
    return out
