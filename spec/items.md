# cc:Mail text items: format rules for senders and receivers

Compatibility: these rules are what a receiver compatible with cc:Mail Remote 3.40B requires of
a text item; a message built by them is displayed by that client.

"Sample check" means the bytes of stored client message files (MSG00001..MSG00006 of a test
client directory) agree with the description. They are not the source of any claim.

Descriptor offsets count from the tag byte (06 12 ...), as in session-layer.md 4.6. The
descriptor table starts at header + 0x20, one entry every 0x14 bytes.

## 1. What a receiver requires before it reads a text item

### 1.1 Header record

A receiver rejects the whole message (the header record cannot be loaded) unless:
- at least 0x20 bytes are present;
- word[0C] > 0;
- word[0A] = 'M' or 'F';
- 0x20 <= word[8] <= 0x1000;
- dword[0] - dword[4] >= 0 and <= 0x1000 - word[8];
- a TLV walk from 0x20 lands exactly on word[8] + addressing length, with no negative len.

Items are looked up by heading level (0 for a plain message) and type: text (1), graphics (2),
file (3), fax (4), update (5).

### 1.2 Reading a text item

- Two passes over the type-1 items of the level: +A = 1 (attribute layer), then +A = 0
  (characters). The default attribute is 7.
- A pass whose item is absent is skipped: a missing +A = 1 item is tolerated.
- In pass +A = 1 the default attribute := word +8, also when the item's length is 0.
- The length is a **word**: word +0C. Length 0 = the item is present and is not read.
- Offset dword +10. Non-zero: the item is at that offset in the message file (+ message base).
  0: the item is in a separate item file named from item number +6.
- The text is read as cells (attribute, character). The item fails when:
  - a read returns nothing (also after a CR);
  - the cell count reaches 0x5000;
  - after both passes the cell count is 0.
  A failed item is reported as "cannot be read".
- How a message without a type-1 item with +A in {0,1} is shown is not determined (§6).

**End-of-item rule.** A receiver tests for the end of the item only after a CR and the byte
that follows it. If the item's last byte is not the byte following a CR, it reads past the end
and the item fails ("cannot be read"). Hence a text item must end with CR LF (§5).

**Attribute layer** (+A = 1, read only when its length is not 0):
- Format: `n attr` byte pairs; each gives n cells of attribute `attr` with a space.
  n == 0 is a line end (CR LF).
- The characters of the +A = 0 item are then laid over the cells. At each CR the receiver skips
  to the next line-end cell, with no bound.
- It fails when a read fails or the cells exceed 0x5000. Unlike the text pass, it re-tests the
  bytes remaining after every run.
- Attribute bytes 07/70/0F/01/09/78 are taken as they are; others may be remapped by the
  receiver (the text pass uses 7 in that case).

### 1.3 Other item types: conditions that make a receiver reject the item

| item | failing condition |
|---|---|
| fax (type 4) | +A (format; 0 → 4) not in {4,6,7,0E,10,12}, or the image cannot be rendered |
| graphics (type 2) | not determined |
| item in a separate item file | the file cannot be opened; further conditions not determined |
| forwarded/copied content | the same checks as 1.2 for its text, graphics or fax |
| file item | not determined |
| a message with no text, graphics or fax item at the level | nothing to show |

### 1.4 Test vector: a text without a final CR LF

- MSG00006: single text item (type 1, +A = 0, length 0x5B, offset 0x34). The text ends
  `...ends here.` without CR LF (sample check). By 1.2 it is read past its last byte and the item
  fails.
- +8 = 0, the missing +A = 1 item and tag 16 are not the cause (tolerated, or not read when
  reading text).
- Prediction from the same rule: MSG00002 (ends `col.`) and MSG00004 (ends `5B7.`) fail the same
  way; MSG00001/3/5 end in `\r\n` and display. If MSG00002/4 were seen to display, this
  description has to be re-checked.

## 2. Descriptor words +8 and +A; the zero-length first item

Meaning for a receiver:
- **+A** selects the role of a type-1 item: +A = 1 is the attribute layer, +A = 0 is the
  characters.
- For fax items +A is the image format.
- **+8 of the +A = 1 item** = the default video attribute of the text.
- **+8 of the +A = 0 item** = number of CR LF line ends. When reading text a receiver uses it
  only in a size estimate `len - lines`.
- A graphics item's +A/+8 are read when it is shown; their meaning is not determined.

A sender:
- A new descriptor has +8 = 0, +A = 0.
- For one text body it writes two type-1 items (this is what the original client writes):
  - Item A: +A = 1, +8 = default attribute. Its data is the attribute runs, present only if some
    cell has a non-default attribute; otherwise length = 0.
  - Item B: +A = 0, +8 = line count. Its data is the characters with CR LF.
- It always ends the text with CR LF (the original client appends one when the last line has
  none), so stored text never lacks a final CR LF.
- When forwarding or copying, +8/+A are copied from the source descriptor.
- Sample check: messages from the original post office software have item 1 = +A 1,
  +8 0x17/0x1F (white on blue / bright white on blue), length 0 (no attribute runs); item 2
  +8 = 0x2E / 0x1F = 46 / 31 CR LF in the text.
- Other +8/+A values occur; their meaning is not determined. A type-1 item with +A = 0FFFFh is
  read as a special case; its role is not determined.

For one plain body, a sender writes:
- item 1: type 1, +A = 1, +8 = attribute (0x07 is the receiver's default; the samples use 0x17),
  length 0, offset = the text's offset (not read when the length is 0);
- item 2: type 1, +A = 0, +8 = CR LF count, length, offset.

The +A = 1 item is optional for display (1.2).

## 3. Transposition restarts at each item's first byte

- A receiver seeks to the item offset and reads in blocks of min(0x200, item bytes remaining),
  untransposing exactly the bytes of each block.
- So the transposition runs in 512-byte blocks counted from the item's start, and the last block
  is the remainder. File offset alignment does not matter.
- A sender transposes each item the same way: every 0x200 bytes from the item's start, and the
  final partial block too.

## 4. Stored file vs wire record

Same layout, same offsets, same byte order: `[fixed 0x20][descriptors][body][addressing TLVs]`.
In a stored message file each header region is transposed by itself, in <= 0x200-byte blocks:
- region A: bytes 0..0x1F as one 0x20-byte block;
- region B: bytes 0x20..word[8]-1 as blocks from 0x20;
- region C: the addressing part, at dword[4], as blocks from dword[4];
- the body is stored as on the wire (its items are already transposed per §3).

A reader of a stored file undoes the same three regions.

So the "reordered/byte-reversed" look of stored files is only this per-region 17-column
transposition. Sample check: untransposing 0x20 / word[8]-0x20 / the addressing part separately
gives the wire bytes for MSG00001..06.

**Correction:** the parenthetical in session-layer.md 4.4 ("byte order ... as on the wire ...
not touched") is wrong; the three header regions are transposed. Stored files written by other
programs: not checked here.

## 5. Recipe: one text body a receiver will display

Wire header record:
- fixed part (LE):
  - dword[0] = word[8] + body length + addressing length;
  - dword[4] = word[8] + body length;
  - word[8] = 0x20 + 0x14 * descriptors (<= 0x1000);
  - word[0A] = 0x4D;
  - word[0C] = 1 (must be > 0);
  - dword[0E] = 0, then date, time;
  - word[1A] = 1 heading; word[1C] = descriptor count; word[1E] = last item number;
- descriptors (`06 12` + 18 bytes);
- addressing TLVs. The addressing length must be <= 0x1000 - word[8], and the TLV walk over
  descriptors + addressing must end exactly (1.1).

Descriptors, all level +2 = 0, type +4 = 1:

| item +6 | +8 | +A | +0C length | +10 offset |
|---|---|---|---|---|
| 1 | attribute, e.g. 0x17 (or 0x07) | 1 | 0 | word[8] |
| 2 | number of CR LF in the text | 0 | L | word[8] |

Body = transpose(text) at offset word[8], with 512-byte blocks counted from the item start (§3).

Constraints:
- The text must end with CR LF (1.2). More exactly, the last two bytes must be a CR (one that is
  not itself the byte after a CR) and one following byte (a receiver takes any byte there).
- L <= 0xFFFF: only the low word is used. L = 0 is accepted.
- Cells = L - CR LF count must stay < 0x5000.
- The offset must be non-zero; 0 means a separate item file.
- No alignment is required: a receiver seeks to the exact offset.
- No TLV is read when reading text. Tag 07 (a per-heading title string) and tags 01/03/05 are
  used elsewhere: header display, and the author check on send (session-layer.md 4.3).

`ccmail/message.py` `compose()` follows this recipe (final CR LF, +8 = CR LF count, item 1 as
above, items = last_item = 2, word[8] = 0x48).

## 6. Not determined

- What a receiver tests before rejecting an item held in a separate item file, a
  forwarded/copied item, or a file item.
- How a message without a type-1 item with +A in {0,1} is shown.
- How a very long text is shown. Reading it into cells fails at the 0x5000-cell limit; the
  alternative is not determined.
- The meaning of +A = 0FFFFh and of other +8/+A values seen from senders (§2).
- What makes a graphics or fax item fail to show.
- What a receiver shows when the attribute layer has fewer line ends than the text (unbounded
  scan for the next line end). One open of such a message settles it.
- Whether MSG00002/MSG00004 fail when opened. §1.4 predicts they do. One open of MSG00002
  settles it, and an A/B with MSG00006 plus a final "\r\n" confirms the cause.
