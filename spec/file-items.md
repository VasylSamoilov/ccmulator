# cc:Mail items other than text: file, Mac file, fax, graphics; forwarded and returned messages

Compatibility: this server is compatible with cc:Mail Remote 3.40B and RCONNECT 1.00 clients and
with cc:Mail Router 6.x post offices; its Internet gateway aims at feature parity with cc:Mail
Link to SMTP R8.10 and the cc:Mail R8 POP3/IMAP servers.

This spec describes the format of these items as they travel in a message, and how a gateway
turns them into MIME parts and back.

The sample post office and the sample message files (`MSG00001..14`) hold only text items, so
**nothing here about file, fax or forward data has been checked against a real message**. Sample
checks below cover only the parts common to text messages (descriptors, titles, word[1A]). §9
lists the tests that would settle the open points.

## 1. The item model: logical items, parts, titles

This corrects session-layer.md §4.2/§4.6 and items.md, which read +2 and word[1A] as "heading
levels" (see §8).

- **Logical item.** A logical item is one entry of the message's item list: "Text item", "File
  item: X", and so on.
  - Header word[1A] is the number of logical items.
  - Descriptor +2 is the index of the logical item (0-based) that the part belongs to.
  - A writer adding an item uses index = the current word[1A]. The new descriptor gets +2 =
    index and the title goes into title position `index`. word[1A] is incremented when the new
    part's index equals word[1A].
- **Parts.** A logical item is made of one or more tag-06 descriptors (parts) with the same +2.
  - Text: two parts, the attribute layer (+A = 1) and the characters (+A = 0) (items.md §2).
  - DOS file: one part.
  - Macintosh file: up to three parts (§2.2).
  - Fax: one part.
  - Graphics: one part, possibly with a companion part (§4.2).
  - Word[1C] is the number of descriptors and word[1E] the last item number.
  - At assembly the parts are renumbered +6 = 1..n in descriptor order, and word[1E] = n.
- **Titles.** There is one tag-07 TLV per logical item, in index order, in the addressing part.
  - Data: the title bytes + NUL, or length 0 for no title.
  - Writer: the old 07 entries are deleted first. Then for i < word[1A] it writes `07`, then
    len = trimmed length + 1, then the bytes and a NUL; when the title is all blank it writes
    len = 0.
  - Reader: for i < word[1A], the next tag 07 holds the title of item i (len − 1 bytes).
  - A gateway uses the title as the attachment name (smtp-link.md §2.4).
  - Sample check: every sample message has word[1A] = 1, its parts at +2 = 0, and exactly one
    `07 00`. This holds for MSG00001..14. Which program built each file is not known, and some
    may come from this project's `compose()`, so this check is weak.
- **Limits.**
  - A title must be at most **60 bytes**: TLV len ≤ 61. Readers hold 60 bytes and do not check
    longer titles.
  - Logical items per message: 20 (0x14) (limits.md §4).
- **Order of the TLVs.** Part 1 is the 32-byte fixed part, then the 06 descriptors (contiguous,
  from 0x20), then the 13 entries. Both new descriptors and new 13 entries are inserted at
  0x20 + 0x14·word[1C], i.e. after the last 06 and before the existing 13 entries. Word[8] =
  offset of the first tag 01. Tag 07 entries sit in the addressing part (after 01/03/05 in all
  samples).

## 2. File items (type 3)

### 2.1 DOS file: the item data is the file, byte for byte

A DOS file item as written by a client attaching a file:

1. Title:
   - the file name, with everything up to the last `:` or `\` dropped (paths ≤ 0x4F
     characters);
   - then `" " + date + " " + time` from the file's time stamp.
   - Date:
     - the order follows the author's country date format: 0 = M/D/Y, 1 = D/M/Y, 2 = Y/M/D;
     - the separator is always `/`;
     - numbers are not zero-padded, and the year is year − 1900, so 1993 is `93` and 2026 is
       `126`.
   - Time:
     - 12-hour `h:mm` followed directly by `AM`/`PM`;
     - or 24-hour `h:mm` when the author uses a 24-hour clock.
   - Example: `REPORT.TXT 11/24/93 10:15PM`.
2. Header room for the new descriptor + title: strlen + 0x17. 0x17 = 0x14 (descriptor) + 2 (TLV
   head) + 1 (NUL).
3. Descriptor type 3 at the current index, then:
   - +0C = file length;
   - +8 = the author's date order (0/1/2 above);
   - +A stays 0.
4. Item data: the file bytes with the forward transposition applied in 512-byte blocks counted
   from the item's first byte.

So:

- **There is no header inside the item data.** The data is the file's bytes. Its length is
  descriptor +0C (dword) and equals the file length.
- **No compression or encoding.** The only scramble is the 17-column transposition, applied in
  512-byte blocks counted from the item start, with the last block the remainder. This is the
  same as for text (items.md §3).
- **The file name and date live only in the title (tag 07).** The descriptor holds the date
  order (+8), and nothing else about the file. No DOS attributes, no size field besides +0C.

How a client saves a file item to disk (peer behaviour):

1. First type-3 part at this index (any +A).
2. Date order = +8 & 3.
3. Title trimmed.
4. Proposed file name = the first word of the title, with anything up to the last `:`/`\`
   dropped.
5. If more words follow, they are parsed:
   - the date with the date order, using the reader's country date separator;
   - the time.
6. Data: untransposed in 512-byte blocks and written as is.
7. If both the date and the time parsed, the file time is set from them.
8. Otherwise the file keeps the current time. A title that is just a file name is therefore safe.

### 2.2 Macintosh file: three parts

A Mac file is one logical item with up to three type-3 parts:

| part | +A | data | blocks of the transposition |
|---|---|---|---|
| data fork | 0 | fork bytes | 512 from part start |
| resource fork | 1 | fork bytes | 512 |
| Finder info | 2 | 0x16C bytes, below | **256**: 0x100 + 0x6C |

- Order: the data fork (if its length is not 0), then the resource fork (if not 0), then the
  info part.
- A client that handles only DOS files shows the item as one file item and saves the first
  type-3 part, which is the data fork when there is one.
- Some writers also create type-3 parts with +A = 3, +A = 4 with +8 = 3, and +A = 5. Not
  determined: their meaning.

The 0x16C-byte info part (zero-filled before the fields are set):

| off | size | content (Mac fields big-endian, as on the Mac) | from AppleSingle | from MacBinary | to AppleSingle |
|---|---|---|---|---|---|
| 0x000 | 0x100 | ICN# icon: 128-byte bitmap + 128-byte mask | entry 5, length must be 0x100; none → default icon | default icon | entry 5 (0x100 bytes) |
| 0x100 | 0x20 | 0 (not determined whether any writer uses it) | — | — | — |
| 0x120 | 0x10 | FInfo: type 4, creator 4, flags 2, location v 2, h 2, folder 2 | entry 9 bytes 0..15 | type 0x41, creator 0x45, flags = byte 0x49 then 0, v 0x4B, h 0x4D | entry 9 bytes 0..15 |
| 0x130 | 0x18 | 0 | — | — | — |
| 0x148 | 4 | creation date, Mac seconds since 1904 | entry 8 dates converted from the 2000 epoch (+0x15180·days 1904..1999) | MacBinary 0x5B, raw | entry 8 create, converted back to 2000 |
| 0x14C | 4 | modification date | entry 8 | MacBinary 0x5F | entry 8 modify |
| 0x150 | 4 | backup date | entry 8 | 0 | entry 8 backup; access = 0x80000000 |
| 0x154 | 0x10 | FXInfo | entry 9 bytes 16..31 | 0 | entry 9 bytes 16..31 |
| 0x164 | 8 | 0 | — | — | — |

Transposition of the info part:

- The first 0x100 bytes and the last 0x6C bytes are transposed as two separate blocks. This part
  is excluded from the 512-block transposition of the message (type 3 with +A = 2).
- Readers take it back the same way (0x100 + 0x6C blocks); for the gateway reader this is
  inferred, not confirmed.
- Formula: stored = T(info[0:0x100]) ‖ T(info[0x100:0x16C]).

Names of Mac files:

- From AppleSingle, the title is entry 3; from MacBinary, the name at byte 1 (length) / 2.
- To AppleSingle, entry 3 is the item title.
- Mac items have no date stamp in the title.

## 3. Item titles

- Stored as tag 07 (§1), one per logical item, in index order. They are not in the descriptor or
  in the item data.
- The date and time in a file title follow the author's country format.
- Title stamps:
  - A writer that takes the file from disk appends the file date/time to the title
    (`" " + date + " " + time`, §2.1).
  - A writer given the data inline keeps the title as given; such file items get +8 = 0.
- Removing the stamp (gateway outbound):
  1. If the last `:` is followed by two digits, cut after them.
  2. Cut at the last space (the time) and trim.
  3. If the previous word has ≥ 2 digits, cut it too (the date).
  - So `REPORT.TXT 11/24/93 10:15PM` → `REPORT.TXT`, while a bare `REPORT.TXT` is unchanged.
- Untitled items in MIME: `TextItem`, `FaxItem`, `FileItem` (smtp-link.md §2.4).
- Charset: the title bytes are in a client code page. Not determined: which of the code-page TLVs
  20/21/31 (codepages.md) covers titles. Plain ASCII titles avoid the question.

## 4. Fax and graphics items

### 4.1 Fax (type 4)

- **Data = a PCX-style file.** It starts with a 128-byte PCX header, followed by the image
  rows. Item length = 0x80 + row data.
- **Header checks.** A fax item header is valid only if:
  - all 0x80 header bytes are present;
  - byte 0 = 0x0A, byte 1 (version) ≥ 2, byte 2 (encoding) = 1, byte 3 (bits/pixel) = 1;
  - byte 0x40 = 0, byte 0x41 (planes) = 1;
  - Xmin ≤ Xmax, Ymin ≤ Ymax;
  - bytes/line (0x42) − ((Xmax − Xmin + 8) >> 3) ∈ {0, 1};
  - Xmax ≤ 0x6C0 (1728, the fax line width).
- **A client writing a fax item:**
  - checks the 0x80 header;
  - clips the width to 1728;
  - writes the header as one 0x80 block through the transposition;
  - re-encodes the rows;
  - rewrites the header at offset 0 (with the final PCX Ymax);
  - sets the descriptor type 4, +8 = +A = 0, +0C = 0x80 + data.
- **Encoding byte 2.** Two row codings exist:
  - 1: standard PCX RLE rows (a count byte ≥ 0xC0 carries a count in its low 6 bits).
  - 3: each row is CCITT T.4 one-dimensional Modified Huffman. A converter to PCX re-encodes it
    as PCX RLE and sets byte 2 := 1 and bytes/line := (width + 7) >> 3.
    - The codes are the exact T.4 tables for white, black and the extended make-up codes (1792+)
      (white 0 = `00110101`, black 0 = `0000110111`, white make-up 64 = `11011`, 1728 =
      `010011011`).
    - Each row starts with a fresh byte, and bits are taken MSB first.
    - Besides the 91 T.4 codes, the known decoder has two 8-bit prefixes, `00000000` and
      `00000001`, leading towards the EOL / extended make-up codes. Its path to the extended
      make-up codes appears unreachable, so **EOL handling is not determined**.
    - Without EOLs this would be TIFF Compression = 2 (CCITT 1-D modified Huffman RLE, rows
      byte-aligned), FillOrder 1. With EOLs it is T.4 (TIFF Compression 3). Settle with test C.
- **Byte 0x40 ≠ 0.** Each row is written twice and Ymax := Ymin + 2·height − 1; byte 0x40 is
  cleared. It is a "low-resolution, double the lines" flag.
- **Block layout of the transposition.**
  - The header is one 0x80 block, for writers and readers alike.
  - The rows follow in 512-byte blocks counted from offset 0x80. Not determined: whether every
    writer and reader agrees with this for the rows (one writer buffers 0x2000 bytes of rows)
    (§9).
- **Fax descriptor +A.**
  - Writers write 0.
  - A reader accepts {4,6,7,0E,10,12} with 0 → 4 (limits.md).
  - These are the same BIOS video-mode numbers as the graphics +A (§4.2), so +A is probably a
    display-mode hint, not part of the image. Not determined.

### 4.2 Graphics (type 2)

- A screen snapshot.
- Descriptor:
  - +A = BIOS video mode, +8 = a colour-register value.
  - Mode 4/6 → 0x3F40 bytes. Mode 7 → 0x7E96 bytes. 0x0E/0x10/0x12 → no fixed size.
  - 0x3F40 = 0x2000 + 8000 fits a CGA dump of B800:0000 (two interleaved banks).
    0x7E96 = 3·0x2000 + 7830 fits a Hercules 720×348 dump (four banks of 87 × 90 bytes). Both
    readings are inferences from the sizes.
- A companion type-2 part with +A = 0xFFFF may sit at the same index. Not determined: its
  content.
- Compatible gateways export graphics as `application/octet-stream`, no file name
  (pop3-imap.md §3). The gateway should do the same (`graphics-<mode>.bin`) unless a converter is
  written and checked against a capture.

## 5. Forwarded and returned messages (tag 13)

### 5.1 Layout

- **Tag 13 entry** (part 1, after the 06 descriptors; 0x14 bytes, zero-filled when inserted):

  | off | size | meaning |
  |---|---|---|
  | +0 | 1 | 0x13 |
  | +1 | 1 | 0x12 |
  | +2..+9 | | 0 |
  | +0A | word | kind: 0 Forwarded, 1 Forwarded with Changes, 2 Returned. A client sets 1 on the first 13 when the forward has been edited (the trigger is inferred); a post office writes 2 for returned mail |
  | +0C | dword | length of the embedded header record (= the old record length; clients and post offices) |
  | +10 | dword | offset of the embedded record in the message file; 0 = "the source message itself" while composing |

- **The embedded record** is a whole earlier header record: fixed part, its 06/13 entries and
  its addressing TLVs.
  - It is contiguous in the body, with word[0A] := 'F' (0x46).
  - It is written as three transposed regions: [0,0x20), [0x20,word[8]), [word[8],end).
  - 'F' means "addressing part at word[8]" (items.md §1.1).
  - Its dword[0]/dword[4] are copied unchanged from the original, so
    dword[0] − dword[4] = the addressing length still holds.
  - It must be at most 0x1000 bytes.
- **Body order** (clients and post offices alike):
  1. The item data of all descriptors in descriptor order, from word[8].
  2. Then every embedded record in tag-13 order.
  3. dword[4] = the end.
  - Item data is copied as stored; embedded headers are transposed per region.
- **The items are flat.** When forwarding, a client builds the new header keeping only tags 06,
  07, 05 and 13 of the original:
  - The original's descriptors and titles stay in the outer header, at their indices.
  - The forwarder's new items are appended at index = word[1A]. This is confirmed for attached
    files; for the forwarder's own text it is inferred.
  - A new tag 13 is inserted before the older ones, so the newest comes first.
  - +0C = the original record length; +10 = 0 until assembly.
  - The embedded record keeps its own (stale) 06 entries. Nobody reads them for display: items
    are always taken from the outer table.
- **Returned mail** (post office):
  - gathers the tag-10 entries with their 0F/14 followers;
  - adds a tag 13 with kind 2 and length = the original record length;
  - removes tags 05 and 20 (inferred);
  - adds author `Administrator`, the 0F path and subject "Message not deliverable";
  - addresses it back.
  - The items of the original stay.

### 5.2 Presentation of forward history

- A reader presents, after the outer heading, for each tag 13 in order a banner line (" Returned
  ", " Forwarded with Changes " or " Forwarded ", filled out with dashes, §7.2) and then the
  embedded heading loaded from +10.
- **Compatible gateways (SMTP, POP3, IMAP)**: no tag-13 or embedded-heading handling was found.
  They enumerate items only (smtp-link.md §2.4, pop3-imap.md §3).
  - So whether forward history reaches MIME mail at all is not determined (§9). The statement
    "tag 13 → message/rfc822" in session-layer.md §7 has no precedent in a compatible gateway.

## 6. MIME mapping both ways

The rules of compatible gateways are in smtp-link.md §2.4/§3.4 and pop3-imap.md §3. In short:

| direction | rule |
|---|---|
| out | file item → `application/octet-stream; name="<title minus stamp>"`, base64 76-col (default) or x-uuencode; **no Content-Disposition** on binary parts; a 7-bit file (not .SAM/.LWP) → `text/plain; charset; name=`, 7bit, `Content-Disposition: attachment; filename=` |
| out | Mac file (info part present) → `application/applefile` (AppleSingle from the three parts: entries 3, 5, 8, 9, 2, 1) or `application/mac-binhex40` |
| out | fax → like a file (title or `FaxItem`), kind only in the uuencode preamble; graphics → octet-stream |
| out | uuencode preamble `The following is an attached <kind> item from cc:Mail. …` + Cut Here line + `begin 644 <name>` (`FileItem` if 8-bit) |
| out | one item → no multipart; ≥ 2 → `multipart/mixed; boundary="simple boundary"` (SMTP gateway) / `MIME.PART.BOUNDARY.=.<hex>` (POP3/IMAP, pop3-imap.md §2) |
| out | POP3: `name=` + `Content-Disposition: attachment; filename=` for type 3 only; Content-Description = title |
| in | file name: Content-Type `name=`, else Disposition `filename=`, else Content-Description; > 60 → 58 + `~` |
| in | non-MIME `begin NNN name` … `end` → file item; the preamble kind Fax/Text/File honoured; AppleSingle/AppleDouble magic → Mac file (three parts); ≥ 20 blocks refused |
| in | first text part → text item; later text parts → file `FileItem.txt` unless Content-Description `cc:Mail Note Part`; text > 20480 → file `TextItem.txt`; > 80 items refused |
| in | whole RFC 822 header (Bcc removed) → file item `RFC822.TXT` (option, default on) |
| in | recognising Mac formats: AppleSingle = magic `00 05 16 00` and 16 zero filler bytes at offset 8 (version not checked); MacBinary = byte 0 = 0, byte 0x4A = 0, name length ≤ 63, CRC at 0x7C or bytes 0x65..0x7D zero |

Sizes:

- Item length is a 32-bit dword; no cap was found in compatible clients, post offices or
  gateways (limits.md §4).
- The gateway's inbound message-size limit applies (smtp-link.md §3.4).

## 7. Recipe for our gateway

Not yet checked against a real program (§9 test A).

### 7.1 Build a message with a text body and one file (filename, bytes)

1. Logical item 0 = text, as items.md §5: two descriptors with +2 = 0.
2. Logical item 1 = the file: one descriptor `06 12`, then:
   - +2 = 1, +4 = 3, +6 = 3;
   - +8 = 0 (M/D/Y, used only to parse a date stamp in the title);
   - +A = 0;
   - +0C = len(bytes);
   - +10 = offset.
3. Fixed part: word[1A] = 2, word[1C] = 3, word[1E] = 3, word[8] = 0x20 + 3·0x14 = 0x5C.
4. Body: transpose(text) at 0x5C, then transpose(file) right after it. Each is transposed from its
   own first byte, in 512-byte blocks. No alignment is needed.
5. Addressing part: `01 user`, `03 user1`, `05 subject`, then `07 00` (item 0 untitled) and
   `07 0B "REPORT.TXT\0"` (item 1).
   - Title rules: ≤ 60 bytes, plain ASCII 8.3 preferred.
   - Clients take only the first word as the file name (§2.1), so a name with spaces is cut at
     the first space.
   - Leave out the date stamp. Our own readers must still strip one: §3 rule.
6. Sizes: dword[4] = 0x5C + body length; dword[0] = dword[4] + addressing length.

Example (round-trip checked) for text `See the attached file.\r\n` (24 bytes) and file
`Hello, file!\r\n` (14 bytes), dated 25 Nov 2026 14:30:00:

```
part 1, plain (fixed + 3 descriptors):
  0000  ac 00 00 00 82 00 00 00 5c 00 4d 00 01 00 00 00
  0010  00 00 19 0b 7e 00 00 1e 0e 00 02 00 03 00 03 00   word[1A]=2 word[1C]=3 word[1E]=3
  0020  06 12 00 00 01 00 01 00 17 00 01 00 00 00 00 00   idx0 text attr layer, len 0
  0030  5c 00 00 00 06 12 00 00 01 00 02 00 01 00 00 00   idx0 text chars, 1 CR LF
  0040  18 00 00 00 5c 00 00 00 06 12 01 00 03 00 03 00   len 0x18 @0x5C | idx1 type 3 #3
  0050  00 00 00 00 0e 00 00 00 74 00 00 00               +8 0 +A 0 len 0x0E @0x74
body as sent (offset 0x5C):
  005c  74 74 2e 68 0d 68 63 61 65 69 20 74 20 65 65 6c   transpose(text)
  006c  20 61 64 53 66 65 65 0a 6c 6f 2c 0a 0d 21 65 66   ... | transpose(file) from 0x74
  007c  65 6c 6c 69 48 20                                 "lo,\n\r!efelliH "
addressing TLVs (offset 0x82):
  0082  01 05 75 73 65 72 00 03 06 75 73 65 72 31 00 05
  0092  0a 66 69 6c 65 20 74 65 73 74 00 07 00 07 0b 52   07 00 | 07 0b "REPORT.TXT\0"
  00a2  45 50 4f 52 54 2e 54 58 54 00
```

- The wire record is part 1 + the addressing part, and the body is sent after 86
  (session-layer.md §4). The stored file applies the region transposition of items.md §4 to
  part 1 and the addressing part.
- A small check of the permutation: transpose(`ABC`) = `BCA`.
- A 600-byte file is stored as T(bytes[0:512]) ‖ T(bytes[512:600]).

### 7.2 Read one back

1. For each logical index i < word[1A], collect the descriptors with +2 = i.
2. Title = the i-th tag 07, minus a trailing date stamp.
3. If a type-3 part has +A = 2, it is a Mac file:
   - data = +A 0, resource = +A 1;
   - info = untranspose(stored[0:0x100]) ‖ untranspose(stored[0x100:0x16C]);
   - make AppleSingle as in §2.2 and §6, or BinHex.
4. Else the data = untranspose(the +A 0 part), in 512-byte blocks from its offset.
5. MIME: `application/octet-stream; name="<title>"`, base64.
   - Compatible gateways omit Content-Disposition on binary parts. Adding
     `attachment; filename=` is our own choice, and harmless.
   - A 7-bit file with a name goes as `text/plain` + Disposition (§6).
6. Fax: untranspose [0,0x80) as one block, then 512-blocks from 0x80.
   - Byte 2 = 1: the result is a PCX file → `image/x-pcx; name="FAXnn.PCX"`. Double the rows
     if byte 0x40 ≠ 0 (§4.1).
   - Byte 2 = 3: wrap the rows as TIFF (Compression 2 if test C shows no EOLs, else 3; FillOrder 1;
     width = Xmax − Xmin + 1, rows = Ymax − Ymin + 1) → `image/tiff`. Or convert to PCX (§4.1).
   - Until §9 test C confirms the block layout of the rows, also offer the raw item as
     `application/octet-stream`.
7. Graphics: `application/octet-stream`.
8. Forward history (no reference in a compatible gateway, §5.2): render it as a leading text
   part: per tag 13 a banner line — 35 `-` + ` Returned ` + 35 `-`, or 28 `-` +
   ` Forwarded with Changes ` + 27 `-`, or 34 `-` + ` Forwarded ` + 34 `-` — then `\r\n` and the
   embedded heading lines (`From:`, `Date:`, `To:`…); after the last one, an all-dash line. A
   `message/rfc822` part would be our own invention: the original's items are not inside the
   embedded record (§5.1).

### 7.3 Inbound MIME → items

Follow §6:

- The first text part becomes the text item. Every attachment becomes one logical item:
  file part(s) + a tag-07 title from name / filename / Content-Description (≤ 60 bytes;
  > 60 → 58 + `~`).
- AppleSingle/AppleDouble → three parts (+A 0/1/2). The 0x16C info is built as in §2.2 and
  transposed as 0x100 + 0x6C.
- The RFC 822 header becomes file `RFC822.TXT` (default on).
- Keep to 20 logical items.

## 8. Corrections to the other specs

| spec | statement | correction |
|---|---|---|
| session-layer.md §4.2 word[1A], §4.6 +2 | "number of headings", "heading level the item belongs to" | number of logical items / index of the logical item (§1). Forwarding does not add a level: items stay flat (§5.1). |
| session-layer.md §4.3 tag 07 | "no reader found" | item title, one per logical item (§1). |
| session-layer.md §4.3 tag 13, §4.6 | "+10 file offset"; "the original's items have +2 = that heading's level" | +0C = record length too; +10 = 0 while composing; items flat; record stored in 'F' form (§5.1). |
| session-layer.md §7 | tag 13 → message/rfc822 | no compatible gateway does this (§5.2). |
| items.md §2 ("Other +8/+A values occur") | +8 written by the attach command, meaning not determined | the author's country date order (§2.1). |
| items.md §1.1 | "heading level" | current logical item index. |
| limits.md §4 | "Headings / forward levels (word[1A]) 20"; "unless item type 32" | 20 logical items; "type 32" probably refers to the update item (type 5), not confirmed. |
| limits.md §4 fax/graphics | "Graphics item: not traced" | §4.2. |
| pop3-imap.md / smtp-link.md "decode our stored file item format (items.md UNKNOWN)" | — | file data = the file transposed (§2.1). |
| `ccmail/message.py` `item_list()` | returns file items in stored (transposed) form | untranspose non-text parts too (§7.2). |

## 9. Open points and how to settle them

| point | settle with |
|---|---|
| Not determined: fax coding 3 — are EOL codes present? (the two 8-bit prefixes and the apparently unreachable extended make-up path, §4.1) | a real cc:Mail fax item from a fax gateway; or test C |
| Not determined: are fax rows 512-blocks from 0x80 for every writer and reader? | **test C**: import a small PCX as a fax item with a compatible client's import tool, export it again, and compare the .PCX |
| Not determined: fax/graphics +A meaning (mode set {4,6,7,0E,10,12}) | a fax/snapshot display test with a compatible client |
| Not determined: graphics companion part (+A 0xFFFF), +8, and the layout of modes 0E/10/12 | a snapshot test in a DOS emulator |
| Not determined: file parts +A 3, 4 (+8 3), 5 | further analysis of a compatible gateway |
| Not determined: info part bytes 0x100..0x11F | an AppleSingle from a real Mac client |
| Not determined: a client's date parse with years ≥ 100 and `/` while the country separator is `-` (does saving restore the file date?) | test: save a file attached in 2026 and look at the DOS date |
| Not determined: code page of titles | which of TLV 20/21/31 a compatible gateway uses when reading titles |
| Not determined: how compatible gateways (SMTP, POP3, IMAP) present tag 13 history (if at all) | **test B**: a client forwards a message to a user served by a compatible POP3 server (and the SMTP gateway); fetch and look |
| The whole recipe | **test A**: build §7.1, deliver it to a client (our server), then display the file item and save it to disk, and compare the file; also import a file item with an explicit size with a compatible client's import tool and dump the stored file's descriptors and TLVs |

None of these tests has been run yet.
