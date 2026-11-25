# Directory updates

The directory update message: how a client asks for updates, the update message and its item
text (records, keywords, location letters), and the rules by which a receiving client applies
the records.

Compatibility: this server is compatible with cc:Mail Remote 3.40B and with the HP 200LX / 100LX
palmtop cc:Mail and its directory update tool; the update format below is the one cc:Mail
Router sends. Roles: **client** = a DOS mobile client, **palmtop client** = a palmtop client
that applies updates from attachments, **post office** = the peer that sends updates (a
Router-compatible post office), **server** = this server.

No capture of a directory update exists in either direction, so nothing here is confirmed on
the wire yet.

Wording: "level-0 item" below follows the older specs; per file-items.md §1 descriptor +2 is the
logical item index and header word[1A] the number of logical items, so "level 0" = the first
logical item, and word[1A] = 1 = a message with exactly one item.

## 1. The update request (client → post office)

### 1.1 The "after" date and time

A client asks for directory updates "after a date and time"; there is no "full directory" versus
"changes" choice in the request. The default is **now** (the client's current date and time),
printed in the user's date format setting (1 = dd/mm/yy, 2 = yy/mm/dd, other = mm/dd/yy; the
year is printed as the number year-1900, e.g. `126` for 2026) and 12- or 24-hour time. The text
is at most 0x10 characters: date first, then (after the next word break) time. If no request is
made, nothing is sent; a date or time that does not parse is not accepted.

Date text: three integers separated by `/` or the country date separator; order from the date
format (1 = d m y, 2 = y m d, other = m d y); month 1..12, day 1..31; the year is not checked
and only its low byte is kept. Result dword: byte 0 = day, 1 = month, 2 = year as typed (low
byte), 3 = 0.

Time text: either `hhmm` (one number of 3+ digits ending the text: hour = n/100, minute =
n%100) or `h` `:`|country time separator `m`, then an optional am/pm word (first letter compared
case-insensitively: pm adds 12 below 12, am turns 12 into 0). Hour 24 → 0, hour > 24 or
minute > 59 → fail. Result dword: byte 0 = 0, 1 = minute, 2 = hour, 3 = 0; **if the whole dword
is 0 (midnight), byte 0 is set to 1**, so 0 never means "a time was given".

### 1.2 The message

Built in a 0x1000-byte header buffer and queued, then sent in the next session like any other
outgoing message (session-layer.md §4):

| element | value |
|---|---|
| fixed part | the standard fixed part, then word[1A] = word[1C] = word[1E] = 0 before the item is added |
| 01 | the owner (own user entry) with its 0F path |
| 03 | `Administrator` |
| 0F | the home post office name, only if one is set |
| 05 | "Directory update request" |
| 18 | empty (length 0) |
| 16 | `02 00` = Urgent |
| 06 | one level-0 item of type 6, item data length 0x14 (stored at descriptor +0C) |

So on the wire (before the 01/03 copies the send path adds, session-layer.md §4.3) the request
is: 01 owner [0F...], 03 `Administrator`, 0F home PO, 05 subject, 18 empty, 16 Urgent, 06 item.

The descriptor stride is 0x14; the item **data** is also 0x14 bytes:

| off | size | value |
|---|---|---|
| +00 | word | 0x0014 |
| +02 | word | 0 |
| +04 | word | 1 |
| +06 | word | 1 |
| +08 | word | 0 |
| +0A | word | 0 |
| +0C | dword | "after" date: day, month, year-as-typed (low byte), 0 (§1.1) |
| +10 | dword | "after" time: 0 (or 1 for midnight), minute, hour, 0 (§1.1) |

Not determined: the meaning of words +00..+0A; nothing known reads them (they look like a small
fixed structure header: size 0x14, then 0, 1, 1, 0, 0).

The 20 bytes are stored with the forward 17-column transposition applied to each <= 0x200-byte
piece (items.md §4). When the message is queued, item data is copied raw into the message body
(file-items.md "Body order"), and the sender sends the body raw. So **on the wire the item data
is `transpose(20 bytes)`**; untranspose it as one 20-byte block (`ccmail.message.untranspose`).
Example: 25 Nov 2026 10:30 → plain
`14 00 00 00 01 00 01 00 00 00 00 00 19 0b 7e 00 00 1e 0a 00`, on the wire
`00 01 00 0b 19 00 00 0a 00 00 00 00 00 00 00 00 14 1e 7e 01`.

Year: the default text has year-1900 (`126` in 2026). A user who keeps the default or types the
same form gives byte +0E = year-1900. A typed 4-digit year gives its low byte (1994 → 0xCA,
2026 → 0xEA). A server reading the request should take +0E as year-1900 when it is ≥ 70 and
treat a value that makes a date in the future as "everything" (our rule, not a peer's).

The client does nothing with the result of the request. It does not wait for an answer; the
answer is just mail that arrives in a later session (§3).

### 1.3 Peer post office

A Router-compatible post office recognises the request by tag 18 and never answers it; the
type-6 item is never read. The format of an answer is therefore not defined by the request
handling; §2 describes the update messages a post office sends to its clients through directory
exchange (ADE), which is what the receiving client (§3) is built for.

## 2. Update messages a post office sends to a client

This is the post office's behaviour (DB6; DB8 differences in brackets). A client gets directory
updates only by directory exchange propagation, in the post office's turn of any session with
that user; the request of §1 plays no part (§1.3).

### 2.1 When a user gets updates

- Post office's turn, with exchange letter D set (the default exchange letters are M D B):
  directory updates are sent before mail.
- Conditions: DB version ≥ 6; exchange policy bit 4 for the user [DB8: a setting of the own post
  office entry]; a directory-update
  bulletin board [DB8: the folder named exactly `##Directory Updates`] whose distribution list
  contains the user. DB8 adds the user to the list automatically when allowed, starting at the
  current message, no backlog.
- Which messages: those in the board after the user's high-water mark (kept per member, written
  after the send), not authored by the user.
- The user's propagation word filters records: 2 = entries at this PO, 8 = other POs,
  100h = aliases, 400h = mailing lists, 800h = bulletin boards. Users without their own word take
  the post office default; a plain local user gets 11h, which passes nothing.

So the post office sends a **copy of the board's update messages** (made by administration or
arriving from other POs), filtered per record, not a directory built for the user. The client's
"after date and time" plays no part. A full directory reaches a user only as a directory
synchronisation (exchange letters S / R), not in the default exchange.

### 2.2 The message

Header as rewritten by the post office:

| element | value |
|---|---|
| 05 | the stored subject, normally "ADE update message" |
| 07 | the stored one, `CCMUPDAT <date> <time>`, e.g. `CCMUPDAT 11/25/26 3:07PM` (date in the system date order, 0 = M/D/YY unpadded, year 2 digits, '/'; time H:MMAM/PM or H:MM, no seconds). Not regenerated. |
| 06 | one level-0 **type-3** (file) item, the filtered text; the post office never writes a type-5 descriptor (it writes only types 1/3/4) |
| 01 | `Administrator` + 0F `<own PO>` (inserted) |
| 21 | code page word |
| 04, 1B | the board name, `##Directory Updates` |
| 03 | the user, **no 0F** |
| 0C | `~WAMM_Mailbox` / `#WAMM_Mailbox` if they exist |
| 1C | word 2 \| 10h \| 20h [DB8: 2] |
| 16 | none |

Everything else from 01 on is removed. Consecutive board messages are merged: their records go
into one file, which replaces the first level-0 type-3 item of the last one, and one message is
sent.

On the client: 1B makes it be filed into a folder named `##Directory Updates` if the user has
one, else the inbox (session-layer.md §6.3); the client turns the item into an update item
(§3.1), and the user applies it from the message.

### 2.3 Item text

Per record: the author's own lines are kept (`"%s\r\n"`), but `Synch:`, `Format:` and `REM`
lines are dropped, DB8 `Uname:`/`UAltName:`/`UCmts:` too unless extended fields are on, and
ADE20 records are converted (`Addr:` deleted, `Achng:` renamed `Addr:`). With
propagation bit 2000h and not 1000h an `Achng: <own PO>` line is added. The text uses the
512-byte block transposition from the item start.

Records the post office writes itself (synchronisation, deletes): `Name: %s`, `Locn: %s`,
`Addr: %s` (non-PO entries; a PO only with option 4), `Achng: %s` (option 10h), `Cmts: %s`,
each CR LF. Letters: P post office, A alias, R remote user, L other user, M mailing list, B
bulletin board; delete = `D` + letter (`Locn: DL`). Propagation field after a space: 4 hex
digits, least significant nibble first (C0E0h → `0E0C`). Name text: `Last, First` (", "). A
user's `Addr:` is its PO name.

Read against §3: a client takes only the first Locn letter (propagation field ignored; `DL` =
delete), maps L to R, refuses M and B (unknown location), and has no `Achng:`/`Uname:` keywords
(the post office removes them for users except an added `Achng:` with bit 2000h, which a client
rejects as an unknown line — so client users must not have bit 2000h). The 07 has no '.', so
the update number is 0 and the sequence check is by date/time only; the year `26` is read as
1926 by the client (§1.1), harmless since both sides of the compare come from the same post
office.

## 3. Applying an update item (receiving client)

### 3.1 When it runs

**A CCMUPDAT file item counts as an update item.** When a message is loaded for viewing, the
client checks the header in memory: if there is no level-0 type-5 item, and word[1A]
(headings) = 1, and there is a level-0 type-3 item, and a tag 07 with length ≥ 8 whose first 8
characters equal `CCMUPDAT` case-insensitively, then the descriptor type of that type-3 item is
changed to 5. A DOS file item's data is the file bytes, transposed in 512-byte blocks from the
item start (file-items.md §2.1), which is exactly what the reader below expects. This is how a
client applies a post office's update messages (§2), which carry a type-3 item, never a type 5.
The change is not written back to the file (in-memory header only; not determined whether a
later save writes it).

A receiving client applies an update only when the user asks for it on the opened message,
which must have a type-5 item at the current heading level. Updates are never applied during
the session or automatically.

1. Find the first type-5 item at that level; data length = descriptor +0C (dword), offset =
   descriptor +10, date format = **descriptor +8 & 3**.
2. Tag 07 handling (§3.2): show the last update, confirm, sequence check. Not confirmed →
   nothing done.
3. Open the local undeliverable-updates file for appending (create it if absent); if that fails,
   stop.
4. Read the item from the message at msgbase + offset in blocks of min(0x200, remaining), each
   read and untransposed, so **the item data is transposed in 512-byte blocks counted from the
   item's first byte**, like a text item (items.md §3). A short read stops the run.
5. Parse lines and apply records (§3.3, §3.4); the user can stop between lines.
6. End: if the run ended normally and the date and time from step 2 are both non-zero, store
   {date, time, number} as the last update. Close the undeliverable-updates file; delete it if
   it is empty. If any PO was added or renamed or an `A` entry's address was set, re-check the
   directory (§3.4). Report the number of records that changed something and the number of
   undeliverable records.

### 3.2 Tag 07: update date, time and number

- The last stored update (date/time and number) is shown, and the user confirms.
- The client reads the message's tag 07 (the first 07 at or after offset 0x20; the text is the
  NUL-terminated string at +2). Parsing:
  1. skip to the second word (spaces, non-spaces, spaces);
  2. **update number** = the decimal number right after the **last '.' before the second word**
     (scanned back from the second word); no '.' → it parses at the start of the text, which for
     `CCMUPDAT` gives 0;
  3. **date** = date parser on the second word, with format = descriptor+8 & 3; then **time** =
     time parser on the word after it (§1.1 rules).
- If the date or the time is missing or invalid, the message header's own date (+12) and time
  (+16) are used.
- Sequence check: identical {date, time, number} to the stored one → no warning; stored number
  and new number both 0 → no warning; otherwise warn when the stored date/time is later than the
  new one, or new number ≠ stored number + 1. The warning ("not in sequence") must be confirmed,
  otherwise nothing is done. Dates compare as dwords (year, then month, then day).
- So the tag 07 a client wants is `<word>[.<number>] <date> <time>`, e.g.
  `CCMUPDAT.12 11/25/126 10:30` with descriptor +8 = 0 (mm/dd/yy). Tag 07 missing: the "text" is
  taken at header+2, which parses as garbage or nothing; always send a tag 07.

### 3.3 Lines

Line reader:
- Bytes are taken one by one; **NUL is skipped**, **CR is skipped**, **LF ends the line**; at most
  0x105 (261) characters are kept, the rest of a longer line is dropped silently.
- At the end of the item data: trailing ^Z characters are removed from the last line, then
  trailing spaces from every line.
- Leading spaces are removed. Tabs are not spaces.
- Each non-empty line is also kept, with CR LF, in a 0x400-byte record buffer while it fits;
  that buffer is what goes to the undeliverable-updates file when the record fails.

Keywords: compared case-insensitively (a..z upper-cased) over the keyword's own length, at the
start of the line; the value is the rest of the line after the keyword with leading spaces
skipped.

| keyword | stored | max length | empty value | duplicate |
|---|---|---|---|---|
| `NAME:` | name | 126 | error "empty" | (a second `NAME:` starts a new record) |
| `CHNG:` (new name) | new name | 126 | error "empty" | error "duplicate" |
| `LOCN:` | first letter only | — | allowed, location stays "none" | error "duplicate" |
| `ADDR:` | address | 255 | allowed | error "duplicate" |
| `CMTS:` | comments | 126 | allowed | error "duplicate" |
| `PSWD:` | ignored (accepted) | — | — | — |
| anything else | — | — | — | error "unknown line" |

A value over the maximum length is error "too long".

`LOCN:` value: the first non-space character, upper-cased. `L` becomes `R`. Accepted: **R, P,
A, D**. Anything else (M, B, C, digits...) → error "unknown location". Everything after the
first letter (the post office's 4-digit propagation field) is ignored. There is no separate
delete prefix: `D` is the whole location ("delete").

Not understood by a client and therefore **errors that make the whole record undeliverable**:
`ACHNG:`, `LOCK:`, `FORMAT:`, `SYNCH:`, `UNAME:`, `UALTNAME:`, `UCMTS:`, `REM` lines, `Error:`
lines.

Parse errors: too long, empty, duplicate, unknown location, unknown line.

### 3.4 Records

- A record starts at a `NAME:` line (clears CHNG/LOCN/ADDR/CMTS, keeps only this line in the
  record buffer).
- It ends at the next `NAME:` line or at the end of the item data. Blank lines do not end a
  record and are skipped.
- A non-blank line before the first `NAME:` (or after a record has ended) starts an error state:
  the record buffer and a "missing update start line" note go to the undeliverable-updates file,
  and following lines are copied there until the next `NAME:`. So **no header lines**
  (`Format:`, `Synch:`) may precede the first `NAME:`.
- A parse error in a record: the undeliverable-updates file gets a start marker, the record so
  far (CR LF lines), then the error line; the rest of the record is copied line by line; the
  record is not applied.
- A record without errors is applied; it counts when it changed something.

Apply rules. Names are normalised before lookup (spaces trimmed and collapsed, spaces around the
first comma removed, ` FAX#` part handled) and looked up in the directory.

1. `A` is handled as `R` plus a later directory check (below).
2. Lookup NAME. Not found and `CHNG:` given → the CHNG name is copied over the name and looked
   up, once, so a rename that was already applied is still found; if neither is known, the
   entry is **added under the new name**.
3. Not found:
   - `D` → nothing, no change;
   - no `LOCN:` letter → error "location not specified";
   - directory already holds 0x7869E (493,214) entries → error "directory full";
   - otherwise **add**: a post office entry for `P`, a user entry for R/L/A; then Cmts and Addr
     if non-empty.
4. Found:
   - `R` on a post office entry → error "location change invalid";
   - `P` on the owner's own entry → error "location change invalid";
   - `D`: the owner's own entry → error "owner may not be deleted". For a non-PO entry with a
     non-empty `ADDR:`, the address is resolved and the entry is deleted only if it resolves to
     the entry it is currently linked to (else no change). Otherwise the entry is deleted.
   - `CHNG:`: if the new name already belongs to another entry → error "duplicate name"; else
     rename.
   - `LOCN:` letter: only `P` changes anything (an existing user entry becomes a post office);
     `R` on a user changes nothing.
   - `ADDR:` given → set address: unchanged text → no change; empty → address cleared; else
     resolved as below.
   - `CMTS:` given → set comments.
   - The record counts if anything changed.

Address resolution, used on add and change:
- The whole address (≤ 126 characters, normalised) is looked up as a directory name; if that
  fails, its first word is (up to the first space, or a leading `"..."` quoted string).
- Found, and not the entry itself, and the found entry's route chain does not lead back to the
  entry → the entry is **linked to that entry**; the rest of the address after the word and
  spaces is kept as the sub-address.
- Not found → the text is stored as an unresolved text address.
- After the run, if a PO was added, a PO was renamed or an `A` record was added/changed, the
  client walks the whole directory and re-resolves every entry that has a text address and no
  link, linking it when the name now resolves. So a user whose PO arrives later in the same item
  is still linked, **if a PO was added in that run**.

So for a user at another post office, `ADDR:` = the post office's directory name. For a post
office, `ADDR:` is its own address text (e.g. a dial string): it does not resolve, so it stays
text. What `A` means to the post office (only its effect here is known): see §2.

Entries a client creates from an update: users and post offices only. Not determined: whether
such an entry can ever carry the alias flag (`A` only tests it).

Apply errors: location not specified (new entry without `LOCN:`), directory full (493,214
entries), location change invalid (`R` on a PO, `P` on the owner), owner may not be deleted
(`D` on the owner), duplicate name (`CHNG:` to a name in use).

What a client cannot receive by update: mailing lists and bulletin boards (location M/B is an
unknown location), passwords (`PSWD:` ignored).

Server rules that follow:
- Never send `ADDR:` on a `D` record (the delete is silently skipped when the address does not
  match).
- Set the type-5 descriptor +8 to the date order used in tag 07 (0 = mm/dd/yy).
- Send POs before their users anyway (links at once, no reliance on the directory re-check).

## 4. Applying update attachments (palmtop client)

### 4.1 Input

- The palmtop client applies updates to its local address book from inbox messages, with the
  mail program not running.
- **Inbox**: every inbox message in order, no subject/author check; only attachments are
  considered (notes skipped), up to 20 per message. An attachment is an update file when **its
  name starts with `CCMUPDAT`, case-insensitive, first 8 characters**.
  - The message is deleted afterwards (after the whole scan) only if it matched, no record of it
    was skipped, and it has exactly one attachment; a fatal error anywhere → nothing deleted.
  - At most 10 deletable update messages per run; the rest need another run. Undeletable ones do
    not count and are re-applied every run.
- **File**: an update file can also be applied directly, with the same rules; the file is deleted
  when no record was skipped.

### 4.2 Text format

- Read in 0x800-byte chunks with a ^Z sentinel; a real ^Z ends the data. An empty file aborts the
  run. **A file whose size is an exact multiple of 2048 bytes hangs the palmtop** (the end of the
  data is not handled at a chunk boundary), so never send one.
- **Lines end in CR LF** (any CR/LF pair; with bare LF the next byte is lost). **The last line
  must end in CR LF** too, or its field is lost.
- Keyword = the text before the first `:`, whole-word, case-insensitive. No leading spaces.
  After the colon **exactly one space** (skipped) or the line end; anything else is an error.
  More spaces become part of the value; trailing spaces kept.
- Known: `Name`, `Chng`, `Pswd`, `Locn`, `Addr`, `Achng`, `Cmts`; other keywords ignored
  (Format, Synch, Uname...). Lines without `:` ignored (blank, REM). Max token 0x37F.
- **The first keyword line must be `Name:`** (value ≤ 126); otherwise the whole run stops (the
  update message counts as corrupted). A record = a `Name:` line up to the next `Name:` or the
  end.
- Fields: Chng ≤ 126; Pswd, Cmts ignored; Addr; Achng overrides Addr; a field twice → error.
- `Locn:` first character only: `D` (upper case only) = delete; `P`/`p` = post office, **record
  ignored silently**; `A`/`a` sets an "alias" style; anything else (L, R, M, B, C, d) = an
  ordinary located entry. Locn is optional when Addr or Chng is given.

| record | action |
|---|---|
| error, or no Locn/Addr/Chng, or Locn alone, or D with Chng | skipped (logged) |
| P | skip, no log |
| D | delete the name (not found = success) |
| Addr/Achng | delete the name, then add; with Chng: delete old, add new |
| Chng only | rename, keeping the old entry's PO |

### 4.3 Applying to the local address book

- Match: name, case-insensitive, whole name, first match only.
- Add: delete, then create an entry named with the raw `Name:` value and a cc:Mail address
  `swap(Name) + " at " + Addr`, where swap turns `Last, First` into `First Last` at the first
  comma. With `A`: the address is `swap(Addr)` alone (and the alias style is not reset on other
  paths, so it can leak into the next add — do not send `A`).
- Rename with Chng only: the PO is the text after the first " at " of the old address.
- Cmts and Pswd are never written. No lists, no post offices.

### 4.4 Errors

- Each skipped record is logged with its first and last line number (1-based), and the message
  is then kept (§4.1).
- The run aborts on a corrupted update (first keyword not `Name:`), an open or read failure, an
  empty file, the user pressing Esc/Enter (checked once per record), or an address book error.
- After an add/rename failure, parsing continues on a closed file: outcome not determined.

### 4.5 Post office output and the palmtop

The post office's per-entry text (§2.3) suits the palmtop: `Name:` first, one space after each
colon, CR LF. `Locn: DL` deletes (first letter D), `Locn: P` is skipped, `Locn: R 0E0C` is an
ordinary entry. A board message whose text started with `Format:`/`Synch:` would abort the
palmtop's run, but for users the post office drops those lines.

## 5. Byte-level examples

The item texts below satisfy both the client rules of §3.3 and the palmtop rules of §4.2.
Neither example has been run on a client or a palmtop yet.

One message format serves both clients: **one logical item, type 3 (file), titled
`CCMUPDAT <date> <time>`** (the client converts it to an update item, §3.1; the palmtop takes
attachments named `CCMUPDAT*`, §4.1), like the post office's (§2.2). Choices:
- tag 07 `CCMUPDAT 11/25/126 10:30`: mm/dd/(year-1900) as the client's own default prints it; no
  `.n`, so no sequence numbering (like the post office; the client then only compares
  date/time);
- descriptor +8 = 0 (the client reads the date as mm/dd/yy);
- no text item: the 07 that the client checks is the **first** one, which must be the file's
  title, and word[1A] must be 1;
- 01 `Administrator` + 0F own PO, 03 the user without 0F, 05 "ADE update message", like the post
  office; no 04/1B (we do not want it filed into a `##Directory Updates` folder; optional);
- the item text ends in CR LF; if its length is a multiple of 2048, add one more CR LF (both
  clients skip blank lines);
- `L` for users (the client maps to R), `P` for post offices, `Addr:` = the user's PO name, `DL`
  to delete, no `Addr:` on deletes, no Achng/Lock/Format/Synch/REM/Uname lines, no M/B/A
  records.

Fixed part (both examples): dword[0] total, dword[4] addressing offset, word[8] = 0x34, `M`,
word[0C] = 1, dword[0E] = 0, date 25 Nov 2026 (`19 0b 7e 00`), time 10:30:00 (`00 1e 0a 00`),
word[1A] = 1, word[1C] = 1, word[1E] = 1. Descriptor `06 12`: index 0, type 3, part 1, +8 0, +A 0,
+C length, +10 = 0x34.

### 5(a) Reply to a client's request: own PO `HQ`, other PO `BRANCH`, users Smith/Doe (HQ) and Brown (BRANCH); recipient `Doe, Jane`

Item text (161 bytes, CR LF lines):

```
Name: BRANCH
Locn: P
Addr: HQ
Name: Smith, John
Locn: L
Addr: HQ
Name: Doe, Jane
Locn: L
Addr: HQ
Name: Brown, Bob
Locn: L
Addr: BRANCH
Cmts: Sales
```

`Addr: HQ` on BRANCH links it to the home PO entry, which the client already has (§3.4 address
resolution); the post office itself writes Addr for POs only with option 4 (our choice here).
The recipient's own record is harmless (`L` on the owner changes nothing; `P` or `D` would be
errors). HQ itself is not sent (it is the client's home PO).

Header record on the wire (part 1 + addressing, 133 bytes):

```
0000  26 01 00 00 d5 00 00 00 34 00 4d 00 01 00 00 00
0010  00 00 19 0b 7e 00 00 1e 0a 00 01 00 01 00 01 00
0020  06 12 00 00 03 00 01 00 00 00 00 00 a1 00 00 00
0030  34 00 00 00 01 0e 41 64 6d 69 6e 69 73 74 72 61   ....Administra
0040  74 6f 72 00 0f 03 48 51 00 03 0a 44 6f 65 2c 20   tor...HQ...Doe,
0050  4a 61 6e 65 00 05 13 41 44 45 20 75 70 64 61 74   Jane...ADE updat
0060  65 20 6d 65 73 73 61 67 65 00 07 19 43 43 4d 55   e message...CCMU
0070  50 44 41 54 20 31 31 2f 32 35 2f 31 32 36 20 31   PDAT 11/25/126 1
0080  30 3a 33 30 00                                    0:30.
```

Body (161 bytes) = `transpose(item text)`:

```
0000  4e 72 68 0a 44 4c 3a 6e 48 3a 0d 20 6e 61 6f 0a
0010  0d 42 65 20 0a 53 3a 6d 63 4e 0a 52 73 0a 51 6f
0020  72 20 64 6f 0d 6d 0d 48 4a 64 2c 41 72 4c 43 48
0030  20 20 64 65 0a 42 20 0a 61 3a 6d 4c 0d 0d 48 42
0040  72 53 52 64 69 4c 3a 3a 6d 6f 4e 0a 43 3a 2c 41
0050  6f 0d 20 3a 0d 65 50 3a 63 4e 4c 0d 62 20 6c 6d
0060  20 65 6f 0a 0a 51 6f 3a 61 63 4e 0d 48 6e 3a 2c
0070  64 3a 41 64 74 0d 20 20 65 63 43 6f 0a 6e 20 61
0080  72 6e 41 73 4e 6e 61 0a 51 65 20 20 64 20 4c 0d
0090  68 3a 4a 64 77 0a 74 42 41 6d 20 65 6e 61 4c 41
00A0  0d
```

Expected client result (from §3, not run): each new entry is entered; the user's own entry
makes no change if its address is already HQ; BRANCH added → directory re-check; stored last
update = 25/11/126 10:30, number 0.

### 5(b) CCMUPDAT for the palmtop: add `Brown, Bob` at BRANCH, delete `Old, Fred`

Item text (68 bytes):

```
4e 61 6d 65 3a 20 42 72 6f 77 6e 2c 20 42 6f 62 0d 0a   Name: Brown, Bob
4c 6f 63 6e 3a 20 4c 0d 0a                              Locn: L
41 64 64 72 3a 20 42 52 41 4e 43 48 0d 0a               Addr: BRANCH
4e 61 6d 65 3a 20 4f 6c 64 2c 20 46 72 65 64 0d 0a      Name: Old, Fred
4c 6f 63 6e 3a 20 44 4c 0d 0a                           Locn: DL
```

Same header as 5(a) except dword[0] = `c9 00 00 00`, dword[4] = `78 00 00 00`, descriptor +C =
`44 00 00 00`. Body (68 bytes):

```
0000  77 0a 6d 63 3a 6e 48 64 20 3a 0d 0d 42 72 4f 44
0010  20 64 20 20 2c 64 3a 3a 61 4c 41 46 72 4c 4e 4c
0020  6e 41 65 6e 65 63 43 65 6d 6f 4e 72 0d 42 2c 0a
0030  6f 0d 61 6f 62 20 64 0d 4e 0a 52 20 6f 3a 6c 4c
0040  42 20 0a 0a
```

Palmtop result: entry `Brown, Bob`, address `Bob Brown at BRANCH`; `Old, Fred` removed (or
nothing if absent); message deleted (one attachment, nothing skipped). The same message works
for the DOS client.

## 6. What our server must build

- **The client's request** (§1): store it; read the 20-byte type-6 item (untranspose; date at
  +0C, time at +10). Reply in the user's next session with one update message (§5) holding the
  entries changed after that date/time (if we keep change times) or all entries (cheap:
  unchanged entries make no change). A peer post office never answers it, so this is our own
  behaviour.
- **Every directory update** for client and palmtop users: the §5 format. Only users (L) and
  post offices (P); deletes as `DL`/`DP`; renames as `Name: old` + `Chng: new`.
- Tell the user (subject/README) that the update is applied from the message on the DOS client
  and by running the update tool on the palmtop.

## 7. Open points

1. Not determined: words +00..+0A of the request item (0x14, 0, 1, 1, 0, 0); nothing reads them,
   and their meaning is not needed.
2. Not determined: whether the client's in-memory type change (type 3 → 5) is ever saved back to
   the message file.
3. Not determined: how the palmtop names a received type-3 item as an attachment (from the tag 07
   title, with or without the date stamp, or a generated name), i.e. whether it is seen as
   `CCMUPDAT...`; one test with §5(b) would show it. Also whether the palmtop accepts a message
   with no text item.
4. Not determined: the palmtop's behaviour after an add/rename failure (reads on a closed file).
5. Not determined on the post office side, and not needed for our server: the DB8 high-water
   mark, the DB8 body transform, the meaning of Locn `C`, whether administration ever posts
   type-5 items, default propagation words.
6. Not determined: year handling in the client's sequence check across 1999/2000 (2-digit years
   from the post office vs year-1900 from the client); it only affects the "not in sequence"
   warning.
7. Not determined: the alias flag on entries created by an update (`A`); we never send `A`.
