# Limits

The size and count limits a compatible implementation must respect on the wire and in
messages, and what happens when one is exceeded.

Compatibility: this server is compatible with Lotus cc:Mail Remote (DOS), cc:Mail Router (DOS
and NT, DB6 and DB8 post offices), Lotus's SMTP gateway and POP3/IMAP servers. The values below
are the ones those peers apply, stated as rules by role.

Roles:

| role | meaning |
|---|---|
| **client** | a mobile client (the calling or answering client side of session-layer.md) |
| **post office** | the peer that answers clients and exchanges mail with other post offices (router-answer.md, router-to-router.md); **DB6** / **DB8** where the two post office database formats (podb.md) differ, **NT** / **DOS** where the Windows NT and DOS post office programs differ |
| **gateway** | an Internet mail gateway (smtp-link.md) |
| **POP3/IMAP** | POP3 / IMAP4 access to a post office (pop3-imap.md) |
| **import** | the client's message import file format |

"len+1" = byte length counting the NUL. "Not found" means no check was found; it does not prove
that no check exists. Wire codes (82, 83, 8A, 8C, 8E, 96, 9D ...) are those of session-layer.md.

The post office database format sets no string or password lengths: every string field is held
in a variable data record, and the index key lengths (12, 16, 17, 16) are key prefixes (a longer
value is cut and compared in full afterwards, podb.md §4, §10), not limits. The only format
bound is the 16-bit length word of a variable data record (podb.md §2). Integer counters are
32 bit. The real limits are the ones below.

## 1. Names (directory entries, post offices, lists, aliases, comments, addresses)

| item | rule | role | when exceeded |
|---|---|---|---|
| User name, "To:" name, home post office name, profile strings | at most 126 chars as produced by a client | client | the client does not produce more |
| Address entry (name and post office typed together) | up to 255 chars, then parsed | client | how it is split into name + PO and capped after parsing: not determined |
| Folder / private mailing-list title | 30 | client | not produced; a duplicate title is refused; whether that compare ignores case: not determined |
| Names a client produces | a space at position 0 or next to a space is dropped; after the first comma a space is inserted, not when the text has " FAX#"; trailing spaces stripped | client | — |
| Stored name form | split off " FAX#…", strip leading spaces, collapse runs, at the first comma drop the spaces around it and store `Last\0First\0`; "First Last" stored as typed; length = total incl. both NULs (this is the length the client sends and compares) | client | — |
| Forbidden characters | none: no filter for `@`, ` at `, `#`, control chars or bytes ≥ 0x80 | client | — |
| Own name = a post office | a client refuses to rename its user to a post office entry | client | refused |
| Name compare | the stored length must equal the sent / looked-up length; then whole string, then `A\0B` vs "B A" both ways; case-insensitive for a–z only, bytes ≥ 0x80 exact | client | no match → 83 |
| User / post office name at create | len+1 ≤ 0x7F (126 chars); for a comma name both parts count | post office (DB8) | refused |
| Bulletin board / mailing list name at create | len+1 ≤ 0x7E (125 chars) | post office (DB8) | refused |
| Rename | a leading `#` is dropped for boards and lists, then the same 126 / 125 test; comma normalisation only for users | post office (DB8) | refused; duplicate refused |
| Duplicate name at create | refused | post office (DB8) | refused |
| Comments at create | len+1 ≤ 0x7F (126) | post office (DB8) | refused |
| Other string attributes | byte length (×2 for Unicode) ≤ 127 | post office (DB8) | refused |
| Address field | no length check (bound = the data record length word) | post office (DB8) | — |
| Name normalisation at create / lookup | trim, collapse spaces, first `,` → `Last\0First` (parts trimmed); no "First Last" reordering | post office (DB8) | — |
| Character checks | none (comma, `@`, control, ` at `) | post office (DB8) | — |
| Name match | a **prefix** compare over the query's length (fails if the query is longer); a leading `#` is ignored on the query and on stored board / list names; single-byte code pages compare by collation weights, i.e. case-insensitively, with the lower-case table only as a tie-break | post office (DB8) | — |
| Name compare | stored length == sent length; case-insensitive (ASCII a–z, or a code-page compare with the configured code page, default 437, under a condition not determined); both word orders | post office (DB6) | unknown → 83 (R/O) |
| Name lookup | normalised (strip spaces, comma split), then a code-page compare; whether the NUL must be counted: not determined (router-to-router.md §8.3) | post office (DB8) | — |
| Login name field (wire) | 1..128 bytes (0 fails) | post office | nothing sent, call ends |
| Directory update fields (router-to-router.md) | NAME 126, LOCN 126, ADDR 383, CMTS 126, CHNG 126, ACHNG 383, PSWD 10, LOCK 126, UNAME / UALTNAME / UCMTS 512; length only | post office | record written to the undeliverable updates with `Error: /code=2 /text=Update field too long` |
| Directory update name characters | no rejection; spaces collapsed, comma → `Last\0First`, trimmed | post office | — |
| Post office names | peers' administration refuses spaces in a new post office name and trims / collapses names; no peer refuses a comma (the product documentation says neither commas nor spaces) | all | — |
| Inbound author (SMTP) | `Name <addr> at GATEWAY`; CR / LF / TAB / `,` → space; ≤ 126 incl. " at gateway": first the bare address, then cut + `~` | gateway | cut with `~` |
| Non-local recipient name | ≤ 126, cut + `~`; display name dropped if it has `=?`, `\`, ESC$B, 8-bit bytes or is > 64 chars | gateway | cut / bare address |
| Name with `@` and a `.` after it | used verbatim as the address; bytes > 0x7E force a directory lookup; local part quoted when it has specials or bytes outside 0x20..0x7E | POP3/IMAP | — |
| IMAP APPEND author | `phrase <addr>`, 127 chars | POP3/IMAP | cut (pop3-imap.md §5) |
| TLV string entries in a header | the len byte = strlen+1. Readers treat it as **signed**: a client rejects negative lengths, a post office walks with a sign-extended length. So every header string (name, 0F PO, subject, folder 1B, receipt token) must be ≤ 127 bytes incl. NUL | client, post office | client: the message is not loaded and its entry is deleted; post office: the walk misses the end → message aborted, no 88 |

User name formats in the product documentation: "Last, First", "First Last" or a single word.

## 2. Passwords

| item | rule | role | when exceeded |
|---|---|---|---|
| Password a client produces (login, setup, change) | at most 10 chars | client | not produced |
| Stored form | **upper-cased** (a–z only), filled up to 64 bytes with random `A–Z0–9`; stored length = strlen+1 (≤ 11) | client | — |
| Minimum length | none in the client; only the post office's `8C 99` | client | — |
| Wire | 1 length byte = stored length incl. NUL, then the bytes; on a change: `new\0old1\0[old2\0]`, up to 2 old ones, only to the home PO | client | — |
| Password field (wire) | 1..128 bytes, same reader as the name | post office | call ends |
| Compare | split at NULs, ≤ 3 strings tried; each **upper-cased**, encoded, compared over strlen+1; no length cap beyond the 128-byte field | post office (DB6) | `8C 98 00` |
| Stored form | upper-case, random pad to 64 | post office (DB6) | — |
| Minimum length | policy value; checked **after** a successful match; skipped for post office entries | post office (DB6) | `8C 99 (min+1)` |
| Maximum | after code-page translation **len+1 ≥ 64 refused → max 63 bytes**; at login strlen > 64 refused, and the login copy keeps 64 bytes + a forced NUL | post office (DB8) | refused |
| Normalisation | in the post office code page: single-byte → Unicode, **lower-case fold** for U < 403 (A–Z → a–z, U+00C0–00DE → +0x20 except ×, Latin Ext-A; codepages.md), back to the code page. So passwords are case-insensitive and stored lower-case (podb.md §10) | post office (DB8) | — |
| 64-byte stored password | `(norm(pw)+NUL+random fill to 64) XOR KS`; a decode with no NUL in the 64 bytes is refused | post office (DB8) | refused |
| Minimum length at login | strlen < minimum → warning after a successful login | post office (DB8) | `8C 99` |
| Change password | new strlen < minimum refused | post office (DB8) | refused |
| Expiry / pre-expired / locked | expiration period vs the last change date; a change date of −1 = pre-expired; locked; lock-out after the configured maximum of login tries | post office (DB8) | refused; the post office answers `8C 9B d` expired, `8C 9A 00` pre-expired, `8C 97 n` locked (router-answer.md §1.5) |
| Call password | post office to post office sessions only; same normalisation; max 63; **no minimum, no 10-char cap** | post office (DB8) | refused |
| Call password sent | length byte strlen+1; DB6: the stored length | post office | — |
| Password policy ranges | users type at most 10 chars; minimum length 0..10, expiration 0..365 days, login tries 0..99 | post office administration | — |
| Directory update `PSWD:` | 10 | post office | code 2 |

All peers compare case-insensitively. **DB6 upper-cases and DB8 lower-cases** before encoding,
so the stored bytes differ, but the accepted set is the same for ASCII. For bytes ≥ 0x80 they
differ: DB6 folds a–z only, while DB8 folds through the code-page fold table (cp437: 80→87,
8E→84, 8F→86, 90→82, 92→91, 99→94, 9A→81, A5→A4). A client folds a–z only.

## 3. Message header

| item | rule | role | when exceeded |
|---|---|---|---|
| Header record when loaded from the store | 0x20 ≤ word[8] ≤ 0x1000; addressing part (dword[0]−dword[4]) ≥ 0 and ≤ 0x1000 − word[8]; TLV walk must end exactly | client | not loaded; its entry is deleted |
| Header received on the wire | HL (16 bit), then exactly HL bytes, **no check**; a header longer than the client's receive buffer (at least 0x2000 bytes, real size not determined) overruns it, so never send one that long | client | overrun; the 0x1000 checks apply only on later load (row above) |
| Header room when composing | 0x1000 bytes, including room the client keeps in reserve | client | no more addresses accepted |
| Header a client emits | cc / bcc 03 copies appended with no bound, so HL can exceed 0x1000 | client | — |
| Header received | 16-bit length, **no check**; up to 8192 bytes accepted (4097..8192 too), more overruns the post office, so never send more than 8192; then the TLV walk must end exactly at HL | post office (NT) | > 8192 overrun; walk mismatch → abort (no 88) |
| Header received | same walk; the bound is about 0x2132 bytes | post office (DOS) | same structure |
| Route growth | running header size + new route tags > 4096 → rolled back | post office | that recipient gets **83** |
| Header sent | tag 22 appended only if `hdr+10 ≤ 0x2000` and hdr < 4096 | post office | tag not added |
| Header stored | used + new + 2 < 4096 per added attribute | post office (DB8) | attribute not added |
| Heading record | 0x1000 | import | refused |
| Each TLV | len byte, signed on read → ≤ 127 incl. NUL (§1 row "TLV string entries") | client, post office | as in §1 |
| TLV lengths written | 1-byte length (low byte); no refusal of ≥ 256 found | post office (DB8) | length byte wraps |
| Subject | 60 chars | client | not produced |
| Subject | len+1 ≤ 0x3D (60) | post office (DB8) | **not stored** |
| Subject | 60 | import | refused |
| Subject inbound SMTP / IMAP APPEND | cut at 60; TAB / CR / LF → space; missing → "No subject given" | gateway, POP3/IMAP | cut |
| Subject outbound | cut at the first CR / LF | gateway, POP3/IMAP | cut (pop3-imap.md §2) |
| Author | no per-field check in DB8 (1-byte TLV length); import FROM ≤ 126; gateway ≤ 126 with `~`; IMAP 127 | post office (DB8), import, gateway, POP3/IMAP | —; refused; cut |
| Author check on send | the 01 author must equal the user (post office: equal the caller, unless the caller is a post office) | client, post office | client: message skipped; post office: verdict **96** for all |
| Recipient name entry | import TO / CC / BCC / RRQ / RRT ≤ 126; a client produces ≤ 126 (TLV ≤ 127 incl. NUL) | import, client | refused; not produced |
| Number of recipients | no count cap; bounded by the 0x1000 header room | client | no more addresses accepted |
| Number of recipients | counter ≥ **1000** → 83. The counter is incremented per entry written to the target arrays, including mailing-list expansion. Whether 0F entries count too: not determined | post office (NT) | 83 for the rest |
| Number of recipients | not examined | post office (DB8), POP3/IMAP | not determined |
| Number of recipients | > 50: non-local ones dropped; still > 50 → refused | gateway | "Too many recipients. … less than 50 recipients." (smtp-link.md §3.3 step 5) |
| To / Cc / Bcc separately | one shared count or budget, no per-class cap found (client, post office, gateway); DB8 store and POP3/IMAP not examined | all | — |
| 0F path entries | no numeric cap; a client walks to the last 0F; a post office is bounded by the 4096 header rule | client, post office | post office: 83 via 4096 |
| Circular routing | optional post office check (default off): n equal 0F names → circular routing | post office | 83 |
| Headings / forward levels (word[1A]) | 20 | client | forward refused |
| Receipt token (tag 15 from 0E) | copied only when 0 < len < 0x7F | client | not copied |
| RRQ / RRT tracking text | 126 | import | refused |
| Header line | 262 bytes (0x106) | import | rest of the line dropped, no error |
| SMTP header block | > 0x19000 bytes (100 KB) bounced | gateway | "The RFC 822 header is over 100k." |

## 4. Message body and items

| item | rule | role | when exceeded |
|---|---|---|---|
| Total message size fields | dword[0] (total stored size) and dword[4] (body end) are 32 bit; dword[0] is what every message size test compares (session-layer.md §4.2) | client, post office | see §7 |
| Disk space on receive | free < dword[0] + 0x200 | client | **8A** |
| Database file | offset + record size > 0x7FFFFFFF | post office (NT) | refused |
| Store unit | message length field = ceil((size+8)/504)·504 (32 bit, podb.md §7) | post office | — |
| Items per message | ≥ **20** refused (unless item type 32, meaning not determined) | post office (DB8) | refused |
| Items per message | 20 | import | refused |
| Items per message (compose) | no count cap found; descriptors use 0x14 bytes of word[8] ≤ 0x1000, so at most (0x1000−0x20)/0x14 = 203 descriptors (06 + 13 together) can load | client | header room / load failure |
| Items per message (SMTP inbound) | > 80 refused | gateway | refused |
| Attachments (SMTP inbound, non-MIME) | ≥ 20 uuencode blocks refused | gateway | "Too many file attachments … less than 20 attachments" |
| Items re-attached to a bounce | max 19 | gateway | rest dropped |
| Text item size (read) | the length is taken as a **word** (low 16 bits of +0C) | client | high bits ignored |
| Text item cells | 0x5000 cells (= bytes − CR LF count), in the reader (text and attributes) and in the editor | client | reader: error; editor: no more text accepted; file import cut at the last whole line |
| Auto-show gate | `L − lines + header_rows + 0x51 ≤ 0x5000` | client | not shown automatically (the other display path is not determined) |
| Text must end with CR LF | otherwise the reader reads past the end (items.md §1.2) | client | error |
| Text item | > 0x5000 bytes | import | silently becomes a file item (type 3) |
| Text item (SMTP inbound) | > 20480 bytes | gateway | becomes file item `TextItem.txt` |
| Text item (outbound) | at most 22528 bytes are read | gateway, POP3 | text cut |
| Text item (IMAP) | not determined | POP3/IMAP | — |
| Item data size, any type | 32-bit +0C; no cap found in a client or a post office; DB8 store not determined | all | not determined |
| Total message size (DB8) | not examined | post office (DB8) | not determined |
| Body transfer | exactly dword[4] − word[8] bytes after 86 (a post office sends in 4 KB pieces) | client, post office | — |
| File item name | DOS path ≤ 0x4F (79) | client | refused |
| Item title | 60 columns (medium confidence) | client | not produced beyond column 60 |
| File name (SMTP inbound) | uuencode begin-line name > 60 → 58 + `~` | gateway | cut |
| File name (POP3/IMAP out) | title minus trailing date / time | POP3/IMAP | — |
| Fax item | +A (format) must be in {4,6,7,0E,10,12}, 0 → 4; size cap not found | client | error |
| Graphics item | not determined | client | not determined |

## 5. Text lines

| item | rule | role | when exceeded |
|---|---|---|---|
| Editor line | 80 columns (0..0x4F), word-wrapped at the client's right margin | client | a client produces at most 80 columns |
| Lines per text item | no separate cap found; bounded by the 0x5000 cells; +8 of the text descriptor = CR LF count (16 bit, items.md §2) | client | — |
| Received line longer than 80 columns | the reader builds cells with no line-length test; how it is shown: not determined | client | not determined |
| Import text line | 80, or 480 with HILITE | import | hard split into more lines; CR dropped |
| Directory update item line | 527 | post office | rest of the line not read (router-to-router.md §4.3) |
| SMTP outbound 7bit text | no wrapping | gateway | — |
| SMTP outbound QP | soft break after 70 | gateway | — |
| uuencode lines | 45 bytes | gateway | — |
| SMTP inbound text lines | not examined | gateway | not determined |
| Line handling (DB8) | not examined | post office (DB8) | not determined |
| POP3 | lone `.` doubled; no wrap (pop3-imap.md §3) | POP3/IMAP | — |

## 6. Mailbox, folders, directory

| item | rule | role | when exceeded |
|---|---|---|---|
| Folders | 200 | client | no new ones accepted |
| Private mailing lists | 200 | client | same |
| Members per private list | 200 (medium confidence) | client | not determined |
| Messages listed per inbox / folder / list | 1600 (0x640) | client | list cut to 1600 |
| Messages stored per folder | no cap found | client | — |
| Archive file | 1600 | client | error |
| Folder name | 30 | client | not produced |
| Folder name | > 0x4F refused (pop3-imap.md §4) | POP3/IMAP | IMAP error |
| Folder name, folder count, messages per folder | no length or count check found (duplicate check only) | post office (DB8) | not determined |
| Received tag 1B folder | never creates a folder; missing → inbox | client | inbox |
| Per mailbox / per folder / per PO message counts | none; message numbers not bounds-checked; counters are 32 bit | post office | — |
| Directory entries | 0x7869E = **493,214**: checked on directory updates, not on interactive add | client | the update record is rejected |
| Users (total) | ≥ 493,214 refused | post office (DB6) | refused |
| Post offices | count field == 0xFFFF (65535) | post office (DB6) | refused |
| Call entries | < 4096 per PO record | post office (DB6) | directory update code 17 "Maximum call entries exceeded" |
| Directory update add limits | codes 9 "Maximum directory entries exceeded", 10 "Maximum local users exceeded" | post office | `Error:` line in the undeliverable updates; the compares behind 9 / 10: not determined |
| Members per public list | no cap found; expansion bounded by the 1000-recipient rule | post office | 83 |
| Directory entries / members (DB8) | not found | post office (DB8) | not determined |

The documentation says 490,000 directory entries; the enforced value is 493,214 in both the
client and the DB6 post office.

## 7. Session and response limits

| item | rule | role | when exceeded |
|---|---|---|---|
| Messages per session | optional (default **0 = none**, range 1..999, ≤ 0 or ≥ 1000 rejected); counts **accepted (stored) messages per session, each direction separately** | post office (NT and DOS) | receive: 82 for every 03 then **9D**; send: stops for the turn |
| Messages per call | a client compares with 0x641 (1601) at connect + login (session-layer.md §5); whether it caps the send list at 1600: not determined. Receive: no count cap found | client | not determined |
| Message size limit | optional (default **0 = none**), in units of 1000 bytes, no range check; compared with dword[0] | post office (NT and DOS) | receive: all 82 then **8E**; send: message skipped, not offered |
| Message size limit | optional (default **0 = off**); n is a signed 16-bit decimal, × 1000, no range check | client | receive: 82 per 03, then **8E**; send: skipped |
| Call-list size limit | a call entry's word (KB): larger messages do not count toward the minimum and are skipped at send | post office (DB6) | skipped |
| After the peer answers 8E (post office sending) | the send turn has a size limit (0 = none); a message is offered only if the limit is 0 or dword[0] ≤ limit, otherwise it is skipped. On verdict 8E from a post-office peer (router-to-router.md §2.3) with limit < dword[0], the limit is set to **200·(5·⌊size/1000⌋+5) = 1000·⌊size/1000⌋ + 1000 bytes**. Since a message is offered only when the limit is 0 or size ≤ limit, limit < size can hold only when the limit is 0. In effect this turns "no limit" into a cap just above the refused size, for the rest of this send turn: later larger messages are skipped. Same in DB8 and DB6 | post office | message kept, retried next call |
| 8E on a client's upload | message kept in the outbox | client | resent next call |
| Total bytes per session | none found | client, post office | — |
| Idle timeout | default 30 s, range 1..300 (two line modes force 60); bounds the sniff phase, every login byte, the next code in the caller's turn, and link-dead detection (restarted on progress) | post office | data connection not requested / lost |
| Idle timeout | default 30 s, no range check | client | link dropped |
| Message wait | default 0x14A = 330 s; each verdict / 86 / 87 wait on download | post office | data connection lost |
| Client waits | in seconds: verdicts 0x5A = 90 s, 86 and next command 0xB4 = 180 s, 87 0x14A = 330 s (session-layer.md §4.1) | client | link lost |
| Connect wait | optional n (default 0); opener wait = 200·(5·n+150) ms = 30 s + n s | post office | control 10h, call ends |
| Directory download (A5) | wait 30 s for 86, 512-byte pieces, wait 30 s for 87 (router-answer.md §2.1) | post office | ends |
| Refusal after 8C | exactly **3 bytes `8C reason value`**, no text; reason from the table `00 00 00 00 97 98 00 99 9A 9B`; value = low byte of a word: 97 = **configured lock-out limit**, 98 = 0, 99 = **min length + 1**, 9A = 0, 9B = expiry days; a bare 8C for an unknown caller when read-only access for unknown callers is off, and for a non-negotiated post office caller when the post office refuses old post offices (router-to-router.md). DOS and NT identical | post office | — |
| Refusal reading | reason + value are read only if already received; the value is shown **as is** (no −1) for 97 / 99 / 9B, so for 99 the user is told min+1 as the minimum length; every reason ends the call | client | — |
| Values > 255 | the value byte is the low byte of a word (policy ≤ 99 tries, ≤ 10 min length; expiry days up to 365 wrap) | post office | expiry > 255 days shown mod 256 |
| Unexpected code instead of 85 | anything but 85 (91 included) → message stays, next one offered | client | silent |
| Unexpected verdict (9C / 9D / 9E / 96 / A0 / A4) | that recipient stays pending | client | resent later |
| Unexpected reply instead of 86 | 89 / 8A / 8E / 8F are reported to the user; any other → silent, next message | client | message kept |
| Unexpected reply instead of 87 | 8F / 90 / 2B handled; other → not marked sent, resent next call | client | resent |
| Receiver: not 84 / 88 / 8D | the receive loop ends, the session goes on (turn reversal) | client | — |
| Login reply not 8B / 8C | taken as accepted (any reply other than 82 → read-only, R/O); a second 8B after the password is not looped | client | — |
| SMTP | one message per connection (smtp-link.md §2.3) | gateway | — |

## 8. Wire

| item | rule | role | when exceeded |
|---|---|---|---|
| Name / password length byte (receive) | N > 0x80 or N = 0 rejected | client | call ends silently (both on the calling and the answering side) |
| Name length byte (send) | stored N sent with no check; in practice N ≤ 127 (a peer must not be sent N > 0x80) | client | — |
| Name / password length byte (receive) | 1..128 | post office | call ends, nothing sent |
| Length bytes sent | count the NUL (strlen+1); e.g. a capture shows `05 "user\0"` | client, post office | — |
| Frame data L | LSEC ≤ 0x79 (121), HSEC ≤ 0x3F8 (1016); ASCII tx 0x4E / 0x2A2 | client, post office | client: treated as a CRC error; post office ASCII: NAK |
| Rx window | 4 (link-layer.md) | client, post office | dropped / NAK |
| Header length word | 16 bit LE | client, post office | see §3 |
| Negotiation packet data | `len` not checked, room for 128 bytes (negotiation.md §2.3) | post office (NT) | overrun; keep ≤ 120 |
| Directory download size | 4-byte size, then 512-byte pieces | post office | — |
| TCP port | 3264 (0CC0h); optionally 21 | post office | — |

## 9. What the server should enforce

Two directions. **Accept** whatever the loosest real sender can produce. **Emit** only what the
strictest real reader accepts.

Accept (input from clients, post offices, gateways):
1. Login name / password length byte 1..128 (a client's receive side has the same bound,
   N > 0x80 rejected). Read the bytes and strip trailing NULs.
2. Header length word up to 0xFFFF, read fully into a bounded buffer. Refuse (hang up, as a
   post office does on a bad walk) when the TLV walk does not end exactly or any len byte is
   ≥ 0x80. Accept HL > 0x1000: a client itself sends that when it appends cc/bcc 03 copies.
   Store it only if it still loads for a client (rule 1 of Emit).
3. Names: compare case-insensitively (a–z as DB6 and the client do; use the DB8 code-page fold
   for bytes ≥ 0x80 only when acting as a DB8 post office), with "Last, First" ≡ "First Last".
   Trim and collapse spaces as DB8 and the client do. Do not reject `@`, `#`, comma or 8-bit
   bytes: no peer does, except administration for a new PO name with spaces.
4. Passwords: case-insensitive; up to 3 NUL-separated strings. Lengths: DB6 compares the whole
   string, up to the 128-byte field; DB8 refuses len+1 ≥ 64. Real clients send ≤ 11 bytes
   (10 chars + NUL), so either rule works. Answer `8C 98 00` for a password that is too long,
   as for a wrong one.
5. Recipients: up to 1000 recipient slots incl. 0F entries; beyond → 83 for the rest. Routed
   headers that would grow past 4096 → 83 for that recipient.
6. Messages per session / message size: configurable, default off. When over: 82 for every 03,
   then 8E / 9D (a client only understands 8E).
7. Timeouts: 30 s idle per byte/code restarted on progress (range 1..300), 330 s for
   verdict/86/87 waits when we send. A client waits up to 90/180/330 s on its side.

Emit (what we send or store):
1. Header record: word[8] ≤ 0x1000 and addressing ≤ 0x1000 − word[8], i.e. **total header
   ≤ 0x1000** (the client's load check), counted **after** adding the 03 copies of cc/bcc and
   the 03 = caller entry on download (router-answer.md §2.4). A client stores the record as
   received and checks on load. TLV strings ≤ 127 bytes incl. NUL (signed len). At most 203
   descriptors.
2. Names ≤ 126 chars (+NUL = 127) for users and POs, ≤ 125 for `#` lists/boards; comments
   ≤ 126; login name/PO name length byte ≤ 0x80.
3. Subject ≤ 60.
4. ≤ 20 items (DB8, import); ≤ 20 headings (client).
5. Text item: length ≤ 0xFFFF (a client reads a word), cells (bytes − CR LF) < 0x5000, ending in
   CR LF, lines ≤ 80 columns for the client editor. Longer text → split into several text items
   or attach as a file item (the import format and the gateway do the latter).
6. Messages to a client per call ≤ 1600 is harmless (possibly its own send cap; its receive side
   has no cap), but a folder shows at most 1600. Keep a client mailbox under 1600 per folder.
7. Passwords we store or send: ≤ 10 chars typed by users, ≤ 63 bytes in DB8 form; store the DB8
   form lower-cased, the DB6 form upper-cased.
8. Refusal after a password: exactly `8C reason value` (3 bytes), value ≤ 255; send 99 with
   min+1 as a post office does (the client shows it unchanged).
9. Directory: ≤ 493,214 entries for a client.
10. Frames: L ≤ 0x79 (LSEC) / 0x3F8 (HSEC), ASCII 0x4E / 0x2A2.

## 10. Open points

| # | Not determined |
|---|---|
| 1 | Real size of a client's header receive buffer (at least 0x2000 bytes) |
| 2 | How a client splits and caps the 255-char address entry (name / PO parts) |
| 3 | Items / attachments cap in client compose (documented values 20 / 19) |
| 4 | Whether a client's duplicate folder/list title compare ignores case |
| 5 | What a client stops offering at 200 private list members |
| 6 | Default client editor margins |
| 7 | How a client shows a text over the auto-show gate |
| 8 | Graphics item checks; fax/graphics size limits |
| 9 | Item data size cap in a DB8 store |
| 10 | DB8 folder name length / folder, message, entry, member counts |
| 11 | Checks behind directory update codes 9/10 (max directory entries / local users) in DB8 |
| 12 | DB8 name compare: NUL counted or not; its case rule |
| 13 | Meaning of item type 32 in the DB8 item count |
| 14 | IMAP text item size limit |
| 15 | SMTP inbound line length handling |
| 16 | 32,000 messages per folder / bulletin board (documented value): not found in the client; the DOS-era client was not examined |
| 17 | DOS post office equivalents of the constants in §6 and of the 1000/4096 caps |
| 18 | Whether a comma in a PO name breaks anything (no peer refuses it); a test with an administration program and a client would show it |
| 19 | Message / item size options of the import format |
| 20 | DB8 collation weights (case rule for bytes ≥ 0x80 in name compares) |
| 21 | Client handling of received lines > 80 columns |
| 22 | Recipient count, total size and line handling in a DB8 store, POP3, IMAP (not examined) |
| 23 | Meaning of the client's 0x641 compare at connect + login (send cap per call?) |
| 24 | Whether 0F entries count toward the post office's 1000 |
