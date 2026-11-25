# Session layer (above the reliable link)

Compatibility: this server is compatible with cc:Mail Remote 3.40B and RCONNECT 1.00 clients and
with cc:Mail Router 6.x post offices.

This describes the session layer between a client and a post office: codes, sequences, the
header record and the timeouts. Captures of real sessions agree with it.

"R" = the client, "P" = the peer (the post office). A client can also *answer* a call from a post
office (§3.6); what the client sends as the answering side is what a server must send.

## 0. Byte stream conventions

- The session layer never sees frames. It sees a reliable byte stream in each direction (the
  link, link-layer.md).
- Every session code is one byte. Code waits **skip 0x91** (filler); plain data reads do not.
- A code wait restarts its timer while the own send side makes progress, and gives up after its
  limit. The limits are 0x5A, 0xB4 and 0x14A, most likely seconds (90, 180, 330 s). Not
  determined with certainty: the unit.
- Any data read or write fails when there is no receive progress for the configured byte
  timeout while the send side is also stalled ("data connection lost").
- All multi-byte integers on the wire are little-endian 16/32-bit integers.

## 1. Opener `ff aa 55 11` / `0f` (link start, not session data)

- The caller sends the 4 constant bytes `ff aa 55 11`. No version, capability or serial number is
  carried.
- It then pumps the link until the reply arrives, the user aborts, or a timeout of 0x222 timer
  ticks (≈ 30 s) expires. The reply is a link **control** frame (ctl bits 7-6 = 10): low 5 bits
  of its p0 = **0x0F → accepted**, **0x10 → refused**. So the `<P 0f` of a capture is the p0 of
  a control frame (ctl 0x80), not a session byte. If the link signals a framing change during the
  wait, the caller switches framing and resends the opener (link-layer matter).
- Caller: opener not accepted → the call ends.
- Answering side: waits for the same 4 bytes from the RX stream, then has the link send a control
  frame with code 0x0F. A client in answer mode never sends 0x10.
- The framing (HSEC/LSEC/ASCII) is set before the opener; it is not negotiated by any session
  byte (link layer).

## 2. Session codes (complete list)

All codes are single bytes.

| code | name | direction | arguments | receiver handling |
|---|---|---|---|---|
| 80 | session request | caller → answerer | none | answerer drains further bytes, then sends 81 |
| 81 | session accept | answerer → caller | none | caller waits for it up to the byte timeout, else the call ends |
| 8B | password please | P → R | none | R sends the password (§3.3), reads the next code |
| 8C | refused | answerer → caller | optional 2 bytes: reason, value (§3.4) | call ends. A client in answer mode sends it (bare) to an unknown caller when set to refuse unknown callers |
| 82 | yes / accepted | both | context dependent | see §3, §4 |
| 83 | no / read-only | both | context dependent | see §3, §4 |
| 84 | I have a message | sender → receiver | none | receiver sends 85 |
| 85 | send it | receiver → sender | none | anything else aborts this message |
| (len) | header length | sender → receiver | 16-bit LE, then the header record | |
| 82/83 per recipient | recipient verdict | receiver → sender | one byte per tag-03 entry, in order | §4.3 |
| 86 | send the data | receiver → sender | none | sender sends the raw data bytes |
| 89 | unknown recipients (none accepted) | receiver → sender | none | message not sent |
| 8A | insufficient disk space | receiver → sender | none | message not sent |
| 8E | message size too long | receiver → sender | none | message not sent |
| 8F | message cannot be stored | receiver → sender | none | in place of 86 or of 87: message not sent |
| 87 | message stored | receiver → sender | none | success, outbox updated (§4.5) |
| 90 | message cannot be delivered | P → R, in place of 87 | none | message not sent |
| 2B | data connection lost | P → R, in place of 87 | none | message not sent, connection ends |
| 88 | no more messages from me | either | none | receiver ends receiving |
| 8D | no more messages, and I will not receive | either (a send-only caller) | none | receiver ends receiving and returns "no turn reversal" → hang up |
| 91 | filler / keep-alive | P → R (the supported clients never send it) | none | skipped by code waits only (not by data reads) |
| 97..9B | refusal reason | after 8C | 1 value byte follows | §3.4 |

There are no other codes; there is no directory, bulletin-board or mailing-list command: such
things travel as ordinary messages (§6).

## 3. Connection and login

### 3.1 The client calls the post office

```
R> 80
<P 81                                (wait: byte timeout)
R> L name[L]                         (§3.2)
<P c1
   c1 = 8B: R> L' password[L'] ; <P c1'   (§3.3), continue with c1 := c1'
   c1 = 8C: [reason value]  → refused, end    (§3.4)
   else   : <P L'' poname[L'']
                , c1 = 82 connection accepted
                , c1 other read-only connection accepted
R> 82  if poname is the post office being called
R> 83  otherwise → end
```

Capture: `R> 80 | <P 81 | R> 05 "user\0" | <P 8b | R> 04 "123\0" | <P 82 07 "MYPOST\0" | R> 82`.
The first `82` of the observed `R> 82 88` / `R> 82 84` is this post-office-name confirmation.

### 3.2 Name field

- A stored name is `A\0` or `A\0B\0`, with stored length N. If strlen(A)+1 < N, the client sends
  `"B A\0"` (B, space, A); otherwise `"A\0"`. N is sent unchanged.
- Wire: 1 byte N, then N bytes. N counts the terminating NUL (capture: `05 "user\0"`).
- Receiving a name: 1 byte N, N > 0x80 rejected, then N bytes. A client in answer mode looks the
  name up in its directory, accepting the same "B A" form (it re-splits at the space when
  strlen+1 < N).

### 3.3 Password field

- Normal: wire = 1 byte length, then the stored bytes. The length is the stored length; the
  capture shows `04 "123\0"`, so the stored length includes the NUL.
- **Password change**: when the user sets a new password, the client keeps the previous ones.
  When calling the **home** post office with old passwords kept, the client appends up to **2**
  old passwords after the current one:
  wire = `len(new)+len(old1)[+len(old2)]`, `new\0 old1\0 [old2\0]`. After the next byte has
  been read *successfully*, whatever its value, the old passwords are forgotten. The post office
  has to recognise the concatenation; there is no separate change command.

### 3.4 Refusal `8C` and its extra bytes

After 8C the call is refused. The supported clients read `reason` and `value` **only if a byte is already
buffered**, so a post office sends the 3 bytes together. A bare 8C is a plain refusal.

| reason | meaning | value |
|---|---|---|
| 97 | mailbox locked after a number of calls with an incorrect password | the number |
| 98 | password does not match the home post office mailbox password | read, ignored |
| 99 | password must be at least a minimum length | minimum length |
| 9A | the administrator has set a pre-expired password | read, ignored |
| 9B | password expired a number of days after being set | days |
| other | no further meaning | - |

Wrong password and lockout therefore look like: `<P 8c 98 xx` and `<P 8c 97 nn`. 8C may come
straight after the name or after the password. There is no retry on the wire: the client ends the
call; the retry count lives in the post office.

### 3.5 Wrong post office name

After the 82/83 accept byte the post office sends its name. The client looks it up in its
directory and compares the result with the post office it dialled. Mismatch: `R> 83`, call ends.
Match: `R> 82`.

### 3.6 A client answering a post office's call

```
(link opener)               <P 80        R> 81
<P L name
R> 82  caller found in directory
R> 83  unknown caller, read-only allowed
R> 8C  unknown caller and refuse unknown callers set → end
R> L own name
<P c   c != 82 → end
       c == 82 → accepted (read-write or read-only)
```

A client in answer mode never asks a caller for a password (never sends 8B) and sends 8C without
reason bytes. **Read-only** = the caller was not found in the directory: its messages are
accepted, but no messages are selected for it, so it only gets `88`.

### 3.7 Caller options that change the session

| option | effect on the wire |
|---|---|
| send only | caller ends with **8D** instead of 88 and does not receive |
| receive only | nothing is selected for sending: caller sends just 88 |
| refuse unknown callers | answering: unknown caller gets 8C instead of 83 |
| message size limit n | limit n*1000 bytes: sender skips larger messages; receiver answers 82 per recipient, then 8E |
| byte timeout | 81 wait and read/write stall timeout |

## 4. Message transfer

### 4.1 One message

```
S> 84
R> 85
S> HL(2 bytes LE) header[HL]
R> v1 v2 ... vk   one byte per tag-03 entry (82 = for me, 83 = not for me)
                  (size over the limit: all 82, then 8E)
R> 86 | 89 | 8A | 8E | 8F
S> body (dword[4] - word[8] raw bytes)
R> 87 | 8F  (a post office also: 90, 2B)
```

- The sender waits for each verdict up to 0x5A, for 86 up to 0xB4, for 87 up to 0x14A (§0). The
  receiver waits for the next command up to 0xB4.
- The receiver waits until its verdicts are sent (up to 0x1E) after the last verdict and before
  deciding 89/8A/86.
- Receiver decisions in order: size limit (8E); recipients: tag-03 data length equal to the
  stored length of its own name and the name matches → 82 (count++), else 83; none accepted →
  89; free disk < dword[0] + 0x200 → 8A; else it writes the header (§4.4) and sends 86.
- After 86 the body length is implicit: the receiver reads exactly dword[4] - word[8] bytes. No
  per-chunk framing, no checksum (the link provides integrity).
- If the disk write fails, the receiver still swallows the remaining bytes, does **not** send 87,
  and sends 8F instead.
- Success (87 sent): the message is filed in the inbox (flags from tags 0E/16) or in the folder
  named by tag 1B (§6.3).

### 4.2 Header record

The header record on the wire = header part 1 (`word[8]` bytes) + addressing part
(`dword[0] - dword[4]` bytes), concatenated. The sender builds it from a stored message file. The
receiver splits it again when it writes the file (§4.4).

Fixed part, 32 bytes:

| off | size | meaning |
|---|---|---|
| 00 | dword | total stored size = file size = HL + body length |
| 04 | dword | offset of the addressing part in the file = end of the body |
| 08 | word | length of part 1 (fixed part + tag-06/13 descriptors) = file offset of the body; 0x20..0x1000 |
| 0A | word | 0x4D 'M' (clients write it); 0x46 'F' also accepted (addressing part read from word[8] instead of dword[4]) |
| 0C | word | number of post offices this copy is still to be sent to; must be > 0; the receiver stores 1; the sender decrements it on full delivery |
| 0E | dword | clients write 0. A post office filled it in a download (`6d 05 37 a4`), the same 4 bytes as the end of its tag 22. Meaning not determined |
| 12 | dword | date: byte 12 = day, byte 13 = month, word 14 = year − 1900 |
| 16 | dword | time: byte 16 = second, 17 = minute, 18 = hour, 19 = 0 from clients. A post office wrote 0x20 in byte 19: meaning not determined |
| 1A | word | number of headings (1 + embedded forwarded/returned headings). Corrected in file-items.md §1: the number of logical items |
| 1C | word | number of tag-06 item descriptors |
| 1E | word | last item number used |

Then TLV entries from offset 0x20 until the end: `tag(1) len(1) data[len]`. len is a signed
char; a reader rejects negative lengths and requires the entries to end exactly at the record
length. String entries are written with len = strlen+1 (NUL included), or 0 for an empty string.

### 4.3 Tags

| tag | meaning | data | notes |
|---|---|---|---|
| 01 | From (author) | name string | a client sends only messages whose author is its user; others are skipped (author mismatch) |
| 02 | Forwarded by | name | |
| 03 | To, still to be delivered | name | one verdict per 03 on the wire |
| 04 | Sent to (03 already delivered or routed elsewhere) | name | |
| 05 | Subject | string | the directory-update request has "Directory update request" |
| 06 | item descriptor, len 0x12 (§4.6) | 18 bytes | |
| 07 | kept with 05/06/13 when a header is rebuilt; len 0 in both captures; no reader found. Corrected in file-items.md §1: the item title, one per logical item | | |
| 08 | To folder (address to a folder) | name | |
| 0A | To mailing list | name | |
| 0B / 0C | cc, pending / sent | name | |
| 0D | cc mailing list | name | |
| 0E | Return receipt requested | string token (may be empty) | receive flag 2; echoed in receipts (§6.2) |
| 0F | address component of the preceding name entry: post office names along the route, one per 0F | name | routing uses the **last** 0F |
| 10 | Unknown recipient (returned mail) | name | |
| 11 / 12 | bcc, pending / sent (shown only to the author) | name | |
| 13 | embedded heading descriptor, len 0x12: +0A kind (1 = "Forwarded with Changes", 2 = "Returned", other = "Forwarded"), +10 dword = file offset of the embedded header record | 18 bytes | full layout in file-items.md §5.1 (+0C = record length; +10 = 0 while composing) |
| 14 | original name when the addressed directory entry was an alias; follows the 0F list | name | |
| 15 | receipt token: copy of the original's tag-0E data | string | |
| 16 | priority: first data byte 0 Normal, 1 Low, 2 Urgent | `02 p 00` (string) | receive flags 8 (Low) / 0x10 (Urgent) |
| 18 | set (empty) on the directory-update request; meaning not determined | len 0 | |
| 1B | destination folder name for the receiver | string | §6.3 |
| 1D, 20, 21, 22, 31 | sent by a post office (download capture); the supported clients do not read them | opaque | stored and forwarded unchanged |

Recipient handling by a sending client:

1. It counts the pending 03/0B/11 entries (the remaining count).
2. It copies the header and routes the copy for the destination being called. For each pending
   entry, it takes its last following 0F (or the name itself) and looks it up in the directory. If
   the name is not in the directory, it uses the home post office. It follows the routes until the
   destination being called is reached; entries not routed to this destination become 04/0C/12 in
   the copy.
3. For every remaining pending 0B and 11, it **appends** a tag-03 entry with the same name at the
   end of the copy. So every addressee for this hop (To, cc, bcc) appears as a 03 entry on the
   wire; cc/bcc keep their own 0B/11 entry for display.
4. Verdict 82 for the i-th 03 entry: if it lies inside the original length, the stored 03
   becomes 04. If it was an appended one, the matching stored 0B/11 (same name) becomes 0C/12.
   The remaining count is decremented each time. A non-82 verdict leaves the entry pending.

Hence on the wire the receiver sees, after the fixed part and descriptors, for example (upload):
`01 05 "user\0"  03 05 "user\0"  05 11 "test message one\0"  07 00`.

### 4.4 How the receiver stores the record

word[0C] := 1. The receiver writes header bytes 0..0x1F, then 0x20..word[8] at file offset 0x20,
then the addressing part (header bytes word[8]..HL) at file offset dword[4]. The body
goes to file offset word[8]. File layout:
`[fixed+descriptors][body (items, embedded headings)][addressing TLVs]`, total dword[0].
(Byte order in the file is as on the wire.)

### 4.5 After 87 (sender)

- All pending recipients delivered (remaining count 0): word[0C]--. If word[0C] is still
  non-zero, the message stays queued with the updated part 1 and addressing part. If it reached
  0, the message leaves the outbox.

### 4.6 Items (tag 06 descriptors) and the body

Descriptor layout (offsets from the tag byte; entries are 0x14 bytes apart from header+0x20):

| off | size | meaning |
|---|---|---|
| +0 | 1 | 06 |
| +1 | 1 | 0x12 |
| +2 | word | heading level the item belongs to (0 = the message itself). Corrected in file-items.md §1: the index of the logical item |
| +4 | word | item type: 1 Text, 2 Graphics, 3 File, 4 Fax (if fax enabled, else Other), 5 Update (directory update), other e.g. 6 = Other |
| +6 | word | item number (1..word[1E]) |
| +8 | word | clients write 0 for text; other writers wrote 0x17/0x1F (item 1) and 0x2E/0x1F (item 2). Meaning not determined for text; for file items see file-items.md §2.1 |
| +A | word | clients write 0; captures show 1 on item 1. Text: attribute layer (1) / characters (0), see items.md §2 and file-items.md §1 |
| +C | dword | item data length |
| +10 | dword | item data offset in the message file (relative to the message start) |

- The body sent after 86 is the file bytes word[8]..dword[4]: all item data and embedded
  headings at their offsets. Item boundaries are only in the descriptors; the receiver writes
  the bytes back at the same offsets, so the descriptors stay valid.
- Text item data is in cc:Mail's stored (column-transposed) form. With several items, the
  512-byte blocks are counted from each item's own start (file-items.md §2.1, §7.1).
- File, fax and graphics item formats: file-items.md.
- Forwarded/returned messages: a tag-13 descriptor in the outer header points (+10) at an
  embedded copy of the original header record inside the body. The original's items have
  +2 = that heading's level. Corrected in file-items.md §5.1: items stay flat in the outer table.

## 5. Session order and end

Caller (connect + login, then send, then receive):

1. The client sends its selected messages for this post office (each per §4.1), in three passes
   over the selected messages by two local marks (meaning not determined), then the rest.
2. Then `R> 88` and receive. A send-only caller: `R> 8D` and no receiving.
3. Receive loop: `<P 84` … per message; `<P 88` or `<P 8D` ends; any other byte ends too.
4. Hang-up. The post office's 88 is final: the client sends nothing after it.

Answering: login (§3.6), **receive first**, then send, then **R> 88** (in answer mode always 88,
never 8D), then hang up. If the caller ended with 8D, the answering side hangs up without sending.

Checked against captures:

| capture | wire | meaning |
|---|---|---|
| no mail | `R> 82 88 | <P 88` | 82 = PO name OK, 88 = nothing to send, P's 88 ends receive |
| upload | `R> 84 | <P 85 | R> 6b 00 hdr[107] | <P 82 | <P 86 | R> body[2991] | <P 87 | R> 88 | <P 88` | §4.1; header = 0x48 part 1 + 0x23 addressing (0xC1A-0xBF7); body = 0xBF7-0x48 = 0xBAF |
| download | `R> 82 88 | <P 84 | R> 85 | <P 90 00 hdr[144] | R> 82 | R> 86 | <P body[1912] | R> 87 | <P 88` | `90 00` is the length word 0x0090, not code 90; 144 = 0x48 + (0x808-0x7C0); body 0x7C0-0x48 = 0x778 |

## 6. Directory, receipts, bulletin boards, mailing lists

There is no special session command for any of these. All of them are ordinary messages.

### 6.1 Directory update

- Request: a client sends a message with To `03 "Administrator"` + `0F <home post office>`,
  `05 "Directory update request"`, `18` (empty), `16 02 02 00` (Urgent), and one item of type 6
  with 0x14 bytes of data. The 20 data bytes were thought to be an "after date and time".
- Updates arrive as messages carrying an item of type 5 ("Update item"). The client applies
  them after the session.
- **Corrected in spec/directory-updates.md:** the 20 bytes are settled (§1.2). Post offices send
  updates as one **type-3** item titled `CCMUPDAT …`, and the client converts it to an update
  item; a post office never writes type 5 and never answers the request (§1.3, §2).

### 6.2 Return receipts

- Requested by tag 0E in the original. When the recipient reads the message, the client builds
  the receipt:
  - fixed part;
  - `05` "Receipt of …" subject (with the date);
  - `15` = the original's 0E data when 0 < len < 0x7F;
  - the original's author block (01 entry plus its 0F/14 entries) copied with the tag byte
    changed to 03.
- The receipt is queued and sent like any message.
- Not determined: a client's own tag-0E value on outgoing mail.

### 6.3 Folders and bulletin boards

- Addressing to a folder is tag 08 ("To folder:").
- A message received with tag 1B is filed into the local folder of that name if one exists, else
  the inbox. Under a condition of the client's environment this is not done. Not determined:
  which condition.

### 6.4 Mailing lists

- Expanded locally into recipients; the names appear as 0A "To mailing list" / 0D "cc mailing
  list" for display.
- Not determined: how expansion works, and whether a client ever sends 0A/0D entries.

## 7. Mapping for an internet mail gateway

| cc:Mail | RFC 5322 / MIME |
|---|---|
| 01 name (+0F path) | From (display name; address = name@post office from the 0F chain or the home PO) |
| 02 | Resent-From / "Forwarded by" |
| 03/04 | To (04 = already delivered elsewhere; keep for display) |
| 0B/0C | Cc |
| 11/12 | Bcc (never export to other recipients; shown only to the author) |
| 0A, 0D | list names (informational, group syntax) |
| 08 | delivery to a shared folder (newsgroup / shared mailbox) |
| 05 | Subject |
| fixed 12/16 | Date: day, month, year-1900 / sec, min, hour; local time, no zone on the wire |
| 16 | Importance/X-Priority (0 normal, 1 low, 2 urgent) |
| 0E / 15 | Disposition-Notification-To / the receipt's reference |
| 10 | DSN "unknown recipient" |
| tag 06 type 1 | text/plain part (stored form: undo the transposition) |
| type 3 | application/octet-stream attachment |
| type 4 / 2 | fax / graphics: image parts |
| type 5 | directory update (not mail) |
| tag 13 + embedded header | message/rfc822 part (forwarded). Note file-items.md §5.2: no compatible gateway does this; file-items.md §7.2 renders the history as text |
| 1B | target folder (IMAP mailbox) |

To accept mail from a client (upload), a server must:

1. Answer each 03 entry with 82, or 83 for names it does not know.
2. Then send 86 (or 89 if none was accepted), read exactly dword[4]-word[8] bytes, and reply 87.

To deliver (download), the server must:

1. Build part 1, starting with word[0C] ≥ 1 and wordA = 'M'.
2. Add exactly one 03 entry whose data equals the client's own name as stored (same length).
3. Wait for 85, the verdicts and 86, send the body, then wait for 87.

## 8. Open points

1. Not determined: fixed dword 0E and time byte 19 (a post office fills them).
2. Not determined: item descriptor words +8 and +A for text items.
3. Not determined: tags 18, 1D, 20, 21, 22, 31 (tag 07: file-items.md §1). A post office's
   20/21/31 entries carry the 2-byte value `52 03` (850, probably the DOS code page). The
   supported clients were not found to read any of them.
4. Text transposition with several items or embedded headings: per item or per file 512-byte
   block? (file-items.md §2.1 and §5.1: per item, embedded records per region.)
5. Not determined with certainty: the timeout unit of code waits (most likely seconds).
6. Directory-update request item: its 0x14 data bytes (settled in spec/directory-updates.md §1.2).
7. Not determined: the value of a client's own tag 0E on outgoing receipt-requested mail.
8. Code 0x10 in the opener reply (post office refuses the link) is only seen from the receiving
   end; when an answering post office sends it is in spec/router-answer.md §1.3 (opener late,
   or operator abort).
9. Not determined: whether the post office accepts a password length that excludes the NUL.
   The client sends the stored length; the capture shows the NUL included. (The answering post
   office's compare needs the NUL, spec/router-answer.md §1.5.)
