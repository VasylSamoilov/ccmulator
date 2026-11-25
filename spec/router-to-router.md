# Post office to post office exchange

Compatibility: cc:Mail Router 6.x post offices exchange mail, non-delivery reports and directory
updates with each other as described here. This server is compatible with them as a peer post
office.

Conventions:
- "C" = **the calling post office**, "A" = **the answering post office**. Session codes are those
  of `spec/session-layer.md` §2.
- "the negotiation" = the `B0 80` / `AE` / `AF 01` exchange specified in `spec/negotiation.md`.
  This file treats its results (cipher on/off, extended fields, character sets) as given.
- Peer post offices exist in two database formats, an **old format** and a **new format**
  (`spec/podb.md` describes the new one). Wire behaviour is the same in both unless a step names a
  difference.
- **Location letters** (the `Locn:` letters of §4.3 and the directory's Location field):
  P = post office with a mailbox here; p = post office reached through another post office (its
  address = that post office's name); L = local user; l/r = users of another post office (address
  = their home post office); A = alias; R = see §8 #6; M = mailing list; B = bulletin board;
  C = call entry (§8 #7). "A post office entry" below means a P or p entry.

## 1. Calling side

### 1.1 When a post office calls

Calls are local policy (a schedule, or a call on demand); each call goes to one peer. A call
carries a set of **exchange categories**: M mail, D directory, B bulletin, S synch, R synch
request, T. S or R without D or B adds D. A call can also be:
- **send-only** (S/O): C sends, then 8D, and does not receive (§1.4);
- **receive-only** (R/O): C sends nothing and receives;
- **create-only** (C/O): the directory and bulletin messages for the peer are built (§4, §5) but no
  call is made.

A call can carry a size limit (a message larger than limit·1000 bytes is skipped), a minimum
number of queued messages for the call to happen (0 = call regardless), and a priority filter
(urgent/low). A failed call is retried a configured number of times.

### 1.2 The peer's address → transport

The post office dialled is the **last next hop**: the next-hop chain is followed to its end. So
calling a `p` entry dials the post office it is reached through.

The address (the directory "cc:Mail address" field) is split into space-separated words. Word 0
decides:

| word 0 (case-insensitive) | result |
|---|---|
| contains `:` or `\\`, and the entry is a post office | direct access to the other post office's files, no wire |
| `SPX[/opts]` | SPX, address = word 1 |
| `TCPIP[/opts]` (also `TCPIP/FTP`) | **TCP**, host = word 1 (name or dotted IP) |
| `COMn[/speed][/opts]` or other text | modem (`ATDT`/`ATDP` + number); the number is word 0 or word 1 depending on whether a port word was given |
| other keywords | gateways, host links or unsupported transports; not post office to post office |

- TCP port = **0CC0h = 3264**. A peer can be switched to port 21 instead. The address carries no
  port. Connect timeout 30 s. The byte stream is raw: no framing of its own.
- **Packet link or raw**: plain `TCPIP host` = **raw session bytes, no opener, no frames**.
  `TCPIP/LSEC host` or `TCPIP/HSEC host` = packet link: LSEC with /LSEC, else HSEC; ASCII coding
  with /ASCII. (The packet link starts when the speed index is ≤ 2 or one of /EC /LSEC /HSEC is
  given; plain `TCPIP` is speed index 4 with no options.) Opener and link:
  `spec/router-answer.md` §1.3 and §4.
- **A peer that also listens on TCP ignores the per-address suffix.** It calls in the link mode it
  listens with (`TCPIP` = raw, `TCPIP/LSEC` = packet link). The suffix applies only when the peer
  does not listen on TCP.
- A bare IP address (`192.108.1.101`) is not recognised as TCP; it is taken as a modem number.
  Always write the `TCPIP` word.

### 1.3 Login

```
C> B0 80                         always
   wait TIMEOUT/ (30 s) for 81 or AE (91h not skipped)
     AE → the negotiation, then C> 80, wait 81 again
     81 → go on
   timeout → "data connection not accepted", hang up
   C configured with NR and not negotiated → C> 8C, end
C> L name[L]                     own post office name
<A x  (TIMEOUT/)
   A0 → A is temporarily shut down (pass-through post office), end
   8B → C> L pw[L]               call password; <A x again
   8C → wrong password, end; the reason bytes are not read
   9F → "connection to old post offices disabled", end
   other (82 or 83) → <A L name[L] (≤ 128)
      lookup(name) == the dialled entry
        → C> 82; x == 82 accepted, else accepted read-only
      else → C> 83 (wrong name requested), end
```

- **Name sent**: length byte (counts the NUL), then the name. A two-part name `A`, `B` (stored as
  `A\0B\0`, e.g. `Smith\0Alice\0`) is sent as `"B A"`, with the same length.
- **Password sent**: the post office's **call password**; if none is set, its post office
  password. New format: length strlen+1 (counts the NUL). Old format: the stored length, which may
  or may not count the NUL. Whether a call password can hold the "new\0old\0" list the answer side
  accepts (§2.2) is not determined.
- **Name check of the answerer** (C side): the answerer's name must resolve in C's directory to
  exactly the entry C dialled. Match: same length as sent, text case-insensitive, either word
  order. So the answerer must send `strlen+1` bytes with the NUL.
- 9Fh is a reply that C understands; known answerers never send it. Which peers send it is not
  determined.
- The negotiated peer character set is switched on around the name read
  (spec/negotiation.md §4). With no negotiation the values are 0 and nothing changes.

### 1.4 Turn order and hang-up

| step | C does |
|---|---|
| 1 | record the connection time for the peer (local) |
| 2 | unless R/O: **send its messages for this post office** (§3.3) |
| 3 | S/O: C> **8D**, do not receive |
| 3' | else C> **88**, then **receive** until A's 88 / 8D / other byte |
| 4 | hang up; nothing is sent after A's 88 |

So the turns are the same as a client calling a post office: **the caller sends first**, the
answerer sends second and finishes with 88 (`spec/router-answer.md` §1.7). A lost link skips the
remaining steps. Step 2 uses the call's exchange categories (none set → M, D, B), size limit and
priority filter (§1.1).

## 2. Answering side when the caller is another post office

### 2.1 Recognition

There is no separate path. The answering post office treats every caller the same way
(`spec/router-answer.md` §1.2..§1.6). A calling post office shows up only as:
1. `B0 80` before the session start: with no packets and speed index > 2 (raw TCP), A waits for
   5.12 s of silence and then sends AE. This is the negotiation.
2. A **name that resolves to a post office entry** (P or p). "Post office caller" is decided by
   this wherever it matters. This settles `router-answer.md` open point 10 to this extent.

### 2.2 Authentication of the calling post office

- Name lookup. Unknown → 83 (read-only), no password asked. A configured with "no read-only
  connections" → bare 8C.
- Known → 8B, then the password is checked (old format):
  - The caller's password is compared with the password stored for its post office entry. For a
    post office entry **lock-out and password policy are skipped**: no minimum length, no expiry.
    Up to 3 NUL-separated strings are tried, case-insensitive, over strlen+1 bytes. A match on the
    2nd or 3rd stores the 1st (password change by the caller).
  - **No stored password → accepted, and the sent password is stored** (automatic password
    resynchronization after the administrator blanks the entry's password), except for an entry
    whose address names another entry: then `8C 00 00`.
  - Mismatch → `8C 98 00`.
  - New format: the login result codes are those of router-answer §1.5. The compare and storage
    rules are not determined.
- A sends **82 + its own name**, then reads C's 82/83: 83 → "wrong post office name requested",
  end. This is C rejecting A's name (§1.3), not A checking C.
- A configured with NR and the caller not negotiated → bare 8C ("connection to old post offices
  disabled").

### 2.3 What changes in the session for a post-office caller

| point | client / user caller | post-office caller |
|---|---|---|
| author check on receive (96) | author must be the caller | skipped (router-answer §2.2) |
| CRD/n circular check | no | yes (§3.6) |
| '#' names, "Administrator" / ADE requests | from known callers only | from known callers only (a post office entry is known) |
| bulletin '#BB' recipients | gate bit 10h | gate bit 8 |
| send: entry immediately followed by `0F <own PO name>` | becomes 03 / copy appended | **becomes 04 / 0C / 12** (already delivered here), not sent |
| send: `03 = caller` appended when missing | yes | **no** |
| after 8E | message kept | kept, and the size limit for this session is raised to 200·(5·(size/1000)+5) |
| after 87 | message not offered again | message not offered again |

The order of A's send turn (directory pass, mail, bulletins, exchange-category gates, maximum
message count) is the one in router-answer §2.4. It is the same send routine that C uses in its
own turn.

## 3. Message forwarding

### 3.1 Address path = 0F run after a name

A recipient (03/0B/11) or author (01/02) entry may be followed by a run of `0F <PO name>` entries.
Routing writes them **destination first, nearest hop last**: the target post office, then each
next hop up the chain; an alias adds a `14` with the original name. Re-routing deletes the 0F run
from a given position, then inserts the target and its next-hop chain. Example at the origin: To
`Joe` at PO C, which is reached through B → `03 "Joe" 0F "C" 0F "B"`, queued to B.

### 3.2 Receiver verdict per 03

Order of tests for one 03 entry (result 82 unless noted):
1. ≥ 1000 recipients, or a '#' name from an unknown caller → 83.
2. **Route**: scan the 0F run. It stops at the first non-0F, or at a 0F naming **this** post
   office. It takes the last 0F before the stop that names a known post office (P/p), stepping
   backwards past unknown ones. Found → the run **from that 0F on** (which drops the 0F naming this
   post office) is replaced with the target and its next hops. Header > 4096 → restore, 83. Queued
   for the final next hop. Cannot be queued → 83.
3. No route and the name starts with '#': bulletin board / mailing list (§5). "##Directory
   Updates" addressed directly → 83.
4. Directory lookup (duplicate-name resolution by path, then by name). "Administrator" → the
   administrator's mailbox, plus the ADE handling of §4.
5. Not found → alias via tag 14, else **83**.
6. Found and the entry has a next hop (i.e. an l/r/p user of another post office): CRD/ check
   (§3.6). Then the alias (entry tag becomes 14h, route added) or the route is appended. Header >
   4096 → 83. Queued for the next hop.
7. Found, local: delivered to the user's mailbox with the entry's own tag (3/0B/11).

After the verdicts, the message is stored once for every target. The stored header carries **word 0C = number of targets** and **dword 0E = the post office's message
serial** (incremented per message). This settles `router-answer.md` open point 6 for word 0C and
dword 0E (old format): word 0C is a reference count, not a "post offices still to go" counter.
Replies: 8A (no space), 8F, 86, 87 if anything was delivered, else 90.

### 3.3 What is sent to a given post office P

- Source: the messages queued for P, then those queued for P's next hops. Categories run in
  passes: directory, then mail urgent → normal → low, then bulletin, each gated by the call's
  exchange categories.
- Per message:
  1. Size limit skip.
  2. For the queue entry and, when different, for the called entry: every pending 03/0B/11 whose
     0F run (immediately after the name) contains P's name is kept. Every other pending entry is
     changed in **this outgoing copy only** to 04/0C/12. If nothing is kept for the called entry
     → the message is skipped. (For a user destination the name itself is compared.)
  3. For each still-pending 0B and 11: if the entry right after it is `0F <own PO name>` → 0C/12.
     Otherwise **a `03` copy of the name is appended at the end** (without its 0F run).
  4. Each still-pending 03 followed by `0F <own PO name>` → 04.
  5. New format only: a tag 22 (8-byte id) is appended if missing, dword[0] += 10. Tag 32 only in
     mailbox-sync mode.
  6. Nothing pending → skipped.
- Wire: 84 → 85 → word + header → **one verdict per 03 entry in header order** (MSGWAIT/, 91h
  skipped) → 86 / 89 / 8A / 8E / 8F / 9C / 9D / 9E → body → 87 / 8F / 90 / 2B. A0/A4 instead of 85
  = peer shut down.
- Verdict handling: the old format marks **only 83** as tag 10; the new format marks **any
  verdict ≠ 82**. After 87, any mark → non-delivery report (§3.5). 89 → report as well.
- 8E keeps the message; for a post office the size limit is raised (§2.3). 9C/9D/9E stop that
  priority / the message count / that category for the rest of the turn. 9E drops the category
  from the call.
- Return receipt requested and delivered: the sender builds the receipt itself, "Receipt
  returned."

### 3.4 "Sent to" handling (summary)

On the wire the receiver sees only the entries pending for this hop: 03 originals, plus 03 copies
of cc/bcc. 04/0C/12 entries are display-only and get no verdict. The sender's stored message is not
rewritten per recipient (unlike a client, session-layer §4.5). After 87 the whole queue entry is
done (§2.3).

### 3.5 Undeliverable mail

- **Non-delivery report**: §3.5.1–3.5.6 below.
- "Bad PROFS message" is for PROFS gateways only.
- Bulletin / ADE propagation refused → local notice to the administrator.

The same report is built for **every** destination of the send turn, a post office or a client
(a post office also downloads to users, appending `03 <caller>`): case (a) "a post office
refused" and case (b) "a client refused the download".

#### 3.5.1 When

- During the wire exchange: the i-th verdict 83 turns the i-th 03 entry of the **outgoing copy**
  into tag 10. The old format marks only 83; the new format marks every verdict ≠ 82.
- A report is due after 87 with at least one tag-10 mark, or after 89. No report otherwise: after
  8A, 8F before the body, 8F/90 after it and any unknown code, the message stays queued. After 8E
  and 9C/9D/9E it is also kept; 2B = link lost.
- When a report is due, it is built from the queued message, the outgoing copy and the stored
  header length. The message then counts as sent and is not offered again, **also when no report
  could be built**.
- The stored header length = the header length as loaded, before the 03 copies of cc/bcc are
  appended = the length of the stored header record.

#### 3.5.2 Author and To

- Author entry = the **last 02**, else the first 01.
- The run of 0F entries right after the author is scanned, stopping at a non-0F or a 0F naming
  this post office; the last entry of the run that is a known post office (P/p) is taken, stepping
  back past unknown names.
  - found → To = the author entry **and its 0F entries before the found one**, tag set to 03, then
    `0F <found post office's directory name>` and `0F` for each further next hop. After each
    appended hop the report's author (now `01 Administrator`) gets its 0F run ended with this post
    office: `0F <own name>` is inserted unless the last 0F already names it (case-insensitive).
    Target = that post office.
  - a non-empty run with no known post office → **no report** ("sender name not in mail
    directory").
  - empty run → directory lookup of the name; not found → no report (same reason). Found → To =
    `03 <directory name>` (the name as the directory renders it, length with the NUL; plus `0F`
    next hops that are post offices and `14 <alias>` when the entry is an alias), then
    **`0F <own post office>`**. Target = that entry.
- There is no suppression of reports about reports. A refused report has author `Administrator`
  + `0F <refuser>`: when the refuser is a user (case b) or an unknown post office, no post office
  is found → no report. When the refuser is a known post office, a second report goes to
  Administrator there. The directory lookup is a plain name lookup with no "Administrator" case,
  so an empty-run "Administrator" author only resolves if the directory has an entry of that name
  ("Administrator" maps to the administrator only in the verdicts). Whether a directory can hold
  such an entry is not determined.

#### 3.5.3 Header edits, in order (on the outgoing copy)

1. Collect every tag-10 entry with the 0F entries after it, then the 14 entries after those
   (searched from offset 32, so part 1 too), into a side buffer.
2. Open a 20-byte zeroed slot at **32 + 20 × word[1C]** (right after the tag-06 descriptors,
   before any older tag 13) and shift the rest. The slot becomes: `13 12`, +2..+9 = 0, **+0A word
   = 2** ("Returned"), **+0C dword = the stored header length**, +10 dword = 0. Target list
   emptied.
3. From the first 01 entry on (from 32 if there is none) every entry is deleted whose tag is not
   **06, 07, 05, 13, 20, 21, 23, 16, 1D**. Entries before the first 01 stay. Gone: 01/02, 03/04,
   0B/0C, 11/12, 0F, 10, 14, 0E, 15, 22, 31, ...
4. Fixed part: word 0A = 4Dh, word 0C = 0, dword 0E = 0, dword 12 = date, dword 16 = time,
   word 8 = dword 4 = dword 0 = 0. Words 1A/1C/1E untouched.
5. Every 05 and every 20 deleted (whole header).
6. Appended in this order:
   - `01 "Administrator"` (len = strlen + 1)
   - `0F <name of the queue entry>`: **the post office called** (case a) or **the user called**
     (case b)
   - [`0F <own post office>`, routed author only, 3.5.2]
   - `05 "Message not deliverable"`
   - `20 02 <the post office's code page>` — **old format only**
   - the saved tag-10 runs
   - To (3.5.2)
   - cc, when the post office is configured to copy the administrator on reports: routed author →
     `0B Administrator` + the same path as the To, same target (the target list does not add it
     twice); local author → `0B Administrator 0F <own>` and the local administrator as a second
     target.

#### 3.5.4 Store

- **word 8 = offset of the first 01**: part 1 = fixed part + 06 descriptors + the new and older
  tag-13 entries + whatever kept entries (07, 21, 16, 23, 1D) stood after the old first 01.
- The first word[1C] descriptors (at 32 + 20i): +6 := i + 1, +10 := running offset starting at
  word 8, offset += +0C. Then every tag 13 in header order: +10 := running offset, offset += +0C.
  word 1E := word[1C]; dword 4 := end offset; dword 0 := dword 4 + len − word 8. word 0C :=
  number of targets, dword 0E := the post office's message serial.
- Body: item data copied from the original at the old offsets, in descriptor order; then for each
  tag 13 a **header record is re-read from the stored original** at the old +10 (0 for the new
  slot = the original message itself), its **word 0A := 46h 'F'**, and it is written in stored
  form: the 17-column transposition (table 09 04 05 0D 0C 0B 01 07 0A 03 02 10 08 0F 00 0E 06)
  applied separately to the 32 fixed bytes, to part 1 after them, and to the addressing part, each
  from its own first byte in 512-byte pieces. Then the outer addressing part, padded to 512.
- The body goes on the wire raw (no untranspose), so on the wire the embedded header is in stored
  form. A receiving client reads it at +10: 32 bytes untransposed, part 1, then for 'F' the
  addressing part from offset word 8, length dword 0 − dword 4. Clients store headers in the same
  stored form.

Resulting layout (case b, author local, one text item):
```
fixed   word8 = offset of 01, word0A 'M', word0C targets, dword0E serial, new date/time,
        word1A/1C as the original, word1E = word1C
06 12 ... (items renumbered, offsets from word8)
13 12  00*8  02 00  <len of stored record>  <offset after the items>
[07 .. / 21 .. / 16 .. kept]
01 "Administrator"  0F <refuser>  05 "Message not deliverable"  20 02 <cp>
10 <name> [0F ...] [14 ...] ...      03 <author>  0F <own>
body: items ...  then the original header record, magic 'F', in stored form
```

#### 3.5.5 Client display

Peer behaviour (verified with a cc:Mail Remote client): the report shows as from Administrator
at <refuser>, subject "Message not deliverable", one "Unknown recipient" line per tag 10, a
"Returned" rule (tag 13 +0A = 2), the embedded header (with the original's date and size) and then
the original text; the items keep +2 = 0, word 1A is not changed, and they are listed as the
report's own items.

#### 3.5.6 New-format differences

- No tag 20 entry; 05 and 20 are still deleted.
- The cc to the administrator is a separate post office setting.
- Tag 10 for any verdict ≠ 82.
- Store: the same offset rules as the old format.

This server (`message.non_delivery`, `message.report_address`, `store.non_delivery`,
`session.Call._returned`) follows the old format, including the tag 20, with these differences:
dword 0E = 0 (no post office serial); the code page = po.json `codepage`; the cc needs po.json
`"ndr_cc_admin": true`; the 0F hop chain is a single post office; the stored original is the copy
in our queue or mailbox, and for a download the report is built from that stored copy (not the
code-page-converted copy sent to the client), so the kept tag 21 matches the item bytes. Tag 31 is
dropped as the peer drops it; the names then count as the post office's default code page (exact
for ASCII names; for others an interpretation, not settled by the peer's behaviour).

Not determined: what a peer puts in time byte 19 (captures showed 20h); whether old tag-13 lengths
always equal the re-read record length (the body is copied by the loaded length, the offsets
advance by +0C); whether a directory can hold an entry named "Administrator".

### 3.6 Circular routing (CRD/n)

Only for a post-office caller and a recipient with a next hop. A post office with a
circular-routing limit n counts the 0F entries equal to the next hop's name. If the count reaches
n, the verdict is **83**, and a "Circular routing detected" message (author `ROUTER`) is sent to
the local administrator and to `Administrator` at the next-hop post office.

## 4. Directory exchange (ADE) between post offices

All ADE traffic is ordinary messages (84 ... 87).

### 4.1 When it is sent

- In the sender's turn, **before mail**, if the call's categories have D.
- Gates:
  - the post office supports ADE;
  - directory exchange is enabled for post office partners (separately for user partners);
  - the partner is on the propagation list of the directory-updates board ("##Directory Updates";
    the new format names it `#Directory Updates`).
- Updates: the board's messages after the per-partner high-water mark. A message is never sent back
  to the post office it came from. Each update is re-filtered for the partner (send filter, §4.5).
- Synch (category S) / synch request (category R) need partner propagation bits: 0Eh directory,
  400h lists, 800h bulletin boards.
- New format: a partner that is **not** on the propagation list and has **no** prop of its own is
  added to the list automatically when the post office default prop is not 0 or 17. Its
  high-water marks are copied from the post office's own. A partner with its own prop must be on
  the list already (assigning a propagation type puts it there; verified with type Peer, §7.1).
- While ADE work runs inside a session, 91h fillers are sent every 15 s (default; ADETM/n).

### 4.2 Message format

| element | value |
|---|---|
| 01 | `Administrator`, plus `0F <own PO>` for a synch request or partner prop 200h |
| 03 | `Administrator` + `0F <partner>` + `0F` each next hop (last 0F = next hop) |
| 05 | "ADE update message" / "ADE synchronization message" / "ADE synchronization request message" |
| 07 | "CCMUPDAT %y" / "CCMSYNCH %y" / "CCMSYNCH.REQ %y", %y below |
| 06 | one level-0 item of type 3 (File), stored with the 512-byte block transform (items.md §3/§4) |
| 21 | code page word |
| 1C | word 2 (ADE), \| 10h and \| 20h from sender settings (below) |
| 0C | ~WAMM_Mailbox / #WAMM_Mailbox copies (statistics) |
| 16 | none (normal priority) |

All other addressing is stripped before sending to a post office (keeps 05 06 07 13 16 1D 20 21
23 and 01/02 with their 0F/14 runs).

- **%y** = date + " " + time.
  - Date, by the sender's date-format setting: 0 → `M/D/YY` (month and day without padding),
    1 → `D/M/YY`, 2 → `YY/MM/DD` zero-padded. The year is year % 100, written as 2 digits with a
    leading 0.
  - Time, by the time-format setting: 0 → hour 1..12, ":", minutes as 2 digits, then "AM"/"PM"
    with no space; else the 24-hour hour, no suffix.
  - Example: `CCMUPDAT 11/25/26 9:45PM`. Verified: `CCMUPDAT.UND 11/25/26 9:45PM` and
    `CCMUPDAT 11/25/26 9:48PM` were seen from peers (§7.5).
  - The receiver compares only the name prefix (§4.4), so the date text is informative.
- **From**: a receiver authorises by the 0F right after the author (§4.4), so a sender must write
  `01 Administrator 0F <origin PO>`.
  - A post office forwarding board messages adds that 0F only for a synch request or a partner
    with prop 200h. Otherwise it keeps the From of the stored board message.
  - Update messages created by a peer's administrator carry `01 Administrator 0F MYPOST` (seen),
    with subject "Automatic Directory Update" and tags 20/21 and 1D.
  - Not determined: where a receiving post office gets the origin of a message whose From has no
    0F. No insertion of the caller's name after the author was found in the receive path.
- **1C**: send `0002`. Bit 10h comes from a sender setting, bit 20h from a setting of the partner
  entry; their meanings are not determined (§8 #11). On a new-format post office that own setting
  is never on, so it answers a 1C with bit 20h with an "ADE20 format change request".
- **The answer to a synch request is the request message itself, refiled** with the new item
  (verified):
  - 07 = `CCMSYNCH     <date>`: bytes 8..11 of the request's `CCMSYNCH.REQ <date>` blanked;
  - subject "ADE synchronization request message", date and time of the request;
  - From `Administrator` 0F <answering PO>, To `Administrator` 0F <requester>, tags 21, 1C 0002.

### 4.3 Item text (CR LF lines)

- **Synch header lines**: `Synch: /directory`, `Synch: [-]/postofc=<PO>`, `Synch: /alias`,
  `/domain`, `/enterprise`, `/mlist`, `/bboard`, `/test`, `Format: /ade20`. A synch request is
  only these lines.
- **Entry record**:
  - `Name: <name>`;
  - `Locn: [D]<letter>[ <prop>]`: letter L R A P M B (C on input); D = delete; prop = 4 hex digits,
    **least significant nibble first**;
  - `Addr: <address>` (for a post office entry written only when an entry setting of the sender
    asks for it);
  - `Achng:` (new address), `Cmts:`;
  - new format with extended fields (negotiation type 24) only: `Uname:`, `UAltName:`, `UCmts:`.
- An old-format synch ends with `Name: <own PO>` / `Locn: P`. A new-format synch has no such
  record: the header lines, then every user and post office entry in name order that passes the
  send filter (§4.5) and is not hidden, then mailing lists and boards.
- Exact strings: `%s /directory`, `%s /postofc=%s`, `%s -/postofc=%s`, `%s /alias`, `%s /mlist`,
  `%s /bboard`, `%s /test` with `%s` = `Synch:`, and `Format: /ade20`. Record lines: `Name: %s`,
  `Locn: %s`, `Addr: %s`, `Achng: %s`, `Cmts: %s`, each + CR LF. `Cmts:` is always written, even
  when empty. Senders never write `Chng:`; receivers read it.
- A user's `Addr:` (new format) = the name of its home post office, then " " + its cc:Mail address if that is
  non-empty. So a local user is written `Addr: <own PO>`. **Verified** synch:

  ```
  Synch: /postofc=MYPOST
  Format: /ade20
  Name: admin
  Locn: L
  Addr: MYPOST
  Cmts: admin comment
  ...
  ```

  This is a synch sent to a partner with prop 0053h: `prop & 2` and not `prop & 8` →
  `/postofc=<own>`. Content bit 100h → `Format: /ade20`.
- Locn letters written: P for a post office, A for an alias, R or L for a user.
- **Update keywords**: case-insensitive prefix, each at most once. Lines up to 527 characters;
  `REM` lines are skipped; a trailing ^Z is cut.

  | keyword | max length | empty allowed |
  |---|---|---|
  | `NAME:` | 126 | no |
  | `LOCN:` | 126 | no |
  | `ADDR:` | 383 | yes |
  | `CMTS:` | 126 | yes |
  | `CHNG:` (new name) | 126 | no |
  | `ACHNG:` | 383 | yes |
  | `PSWD:` | 10 | no |
  | `LOCK:` | value LOCK / UNLOCK | |
  | `FORMAT:` | | |
  | `UNAME:` / `UALTNAME:` / `UCMTS:` | 512 | |

- Error lines go into the returned `CCMUPDAT.UND` as `Error: /code=%d /text=%s`. The 20 codes:

  | code | text |
  |---|---|
  | 1 | Name field missing |
  | 2 | Update field too long |
  | 3 | Update field may not be empty |
  | 4 | Duplicate update field |
  | 5 | Invalid location status |
  | 6 | Invalid propagation field |
  | 7 | Invalid update format |
  | 8 | Location not specified |
  | 9 | Maximum directory entries exceeded |
  | 10 | Maximum local users exceeded |
  | 11 | Invalid location change |
  | 12 | Administrator may not be deleted |
  | 13 | Changed name already in directory |
  | 14 | Update not allowed |
  | 15 | Entry locked |
  | 16 | Duplicate names not allowed |
  | 17 | Maximum call entries exceeded |
  | 18 | Extended fields not allowed |
  | 19 | (empty) |
  | 20 | Invalid address |
- **Type 5 / type 6 items**: a level-0 type-5 item marks an update. Its text is read like the
  CCMUPDAT file item: the first level-0 item of any type, through the 512-byte block transform. A
  client's 20-byte directory-update request item (type 6, session-layer §6.1) is not read by an
  old-format post office; a client's request is recognised by tag 18 only (§4.4). New format: not
  determined.

### 4.4 Receiving

- Classification:

  | test, in order | class |
  |---|---|
  | tag 13 present | 0 (not ADE) |
  | a level-0 type-5 item | update |
  | otherwise: exactly 1 heading, a level-0 type-3 item and a tag 07 are required (else 0); prefix of the 07: | |
  | CCMUPDAT.UND, CCMUPDAT.RTE | 0 |
  | CCMUPDAT | update |
  | CCMSYNCH.REQ | synch request (3) |
  | CCMSYNCH | synch (2) |
  | CCMINFO.REQ | info request (4) |

- Verdict: 03 `Administrator` from a known caller, ADE supported, class ≠ 0, "##Directory Updates"
  exists, directory exchange with post offices enabled → **82**. If the receiver has a
  `~ADE_Mailbox`, the message is parked there; otherwise it is applied during the session (91h
  fillers while it runs). Otherwise "Administrator" is just the administrator's mailbox (82).
- Authorisation: the author's 0F must be a known post office whose prop has C0E0h. Otherwise the
  message is returned "ADE message rejected (author cannot update directory)".
- Results:
  - a synch request is answered with a synch;
  - a synch is compared, then applied as an update;
  - accepted messages are posted to "##Directory Updates" for onward propagation;
  - rejected messages are returned from `ROUTER` with one of 6 subjects;
  - WAMM statistics messages (05 `/WAMM=nn /text=...`) go to the 0C WAMM mailboxes.
- A client's own directory request (tag 18) is not processed by an old-format post office. This
  settles `router-answer.md` open point 5 for the old format.

### 4.5 The prop word (who may update what)

- **Which prop**: the entry's own prop if it has one. Else 17 (0011h), except:
  - for a post office entry, the post office's default prop for post offices (17 if none);
  - for some user entries (selected by entry settings; new format: local users marked for it),
    the post office's default prop for users.
- **Bit names** (as the post office database names them):

  | bit | name | bit | name |
  |---|---|---|---|
  | 1 | Send_Update | 100h | Send_Aliases |
  | 2 | Send_Local | 200h | Send_Secondary |
  | 4 | Send_Remote | 400h | Send_Mlists |
  | 8 | Send_Other | 800h | Send_Bboards |
  | 10h | Recv_Update | 1000h | Domain |
  | 20h | Recv_Local | 2000h | Enterprise |
  | 40h | Recv_Remote | 4000h | Recv_Mlists |
  | 80h | Recv_Other | 8000h | Recv_Bboards |

- Masks a peer tests:
  - C0E0h = may update this directory;
  - 0D0Eh = what a synch request may ask for;
  - 200h = From gets `0F <own>`;
  - 3000h = domain/enterprise routing checks in the receive filter and the new-format synch
    builder.
- **Receive filter per record** (prop, own name, sender):
  1. If the record carries a prop: `~prop & record.prop & F0E0h` ≠ 0 → refused.
  2. Then by letter:
     - M → 4000h; B → 8000h;
     - P → 80h path;
     - otherwise `Addr` = receiver's own name → **20h** (Recv_Local), `Addr` = the sender
       (author's 0F) → **40h** (Recv_Remote).
  3. Else (no or another address) → 80h path. With ADE/C or 2000h and 40h, an `Achng` = sender
     also passes. The 80h path is 1 if prop & 80h (3000h: also the chain must reach the sender).
  - Consequence: a user record must carry `Addr: <sender>` to pass on 40h, **deletes included**.
    Peers write Addr on their D records (seen: `Locn: DL` / `Addr: MYPOST`).
- **Same filter for the existing entry**:
  - post office entry → 80h path;
  - local entry (no next hop) → 20h;
  - entry whose next hop is the sender → 40h.
- **Send filter** (synch builder and update re-filter):
  - A needs 100h; P → 8 (2000h without 1000h: name = partner only);
  - Addr = own → 2; Addr = partner → 4; else 8.
- Verified: a partner given propagation type **Peer** has prop **0053h** (Send_Update,
  Send_Local, Recv_Update, Recv_Remote). The default props were 0011h.

### 4.6 Applying an update record

Inputs: prop, own name, sender (author's 0F). Error codes as in §4.3.

1. Locn M/B → list/board update; C → call-entry update.
2. Record filter fails → **14**.
3. Name = own post office → no change if Locn P, else 14.
4. Look up the name. Not found but `Chng:` given → retry with the new name; `Achng:` → the address
   becomes the new address. This makes a repeated rename idempotent.
5. Found: the entry filter fails → 14.
   - Entry locked → **15**, unless the record equals the entry and has no Chng/Achng; then it is no
     change and no error.
   - A `~ADE_Mailbox` only changes which statistic is counted.
6. Locn first letter A → treated as R. A non-empty Addr that is not the own post office with
   Locn L → R. Old format always; new format only when the address names a known home post
   office.
7. Found entry and Locn D:
   - the entry is the administrator → **12**;
   - D + L/l on a P entry → **5**;
   - else deleted.
8. Found entry, not D: Locn P on a non-P entry, or non-P on a P entry → **11**.
9. Not found: D → nothing (no error); no Locn → **8**.
10. Add (not found):
    - P without `Addr:` → its address = the sender (it is reached through the sender).
    - Others with Addr: the new format resolves the home post office; the old format creates a P
      entry for an unknown one, address = sender.
    - The entry is created.
11. Change (found):
    - `Chng:` → rename. The new name already belongs to another entry → **13**.
    - A name equal apart from case/form → renamed to the record's form.
    - Then Locn, Addr (P with Addr = own name clears it), Cmts, prop, Pswd (local mailbox only),
      Lock.
    - Result: changed, or "No changes made".
- Verified:
  - users added from OURPO's update appear at the peer as Location `l` with home post office
    OURPO (no address text);
  - a `Chng: Smith, Alice` renamed the entry, stored as `Smith\0Alice\0`;
  - our record `admin` (Addr OURPO) collided with the peer's local admin → 14 "Update not allowed".

### 4.7 Synch: compare and apply (new format)

- Header lines are read into **receive-style** bits, plus keyword bits:
  - `/directory` E0h, `/mlist` 4000h, `/bboard` 8000h, `/domain` 1000h, `/enterprise` 2000h;
  - `/postofc=X`: 20h if X = the receiver, 40h if X = the sender (author's 0F), 80h if X is
    another known entry (unknown → error); `-/postofc=X` clears that bit.
- Scope = those bits & prop. The compare walks the receiver's directory (user and post office
  entries, name order) next to the synch records. An entry that no record names, is in scope
  (entry filter with the scope), is not the own post office or the administrator and is not locked
  is queued for **deletion**. A record that differs is "need to be applied"; equal → "no changes".
  - So `Synch: /directory` with a prop that has 20h can delete the receiver's own users. A
    sender should declare only itself: `Synch: /postofc=<sender>`.
- Then:
  - records with format errors in the synch ("disallowed" in this pass) → nothing applied;
  - "test" → nothing applied;
  - nothing to apply → done;
  - else the 07 is renamed `CCMUPDAT`, the changes (deletes written as D records) are refiled and
    applied as an update (§4.6).
- Records refused while applying: as read, the message is returned with code 5 "ADE synch message
  rejected (attached updates cannot be applied)". The accepted part is refiled, and the reply is
  87 when anything was applied (posted). Reply 90 comes only from a failure to refile, post or
  return the message.
  - Verified: our synch that omitted bob and contained `admin` (the peer's own local user)
    deleted bob at the peer, refused `admin` (14) and was answered **90**. Why the peer took the
    90 path is not determined. Whether its return message was created was not checked: no call
    was made afterwards.
  - The same refusal inside a plain update gave 87 and the return message (§4.9).
  - A sending post office keeps a message queued after 8F/90. Our server does the same: a message
    is moved out of the queue only after 87. What a sending post office does with its own synch
    answered 90 is not determined.

### 4.8 Synch request (class 3)

- At receipt the request is authorised and then posted to the directory-updates board.
- When ADE runs for a partner, the request is answered only if the requester (author's 0F) is that
  partner. The answer is a synch built from the request bits, nibble-swapped (E0h → 0Eh,
  20h → 02h, 40h → 04h, 80h → 08h).
- The request is refused when `swapped & ~prop & 0D0Eh` ≠ 0. So `Synch: /postofc=<answerer>` needs
  only Send_Local (2); `/directory` needs 0Eh.
- The synch is built with the full prop (content 1 = directory, | 100h = `Format: /ade20`).
- Verified: our `CCMSYNCH.REQ` with `Synch: /postofc=MYPOST` was answered **in the same call**, in
  the peer's turn, by the synch shown in §4.3 (prop 0053h).

### 4.9 Returned messages (verified)

```
p1  06 item 0 (type 3) = the original CCMUPDAT item, 06 item 1 (type 3) = CCMUPDAT.UND,
    13 (returned heading), 21 01B5, 07 "CCMUPDAT 11/25/26 9:44PM" (title of item 0)
01 "ROUTER"  0F "MYPOST"
03 "Administrator"  0F "OURPO"
0C "admin"  14 "Administrator"          (the local administrator, as cc)
05 "ADE message received (attached updates cannot be applied)"
07 "CCMUPDAT.UND 11/25/26 9:45PM"
22 <8-byte id>
```
CCMUPDAT.UND = each refused record (as read, blanks trimmed), then `Error: /code=14 /text=Update
not allowed`.

## 5. Bulletin boards and mailing lists between post offices

- Bulletin boards are sent in the sender's turn **after mail**, with category B. They go to every
  distribution-list target that is the called post office or is routed through it, from the
  target's high-water mark on. Never echoed to the post office the message came from. A message
  from another post office is forwarded only when the board is configured to forward (§8 #8b);
  this post office then appends its name as a 0F after the author.
- Header to a post office: every recipient entry is stripped (as in §4.2), then `03 "#BOARD"`
  (name exactly as stored) + `0F <target>` + `0F` each next hop are appended. Tag 1C |= 4.
- Receiving: a '#' name from an unknown caller → 83. A 0F route wins first. Otherwise, if the name
  is a board and the gate passes (bit 8 for a post office): 82, posted to the board. Bulletins in a
  queue need category B; the receiver answers 9E without it (router-answer §2.2).
- Board synch (exchange options /BS /BR /BT): item lines `Synch: /Test` (optional), then
  `Msgs: /msgno=%08lx` (also `/delmsgno=`, `/reqmsgno=`). Message id = hash(origin-PO "/"
  date-time) << 16 | hash(author "/" subject). Header as in §4.2.
- Mailing lists: expanded only at the post office that holds the list. The entry becomes
  0A/0D/1A and the members are appended with their routes; header > 4096 or ≥ 1000 recipients →
  83. To reach a list at another post office, send `03 "#LIST" 0F <that PO>`; the route is taken
  first.

## 6. Other exchanges between post offices

| item | finding |
|---|---|
| time synchronisation | none on the wire |
| statistics | none on the wire (kept locally) |
| WAMM statistics | ordinary messages to ~WAMM_Mailbox / #WAMM_Mailbox (§4.4) |
| broadcast | none |
| capability exchange | only the negotiation (spec/negotiation.md) |
| 91h fillers | sent while delivery runs ADE / list / board work, also by a post-office receiver (router-answer §2.2 step 8, every 15 s by default) |

## 7. Recipe for our server (post office "OURPO")

Build it on the **non-negotiated** path. The peer must not be configured with NR: with NR it sends
8C after 81 when it calls and a bare 8C when it answers. Encryption and the rest are in "the
negotiation". Wire format inside the session = session-layer §2..§4 and router-answer §2. Every
length byte we **send** counts the trailing NUL. Peers do the same for names and new-format
passwords, but not necessarily for an old-format call password (sent with its stored length). So
on input, accept both forms and strip trailing NULs. Login and turn order hold for both formats;
the password check and forwarding are established for the old format (new-format differences are
noted).

### 7.1 What the peer post office must allow (interop note)

| item | value | why |
|---|---|---|
| directory entry for us | name `OURPO`, Location **P** | a post office caller (§2.1); P has a queue for routed mail (§3.2) |
| its password | **set explicitly** to the value our server sends. Old format: a blank password is filled by our first call; new format: not determined | §2.2 |
| its address | `TCPIP <our-host-or-ip>`; the TCPIP word is required (bare IP = modem). A suffix (`TCPIP/LSEC host`) counts only if the peer does not itself listen on TCP | §1.2; port is always 3264 (0CC0h) |
| the peer's call password | what it sends when it calls us; if none is set, its post office password | §1.3 |
| link mode | the peer listens raw (`TCPIP`) or with the packet link (`TCPIP/LSEC`), without NR | §1.2 |
| calls to us | scheduled, with no minimum message count if it should call without mail, or on demand | §1.1 |
| users of OURPO | addressed `name at OURPO` (03 name + 0F OURPO), or `l` entries whose address is OURPO | §3.1 |
| directory and board exchange | sent only if the peer's ADE / board lists include OURPO; leave those unset unless wanted | §4.1, §5 |

**Directory exchange with OURPO.** The peer must have directory exchange enabled, with exchange
with other post offices on, and OURPO must be on its propagation list with a prop.
Verified with propagation type **Peer** (prop 0053h): the peer takes users whose address is OURPO
(Recv_Remote) and sends OURPO its own users (Send_Local). It does not take P records or users of
third post offices (Recv_Other 80h), and it does not send them (Send_Other 8); those need a prop
with these bits. The props stored for the other propagation types are not determined. After
directory changes made by its administrator, the peer posts a CCMUPDAT message ("Automatic
Directory Update") to the directory-updates board and sends it to OURPO at the next connection.

Our side (po.json): `"MYPOST": {..., "ade": true}` (our prop for it defaults to 00D3h:
Send_Update | Send_Local | Recv_Update | Recv_Remote | Recv_Other), or `"ade": {"prop": "0x53"}`.
Commands: `python3 -m ccmail.server ade sync|request|update|list --data DIR [PO]`, then `call`.

### 7.2 (a) We call the peer (TCP port 3264)

Raw mode (no packet layer), one byte stream:
```
us> 80                          then stay silent ≥ 5.12 s: A treats any byte within 512 cs as noise
                                (applies because the TCP speed index is 4 > 2: the answer wait
                                uses the listening speed index 4)
A>  81                          (sniff window = TIMEOUT/ s, default 30, from connect)
us> 06 "OURPO\0"
A>  8B                          (if OURPO is unknown: 83 + name, read-only; skip to "A> L name")
us> L "PASSWORD\0"              case is ignored; one string. "new\0old\0" changes it
A>  82 | 8C r v                  8C 98 00 = wrong password (§2.2)
A>  L "REALPO\0"                its own name
us> 82                          (83 → A ends: "wrong post office name requested")
-- our turn --
us> 84 / A> 85 / us> HL hdr / A> one verdict per 03 / A> 86|89|8A|8E|8F|9C|9D|9E / us> body / A> 87|8F|90
    (repeat; skip 91h while waiting)
us> 88                          (8D = we will not receive: A sends nothing, no 88)
-- A's turn: its queue for OURPO --
A>  84 / us> 85 / A> HL hdr / us> one verdict per 03 / us> 86 / A> body / us> 87
A>  88, then it drains and hangs up
```
Packet mode instead: send the opener and frames as a client does (link-layer.md). A takes the
caller's mode from the first frame. Then `80` gets `81` at once, with no silence wait.

### 7.3 (b) The peer calls us (we listen on TCP 3264)

```
R>  B0 80                       (raw; with a /LSEC address it sends the opener first, answer with
                                 control 0Fh, router-answer §1.3)
us> 81                          never AE (we do not negotiate); must arrive within TIMEOUT/ 30 s
R>  L "REALPO\0"                its own post office name
us> 8B
R>  L "callpw\0"                its call password (else its post office password)
us> 82                          or 83 (unknown: read-only) / 8C 98 00 (wrong password)
us> 06 "OURPO\0"                must resolve in REALPO's directory to the entry it dialled
R>  82                          (83 = wrong name requested: it hangs up)
-- R's turn: its queue for OURPO --
R>  84 / us> 85 / R> HL hdr / us> verdicts / us> 86 / R> body / us> 87   ... R> 88 (or 8D = S/O call)
-- our turn (only after 88) --
us> 84 ... per message for REALPO's users, then us> 88; R hangs up
```

### 7.4 Headers

- **Mail we send** (for REALPO's users):
  - `01 "<user>\0" 0F "OURPO\0"`: the 0F lets replies and non-delivery reports route back
    (§3.5.2); the author check does not apply to a post office caller;
  - `03 "<name>\0"` per recipient, optionally followed by `0F "REALPO\0"` (a 0F naming the receiver
    ends the route scan, §3.2);
  - cc/bcc as 0B/11 **plus** an appended 03 copy each (§3.3 step 3);
  - received cc/bcc arrive the same way: a bare trailing `03 name` with no 0F run, alongside the
    original 0B/11 (+0F). Verdicts are due only for the 03 entries;
  - one verdict comes per 03; word 0C ≥ 1 (the receiver rewrites it, §3.2).
- **Mail we receive** carries `03 <name> 0F OURPO [0F ...]`. Answer 82 for our users and 83 for
  the rest. The sender then marks 83 entries as tag 10 and sends its author a "Message not
  deliverable" report (§3.5). 89 (none accepted) gives the same report for all.
- To be a transit post office we would have to route like §3.2. Not needed for a leaf post office.
- Expect 91h while waiting for 87, and directory (1C & 2) or bulletin (1C & 4) messages only if
  REALPO's ADE / board lists name OURPO. Refusing them with 9E makes the sender drop that category
  for the rest of the session.

### 7.5 Verified ADE exchange (peer MYPOST, us OURPO)

| step | result |
|---|---|
| we call; our turn: CCMUPDAT (admin, alice, bob) + CCMSYNCH.REQ (`/postofc=MYPOST`) | both 82, 87. alice and bob entered at the peer; admin refused (14) |
| peer's turn, same call | the synch of §4.3 (admin, user, user1, user2). We learn user, user1, user2 and refuse admin, which is our own local user (14). Our return ("ADE synch message rejected …") goes to MYPOST's administrator and was delivered there at the next call. The peer's return (§4.9) reaches our admin |
| peer directory readout | alice / bob as Location `l`, home post office OURPO |
| we rename alice → "Smith, Alice" | entered; stored name `Smith\0Alice\0` |
| `send --to user1` (name only, learned) | routed to MYPOST, 82/87, in user1's Inbox |
| MYPOST's administrator adds user3, deletes user2, propagates | next call: we receive "Automatic Directory Update" (user3 L / user2 DL Addr MYPOST): user3 added, user2 deleted, our clients get a CCMUPDAT |
| we delete bob locally, send a synch (`/postofc=OURPO`) | bob deleted at MYPOST, admin refused → reply 90 (§4.7) |

## 8. Not determined

1. Whether a call password can carry `new\0old\0` (rotation from the caller's side).
2. New-format password compare and storage for post office entries (blank-password
   resynchronisation in the new format).
3. New-format name-length rule: whether the NUL must be counted in a received name and the case
   rule. Sending strlen+1, as peers do themselves, is the safe choice.
4. (Removed: local call scheduling details, not protocol.)
5. Which peers send 9Fh (callers read it; known answerers never send it).
6. Location letters beyond P, p, A and l/r: in particular what R covers.
7. ADE details. Settled:
   - %y (§4.2);
   - the tested prop masks and the bit names (§4.5);
   - the apply rules (§4.6), the synch merge (§4.7) and the synch-request answer (§4.8).

   Not determined:
   - what Locn C records are (header keyword `/call`);
   - %y under other date and time settings (only the US form was seen);
   - the props stored for propagation types other than Peer (0053h);
   - where a receiving post office takes the origin of an ADE message whose From has no 0F (§4.2);
   - the CCMINFO.REQ reply (our server logs such a request and does not answer);
   - the old-format synch compare; §4.7 describes the new format.
8. Bulletin boards:
   - (a) the partner option bits other than 800h (board synch), 8000h (synch request) and 200h;
   - (b) the two board options that allow forwarding a message from another post office;
   - (c) tag 1C bits 10h and 20h;
   - (d) the synch-managed propagation path;
   - (e) the "%z" date format inside the message id;
   - (f) the board-synch reply rules.
9. Login and turn order are cross-checked on two peer implementations; forwarding, verdicts, ADE
   and the header rewrites on one only.
10. Whether a peer sends a notice message after all call retries failed (notice or log).
11. ADE:
    - the meaning of the post office's own setting behind 1C bit 10h (duplicate names or ADE20
      format), which also decides whether a received bit 20h triggers the format-change request;
    - new-format handling of a client's directory request (tag 18) and of mail addressed to
      "##Directory Updates";
    - the per-field apply rules: settled in §4.6, except the new-format address resolver and the
      list/board/call appliers.
