# Answering a call: the post office side

Compatibility: this server is compatible with cc:Mail Remote 3.40B and RCONNECT 1.00 clients and
with cc:Mail Router 6.x post offices.

This describes how an answering post office handles a call from a client or from a peer post
office: the sequences, codes, timeouts and verdicts it uses. The description was taken from a
compatible peer post office; captures of real sessions agree with it. Points confirmed for only
one version of the peer are marked "(one peer version)".

"C" = the caller (a client or a peer post office), "P" = the answering post office.
Session code bytes travel inside the packet link (or raw, see 1.2). The session timeouts count
in **seconds**; the short waits and silence checks of the answering post office count in
**centiseconds**.

## 1. Answer-side flow

Wait for a call → modem answer (answer string, manual answer or PBX line) → link and login →
receive the caller's mail → send mail to the caller (only if the caller is known) → `88` → drain
the link and hang up.

### 1.1 Parameters used

The answering post office has these settings that are visible on the wire:

| parameter | default | used in the answer |
|---|---|---|
| byte timeout, 1..300 s | 30 s; forced to 60 s by two modem-type settings | every byte wait during login (1.4), the whole sniff phase (1.2) |
| opener grace period | 0 s | opener wait (1.3) |
| refuse unknown callers | off (unknown callers allowed read-only) | unknown caller refused (1.6) |
| refuse non-negotiated callers | off | every non-negotiated caller refused (1.4) |
| pass-thru | off | pass-thru callers (1.4) |
| extended fields | — | negotiation type 24 (1.2.1) |
| message size limit (KB) | no limit | section 2 |
| send-only / receive-only / call-list options | — | calling side only |

Link mode options (error correction, ASCII, LSEC/HSEC, flow control, parity, binary) shape the
post office's own outgoing calls (section 4); they do not change the answer.

### 1.2 Sniffing the first bytes

The answering post office reads bytes one at a time while any are available and classifies each:

| byte | condition | action |
|---|---|---|
| B0h | any time | negotiation request: wait for the next byte (byte timeout); not 80h → forget, go on sniffing. 80h: if no packets yet and the speed is above 2400 bps, wait for **5.12 s of silence**; a byte in that time → forget. Then send **AEh**, run the negotiation (1.2.1), and go back to sniffing with "negotiated" set |
| 80h | packets already detected, or negotiated, or speed ≤ 2400 bps | session start (1.4) |
| 80h | otherwise (raw at > 2400 bps) | wait for 5.12 s of silence; a byte in that time → treat the 80h as noise |
| 02h | no packets yet | start collecting a binary frame |
| c & 7Fh = 20h | no packets yet | start collecting an ASCII frame |
| other | collecting (fewer than 128 bytes so far) | append |
| other | packets up | ignored |

After 6 or more collected bytes, each new byte runs a frame test: a CRC over the bytes after the
first, looking for residue 1D0Fh. It gives LSEC if the residue is hit at exactly 6 counted bytes,
HSEC if later, nothing otherwise. This is the same test a client uses (link-layer.md). On a hit
the answering post office starts the link in that mode, takes the collected bytes as the first
link input, and waits for the opener (1.3). It answers in the caller's mode at any speed; there
is no HSEC→LSEC downgrade on the answer side (the mode is clamped to HSEC at most).

The whole sniff phase is limited to the byte timeout from the answer (the clock is restarted
when packets come up). Expiry → the call ends without anything being sent.

#### 1.2.1 Negotiation (B0 80 / AE), not used by the supported clients

Who uses it: a calling peer post office (6.x) sends `B0 80` first on every call and waits for 81
(old answerer) or AE. "NMTP" is its protocol id. "MOBP" is the other accepted id. Not determined:
which clients send "MOBP". The supported clients never send B0 (their only opening byte is 80h,
spec/session-layer.md §2).

Packets: 8-byte header `AF 01 type(2 LE) status(2) len(2)`, then `len` data bytes. Anything not
starting `AF 01` ends the negotiation loop. Replies carry type|8000h.

| type | handling by the answering post office |
|---|---|
| 1 hello: data = 4-char id + word version | "NMTP": version 100 → status 0; else counter-offer 100 with status 1. "MOBP": version ≥ 200 turns on mailbox-sync mode; 100 or 200 → status 0, else counter-offer 200. Other id → status 3 |
| 6 key: data word = 1 + 90 bytes | key schedule built from the data; **from then on every session byte is XOR-enciphered**, in both directions. Other word value → status 9, then type 21, cipher off |
| 18, 22, 23 | exchange of a post-office database value |
| 19 | value 1 accepted, else counter-offer 1 |
| 20 | status 9 (refused) |
| 24 | value 100 → send extended fields, else counter-offer 100 |
| 8 | end: the answering post office sends type 9 |
| other | status 7, continue |

The answering post office loops until a type-1 packet was handled, then until type 8. A
negotiated caller then sends 80h again and gets 81 straight away.

### 1.3 Opener and the 0Fh/10h link control reply

- The answering post office scans delivered data for `FF AA 55 11` at **any position**: a wrong
  byte restarts the match. It does not require the opener to be the first data.
- Wait = `200*(5*grace+150)` ms = 30 s + the opener grace period in s, counted down in ms by the
  link timers (section 4).
- Match → link control code **0Fh** queued, opener accepted.
- Operator abort → control **10h**, call abandoned.
- Time-out → control **10h**, unless carrier was lost or the call was aborted (then no 10h).
- Matcher quirk: on a mismatch the breaking byte is not re-tried as `FF`, so `FF FF AA 55 11` is
  missed.
- So **the answering post office refuses with 10h only when the opener does not arrive in time
  or the operator aborts**; never for a client property. Any failure here ends the call.

### 1.4 80 → 81, name

At the session start:
1. Discard every byte already received — anything the caller sent after 80h in the same burst is
   lost.
2. Send **81**.
3. Name: one length byte, must be 1..128 (0 fails), then that many bytes. Each byte wait = the
   byte timeout, restarted while the send side progresses. Failure → the call ends, nothing
   sent. The waits here do **not** skip 91h (unlike the waits in the message exchange).
4. Refuse non-negotiated callers set and the caller not negotiated → **bare 8C**. This applies to
   every supported client.
5. Directory lookup. A stored name of the form `A\0B\0` is compared as `"B A"`, and an entry
   matches when its **stored length equals the sent length** and the text matches
   **case-insensitively**, in either word order.
   Users and post offices are in the same directory: a calling peer post office sends its post
   office name here and is looked up the same way.
6. Pass-thru: only for an entry that belongs to a pass-thru post office; failures send **A0h**
   ("post office is temporarily shut down") and/or **A6h**, not 8C. Not reachable for an
   ordinary local user.

### 1.5 Password request 8B, refusals 8C (known entry)

1. Send **8B**. Read the password field like the name (≤ 128 bytes).
2. Check the password. On a failure send exactly **3 bytes `8C reason value`**:

| failure | wire | value byte |
|---|---|---|
| mailbox entry unusable | `8C 00 00` | 0 |
| mailbox data cannot be read (database error) | `8C 00 00` | 0 |
| mailbox data of an unsupported version | `8C 00 00` | 0 |
| account locked | `8C 97 n` | n = **configured lock-out limit**, not the count |
| incorrect password | `8C 98 00` | 0 |
| no password stored and a password is required | `8C 00 00` | 0 |
| password shorter than the policy minimum | `8C 99 m` | m = minimum length + 1 (counts the NUL) |
| password pre-expired | `8C 9A 00` | 0 |
| password expired | `8C 9B d` | d = expiry days |

Password check details:
- The field is split at NULs: up to **3** strings are tried in order (`new`, `old1`, `old2`).
  The compare is **case-insensitive** and **needs the NUL**: a field without a terminating NUL
  does not match reliably.
- Match on the 2nd or 3rd string = password change: the **first** string is stored as the new
  password, its set date = now, and the failure count = 0. Match on the first: no change.
- No stored password and none required: accepted, and the sent password is stored.
- Policy (only for user entries, not for post office entries): the minimum length is checked
  **after** a successful match; then pre-expiry/expiry; success resets the failure count.
- **Lock-out counting**: a failure increments the count, and when limit ≤ count the mailbox is
  locked; success or limit 0 → count = 0. A wrong password **is answered `8C 98 00` even on the
  attempt that locks**; `8C 97 n` comes from the next call on. A wrong password while the
  password is pre-expired answers `8C 9A`.
- No "no password stored" failure was found in one peer version.

There is **no version gating**: the 3-byte 8C is sent to every client after a password failure.
Clients that read the two extra bytes only when they are already buffered (spec/session-layer.md
3.4) simply ignore them otherwise. The other 8C refusals (refuse non-negotiated, refuse unknown)
are bare.

### 1.6 Post office name reply 82 / 83

- Known entry and password OK → **82**; unknown name → **83** (read-only), **without asking for a
  password**. With refuse unknown callers instead: **bare 8C**.
- Then the post office name: length byte = stored length, text = stored bytes, `A\0B\0` sent as
  `"B A"`. In a capture: `07 "MYPOST\0"`.
- Read one byte (byte timeout, no 91h skip): **82** → accepted (read-write or read-only), login
  done; **83** → the caller rejects the post office name, the call ends with nothing more sent;
  other → the call ends.
- So what decides read-only is only that the name is not in the directory. A read-only caller's
  mail is still received (section 2); nothing is sent to it.

### 1.7 Turn order

Caller first: after login the answering post office receives the caller's messages (until its
88/8D), then sends its own messages, then sends 88 and drains the link. Details and 91h fillers:
section 2.

## 2. Message exchange

Main loop: the receive turn ending with 8D (or aborted) → no send and **no 88**; otherwise, if
the caller is known, the send turn, then 88 and drain. The codes are 82/83, 8A, 8F, 86, 87, 90
whatever database the post office uses.

### 2.1 Caller's turn

- Next code: wait up to the byte timeout (30 s), **skipping 91h**, restarted whenever the send
  side progresses. Expiry → the data connection is lost.
- **88** → caller done, the answering post office's turn. **8D** → the answering post office
  sends nothing, no 88, hangs up.
- 84 → message. A0 pass-thru, A4 "Sending", A2 mailbox sync (answered A3 when not supported;
  A7 for a caller whose directory entry type is 'R'), A5 directory download (84 + 4-byte size,
  wait 30 s for 86, the post office directory file in 512-byte pieces, wait 30 s for 87; no file
  → 88). **Any other byte → ends the turn like 88** and the answering post office starts
  sending.
- Post office shut down → A4 (or A0 for pass-thru), end.

### 2.2 One message (84)

1. Send **85**. Read word length + header. No upper bound on the length is checked; a sender
   must keep headers within 8 KB.
2. Header check: the TLV walk from 20h must end exactly at the length, else the call is aborted
   (no send, no 88).
3. Classification: tag 0E → receipt wanted; tag 16 byte 0 = priority; tag 1C word &2 → directory,
   &4 → bulletin, else mail.
4. Filters, in this order. A refusal = **82 for every 03 entry**, then the refusal code:

| order | condition | code |
|---|---|---|
| 1 | message-count limit reached | 9D |
| 2 | exchange restriction (default all): bulletin needs B, directory D, mail M | 9E |
| 3 | priority filter (mail only): "no Low" rejects Low, "Urgent only" needs Urgent | 9C |
| 4 | size limit KB·1000 < dword[0] (mail only, 0 = no limit) | 8E |
| 5 | author ≠ caller (known user caller, no tag 32; author = last 02 else 01; author "Administrator" always mismatches) | 96 |

5. Tag 32 (mailbox-sync copy): all 82, stored for the caller.
6. Otherwise one verdict per 03 entry, each sent as soon as decided. None accepted → 9E if the
   post office's configuration bars the message type, else **89**.
7. Body: the message cannot be created → **8A**; item check fails → **8F**; header write fails →
   8F; else **86**, then read exactly dword[4] − word[8] bytes; a disk error still swallows the
   rest, then 8F. Then **87** if delivered to anyone, **90** if nothing was delivered or the
   database commit failed (the post office then stops). **2B is never sent.**
8. 91h fillers (only when the send side is idle) are sent during directory, extended-field and
   mailing-list work in delivery, i.e. while the caller waits for 87. Never during plain
   transfer.
9. After each message a configured end time or an operator abort can end the turn.

### 2.3 Verdict per recipient

**83**: empty name; ≥ 1000 recipients; name starting '#' from an unknown caller; the name is this
post office's own entry; route tags would grow the header past 4096; mailbox not writable; unknown
name; 0F path to no known post office.
**82**:
- local user;
- **0F path**: the last 0F naming a known post office routes there; a 0F naming this post office
  ends the scan; routing appends 0F entries and grows dword[0];
- alias: not found → the tag-14 original name is looked up;
- duplicate names: the entry whose path matches;
- '#' names from known callers: mailing lists, expanded, tag set to 0A/0D/1A;
  "##Directory Updates" is special;
- **"Administrator"** → the administrator mailbox; directory and extended-field requests to it
  from a known caller are recognised by item type 5 or by the tag-07 file name CCMUPDAT /
  CCMSYNCH(.REQ) / CCMINFO.REQ — so tag 07 is an item's file name;
- a client's own directory update request (tag 18, and "##Directory Updates" exists) is
  accepted as a directory request. Not determined: where it is answered (the delivery loop skips
  it).
- The circular-routing check applies to post-office callers only. Tag 31 (word) sets the code
  page used for lookups.

Delivery: to recipients of types 3/0B/11/0F; tag 1B picks the folder for local users. The
stored message keeps: receipt wanted (To + tag 0E), Low, Urgent, directory, bulletin.

### 2.4 The answering post office's turn

- Order: three passes, each needing its exchange permission (default all):
  1. directory items (exchange D);
  2. mail in priority order Urgent (tag-16 value 2), Normal (0), Low (1), stopping at the
     priority filter;
  3. bulletins (exchange B).
  So the order is directory, urgent, normal, low, bulletins; within a pass the mailbox order.
  Implemented in `session.send_order` (no priority filter). Messages already marked sent are
  skipped; the message-count limit stops the turn; sync mode (MOBP) sends the outbox first.
- Per message: skip if dword[0] > the size limit; header = stored record; append **tag 22**
  (8-byte message id) if absent, dword[0] += 10; sync mode: tag 32; **append an 03 copy of every
  0B and 11 entry** (for a post office caller, entries routed via this post office become
  0C/12/04); **if the caller is a user and no 03 entry carries its name, append 03 = caller**.
  Tags 1D/20/21/31, dword 0E, time byte 19 and word 0C are not written here. Not determined: who
  writes them.
- Wire: **84**; one byte (byte timeout, **no 91h skip**): 85 → go on, A0/A4 → stop, other → keep
  the message, next one. Then word + header; one verdict per 03 entry, each waited for up to the
  message wait (default 14Ah = 330 s); **a verdict ≠ 82 turns that entry into tag 10**. Reply
  (message wait, 91h skipped): 86 → body (database error → session ends); 89 → non-delivery
  report; 8A keep; 8E keep, for a post office caller the limit is raised; 9C/9D/9E → stop that
  category; 8F keep; A1 delete; other keep. After the body: **87** → done, and if any verdict
  was 83 the sender is notified of the unknown recipients; 8F/90 keep; **2B → link lost**.
- After 87: receipt wanted → **the answering post office builds the return receipt itself**;
  caller entry type R → message deleted; sync mode → marked; else marked sent. A message that
  cannot be read is skipped on the 1st failure and deleted on the 2nd.
- Then 88. The answering post office never sends 8D.

## 3. Version and capability differences

- Nothing depends on a client version: the caller sends no version (opener constant, name,
  password). The only capability exchange is the B0/AE negotiation (1.2.1), used by peer post
  offices 6.x ("NMTP") and a "MOBP" client; with it the session bytes are enciphered.
- Refuse non-negotiated callers refuses every non-negotiating caller, i.e. every supported
  client and every peer post office older than the negotiation (bare 8C, 1.4).
- Old clients that do not read the 8C reason bytes are unaffected (1.5).
- Link mode is taken from the caller's first frame; raw 80h at > 2400 bps needs 5.12 s of silence
  (1.2). LSEC fallback: section 4.
- Timeouts: sniff phase and every login byte = the byte timeout (30 s default, 1..300; 60 on some
  modem types); opener 30 s + grace period; next code in the caller's turn = the byte timeout;
  verdicts/86/87 on download = the message wait (default 330 s); link timers 6.2 s at every
  speed (section 4).
- Caller type: unknown (read-only) caller → mail received with the author check skipped, '#'
  names 83, nothing sent. Known post office (a peer post office) → author check skipped,
  circular-routing check, on download 0F-to-this-PO entries become 0C/12/04 and 8E raises its
  size limit. "MOBP" ≥ 200 → mailbox-sync mode (outbox first, tag 32). Section 2.
- Codes the answering post office may send that the supported clients do not know: 9C/9D/9E/96
  refusals (2.2), A0/A4 shut-down, A3/A7 to A2, A6 pass-thru failure. The supported clients know
  only 89/8A/8E/8F after the verdicts. Not determined: their reaction to the others.

## 4. Link layer

The packet system runs only when a link mode is set (not in raw mode).

| point | answering post office | vs the client / link.py |
|---|---|---|
| frame, CRC | same as the client; a data pass restarts | same |
| header / max L | LSEC 6 / 121, HSEC 7 / 1016. Limits per mode (raw, LSEC, HSEC, ASCII LSEC, ASCII HSEC) = 0, 79h, 3F8h, 4Eh, 2A2h, used as the send **and receive** limit | the client rejects only > 79h/3F8h; in ASCII the answering post office NAKs L > 4Eh/2A2h (one peer version) |
| answer mode | caller's mode; no LSEC probe on the answer side (the probe and fallback are only for calls) | same as ours |
| RTS/CTS | used for HSEC above 2400 bps on a serial line, unless flow control is turned off | n/a over TCP |
| timers | every timer reloads with 1838h = **6200 ms at every speed** (70h ticks = 6.15 s in one peer version), set after connect. 5 timers: 0–3 retransmit, 4 frame assembly; **no ack-delay timer** | the client: 0.77 s at 2400, 1.54 s at 1200; link.py follows the client when the speed is known (70h when unknown = our TCP case) |
| timer quirk | in one peer version time spent in some wait loops is not counted, so real retransmit/assembly delays are ≥ 6.2 s. Not determined: by how much (a timing test with one frame dropped would show it) | |
| expiry | lowest expired timer per pass; timer 4 → NAK; 0–3 → retransmit list if still outstanding | same as the client |
| windows | tx 4; the sequence number advances only on new frames; rx 4: slot full → drop; out of order → NAK; outside window → drop, no ack, no NAK | same |
| re-ack of duplicates | **never**: an ack is pending only on in-order delivery | link.py re-acks (harmless) |
| acks | cumulative, inclusive; ack = 40h\|N(R), p0 00 | same |
| NAK | test **p0 == 04 exactly** (the client tests p0 & 1Fh); NAK = 80h\|N(R) p0 04, unsequenced; resends only N(R)+1; bad frame → one NAK + rescan, no further NAK during that rescan | link.py may NAK again during a rescan |
| send order | pending control (NAK), retransmit list, new data, pure ack | same |
| control codes | sends only 04, 0Fh, 10h; acts only on 04/0Fh/10h (0Fh/10h are used only by the calling side); others acked and ignored. Sequenced control frames take a window slot and a timer. Type 3 = retransmit; a received type 3 is data | same |
| delivery | holds data while the receiver lacks room for L bytes; clears the pending control flag — the same lost-0Fh edge case as the client | ours has a separate queue |
| retry limit | none; the session declares the link dead when nothing is received and the send side does not drain for the byte timeout | link.py: no limit; session uses fixed 90/330 s |
| ASCII | same encoder as the client, state across frames, reset only on link reset; mark/even/odd parity; decoder: 11h clears XOFF, 13h sets it with a 6.2 s hold, sending stops while XOFF | link.py ignores XON/XOFF |
| raw | bytes pass straight through | same |

## 5. Differences between the answering peer post office and the server (this implementation)

Ordered by how likely a real client hits it.

| # | situation | answering peer post office | the server | change |
|---|---|---|---|---|
| 1 | download of mail that only cc's/bcc's the user | appends an 03 copy of each 0B/11, and 03 = caller if missing (one peer version) | sends the stored record unchanged; the client answers 83 → 89 | add the 03 entries before sending; count verdicts on the edited record (session.py send_messages, message.py) |
| 2 | mail to a user at another post office (0F path) | 82, routed (one peer version) | 83 unless the gateway takes it | accept and queue for forwarding (or keep 83 deliberately, documented) |
| 3 | a client's directory update request (To "Administrator" + 0F home PO, tag 18) | 82, administrator mailbox / directory request (one peer version) | 83 → 89 ("Unknown recipients") | treat "Administrator" as a local mailbox; store the request |
| 4 | name not in the directory | **83** (read-only), no 8B; mail received, nothing sent | 8C | answer 83 + PO name; receive with no author check; send nothing; 8C only with a refuse-unknown option |
| 5 | wrong password | `8C 98 00` even on the attempt that locks; later calls `8C 97 limit` with the **configured limit** | `8C 97 count` on the locking attempt, count as value | send 98 on every wrong password; 97 only when already locked, value = lock_after |
| 6 | caller ends with 8D | no 88, hang up | sends 88 | skip the 88 when receive_messages returns False |
| 7 | opener not first / late | scans for FF AA 55 11 anywhere for 30 s (+ grace period), then control **10h** (one peer version) | requires it as the first 4 bytes; no 10h | scan delivered data; on 30 s timeout send_control(0x10), drain, hang up |
| 8 | unexpected byte in the caller's turn | ends the turn like 88 | Refused | treat as 88 |
| 9 | stray bytes before 80 (packet mode) | ignored; bytes after 80 discarded before 81 | Refused | skip non-80 bytes until 80 (keep 91 skip) |
| 10 | a peer post office 6.x calls | sends `B0 80`, accepts a plain 81; name = its PO name (needs the 82/83 path of #4) | Refused ("expected 80, got b0") | skip B0 before 80 and answer 81 (never AE: we do not negotiate) |
| 11 | store failure | 8A before 86 / 8F before 86 / swallow body then 8F / 90 if nothing delivered | always 86, 87 | map failures to these codes |
| 12 | timeouts | next code / name / password byte timeout 30 s restarted on progress; verdicts/86/87 message wait 330 s; link dead after 30 s without progress | 90 s / 330 s fixed per read | 30 s idle timer restarted on any rx/tx progress |
| 13 | verdict 83 or reply 89 on download | entry → tag 10, non-delivery report to the sender, then the message counts as sent; layout in router-to-router.md §3.5 (one peer version) | **done**: same report and layout; checked with a supported client (83/89, then the report shown with its "Returned" heading) | — |
| 14 | malformed header | TLV walk must end at the length, else abort | not checked | validate, hang up |
| 15 | return receipt on download | the post office builds the receipt after 87 for To + tag 0E (one peer version) | none | build a receipt (spec/session-layer.md 6.2 layout) |
| 16 | password policy | 99 too short (value min+1), 9A pre-expired, 9B expired (value days), 8C 00 00 database errors | none | optional |
| 17 | password field compare | up to 3 NUL-separated strings, case-insensitive, a change stores the 1st | any number of strings, case-insensitive | limit to 3 (cosmetic) |
| 18 | link timers when the CONNECT speed is known | 6.2 s at every speed (6.15 s in one peer version) | the client's 0.77 s at 2400 | use 70h ticks always (our TCP case already does) |
| 19 | NAKs during a rescan | one NAK per damaged frame (one peer version) | may NAK again for stray STX | suppress NAKs while rescanning |
| 20 | XON/XOFF in ASCII mode | honoured, 6.2 s hold | ignored | pause tx on 13h (real modems only) |
| 21 | filters/limits | size 8E (after all-82), message count 9D, priority 9C, exchange 9E, author 96, 1000 recipients, 4096-byte header | none | optional; note that the supported clients' reaction to 9C/9D/9E/96 is not determined |
| 22 | download order / size | directory, urgent, normal/low, bulletins; skips > size limit | store order | optional |
| 23 | tag 22 on download | appended | absent | optional (the supported clients do not read it) |
| 24 | re-ack of duplicates | never | re-acks | keep (harmless, helps a lost ack) |
| 25 | raw 80 at > 2400 bps | needs 5.12 s silence first | answers at once | none needed |

## 6. Open points

1. Not determined: the supported clients' reaction to 9C/9D/9E/96 (and to A0/A4/A6 after the
   name).
2. (Withdrawn: concerned client configuration, not the protocol.)
3. Not determined: the real retransmit/assembly delay of the peer version with uncounted wait
   time. A timing test would settle it.
4. Not determined: whether every peer version caps the receive length L in ASCII mode.
5. Not determined: where a client's tag-18 directory request is answered, and what the 20 data
   bytes of the request item are.
6. Not determined: who writes tags 1D/20/21/31, header dword 0E, time byte 19 and word 0C on
   headers built by the answering post office.
7. Not determined: tag 32 content beyond "28 bytes of a post-office database field".
8. Not determined: the default priority filter.
9. Not determined: which clients send "MOBP".
10. That the password policy is skipped for post office entries rests on an inference: the entry
    flag taken to mark a post office is not confirmed.
