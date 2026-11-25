# HP 200LX client: protocol notes

What a compatible post office needs to know about the HP 200LX palmtop's built-in cc:Mail
client on the wire.

**Summary: the client speaks the cc:Mail Remote protocol.** It uses the same frame, the same
CRC-16/GENIBUS with residue 1D0F, the same ctl byte, window 4, the opener `FF AA 55 11` with a
0Fh reply, and the plain `80`/`81` session with the same login, message-transfer codes and turn
order. The differences that matter for a server:

1. **NAK with p0 = 00.** The client sends its NAK as `80h|N(R)` with **p0 = 00**, not 04
   (row 4). A server must take it as a NAK (§2.1); link.py does.
2. **Password change.** With a changed password the client sends `current\0new\0new\0`
   (row 16). A server must store the new password (§2.2); store.py does.
3. **Interactive mode** (`AD`/`AE` plus `AF 01` packets, row 30, §5) is served by
   ccmail/vimserver.py (model and choices §5.12; tested with a real HP 200LX). The client's
   default mode does not use it; the user selects it. After the login the records are remote
   VIM calls (§5.6–5.11).

Where a server may send 91h keep-alives: §4.

Everything else either matches or only changes timing (§2.4–2.9).

## 1. Item table

S = SAME, D = DIFFERENT, NP = NOT PRESENT, NC = NOT CHECKED.

### 1.1 Link layer (link-layer.md)

| # | Item | HP | Client behaviour | Notes |
|---|---|---|---|---|
| 1 | Frame `02 L(1 or 2, LE) ctl p0 H1 H0 [d… D1 D0]`. L counts p0. Data only if L>1. Control frames L=1 | **S** | data/sequenced frames: STX, L (high byte in HSEC), ctl, p0, data; ack/NAK frames L=1 (HSEC high byte 0) | the client reads the data part **only for type 0** with L>1 |
| 2 | CRC-16/GENIBUS, two passes | **S** | CCITT 1021h, MSB first, init FFFF. Output inverted, high byte first. Pass 1 over L..p0, pass 2 over d1..d(L−1) | |
| 3 | Receive residue 1D0F, restart FFFF for data | **S** | header check over 6 bytes (HSEC) or 5 (LSEC); data check over L+1 bytes | |
| 4 | ctl = type N(S) N(R). Ack 40h\|N(R) p0=00. NAK 80h\|N(R) p0=04. Sequenced control 80h\|seq<<3\|N(R). 0Fh accept, 10h refuse | **D** | N(R) = (rx expected+7)%8. Ack: type 1, p0 = 0. **NAK: `80h\|N(R)` with p0 = 00.** Receive: a frame is a NAK only if type 2 and **p0 == 04** (no `&1Fh`); any other type-2 frame is a sequenced frame | **D1** matters: see §2.1. **D2:** the N(R) of a received type-2 sequenced frame is not processed; the client takes it as the ack of its opener |
| 5 | Window 4, mod 8, cumulative inclusive acks, rx window [exp, exp+4), duplicates and out-of-window frames dropped | **S** | 4 tx slots, slot = seq&3; waits up to 23Ah ticks (31 s) for a free slot, then the link fails. Out-of-window frames dropped without ack. Duplicates dropped | |
| 6 | NAK on CRC/length error, on an out-of-order frame, on rx-timer expiry; no re-ack of duplicates | **D** | NAK **only on a CRC error** of a frame inside the window. **No NAK for out-of-order frames** (stored silently). No rx-assembly timer: bytes are read with a 23Ah-tick (31 s) timeout. **Duplicates are re-acked**: every received frame starts an ack-delay timer, and on expiry an ack is sent | no effect on our server: we resend on our own timer and accept re-acks. No max-L check before the data read (L+1 bytes are read whatever L) |
| 7 | Retransmit timers; Remote's speed table | **D** | retransmit ticks by speed: 300 → 400 (22 s), 1200 → 100 (5.5 s), 2400 → 50 (2.7 s), 4800 → 90 (4.9 s), 9600 → 45 (2.5 s), 19200 → 30 (1.6 s), other → 100. Ack delay = 3 ticks (≤2400) or 2 ticks (≥4800). Due frames are resent in **slot order 0–3**, not sequence order. **Retry limit**: more than 5 retries of a frame fails the link | the client needs an ack within 1.6–5.5 s at ≥1200 bps, or it retransmits. Our server acks at once |
| 8 | Receiver max L 79h/3F8h | **S** | receives frames up to 400h bytes (7+3F7h+2). Sends at most L = 79h (LSEC) / 3F8h (HSEC) | there is no ASCII mode, so no 4Eh/2A2h limit; our binary 3F8h frames fit |
| 9 | ASCII coding | **NP** | every byte goes out unchanged; no 20h/30h coding | our server falls back to binary detection |
| 10 | LSEC/HSEC choice | **D** | **LSEC if speed ≤ 2400, else HSEC**. Speed = the configured speed, replaced by the CONNECT speed in modem mode (§3) | answerer-side detection is unchanged |
| 11 | HSEC→LSEC fallback | **NP** | no probe, no second opener | |
| 12 | Raw mode (80/81 without packets) | **NP** | every session runs in LSEC or HSEC | |
| 13 | Opener `FF AA 55 11` as one data frame, wait, 0Fh/10h | **S** (details **D**) | one data frame (seq 0, N(R) 7 → ctl 07, L=4). Answer p0 == 0Fh → accept, **any other p0 → refused**. No 30 s timer: the wait ends when the opener passes the retry limit | Remote treats only 10h as a refusal; here every non-0Fh code is one. Our 0Fh works |

### 1.2 Session layer (session-layer.md)

| # | Item | HP | Client behaviour | Notes |
|---|---|---|---|---|
| 14 | 80 → 81 | **S** | plain `80`, **no B0**. Waits 23Ah ticks (31 s) for `81`; other bytes are ignored. No 81 → hang up | |
| 15 | Name: length byte N (counts the NUL), N bytes | **S** | N = strlen(name)+1, sent as a separate 1-byte write, then the bytes | no "B A" rewriting on the wire; see §2.4 for the name form |
| 16 | Password: length incl. NUL; Remote's change format "new\0old1\0old2\0" | **S** normal / **D** on change | on 8B: N = strlen+1, then the bytes. **With a password change pending:** N covers three strings, `current\0new\0new\0`. Not 8C → the client drops the pending change. 8C → the client stores the new password and drops the pending change | see §2.2. **Remote puts the new password first; the HP puts the current one first** |
| 17 | 8B; 8C + optional reason 97..9B + value | **S** (detail **D**) | 8C: hang up ("Connection Refused"). **No reason bytes are read**; anything after 8C is ignored | our `8C 98 00` / `8C 97 n` are harmless |
| 18 | 82/83 + PO name; client answers 82/83 | **S** | `83` makes the connection send-only. PO name: length ≤ 80h and bytes, compared **case-insensitively** with the configured post office name. Mismatch → `83` + hang up. Match → `82` | the configured name must equal our post office name except for letter case |
| 19 | 84 / 85 / HL word + record | **S** (reader **D**) | client sends: `84`, then reads **one byte without skipping 91** (31 s); ≠ 85 → error. Then HL, the 20h fixed part and two regions. Client receives: waits for 84 (88/8D → done), `85`, HL. It **reads 20h, then word[8]−20h, then dword[0]−dword[4], then HL minus those** | the client's record buffer is 12DAh bytes. Our records must keep HL = word[8] + addressing length (they do) |
| 20 | One verdict 82/83 per tag-03 entry; cc/bcc marking | **S** | client receiving: **`82` for every tag-03 entry**, no name check. Client sending: reads one verdict per To+cc+bcc entry (timeout 5Ah), counts 83s | |
| 21 | 86 / 89 / 8A / 8E / 8F (timeout B4h) | **S** | client sending: 86 → body; 89, 8A, 8E, 8F → message refused; other → refused. Client receiving: 8E if over its maximum message size; **8F** if its disk is short (dword[0] ≥ free + 800h) or the file cannot be written; else `86` | the client never sends 89 or 8A |
| 22 | body, then 87 / 8F / 90 / 2B (timeout 14Ah) | **S** (detail **D**) | client sending: body, then waits (timeout **B4h**): 87 = sent; 8F, 90 → refused; **2B and any other → link error**. Client receiving: reads dword[4]−word[8] bytes in pieces of 100 (≤2400 bps) or 300 bytes, then `87`; if its message buffer is too small → **8F** | we answer 87/8F only |
| 23 | 88 / 8D | **S** | client sends `88` when it has no more messages. It never sends 8D. Client receiving: 88 or 8D ends | |
| 24 | 91 filler | **S** (one reader **D**) | the waits for a session code skip 91 and restart their timer | the 85 after 84 is read without the skip (row 19); see §4 |
| 25 | Header record, fixed 32 bytes | NC | fixed-part values the client sends were not checked | the client reads word[8], dword[0], dword[4], word[1C] (descriptor count) |
| 26 | TLV tags | **S** (partly) | received: 01/02 author (the last 02, else 01), 05 subject, 10 unknown recipient, 03/04/0A To, 0B/0C/0D cc, 11/12 bcc only if equal to the own user name, 06 descriptors. Sent: 03 + 0F entries, 07 empty | |
| 27 | Turn order: caller sends, 88, receives; answerer receives first | **S** | the client sends its messages, then `88`, then receives until 88/8D, then hangs up (no session byte). After a login answered `83` it does not receive | send-only callers send their mail and hang up after their 88 |

### 1.3 Items (items.md)

| # | Item | HP | Client behaviour | Notes |
|---|---|---|---|---|
| 28 | Text items: +A=1 attribute layer, +A=0 text with +8 = CR LF count; text ends in CR LF | **S** | client sending: item type 1, **+8 = 17h, +A = 1** (attribute runs: per line a count and an attribute, default 17h), then item type 1, **+A = 0, +8 = line count**. LF → CR LF, a final CR LF added if missing; then tag 07 (empty). Attachments are type 3 (+8/+A 0). Client receiving: the **first** type-1 item with +A = 0 is the body; later +A = 0 items are kept as extra text files; +A ≠ 0 items are skipped; type 3 → attached files | a missing final CR LF does not fail. Exact attribute-run bytes on send: NC |
| 29 | 17-column transposition in 512-byte chunks from the start of each item/region | **S** | table `09 04 05 0D 0C 0B 01 07 0A 03 02 10 08 0F 00 0E 06`, 200h blocks counted from the item start, remainder last | consistent with items.md §3/§4 |

### 1.4 Things the client has that our spec does not

| # | Item | HP | Client behaviour | Notes |
|---|---|---|---|---|
| 30 | Interactive mode | new | §5. `AD` → `AE`, `AF 01` packets (hello "SVIM"/100, idle timeout, max message size, end 8 → 9), the old login, then `00`/`01` records instead of 84…88 | without `AE` the client reports "The version of Router you are connecting to does NOT support interactive mode!". Served by ccmail/vimserver.py (§5.12) |
| 31 | Ack-delay timer and retry limit | new | rows 6–7 | |

## 2. Differences that matter for our server

### 2.1 NAK with p0 = 00 (row 4)

The client's NAK is `02 01 [00] 80|N(R) 00 crc crc`. A receiver that accepts only p0 = 04 as
a NAK takes this frame as a sequenced control frame with N(S) = 0:
- If rx_expected is 0, the frame is "delivered" as control code 00 and rx_expected moves to 1.
  The client's next data frame (seq 0) then looks like a duplicate and is never delivered. The
  call hangs until the client's retry limit.
- With other rx_expected values, the frame is either stored as a future frame, which corrupts
  the delivery later, or re-acked and ignored, which loses the retransmit request.

The client sends a NAK only after a CRC error on one of our data frames. That never happens over
a TCP bridge, and only rarely over an error-correcting modem, but it is fatal when it does.

**This server** treats a type-2 frame with `p0 & 0x1F` in (04h, **00h**) as a NAK (link.py).
- No sender we know uses type-2 code 00 for anything else: code 0 is the ack, type 1.
- It keeps sending 04 itself; the client checks `p0 == 04` exactly.

### 2.2 Password change (row 16)

The client sends `current\0new\0new\0`. A server that accepts the login on parts[0] (= current)
without storing anything leaves the two sides out of step:
- The client then drops its pending change and keeps the old password. The user believes the
  password was changed; the server still has the old one. The next call works with the old
  password and fails with the new one.
- **This server** (store.py `check_password`): when the field has three parts, parts[0] equals
  the stored password and parts[1] == parts[2] ≠ parts[0], it sets the password to parts[1].
  - The other clients' form is `new\0old1\0old2\0`, with the new password first and already
    stored on the client. Its parts[0] equals our stored password only if the change was already
    applied, and then old1 == old2 is very unlikely.
  - So the rule does not collide in practice.
- Not determined: what a real Router answers to this form. Note that the client stores the new
  password when the reply is 8C (row 16).

### 2.3 Interactive mode (row 30)

session.py hands an `AD` before `80` to ccmail/vimserver.py, which does §5.5 steps 1–6 (§5.12).
Without an `AE` the client reports "does NOT support interactive mode". This is an error
message, not a hang.
- The default mode is the normal batch session and works.
- Interactive mode needs §5.5 steps 1–5, the link-level part.
- The data records that follow are remote VIM calls (§5.6): the wire encoding and all 40
  procedure signatures are given there; the calls the client makes, in what order and with which
  arguments, in §5.7–5.10.
- Do not answer `AE` without steps 2–5: the client would then fail in phase A.

### 2.4 Post office name and user name

- The client compares our post office name with its configured one, ignoring letter case. A user
  must enter exactly our `po.name`.
- **The user name does not always arrive as typed.** In both modes the client turns a name with
  a comma around: `"Doe, John"` → `"John Doe"`. The text before the first comma moves to the end
  after one blank; blanks after the comma are dropped. That name is sent in the login (row 15)
  and in VIMOpenSession. So a user stored as `"Doe, John"` arrives as `"John Doe"`. Our lookup
  must also accept that form (match `"First Last"` against stored `"Last, First"`), or the user
  must store a name without a comma. Our lookup already ignores case.

### 2.5 Send-only

An unknown name answered with `83` gives the client a "send-only" connection. It sends its mail
and `88`, then skips receiving and hangs up. Our server sends `88` and calls `link.drain(30)`,
which may run into the client's hang-up. Make sure a LinkTimeout or LinkClosed there is not
logged as a failure.

### 2.6 Refusals from the client as receiver

- The client answers `8F` when a message does not fit its buffer or disk, and `8E` over its
  maximum message size.
- send_one() leaves such a message pending, so it is offered and refused on every call. That
  is the same issue as newer-client-check.md §2.5. Consider a per-message refusal count.

### 2.7 Timers

- Our 6.2 s retransmit is fine for the client's acks, which come within 2–3 ticks.
- The client retransmits after 1.6–5.5 s (row 7) and gives up after 5 retries. We ack at once,
  which is what it needs.
- Above 2400 bps the client uses HSEC with 1 KB frames and a short timer (1.6 s at 19200). On a
  slow or buffered path, for example a TCP-serial bridge with large buffers, the client will
  retransmit. That is harmless, because we drop duplicates and re-ack them.

### 2.8 Mode and speed

- LSEC at ≤ 2400, HSEC above, binary only. Our sniffer handles both.
- If a modem or modem emulator answers a bare `CONNECT`, the client assumes 300 bps: LSEC with a
  22 s retransmit timer. It still works, only slowly after errors. Configure bridges to report
  `CONNECT <speed>`.

### 2.9 No changes needed

No change is needed for:
- 80/81 (no B0);
- 8C reasons (ignored);
- verdicts (all 82);
- the record layout and HL;
- items and transposition;
- the 0Fh accept;
- the window-4 flow;
- 91 (we never send it).

## 3. Modem command sequence

The command strings come from the client's modem file (`HAYES.MDM` by default); the values below
are that file's. With a null-modem setting no commands are sent and the configured speed is used.

- **Reset:**
  1. `+++` with guard times;
  2. each attention line in turn (`ATZ`, `ATE0V1`);
  3. `ATH0`.
- **Dial**, after the reset:
  1. each setup line (`ATS0=0Q0X4`, `ATS7=60S10=50`);
  2. the RTS/CTS on/off string, by the flow setting;
  3. the volume string;
  4. manual dial: `ATX3S9=6D` and a prompt to make the call by hand. Automatic: `ATS9=6`, then
     `ATDT` or `ATDP` + phone number + the dial suffix.
- Each command ends in CR. After a command starting with `ATZ` the client does not read a reply;
  it waits and assumes `OK`.
- **Result lines**: verbose text framed `CR LF text CR LF`, so V1 is required. Recognised:
  `CONNECT`, `NO CARRIER`, `BUSY`, `NO DIALTONE`/`NO DIAL TONE`, `NO ANSWER`, `ERROR`. The wait
  is the configured dial timeout.
- **CONNECT speed**:
  - a line of fewer than 9 characters (bare `CONNECT`) → **300**;
  - otherwise the decimal digits from position 8 up to the first non-digit (`CONNECT 2400/ARQ`
    → 2400, `CONNECT 14400` → 14400);
  - a result of 0 fails the call.
  - The value chooses LSEC/HSEC and the timers (row 7; a speed not in the table gets the
    100-tick set).
- Configurable speeds: 300, 1200, 2400, 4800, 9600, 19200.
- **At the end**: the client waits for its transmitter to empty, then runs the reset/hang-up
  sequence.

## 4. Where the client skips 91h

| client waits for | skips 91h? | timeout | 91h from us there is |
|---|---|---|---|
| our 84/88/8D (client receiving); each verdict; 86/89/8A/8E/8F; 87/8F/90 (client sending) | **yes**, and restarts its timer | about 188 s (94 s for verdicts) | **safe** |
| 81 after 80 | not skipped, but every byte ≠ 81 is ignored | 31 s, not restarted | harmless, but it does not extend the 31 s |
| AE after AD | every byte ≠ AE is ignored | 5.2 s per try | harmless, no extension |
| the reply after the name or password, the 85 after its 84 | **no** | 31 s | **not safe**: it is taken as the code |
| the PO name | no | 31 s | not safe |
| records, bodies, negotiation packets, interactive records | no | 31 s per read | not safe |

So a server may send 91h keep-alives only:
- **in its own turn as sender**, before each `84` or the final `88` (the client waits about
  188 s);
- **as receiver of a client message**: before the verdicts, before `86`, and before `87` (for
  example while storing a large body; the client waits about 94 s, 188 s and 188 s).

Nowhere else, and never in interactive mode outside these points.

## 5. Interactive mode

Everything in this section happens **inside the packet link**: after the modem connect and the
`FF AA 55 11` / 0Fh opener (the same as in normal mode). All bytes below are link data.
Integers are little-endian. **No cipher and no checksum is involved**, apart from the link CRC.
The byte sequences in §5.4 can serve as test vectors.

### 5.1 Probe: `AD` → `AE`

| step | client | server |
|---|---|---|
| 1 | sends `AD` | |
| 2 | waits **5Fh ticks (5.2 s)** for a byte `AE`; every other byte is read and ignored | sends `AE` |
| 3 | no `AE` in time → repeat from step 1, **3 tries in all** (about 15.7 s) | |
| 4 | 3 failures → hang up with "does NOT support interactive mode" | |

Our server answers `AE` once and skips further `AD` bytes, so a retry that crosses our `AE`
does not get a second one (a second `AE` would land in the client's phase-A reply read).

### 5.2 Negotiation packets

The packet layout is the same as in negotiation.md §2.3:

```
off 0  AF            magic       (the client never checks it on receive)
off 1  n             the client sends 01. On receive: the number of entries in this
                     packet; the phase-A replies must have n = 1
per entry:
off 0  type   u16    request type; reply = type | 8000h
off 2  status u16    0 accept, 1 counter-offer (data = the other side's value), other = refuse
off 4  len    u16    data length
off 6  data[len]
```

The client sends a packet as three link writes: `AF n`, the 6-byte header, the data.

**Phase A: the client's requests.** Each request is one packet; the client reads the reply
before the next request.

| # | client sends | expected reply | client's handling of the reply |
|---|---|---|---|
| A1 | type **1** hello, status 0, len 6: `"SVIM"` + u16 **100** | type 8001h | n ≠ 1 → fail; type ≠ 8001h → fail; status 0 → ok; status 1 → reads 6 data bytes, the u16 at +4 must be 100; status 2 → fail; other → skips `len` bytes, then fails. A failure → hang up |
| A2 | type **2** idle timeout, status 0, len 2: u16 = idle timeout in **seconds** (configured minutes × 60) | type 8002h | status 0 → keep; status 1 → read u16 and adopt it; other → skip `len`, fail |
| A3 | type **3** max message size, status 0, len 4: u32 (0 = no limit) | type 8003h | status 0 → keep; status 1 → read u32 and adopt it; other → skip, fail |
| A4 | type **8** end, status 0, len 0 | (none read here) | the client goes straight on to phase B |

Every reply is read as 2 bytes, then 6, then the data, with a 23Ah-tick (31 s) timeout per read.
A failed phase-A step ends the call.

**Phase B: the server's requests.** The client reads packets (`AF n`, then n entries) and
answers each entry with its own one-entry packet, until an entry of type 8 or 9 has been seen;
it then finishes the current packet.
- A server with nothing to ask sends just `AF 01 09 00 00 00 00 00`. That is what a post office
  peer answers to a type 8 (negotiation.md §2.4).

| server entry | client reads | client replies (type, status, len, data) |
|---|---|---|
| 1 | 6 data bytes, **whatever len says** | 8001h, **status 8**, len 0 |
| 2 (u16) | 2 data bytes, whatever len says | value ≤ own idle timeout: 8002h, 0, 0, and **adopts the value**. Value > own: 8002h, 1, 2, own value (keeps its own). So the smaller value wins |
| 3 (u32) | 4 data bytes, whatever len says | same rule with the max message size: 8003h, 0, 0 + adopt; or 8003h, 1, 4, own value |
| 4 | skips `len` bytes | 8004h, 0, **len field 4**, followed by **22 bytes** `"cc:Mail Mobile Driver\0"` |
| 5 | skips `len` bytes | 8005h, 0, 2, u16 100 |
| 8 | nothing (a non-zero len would desync the stream) | type **9**, 0, 0; end of phase B |
| 9 | nothing | no reply; end of phase B |
| 10 | — | aborts the call |
| 0, 6, 7, ≥ 11 | skips `len` bytes | type \| 8000h, **status 7**, len 0 |

The 8004h reply's length field (4) does not match the 22 data bytes that follow. A reader that
goes by `len` desynchronises. **Never send type 4** to the client.

### 5.3 Login and records

**Login** after the negotiation: the normal one (rows 14–18), with these differences:

| step | client | server |
|---|---|---|
| 1 | `80`, waits 31 s for `81` (other bytes ignored) | `81` |
| 2 | name lstring | `8B` / `83` / `8C` |
| 3 | on `8B`: password lstring, with the change form of row 16 | reply |
| 4 | `8C` → hang up (with the password handling of row 16) | |
| 5 | reads the PO name lstring | `82`/`83` + name |
| 6 | **name mismatch OR the answer was `83` → sends `83` and hangs up**. A send-only connection is refused in interactive mode | |
| 7 | name ok: sends `82` | |
| 8 | sends control record type 1, len 4, data `00 00 00 00` | |
| 9 | reads 1 byte, which must be `01`; then u16 type, u16 len | a control record |
| 10 | type 3 → reads a u32 (no visible effect); type 4 → reads a u16, values 1/2/3 all accepted; other type → skips `len` bytes. Connected | |

Any other first byte at step 9 → the call ends.

**Records.** There are no 84…88 session codes after this login. Both sides exchange records:

| record | layout | client sends | client receives |
|---|---|---|---|
| data | `00` u16 len, data[len] | a 3-byte header, then the data | skips any byte that is neither 00 nor 01; `00` → u16 len, then the data. Data longer than the client's buffer (5400h bytes, §5.6) is discarded and the call fails |
| control | `01` u16 type, u16 len, data[len] | a 5-byte header, then the data | reads type and len and **skips the data**. Control records the client receives are always ignored |

Each data record carries one remote VIM call or its reply (§5.6).

**Disconnect:**
1. The client sets its link retry limit to **1**.
2. It sends control record type 2, len 1, data `00`.
3. It reads `01`, then u16 type, u16 len:
   - type 2 → reads 1 byte, which must be `00`;
   - other type → skips `len` bytes.
4. Clean or not, it then hangs up and does not wait for anything else.

### 5.4 Transcript (test vectors)

C = client (HP 200LX), S = server. Each line is link data, in one or more frames. Values: idle
timeout = 5 minutes (the default) = 300 s; max message size = 0.

```
C> AD
S> AE
C> AF 01  01 00 00 00 06 00  53 56 49 4D 64 00     hello "SVIM" v100
S> AF 01  01 80 00 00 00 00                       8001h ok
C> AF 01  02 00 00 00 02 00  2C 01                idle timeout 300 s
S> AF 01  02 80 00 00 00 00                       8002h ok (or 02 80 01 00 02 00 vv vv)
C> AF 01  03 00 00 00 04 00  00 00 00 00          max message size 0
S> AF 01  03 80 00 00 00 00                       8003h ok
C> AF 01  08 00 00 00 00 00                       end of the client's requests
S> AF 01  09 00 00 00 00 00                       no requests from us; phase B ends
C> 80
S> 81
C> 05 "user" 00
S> 8B
C> 04 "123" 00
S> 82 07 "MYPOST" 00
C> 82
C> 01  01 00  04 00  00 00 00 00                  control record type 1
S> 01  03 00  04 00  nn nn nn nn                  type 3 + u32 (meaning not determined); 01 04 00 02 00 01 00 also passes
C> 00 2A 00  03 00 22 00 00 00 …                  VIMOpenSession, the 42-byte block of §5.6
S> 00 08 00  00 00 00 00  hh hh hh hh             reply "th": status 0, session handle
C> 00 0A 00  00 02 hh hh hh hh 00 00 00 00        VIMOpenMessageContainer(session, NULL)
S> 00 08 00  00 00 00 00  cc cc cc cc             reply "th": container handle
   ... further VIM calls (§5.8–5.10), 000F Ping every (idle minutes · 60 − 30) s ...
C> 00 06 00  08 02 cc cc cc cc                    VIMCloseMessageContainer
S> 00 04 00  00 00 00 00
C> 00 06 00  05 00 hh hh hh hh                    VIMCloseSession
S> 00 04 00  00 00 00 00
C> 01  02 00  01 00  00                           close
S> 01  02 00  01 00  00
```

### 5.5 Comparison with the Router negotiation (negotiation.md)

| aspect | Router (B0 80 / AE / AF 01) | HP interactive |
|---|---|---|
| trigger | caller sends `B0 80`; the answerer replies `AE` (raw, before packets in some cases) | caller sends **`AD`** inside the link and waits for **`AE`**, 3 × 5.2 s |
| packet layout | `AF 01 type status len data` | **the same**. The client treats byte 1 as an entry count, but sends 1 and needs 1 in replies |
| reply convention | type \| 8000h, status 0 / 1 counter-offer / 7 unknown type | **the same** (the client also uses status 8 for a hello it receives) |
| end | 8 → answerer replies 9 | **the same**; the client also serves the answerer's requests until 8 or 9 |
| hello id / version | "NMTP" 100, "MOBP" 200; any other id → status 3 | **"SVIM" 100**. a post office peer would answer status 3, which the client treats as failure |
| other types | 6 key (cipher), 18, 19, 21–24 | **2 idle timeout (u16 s), 3 max message size (u32)**, 4 name, 5 version 100; no cipher type, no 19/6 |
| cipher | type 6 key turns on session enciphering | **none** |
| after it | `80` → `81` old login, then the old 84…88 session | `80` → `81` old login, **then `00`/`01` records, not 84…88** |

So the HP mode is the same packet family, but **not the same protocol**: the trigger byte, the
hello id, the type numbers and the session after the login all differ; a Router that knows only
`B0 80` would never answer `AD`.

A server for it:
1. on `AD` before `80`, replies `AE`;
2. in phase A, accepts hello "SVIM"/100, 2 and 3 with status 0, and treats 8 as the end;
3. sends `AF 01 09 00 00 00 00 00`;
4. runs the normal login, refusing nothing with 83 (the client hangs up on 83);
5. answers the client's `01 01 00 04 00 …` with a control record;
6. then handles data records: the remote VIM calls of §5.6–5.11.

### 5.6 Remote VIM calls

"SVIM" is the server side of VIM (Vendor Independent Messaging) at the post office: the hello
`"SVIM"` + 100 asks the server for a VIM server of version 100 (`VIM_CURRENT_VERSION` = 100 in
VIM.H). After the login the client calls VIM functions on the post office's mailbox.

**One call = one request record + one reply record.** The data record is the block itself; the
first field (`f`) is the procedure number. Example, VIMCloseMessageContainer: request block
`"fh"` = procedure 0208h + container handle, reply block `"t"` = status.

The client's block buffer is **5400h bytes** in both directions, so one data record is at most
21,504 bytes. A longer reply fails the call.

**Block encoding** (little-endian; offsets relative to the start of the block):

| letter | wire | meaning |
|---|---|---|
| `f` `w` `b` | u16 | procedure number / word / vimBool |
| `h` `i` `d` `s` `S` `t` | u32 | handle / int / dword / selector / selector / **status** (`t`: when non-zero the reader stops decoding the rest) |
| `E` | u32 | vimEnumRef: the request sends the low dword only; the reply's low dword is taken and the high dword is set to 0 |
| `R` | 8 bytes | vimRef |
| `z` | u32 offset (0 = NULL) | string; the NUL-terminated bytes are placed **after all following fields** |
| `p` / `P` | u16 / u32 length, u32 offset | byte buffer, data placed like `z` |
| `a` | u16 count, u16 n, count × {Attr u32, Size u32, DataOffset u32 = 0} | vimAttrDesc array without data (request: which attributes) |
| `A` | the same, then for each entry Size·n data bytes at DataOffset | vimAttrDesc array with data |
| `c` | u32 Offset, u32 Size (from a vimBuffFileDesc) | read request |
| `C` | 16 bytes {Size, BufferOffset, Offset, FileNameOffset} + data | vimBuffFileDesc with data |
| `N` | u32 offset → 24 bytes {Type, DName.Type, off AddressBook, off Value, Address.Type, off Address} + strings | vimRecipient |
| `D` | count = the preceding `w`; count × 28 bytes {Class u32, off Type, off Name, off Path, Size u32, Ref 8} + strings | vimItemDesc array (reply only) |

**Procedures** (request format → reply format; every reply starts with the status `t`, whose
values are VIM.H `VIMSTS_*`: 0 success, 1 failure, 5 bad param, 15 name not found, …):

| proc | VIM function | request | reply |
|---|---|---|---|
| 0003 | VIMOpenSession(path, name, password, version, charset) | `fzzzds` | `th` (session handle) |
| 0005 | VIMCloseSession | `fh` | `t` |
| 000F | VIMPing: fixed 14 bytes `0F 00 04 00 00 00 04 00 00 00 00 00 00 00` | — | **the content is not read**; any data record of 0–12 bytes is accepted, a longer one fails. Send `00 00 00 00` (status 0) |
| 0100 | VIMCreateMessage | `fhz` | `th` |
| 0101 | VIMCreateDerivedMailMessage | `fhSd` | `th` |
| 0102 | VIMSetMessageHeader | `fhSp` | `t` |
| 0103 | VIMSetMessageRecipient | `fhSN` | `t` |
| 0104 | VIMSetMessageItem | `fhSzSzC` | `t` |
| 0105 | VIMSendMessage | `fh` | `t` |
| 0106 | VIMCloseMessage | `fh` | `t` |
| 0200 | VIMOpenMessageContainer | `fhz` | `th` |
| 0201 | VIMEnumerateMessages | `fhEiSpda` | `tEbA` |
| 0202 | VIMEnumerateMsgAttrValues | `fhSEiww` | `tEbwp` |
| 0203 | VIMRemoveMessage | `fhR` | `t` |
| 0204 | VIMQueryNewMessages | `fh` | `tb` |
| 0205 | VIMQueryUnreadMailCount | `fh` | `td` |
| 0208 | VIMCloseMessageContainer | `fh` | `t` |
| 0300 | VIMOpenMessage | `fhRz` | `th` |
| 0301 | VIMMarkMessageAsRead | `fhR` | `t` |
| 0302 | VIMGetMessageHeader | `fha` | `tA` |
| 0304 | VIMEnumerateMessageItems | `fhEiwSp` | `tEbwD` |
| 0306 | VIMOpenMessageItem | `fhRzd` | `th` |
| 0307 | VIMReadMessageItem | `fhc` | `tdC` |
| 0308 | VIMCloseMessageItem | `fh` | `t` |
| 0309 | VIMEnumerateMessageRecipients | `fhSEia` | `tEbA` |
| 0400 | VIMEnumerateAddressBooks | `fhEia` | `tEbA` |
| 0401 | VIMOpenAddressBook | `fhz` | `th` |
| 0402 | VIMSetCurrentSubtree | `fhRz` | `t` |
| 0403 | VIMGetCurrentSubtree | `fhw` | `tRwz` |
| 0404 | VIMEnumerateAddressBookEntries | `fhRzEiSpa` | `tEbA` |
| 0405 | VIMCreateAddressBookEntry | `fhSA` | `t` |
| 0406 | VIMMatchAddressBook | `fhRzSpSR` | `tRh` |
| 0407 | VIMGetABEntryAttributes | `fhRza` | `tA` |
| 040C | VIMRemoveAddressBookEntry | `fhRz` | `t` |
| 040D | VIMAddGroupMember | `fhRzszz` | `t` |
| 040F | VIMEnumerateGroupMembers | `fhRzEia` | `tEbA` |
| 0410 | VIMCloseAddressBook | `fh` | `t` |
| 0601 | VIMSetMessageCategory | `fhRz` | `t` |
| 0602 | VIMRemoveMessageCategory | `fhRz` | `t` |
| 0603 | VIMRemoveCategory | `fhzb` | `t` |

In each request the `h` after `f` is the remote handle (session, container, message, item or
address book) returned by an earlier `th` reply. The other letters follow the VIM.H argument
order of the function.

Test vector, VIMCloseMessageContainer(handle 00010002h), inside the link:

```
C> 00 06 00  08 02 02 00 01 00     data record, block "fh" = 0208h, 00010002h
S> 00 04 00  00 00 00 00           reply "t" = VIMSTS_SUCCESS
```

**String placement (`z`):**
- non-NULL `z` at block offset o: the **rest of the format** is encoded first at o+4, length n;
  the field holds the u32 offset o+4+n, and the string with its NUL goes there, after which the
  block ends;
- NULL `z`: field = 0, no data, and encoding goes on with the next letter;
- all offsets are from the start of the block. So the strings come in **reverse order**: the last
  `z` of the format first, the first `z` last.

Test vector, VIMOpenSession as the client sends it (§5.7): path `"cc:Mail"`, name `"John Doe"`,
password `"pw"`, version 100, charset VIMSEL_CP850 (18). 22 fixed bytes, then password, name,
path:

```
03 00              f   0003
22 00 00 00        z   path     -> 34 (22h)
19 00 00 00        z   name     -> 25 (19h)
16 00 00 00        z   password -> 22 (16h)
64 00 00 00        d   version 100
12 00 00 00        s   charset 18 = VIMSEL_CP850
70 77 00                         "pw"        at 22
4A 6F 68 6E 20 44 6F 65 00       "John Doe"  at 25
63 63 3A 4D 61 69 6C 00          "cc:Mail"   at 34      (total 42 bytes)
```

**`C` in a request**: the 16-byte descriptor, then the rest of the format, then the data:
- with a buffer: field +4 = data offset, Size bytes of buffer data there, FileName field
  (+0Ch) = 0;
- without a buffer: field +4 = 0, field +0Ch = data offset, and Size bytes there. With Size = 0
  no data follows, so neither a file name nor file data reaches the server.

**The other letters:**
- `p` / `P`: u16 / u32 length, then u32 offset; NULL gives offset 0 and encoding goes on;
  otherwise placed like `z` (rest of the format first, then `length` bytes, then the block ends).
  The client copies `length` bytes from a reply **without a limit**, so the reply must stay
  within what was asked. Request lengths: strlen **without the NUL** for string selectors
  (SUBJECT, FROM, RDN, NAME, TYPE, CATEGORY, …), 4 for CLASS, 18h for the DATE selectors, 2 for
  PRIORITY and other word selectors, 0 for the rest (NO_FILTER).
- `a` / `A`: u16 count, u16 n, then count × 12 bytes {Attr, Size, DataOffset = 0}. `A` then
  encodes the rest of the format, then each entry's Size·n bytes, DataOffset = their block
  offset (`A` is always last). From a reply the client takes count and n, takes each Size **from
  the wire** and copies Size·n bytes, also without a limit. So a reply must use the requested
  Size. Special case: attribute 4Bh RECIPIENT with count = 1 and n = 1 is a 24-byte compact
  vimRecipient at DataOffset (strings at block offsets), expanded into the 90Ch-byte struct. Any
  other 90Ch-sized attribute, such as 22h FROM in GetMessageHeader, is copied raw, so it carries
  the full vimRecipient: Type, DName {Type, AddressBook[256], Value[1024]}, Address {Type,
  Value[1024]}.
- `N`: u32 offset = the next byte, then the 24-byte struct {Type, DName.Type, off AddressBook,
  off DName.Value, Address.Type, off Address.Value}, then the rest of the format, then the
  non-empty strings. Empty strings get offset 0.
- `D` (reply only): count = the `w` just read. count × 28 bytes at the current position {Class,
  off Type, off Name, off Path, Size, Ref(8)}, 250h bytes of room per entry on the client side,
  within its 5400h buffer. Strings are taken only for non-zero offsets.
- `C` in a **reply**: no descriptor at all. The data bytes follow at once, and their count is
  the dword just read (the `d` of `tdC`). That count must not exceed the requested Size.
- `c`: u32 Offset, then u32 Size.
- `E`: the request carries the low dword; the reply's dword is taken and the high dword zeroed.
  `R` is 8 bytes both ways. `t`: a non-zero status ends decoding.

The implementation is `ccmail/vimblock.py` (both directions, with the client's size limits).

Selectors and item classes are the VIMSEL_* values of VIM.H/VIMEXT.H (decimal in VIM.H; hex
below). The calls map onto our store: message list, header TLVs, items, folders and the
directory.

### 5.7 Session: open, keep-alive, close

**Open:**

| # | call | proc | arguments |
|---|---|---|---|
| 1 | VIMOpenSession | 0003 | path = the host name the user picked (default `"cc:Mail"`); name = the user name (after the comma swap of §2.4); password; version **100** (d); charset **12h VIMSEL_CP850** (s) → session handle |
| 2 | VIMOpenMessageContainer | 0200 | the session, name **NULL** (the default container, i.e. the inbox) → container handle |

- A reply status ≠ 0 to 0003 → the client disconnects (§5.3). One session per call.

**Keep-alive (Ping):** proc 000F (§5.6), every (idle minutes · 10920 − 5460) / 10 ticks, computed
in 16 bits: minutes · 60 s − 30 s, i.e. 270 s for the default 5 minutes. From 7 minutes on the
16-bit product wraps (7 → 544 ticks, about 30 s). The idle minutes are the negotiated idle
timeout (§5.2) / 60, so the server sets this interval through type 2: a phase A counter-offer
(status 1) is adopted as is; a phase B request is adopted when it is smaller.

**Close:**

| # | call | proc | handle |
|---|---|---|---|
| 1 | VIMCloseMessageContainer | 0208 | the inbox |
| 2 | VIMCloseSession | 0005 | the session. Then **always** the disconnect of §5.3 |

- Open address books are not closed at disconnect; the server must drop them when the session
  ends.

### 5.8 Inbox and folders (read side)

All of these use the inbox container or the open message.

**List filter:** selFiltType = 3Ah **VIMSEL_NO_FILTER** (default), or 5Bh SUBJECT with a text,
22h FROM with a name, 13h DATE with a 24-byte vimDateRange (two {zone 2Dh VIMSEL_LOCAL, date =
year<<16 | month<<8 | day, time}; stop time 173B3B63h = 23:59:59.99). flags 0 or 1
(VIM_UNREADONLY). For a folder: selFiltType 100h **VIMSEL_CATEGORY**, data = folder name,
flags 0.

| step | call | proc | arguments |
|---|---|---|---|
| counts | VIMEnumerateMessages ×2 | 0201 | skip 1, **0 attributes**, count FFFFh, list filter; first with flags \| 1 (unread count), then plain (total) |
| page | VIMEnumerateMessages | 0201 | count 20 (14h), skip **−1** (FFFFFFFFh) from the bottom edge position, or skip +1 from the top edge when paging back (the count on the wire is always a positive u16 ≤ 20; §5.12); 5 attributes: {4Ch REF, 8}, {67h UNREAD_MAIL, 2}, {5Bh SUBJECT, 41h}, {13h DATE, 0Ch}, {23h FROM_NAME, FEh} |
| | VIMEnumerateMessages | 0201 | 0 attributes, count 1, skip ±1: moves the other position |
| refresh | VIMQueryNewMessages | 0204 | true → the page again |
| open | VIMOpenMessage | 0300 | ref from the list, key **NULL** |
| | VIMEnumerateMessageItems | 0304 | skip 1, count 1, selFilt 0Dh **VIMSEL_CLASS**, data u32 3Eh **VIMSEL_NOTE_PART**; repeated up to 20 times |
| | VIMOpenMessageItem / VIMReadMessageItem / VIMCloseMessageItem | 0306 / 0307 / 0308 | first note part; convert type NULL, selFlags 0; read Offset 0, Size = note size + 800h (800h–5000h) |
| | VIMGetMessageHeader | 0302 | 4 attributes: {5Bh SUBJECT, 41h}, {13h DATE, 0Ch}, {22h FROM, 90Ch (a vimRecipient)}, {47h PRIORITY, 2} |
| | VIMEnumerateMessageRecipients | 0309 | class 61h TO, then 0Ah CC, then 09h BCC; skip 1, count 1, 1 attribute {4Bh VIMSEL_RECIPIENT, 90Ch} |
| | VIMMarkMessageAsRead | 0301 | the list ref, when the entry was unread |
| attachments | VIMEnumerateMessageItems | 0304 | CLASS = 6 **VIMSEL_ATTACH**, skip 1, count 1 |
| detach | Enumerate (ATTACH) / OpenMessageItem / ReadMessageItem ×n / Close | 0304 / 0306 / 0307 / 0308 | open selFlags 37h **VIMSEL_NATIVE**, convert NULL; reads of min(rest, 1000h) bytes at a running Offset |
| leave | VIMCloseMessage | 0106 | the open message |
| delete | VIMRemoveMessage (inbox) / VIMRemoveMessageCategory (folder) | 0203 / 0602 | ref; folder name |
| file | VIMSetMessageCategory, + VIMRemoveMessageCategory for a move | 0601 / 0602 | ref, folder name |
| folders | VIMEnumerateMsgAttrValues | 0202 | selAttr 100h CATEGORY; count FFFFh with entry size 0 (count only), then 20 names of 80 (50h) bytes per call, skip ±1 |
| | VIMEnumerateMessages | 0201 | 0 attributes, count FFFFh, CATEGORY = folder name (count per folder; also before a folder delete) |
| print | EnumerateMsgAttrValues / EnumerateMessages (4 attributes {67h, 2}, {5Bh, 41h}, {13h, 0Ch}, {23h, 7Fh}) / note-part read | | |

- Operations on all listed or selected messages: 0201 EnumerateMessages, skip −1, 2 attributes
  {4Ch REF, 8}, {67h UNREAD_MAIL, 2}, the list filter (folder: 100h CATEGORY); then per message
  the delete, file or print sequence above.
- **Copy to a local folder:** 0300 OpenMessage(ref, NULL); 0302 GetMessageHeader with 5 entries
  ({62h TYPE, 20h}, {22h FROM, 90Ch}, {5Bh SUBJECT, 3Ch}, {13h DATE, 0Ch}, {47h PRIORITY, 2});
  0309 for TO, CC, BCC (skip 1, 1 attribute {35h VIMSEL_NAME, 100h}, count 1 or 2 per call);
  0304 for CLASS NOTE_PART, then ATTACH (2 per call); per item 0306 (selFlags 37h NATIVE;
  convert `"VIM_TEXT"`) / 0307 / 0308; 0106. The client may instead file on the server with
  0601.
- 0603 RemoveCategory is never sent to the server.

### 5.9 Sending

| # | call | proc | arguments |
|---|---|---|---|
| 1a | new message: VIMCreateMessage | 0100 | session, type **`"VIM_MAIL"`** → message |
| 1b | reply/forward: VIMOpenMessage, VIMCreateDerivedMailMessage, VIMCloseMessage(original) | 0300, 0101, 0106 | OpenMessage(inbox, ref, NULL); derived sel 4Dh **VIMSEL_REPLY** or 21h **VIMSEL_FORWARD**; flags: reply 2 (inherit contents) and/or 4 (all recipients), forward 1 (history) |
| 2 | VIMSetMessageHeader | 0102 | 5Bh **SUBJECT**, size strlen + 1, the subject |
| | VIMSetMessageHeader (optional) | 0102 | 51h **SAVE** = 1 when sending, else 17h **DRAFT** = 1; size 2 |
| 3 | VIMSetMessageRecipient, one per name | 0103 | class 61h **TO**, then 0Ah **CC**, then 09h **BCC**; groups already expanded by the client. vimRecipient: Type = 1Ah ENTITY (or another entry type) or 65h UNKNOWN_RECIP_TYPE when the client's own book has no entry; DName.AddressBook = ""; DName.Value = the name, or the entry's address; Address.Type 37h NATIVE + Address.Value = the name in some cases, else 0 / "" |
| 4 | VIMSetMessageItem (the text; not always sent) | 0104 | class 3Eh **NOTE_PART**, type **`"VIM_UNWRAPPED_TEXT"`**, flags 37h NATIVE, name NULL; `C` with the text inline |
| 5 | VIMSetMessageItem, per attachment | 0104 | class 6 **ATTACH**, type NULL, flags 37h, name = the file name; `C` with Size 0 → **only the name, 0 data bytes** |
| 6 | VIMSendMessage, or VIMCloseMessage to keep it unsent | 0105 / 0106 | message |

- A recipient answered with status 15 (NAME_NOT_FOUND) is reported to the user.
- So an interactive send can deliver text, but **attachments reach the server with only the
  item name** and an empty `C` (Size 0, no data, no file name).
- After a failed step the client cleans up: 0106 CloseMessage, then 0201 EnumerateMessages
  (skip 1, count 1, 1 attribute {4Ch REF, 8}, selFiltType 53h **VIMSEL_SENT** when sending, else
  17h **DRAFT**, filter data NULL, flags 1 VIM_UNREADONLY), then 0203 RemoveMessage of the ref
  found.
- After a successful send no further calls are made for the message.

### 5.10 Address books

| book | name sent to 0401 VIMOpenAddressBook |
|---|---|
| directory | `""` (empty string, not NULL) |
| private | `"VIM_PRIVATE"` |
| public | `"VIM_PUBLIC"` |

| call | proc | arguments |
|---|---|---|
| VIMEnumerateAddressBookEntries | 0404 | subtree ref 0, name NULL, filter 3Ah NO_FILTER; browse: 3 attributes {4Ch REF, 8}, {49h RDN, 7Fh}, {62h TYPE, 4}; counting/positioning with 0 attributes, count FFFFh; also {49h, 7Fh}, {62h, 4} and {4Ch, 8} variants |
| VIMMatchAddressBook | 0406 | attribute 49h RDN, the name, match 24h FULL (43h PARTIAL for type-ahead), subtree NULL |
| VIMGetABEntryAttributes | 0407 | by ref, name NULL; {49h RDN, 7Fh/80h}, {01h ADDRESS, 404h}, {62h TYPE, 4} combinations |
| VIMEnumerateGroupMembers | 040F | skip 1, {35h NAME, 504h} |
| VIMCreateAddressBookEntry | 0405 | 1Ah ENTITY with {49h RDN}, {01h ADDRESS}; `&name` → 26h GROUP with {49h RDN} |
| VIMAddGroupMember / VIMRemoveAddressBookEntry | 040D / 040C | group ref + name; entry ref, name NULL |
| VIMCloseAddressBook | 0410 | when the user leaves the book |

### 5.11 Procedures the server must answer

| sent by the client | not sent |
|---|---|
| 0003, 0005, 000F, 0100, 0101, 0102, 0103, 0104, 0105, 0106, 0200, 0201, 0202, 0203, 0204, 0208, 0300, 0301, 0302, 0304, 0306, 0307, 0308, 0309, 0401, 0404, 0406, 0407, 040F, 0410, 0601, 0602; possibly 0405, 040C, 040D (editing a server book) | 0205, 0400, 0402, 0403, 0603 |

### 5.12 Paging, and our server's model

**How the client pages:**
- It keeps two positions per list: the top edge and the bottom edge (vimEnumRef).
- Counts: two calls, each from a zeroed position with skip 1, 0 attributes and count FFFFh:
  flags | 1 gives the unread count, plain the total. Only the returned count is used, not
  `more`.
- Page down: from the bottom edge with skip −1; page up: from the top edge with skip +1. A
  follow-up call moves the other edge with the same skip and 0 attributes (count 1 on a fresh
  list, else the number the page returned). The returned position replaces the edge the page
  started from. So "±1 from a returned position" must go on in the same direction.
- Display: after skip −1, entry 0 is the **top row** and the rest follow in order. After skip
  +1 the entries are shown reversed. So the server returns entries in the order it walks them,
  and the top of the inbox is the **last** message in server order. Folders (0202) and address
  books (0404) are the mirror image: the first page is skip +1 from 0.
- "All messages": one zeroed position, reused for every batch; skip −1; batches of 20; until
  the total.
- Inbox attributes: REF is passed back as is. UNREAD_MAIL counts when non-zero. SUBJECT is a
  NUL-terminated string in its 41h slot, shown cut to 44 characters. Of DATE only the Date dword
  (+4) is used. FROM_NAME is cut to 28 characters.
- 0202 names: 20 slots of 50h bytes; name i at i·50h, NUL-terminated. The `p` length must be
  ≤ count × 50h, and 0 on the entry-size-0 calls.
- Status 4001 (VIMSTS_CONTAINER_REORG) on a page makes the client recount and go on with a
  stale count. Our server never sends it.

**Our server's choices** (ccmail/vimserver.py). Router's behaviour here is not determined. These
are **our** decisions, taken as the most conservative reading:

| case | our answer |
|---|---|
| position (vimEnumRef low dword) | 0 = outside the list; otherwise the key of the **last entry returned** (messages: the ref serial; folders, items, recipients, book entries: index + 1). From 0, skip +1 → first entry and skip −1 → last entry; from an entry, skip k → the entry k steps away; then up to count entries in the direction of skip. `more` = entries remain beyond in that direction. No entries → the position comes back unchanged. A message that has left the list since keeps its place by message id |
| server order | messages oldest first (by id = arrival time); folder names and book entries by name, case-insensitive |
| handles | session 00010001h, then 00010002h, … (bit 08000000h clear). One session per call. A wrong handle → VIMSTS_INVALID_OBJECT (10). Unknown or refused procedures → VIMSTS_NOT_SUPPORTED (16), never silence |
| inbox | mail/<user>/ (the pending queue a batch call delivers) plus the kept messages with the inbox flag. Reading interactively does **not** take mail off the server, and a later batch call still delivers pending mail, read or not |
| read flag | only 0301 sets it (0300 does not; the client sends 0301 itself). State in vim/<user>/state.json |
| folders | VIMSEL_CATEGORY = folder. 0601 adds a folder and moves the file to vim/<user>/kept/, so a batch call no longer takes it; the message stays in the inbox until 0203 there. A folder exists while a message is filed in it (0202 lists the names in use) |
| 0203 RemoveMessage | removes the message from the **inbox only**; folders keep it, so an inbox delete never drops filed mail |
| batch-delivered mail | once a batch call has delivered a message (delivered/<user>/), it is no longer in the interactive inbox, and its read state and folders are gone with it |
| 0204 QueryNewMessages | true when the mailbox holds a message id not seen by an earlier 0201 or 0204 of this call |
| 0102 SAVE (51h) | accepted and ignored (no sent copies are kept) |
| 0602 | removes that folder. A message in no folder and not in the inbox is moved to deleted/<user>/, never destroyed |
| filters | NO_FILTER = inbox. CATEGORY = folder (case-insensitive). SUBJECT / FROM = case-insensitive substring. DATE = inclusive vimDateRange. DRAFT = our drafts. SENT = none. flags & 1 = unread only. Other selectors → INVALID_SELECTOR (12) |
| 0003 | the name must resolve to the user of the link login; the password is not checked again. Version ≠ 100 → 26. Charset 12h / 11h / 10h → code page 850 / 437 / 1252, other → 12. Everything the session sends and reads is converted to that code page |
| post-login control record | type 3, u32 **0** |
| negotiation | hello "SVIM"/100 accepted (other → status 3). Idle timeout and maximum size accepted as sent (status 0). Phase B: only `AF 01 09 …`. Extra `AD` bytes are skipped, never answered twice |
| items (0304) | text item → NOTE_PART 3Eh, type "VIM_TEXT"; file → ATTACH 6, type ""; others → APP_DEFINED 4. Name = the item title. Item ref = (item number, message ref serial). Empty strings are sent as "" (offset 0 would leave the client's field unset) |
| 0306 convert type | NULL, "" and "VIM_TEXT" are accepted; another conversion of a note part → 7 CONV_NOT_SUPPORTED |
| FROM (90Ch) | the full vimRecipient: Type 1Ah ENTITY, DName.Value = author ("name at PO" when routed), other fields 0 / "" |
| recipients (0309) | TO = tags 03/04/0A, CC = 0B/0C/0D, BCC = 11/12, as "name at PO" when routed. The lone 4Bh attribute → compact form. {35h NAME, size < 504h} → the plain name |
| 0103 | the name is Address.Value when Address.Type = 37h NATIVE and it is set, else DName.Value; "name at PO" is split. A name we cannot route (local, ADE, post office path, gateway) → 15 NAME_NOT_FOUND |
| 0104 ATTACH with 0 data bytes (what the client sends) | **refused with 4 ATTACHMENT_NOT_FOUND**: we cannot attach a file we were not given, and we do not send the message without it. The client then cleans up (§5.9) |
| 0105 | compose (codepage of the session) and deliver like an upload: local mailboxes, ADE / post office routes, gateway. No recipients → 3 ALL_PARAMS_REQUIRED |
| 0101 derived | REPLY with INHERIT_CONTENTS (2), or FORWARD with HISTORY (1), appends the original text items; FORWARD also appends the original file items. Recipients are **not** inherited, because the client sends its own; a reply sent without any gets the original author (and with ALL_RECIPIENTS its To/cc names) |
| 0106 on a created message | with DRAFT = 1 set by 0102 and no refused Set* call: kept in vim/<user>/drafts/, **marked read**, listed only by the DRAFT filter, removable with 0203. Without DRAFT, or after a refused Set* call: dropped (logged). Marked read so that the client's cleanup lookup (DRAFT, VIM_UNREADONLY, count 1) cannot find and remove an older draft |
| address books | NULL, "" and "VIM_PUBLIC" → our directory (directory_entries, post office entries left out). "VIM_PRIVATE" → an empty book. Other names → 15. Read-only: 0405/040C/040D → 16. Type 1Ah ENTITY; ADDRESS (404h) = vimAddress {37h NATIVE, "name" or "name at PO"}; NAME 504h = vimDistinguishedName. No groups, so 040F returns 0 members |
| 0406 Match | RDN/NAME; FULL = equal ignoring case, PARTIAL = prefix. Reply R = entry ref (index + 1, 0), h = the position **at** the match. None → 19 NO_MATCH |
| unserved attributes | zero-filled at the requested size and logged |

Every request and reply is logged decoded (INFO; the password of 0003 is masked) and in hex
(DEBUG), for comparison with a capture of a real HP.

## 6. Open points

1. Interactive mode. Not determined:
   - the meaning of the post-login control record type 1 (4 zero bytes) and of the server's
     type 3 u32 / type 4 u16 answer (§5.3). A capture against a Router that answers `AD` would
     settle it;
   - the meaning of negotiation types 4/5 sent by a server;
   - the server-side meaning of: skip −1 versus +1 with positive or negative counts in
     0201/0202, the empty address book name `""`, a DRAFT message closed without 0105,
     attachments sent with 0 data bytes (§5.9). VIM.H defines the calls but not these cases. Our
     server's answers are listed in §5.12 as our choices;
   - whether a returned enumeration position means the last entry returned or the next one
     (only the "±1 from it continues" usage is settled; we return the last entry);
   - whether the client edits server address books (0405, 040C, 040D).
2. Not determined: how a real Router treats the client's NAK with p0 = 00, and its
   `current\0new\0new\0` password change.
3. Not determined: the client's fixed-header values on send (date/time, word[0C], counts,
   descriptor +8/+A of attachments) and the exact attribute-run bytes of its +A = 1 item. A
   capture would settle them.
4. Not determined: the size of the client's message buffer, which decides when it answers
   8F "Message buffer too small".
