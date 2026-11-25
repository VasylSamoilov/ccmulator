# Newer clients: protocol notes

Compatibility: the newer cc:Mail client transport (cc:Mail Mobile for Windows) speaks the protocol
of link-layer.md, session-layer.md and items.md, with the additions below. This server is
compatible with it.

This file lists what a newer client sends and expects on the wire, measured against that
reference protocol (as built into ccmail/link.py, session.py, message.py), and how a compatible
server answers.

**Result: the link layer and the session layer are the reference protocol, unchanged in everything
our server sends or expects.** Frame, CRC, ctl byte, window, NAK rules, ASCII coding, opener,
session codes and header record are the same.

Text items (items.md) are not interpreted by the client's session transport, so they cannot be
checked at this level (rows 28–29).

The differences that matter (§2):
- the client always sends `B0` before `80`;
- TCP/IP and SPX run the session raw;
- two new optional session requests in the caller's turn (A5 address book, A2 mailbox sync);
- new refusal codes from the client;
- a receiver-side ASCII length limit;
- a fixed 6.2 s timer;
- the answerer refuses with 10h.

## 0. Scope

"Reference" = the protocol of link-layer.md / session-layer.md. "Newer client" = the client
transport described here. An earlier release of the same client also sends `B0 80`; it has the
"NMTP" protocol id and not "MOBP" (negotiation.md §1, §9 #6), and it has no A2/A5 requests.

The newer client exchanges session bytes only in: the login, the message transfer, the 91h filler,
the syncs (A2 mailbox sync, A5 address book), the negotiation, and the dial script (before the
session).

## 1. Item table

S = SAME, D = DIFFERENT, NP = NOT PRESENT, NC = NOT CHECKED.

### 1.1 Link layer (link-layer.md)

| # | Item (reference) | newer client | details | Notes |
|---|---|---|---|---|
| 1 | Frame `02 L(1 or 2, LE) ctl p0 H1 H0 [d… D1 D0]`. L counts p0. Data part only if L>1. Control frames L=1 (HSEC high byte 0) | **S** | L high byte only in mode 2; header only if L≤1 | |
| 2 | CRC-16/GENIBUS: poly 1021 MSB first, init FFFF, inverted, stored high then low. Pass 1 over L..p0, pass 2 restarts over d1..d(L−1) | **S** | FFFF per pass, `~crc`, high byte first | |
| 3 | Receive residue 1D0F, restart FFFF for data | **S** | header check, data check, restart | |
| 4 | ctl = type(2) N(S)(3) N(R)(3). N(R) = rx_expected−1. Ack 40h\|N(R) p0=00, NAK 80h\|N(R) p0=04, sequenced control 80h\|seq<<3\|N(R) with p0 = code. 0Fh accept, 10h refuse | **S** (one detail **D**) | type 2 with code≠4 → sequenced control with L=1; `(p0&1F)` = 0F → accept, 10h → refuse | **D:** a NAK is recognised only if p0 **== 04**; the reference tests `(p0&1Fh)==4`. Our server sends 04, so this does not matter |
| 5 | Window 4, mod 8, cumulative inclusive acks, rx window [exp, exp+4), duplicates and out-of-window frames dropped without ack | **S** | new data only while outstanding ≤3 | |
| 6 | NAK on a CRC/length error (not while rescanning), on an out-of-order frame, on rx-timer expiry. Cancelled by in-order delivery. No re-ack of duplicates. Rescan after the bad STX | **S** | N(S)≠exp → NAK pending; rx timer → NAK; in-order delivery clears it. Ack pending only on delivery; no ack-delay timer | send order NAK/control > retransmit > data > ack |
| 7 | Retransmit and frame-assembly timers; the reference tick values and speed table | **D** | reload always 1838h = **6200 ms** at every speed | equals the reference's 70h set and a post office peer's. The reference's 1.54 s / 0.77 s at 1200 / 2400 bps are gone. Expiries that coincide are kept for the next pass (the reference drops them). No retry limit |
| 8 | Receiver max L 79h/3F8h whatever the ASCII flag | **D** | limits by (ascii, mode): `0079 03F8` binary LSEC/HSEC, `004E 02A2` ASCII. **In ASCII mode L > 4Eh (LSEC) / 2A2h (HSEC) is a bad frame** | our sender already uses ASCII_MAX_L (link.py). Never raise it |
| 9 | ASCII coding: prefix 20h–2Fh + data 30h–6Fh, state across frames, sender limit 4E/2A2, parity, XON/XOFF only in ASCII | **S** | encoder state reset only at link start; sender limit set at link start from the same limits | ASCII mode and parity are client configuration |
| 10 | LSEC/HSEC choice by speed and switches | **D** | caller: packets only if error correction is configured; HSEC if speed index >2; LSEC when forced; ASCII when configured. **A "force HSEC" option is never honoured.** A "no packets" setting exists | the answerer only detects the mode, so nothing changes for our server |
| 11 | HSEC→LSEC fallback | **S** (detail **D**) | probe count 6; on a hit → LSEC, link restart, resend | **D:** the 30 s countdown is not restarted after the fallback |
| 12 | Raw mode (80/81 without packets above 2400) | **D** | raw whenever error correction is off, at any speed, and **always over SPX and TCP/IP**. Raw caller sends `B0 80` bare | TCP caller connects to **3264 (0CC0h)** and falls back to 21; the listener uses 3264, or 21 when configured for the old port. Bytes pass through the socket unchanged |
| 13 | Opener `FF AA 55 11` as one data frame, 30 s wait, 0Fh/10h; answerer matches the 4 bytes in delivered data | **S** caller / **D** answerer | caller: 500 ms pause, 4 bytes, 30 s wait; 0Fh → accepted, 10h → refused, user abort or timeout → failed. Answerer: match with restart, then 0Fh | **D:** the newer answerer **refuses with 10h** on timeout or abort. The reference never does. Our server already does the same (as a post office peer does) |

### 1.2 Session layer (session-layer.md)

| # | Item (reference) | newer client | details | Notes |
|---|---|---|---|---|
| 14 | 80 → 81 | **D** (compatible) | always **`B0 80`**. Then a loop: **81 → old login**; AE → negotiation, then 80, then waits for 81; any other byte ignored; no 81 within its timeout → the call fails. **The choice between new and old is the byte after B0 80: 81 = old, AE = new.** A failed negotiation ends the call | if the client's "refuse unsecure post office" flag is 1, the client answers 81 with 8C and ends the call. Its initial value is 0; what sets it is not determined |
| 15 | Name: length byte N (counts the NUL), "B A\0" when strlen(A)+1 < N; received names N ≤ 80h | **S** | | |
| 16 | Password: length incl. NUL; calling home sends "new\0old1\0old2\0" (≤2 old) | **S** (details **D**) | length strlen+1; old passwords only when calling home and no alternative password is configured; at most 2 | **D1:** with an alternative password configured, that password is sent, no old ones; same format. **D2:** the old-password list is cleared only if the next code ≠ 8C |
| 17 | 8B; 8C + optional reason 97..9B + value | **S** (detail **D**) | 8C: waits **up to 500 ms** for the reason and for the value; bare 8C, or a reason without a value, is reported as an error | the reference reads only what is already buffered. Our `8C 98 00` works either way |
| 18 | 82/83 + PO name; client answers 82 (right) / 83 (wrong) | **S** | lookup, 83 or 82; c1 = 82 → accepted, else receive-only | **new after the name:** A0/A4 = "temporarily shut down", A6 = "database files missing". The earlier release knows only A0 ("cannot be accessed") |
| 19 | 84 / 85 / HL word + record | **S** | sender: 84, A0/A4 → shut down, ≠85 → skip; HL + record. Receiver: 85, HL, record | receive buffer 2000h; HL bound not seen (§3 #7) |
| 20 | One verdict 82/83 per tag-03 entry, in order; cc/bcc marking | **S** on the wire, rule **D** | sender waits 5Ah for each verdict; 82 test; 0B/11 handling. Receiver: per 03 entry, the name is looked up in the client's address book and the id compared with the own id → 82, else 83. **If the header holds tag 32h, every entry gets 82.** Drain 1Eh at the end | the reference matches the exact stored name. Here it is an address-book lookup. A 03 entry equal to the user's own name, as our server writes it, satisfies both. Tag 32h meaning not determined |
| 21 | 86 / 89 / 8A / 8E / 8F (wait B4h) | **S** + new | sender: 8E, 86, 89/8A, 8F, **new 9C/9D/9E** ("priority too low", "maximum messages exceeded", "message type restricted"). Client as receiver: 8A, 8F, 86; nothing accepted → 89 or **9E** (code table `9D 9E 9C 8E 96 89`); **8F** from the client's mail rules or when the user declines the message; **96 "From field must contain your user name"** after all-82 verdicts (only under a condition passed in by the session code on one path, §3 #1) | |
| 22 | body, then 87 / 8F / 90 / 2B (wait 14Ah) | **S** + new | sender: 2B, 87, 8F/90, **new A1**. Client as receiver sends **90** (the reference never does), 87, 8F | |
| 23 | 88 / 8D | **S** | caller 88 + receive, or 8D; receiver: 88, 8D, A0/A4 end; ≠84 end | |
| 24 | 91 filler | **D** | the code reader skips 91. **The client sends 91** during local work: before 84, and while it stores a received body after 86 | every place seen is where the peer waits for a code. Our read_code skips 91 |
| 25 | Header record, fixed 32 bytes | **S** + byte 19 | writer: [0A]='M', [0C]=0, [0E]=0, [12] date, [16] time, [08]=[04]=[00]=0. Date: day, month+1, year−1900, 0. Time: sec, min, hour, **byte 19 = time zone**: (UTC−local)/900 s (quarter-hours west of UTC) in bits 0–5; 40h set when the offset is east of UTC or zero; 80h = DST, which adds 4 | a post office peer's 20h = UTC−8 (session-layer.md, open point 1). The counts at 1A–1E were not located. Send-side limits: part 1 ≤ 1000h, record < 2000h |
| 26 | TLV tags | **S** (partly) | sender walks 03/0B/11 and marks 04/0C/12 in its own stored copy | full tag set not re-verified; tag 32h is new (row 20) |
| 27 | Turn order: caller sends, 88, receives; answerer receives first | **S** + new optional steps | login → **if address-book sync is configured: A5** → **if mailbox sync is configured: A2** → messages → 88 + receive or 8D → hang up | A5: the client waits 30 s for 84 + a 4-byte size, checks disk space, sends 86, takes the data in 200h chunks, answers 87/8F. Any other byte → "address book synchronization refused", timeout → returns; the session continues either way. A2: wait 14Ah; 85 → sync, then A8 with wait 3Ch; **A7** → "not available for a remote-only account"; any other byte → "mailbox synchronization refused". Both return 0 and the session continues. **Timeout → the call ends.** Both are off by default; the negotiation can clear them. The earlier release has no A2/A5 |

### 1.3 Items (items.md)

| # | Item (reference) | newer client | details | Notes |
|---|---|---|---|---|
| 28 | Text items: +A=1 attribute layer, +A=0 text with +8 = CR LF count; text must end in CR LF | **NP** | the session transport has no text-item reader or writer; body handling below the session level was not followed (§3 #6) | display and editing rules are outside the transport |
| 29 | 17-column transposition in 512-byte chunks from the start of each item/region | **S** where present | same table `09 04 05 0D 0C 0B 01 07 0A 03 02 10 08 0F 00 0E 06`, 200h blocks with the remainder last. Used to patch 04/0C/12 tag bytes in a stored header (200h chunks from the region start) | consistent with items.md §3/§4; whether the client transposes anything in transit is not determined |

## 2. Consequences for our server

1. **`B0 80` on every call.** session.py drops bytes before 80 and the link's mode detection skips
   the B0 in raw mode, so `B0 80` → `81` → old login works.
   - Keep answering a plain 81. Never send AE unless the negotiation is implemented.
2. **TCP/IP and SPX run the session raw.** There is no packet framing and no opener: just `B0 80`
   and session bytes over the socket.
   - The client connects to port **3264** and then tries 21. The server listens on 3264 as well as
     on 5003 by default.
3. **Address-book sync (A5) / mailbox sync (A2).** If configured, the client sends A5 or A2 in its
   own turn, before its messages.
   - Taking the byte as 88 would be wrong: the server would then send its own 84 (the client reads
     it as the address book) or 88 (the server hangs up and the client's outgoing mail is not
     taken).
   - Required handling: answer **A5 with 83** (any byte ≠ 84 is a refusal) and **A2 with A7**
     ("not available"; any byte ≠ 85/A7 also refuses), then keep reading the caller's turn. Both
     refusals return 0 and the client goes on to its messages. session.py's receive_messages()
     does this.
   - **Do not stay silent on A2:** a timeout ends the call.
   - What a post office peer answers is not determined.
4. **The "refuse unsecure post office" flag.** When it is 1, the client answers our 81 with 8C and
   gives up, and our server cannot serve that client without the negotiation and cipher
   (negotiation.md). Its initial value is 0 and what sets it is not determined; keep it in mind if
   a client refuses after 81.
5. **New refusals from the client as receiver:** 96, 9E or 8F instead of 86; 90 instead of 87.
   - send_one() treats them as "not stored" and leaves the message pending, so it is offered again
     on every call.
   - Open decision: whether permanent refusals (96 author, 9E type restricted, 8F rules) should go
     back to the sender instead. What a post office peer does is not determined.
6. **ASCII receive limit 4Eh/2A2h.** Our sender already respects it. Keep `max_tx_l` as it is.
7. **91 from the client** arrives only while we wait for a code. read_code() skips it, so nothing
   changes, but never read codes with read_exact().
8. **Time-zone byte 19** (row 25). compose() writes 0 (message.py `tim`), which this encoding reads
   as "UTC, west sign". The effect on display is not determined. If it is set, use the client's
   encoding:
   - west of UTC: quarter-hours west;
   - east of UTC: 40h | quarter-hours east;
   - UTC: 40h;
   - add 80h and 4 quarter-hours in DST.
9. No change is needed for the timers (we already use 6.2 s), NAK p0 (04), the 10h opener refusal,
   the 8C reasons or the HSEC→LSEC fallback.

## 3. Not determined

1. The exact condition under which the client as receiver sends 96.
2. What chooses 9E over 89.
3. The meaning of tag 32h, which makes the receiver accept every recipient.
4. A post office peer's replies to A5/A2/A8 and the full sync exchanges.
5. What sets the client's "refuse unsecure post office" flag.
6. Whether the client stores received bodies exactly as received, where item conversion happens,
   and why it sends 90.
7. Whether HL > 2000h overflows the client's receive buffer. Our records are far smaller.
8. The client's packet drain time, which depends on the speed.
9. When an answering client uses its connect path and when its listen path. Both port numbers
   (3264, 21) are certain.
10. Earlier client release: rows 26 and 28–29 were not checked. It has no A2/A5 session codes.
