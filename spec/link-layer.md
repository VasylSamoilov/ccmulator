# cc:Mail serial link layer

The packet protocol a cc:Mail Remote caller and a post office use on a serial or modem line:
modes, framing, CRC, the ASCII packet encoding, the sliding window, timers and link setup.
Roles: **the caller** (the remote client that dials) and **the answering side** (the post
office). "Sender" and "receiver" mean the two ends of one direction of a link in packet mode.
"tick" = PC timer tick, 18.2 Hz.

## 0. Conventions

- Hex values carry an `h` suffix or a `0x` prefix; byte dumps are hex without either.
- L, ctl, p0, N(S), N(R) are the frame fields defined in §3 and §4.

## 1. Overview

- After CONNECT both sides start in **raw mode**: session bytes are sent as they are.
- The caller then either stays raw (fast line, packet protocol off) or opens the packet protocol
  with an **opener frame** (§6.2). The answering side detects the format from the first bytes and
  accepts (§6.3).
- In packet mode all session bytes travel as the payload of sequenced data frames, with a window
  of 4, cumulative acks, NAKs and timer-driven retransmission (§5).
- When the session has finished and the link has drained, both sides drop back to raw mode.

## 2. Modes

- **raw**: no packet protocol.
- **LSEC**: 1-byte length, frames of up to 128 bytes.
- **HSEC**: 2-byte length, frames of up to 1024 bytes.
- **ASCII** (with LSEC or HSEC): every frame byte is sent as printable characters (§3.1), for
  lines that are not 8-bit clean. Maximum payload L in ASCII mode: 78 (LSEC) or 674 (HSEC).
- Sizes:

| | header | max L (binary) | max L sent in ASCII mode |
|---|---|---|---|
| LSEC | 6 | 79h (121) | 4Eh (78) |
| HSEC | 7 | 3F8h (1016) | 2A2h (674) |

## 3. Frame format

```
binary LSEC:  02 | L          | ctl | p0 | H1 H0 | [ d1 .. d(L-1) | D1 D0 ]
binary HSEC:  02 | Llo Lhi    | ctl | p0 | H1 H0 | [ d1 .. d(L-1) | D1 D0 ]
```

- STX 02.
- L = number of payload bytes, p0 included.
  - Data frame: L = the number of bytes the sender has queued, at most the maximum for the mode.
  - Every control frame: L = 1. HSEC adds a high byte of 0.
  - HSEC stores the low byte first.
- p0 = the first payload byte, or the control code.
- The data part is present only when L≠1. Receiver: L≤1 means the frame ends after the header.
- **CRC**: CRC-16, poly 1021h, MSB first. Init FFFF, output inverted, stored high byte then low.
  In catalogue terms that is CRC-16/GENIBUS.
  - Header CRC (H1 H0) covers L, ctl and p0 (the STX is excluded).
  - Data CRC (D1 D0) starts again from FFFF and covers d1..d(L-1).
  - Receive check: run the CRC over the field plus its CRC bytes and compare the result with
    residue 1D0Fh.
- Sizes:
  - Header is 6 bytes (LSEC) or 7 (HSEC).
  - A receiver rejects L > 79h (LSEC) or L > 3F8h (HSEC), whatever the ASCII mode. A bad L is
    handled like a CRC error.
  - Biggest frame: 6+120+2 = 128 (LSEC), 7+1015+2 = 1024 (HSEC).

### 3.1 ASCII packets

Every frame byte, the STX included, is encoded. The encoder state runs continuously across frames;
it is reset only when the link is reset, **not per frame**.

Let hi(b) = b>>6 and lo(b) = b&3Fh. The encoder keeps a state and a current high part `cur_hi`.

Encoder:
- **State 0**: emit the prefix char `20h + (hi(b) | hi(next)<<2)`, chars 20h–2Fh.
  - next = the following byte of the same frame, if any; hi(next) becomes `cur_hi`.
  - At the last byte of a frame, bits 2–3 are 0 and `cur_hi` keeps its old value.
  - The byte is not consumed yet; state becomes 1.
- **State 1**: emit `30h + lo(b)` (chars 30h–6Fh) and advance.
- **State ≥2**: if hi(b) == `cur_hi`, emit `30h + lo(b)`. Otherwise go back to state 0 for this byte.

So a prefix covers one byte with its own high bits, followed by a run of bytes that share hi = `cur_hi`.

Optional software parity in ASCII mode (the line itself is 8N1):
- mark: bit 7 set on every char;
- even or odd: bit 7 = parity over the 7-bit char.

Decoder:
- Take c &= 7Fh.
- c < 20h:
  - 11h (XON) ends an XOFF pause.
  - 13h (XOFF) pauses sending, until XON or a timeout of one retransmit-timer period (§5.1).
  - Every other control char is ignored and gives no data.
- 20h–2Fh: prefix. P = c−20h; no data.
- ≥30h: byte = (c−30h) | (P&3)<<6.
  - After the first data char the prefix becomes P>>2, so the following chars take hi = (P>>2)&3.
- XON/XOFF is acted on only in ASCII mode. Neither side sends it as part of the protocol. In
  binary mode 11h/13h are ordinary data.

On the wire, a frame that starts from a fresh state 0 begins `20h 32h` for any L<40h. The
answering side relies on this to detect ASCII mode (§6.3).

## 4. The ctl byte

Layout: bits 7–6 = type, bits 5–3 = N(S), bits 2–0 = N(R).
- N(R) is always the last sequence number received in order.
- Before anything has been received N(R) = 7. That is why the opener frame has ctl 07.

| Type | Frame | ctl | p0 | Sequenced |
|---|---|---|---|---|
| 0 | data | `00 sss rrr` | first data byte | yes |
| 1 | ack | `01 000 rrr` = 40h\|N(R) | 00 | no |
| 2, code 4 | NAK | `10 000 rrr` = 80h\|N(R) | 04 | no |
| 2, other code | sequenced control | `10 sss rrr` | code (0Fh accept, 10h refuse) | yes, L = 1 |

A retransmitted frame is sent with its original ctl, but with the current N(R).

Receiver:
- **Type 1**: ack processing only.
- **Type 2 with (p0&1Fh) == 4**: NAK (§5). Then ack processing.
- **Type 2 with any other p0, and type 0**: a sequenced frame. Type 3 is handled the same way;
  no sender is known to build it.
  - A type-2 frame is not passed to the session. (p0&1Fh)=0Fh means "accept" and 10h "refuse"
    (§6.2). Other codes have no effect.
- **The answering side's first frame, ctl 80h**, is therefore a type-2 sequenced frame with
  N(S)=0 and N(R)=0 (it acks the opener). It must carry p0=0Fh for the caller to proceed.
  - The same ctl value would be a NAK if p0=04.

Every received frame has its N(R) processed, whether or not its N(S) was accepted.

## 5. Sliding window

- Sequence numbers mod 8.
- **Tx window 4.** A sender has at most 4 sequenced frames outstanding (sent and not acked).
- **Ack**: N(R) acks every outstanding frame up to and including N(R). Acks are cumulative.
- **Rx window 4**: a receiver accepts N(S) in [expected, expected+4).
  - A frame already held: a duplicate, dropped.
  - Otherwise, if N(S) ≠ expected (out of order), it is held and a NAK is sent.
  - N(S) outside the window: dropped, no NAK and **no ack**.
- **Delivery**: frames are delivered to the session in order. A receiver may hold a frame back
  while the session has no room for it; the sender sees this as a late ack.
- **Send order** when several things are due: NAK or control frame, then retransmissions, then new
  data (while fewer than 4 frames are outstanding), then a pure ack.
  - Data, retransmit and control frames carry N(R), so they make a pure ack unnecessary.
  - An ack is sent only after an in-order delivery. A duplicate or old frame does not cause a
    re-ack; a lost ack is recovered only by later traffic. (Some peers re-ack; see §9.)
- **NAK**: sent for
  - a CRC error in header or data, or a bad L;
  - an out-of-order frame inside the window;
  - a frame-receive timeout (§5.1).
  - A NAK still pending is cancelled by any in-order delivery.
  - The NAK carries N(R) = the last frame received in order; it asks for N(R)+1.
- **On receiving a NAK**: the frame N(R)+1 is retransmitted if it is still outstanding, and its
  retransmit timer is stopped. Only that one frame, not the window.
- **Resync after a CRC error**: the receiver searches the bytes of the broken frame, from the byte
  after its STX, for a new STX, so a frame start hidden inside a damaged frame is found. No second
  NAK is sent during that search.
- **Retransmit timer**: one per outstanding frame, started when the frame has been completely sent
  and stopped on ack or NAK. On expiry the frame is retransmitted if it is still outstanding.
  - There is no retry limit in the link layer. A dead link is detected by the session timeouts.

### 5.1 Timer values

| Timer | 300 bps | 1200 bps | 2400 bps | above 2400, or flow control / HSEC at ≤2400 |
|---|---|---|---|---|
| retransmit (per frame) | 70h ticks (6.15 s) | 1Ch (1.54 s) | 0Eh (0.77 s) | 70h (6.15 s) |
| frame receive timeout (from STX, and again after a good header) | same | same | same | same |
| ack delay (where a peer uses one) | 2 ticks | 2 | 2 | 2 |

- The 1200/2400 values apply only on a plain serial port with no speed lock and no forced flow
  control; otherwise 70h ticks are used at every speed, including HSEC at ≤2400.
- On a frame-receive timeout the receiver sends a NAK and resynchronises.
- Opener wait: 222h ticks (30 s).
- Link drain at the end of a session: up to 5Bh ticks (5 s) until nothing is outstanding.

## 6. Link setup

### 6.1 Choosing the mode (caller)

- **No packet protocol** if the connect speed is above 2400 and error correction is switched off
  by the caller's options ("HSEC/OFF" or "/NOHSEC"). The default is on.
- Mode: LSEC or HSEC if forced by option; otherwise HSEC above 2400, LSEC at ≤2400.
- ASCII mode only by option (an "easy connect" setting forces ASCII + LSEC).

### 6.2 Opener (caller)

1. Wait 9 ticks.
2. Send `FF AA 55 11` as one ordinary data frame: N(S) 0, N(R) 7, so ctl 07, L=4, p0=FF, data
   AA 55 11, then the data CRC.
3. Wait up to 30 s:
   - a type-2 sequenced frame with code 0Fh: accepted;
   - code 10h: refused;
   - otherwise: timeout.
4. **HSEC→LSEC fallback**: a caller that opened in HSEC and receives a frame whose header CRC is
   valid after exactly 6 bytes (an LSEC header) switches to LSEC, sends the opener again and
   restarts the 30 s wait.

### 6.3 Answering side

The link starts in raw mode.
- Byte 80h above 2400 bps: the caller runs without the packet protocol. Discard the input and
  answer the session byte 81h.
- Byte 02: start collecting a binary frame.
- (Byte & 7Fh) == 20h: start collecting an ASCII frame.
- Then collect up to 80h bytes. After ≥6 bytes, check the first CRC:
  - skip the first byte, run the CRC over the rest (decoding ASCII when collecting ASCII);
  - residue 1D0Fh after exactly 6 counted bytes = LSEC, after more than 6 = HSEC.
- On success: switch to that mode, parse the collected bytes as the opener frame, wait up to 30 s
  for the data `FF AA 55 11`, then send the **sequenced type-2 frame with p0=0Fh** (accept),
  ctl 80h for the first frame.
- The answering side uses whatever format the caller used. Nothing is negotiated.

### 6.4 Flow control

- Hardware flow control (RTS/CTS) is used when configured, and by default above 2400 bps and for
  HSEC at ≤2400. A receiver drops RTS when it has ≤16 bytes of room.
- XON/XOFF only in ASCII mode (§3.1).

## 7. What the session sees

- The session receives the payload bytes only: p0 followed by d1..d(L−1), without headers.
  Control frames are not passed up.
- Session opening bytes: the caller sends 80h, the answering side replies 81h. They travel as
  data inside the link, or raw when there is no packet protocol.
- After the session the link drains and returns to raw mode.

## 8. Modem and line (observed caller behaviour)

- The caller dials and waits for `CONNECT` for 444h ticks (60 s), or 255 s with user modem
  strings. It answers with `ATS0=1` and waits for `RING`, then `CONNECT`.
- The caller sets its serial port to the CONNECT speed unless the speed is locked. It reads the
  speed digits after `CONNECT` with a quirk: **the first '0' ends the number**, and the result is
  matched against 1152, 576, 384, 192, 96, 48, 24, 12 (115200 … 1200). A plain `CONNECT` means
  300; an unmatched value keeps the configured speed.
- A direct (null-modem) connection skips the modem part and uses the configured speed.
- The link layer does not watch carrier.

## 9. Peer differences seen on the line

| Behaviour | Seen |
|---|---|
| ack timing | Remote 3.40B acks at once after an in-order delivery; RCONNECT 1.00 acks about 2 ticks later |
| NAK rule | Remote 3.40B and the post office side NAK only a new, in-window, out-of-order frame; RCONNECT 1.00 NAKs every sequenced frame with N(S) ≠ expected, including old duplicates outside the window (see `nak-storm.md`) |
| re-ack of duplicates | not sent by Remote 3.40B; whether the post office side sends them is not determined |

## 10. Open questions

1. Not determined: which side sends control code 10h (refuse), and when. A capture of a refused
   call would settle it.
2. Not determined: which other type-2 codes the answering side sends (receivers act only on 04,
   0Fh and 10h). Captures of a long session would settle it.
3. Not determined: whether the answering side re-acks duplicates. Test it by dropping one of the
   caller's acks.
4. Not determined: whether any peer sends ctl type 3.
5. Edge case: an in-order delivery on the answering side before the accept has gone out cancels a
   pending control frame. Harmless with a caller that waits for the accept before sending data.
