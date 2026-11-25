# Session negotiation (B0 80 / AE / AF 01 packets) and session enciphering

Compatibility: this exchange is what cc:Mail Router 6.x post offices and cc:Mail Mobile clients
put in front of the old `80 → 81` login (spec/session-layer.md §2). A server that implements it
as specified here is compatible with them.

This file covers the option exchange and the stream cipher it can switch on. A constructed
transcript (§6) and verified test vectors (§3.5) are included.

Terms:
- "C" = caller, "A" = answerer.
- **Post office peer** = a peer that uses the protocol id "NMTP" (post office to post office).
- **MOBP client** = a client that uses the protocol id "MOBP" (a mobile client).
- "Session byte" = a byte passed between the session code and the link layer. These bytes go
  inside link frames when packets are up, or bare in raw mode.
- Integers are little-endian.

## 1. Where it sits and who uses it

| side | sends |
|---|---|
| post office peer calling | `B0 80` on **every** call, right after the link start + opener (or raw), where an old caller sends `80` |
| MOBP client calling | `B0 80` the same way |
| older clients | never `B0`; plain `80` (spec/session-layer.md §2) |
| answerer (post office peer or MOBP client) | `AE` when `B0 80` is seen |

Protocol ids: **"NMTP"**, post office to post office; **"MOBP"**, mobile client. Every known
answerer checks the id.

Not determined: whether every mobile client release uses MOBP (§9 #6).

## 2. Byte sequence

### 2.1 Caller

1. Drain input, start the link + opener if in packet mode, clear the cipher flag, then send
   **`B0`, `80`**. A send failure ends the call.
2. Loop until the caller's timeout (TIMEOUT/, default 30 s, on a post office peer) passes with
   no 81:
   - byte **81** → old answerer: no negotiation, go on to login.
   - byte **AE** → run the negotiation (§2.5). **Success**: send `80` (enciphered if the cipher is
     on), then look at one byte if one is ready: 81 → login. Otherwise keep looping. **Failure**:
     a post office peer goes straight to the login check (step 3) **without** sending 80 or
     waiting for 81. A MOBP client gives up the call.
   - any other byte: ignored.
   - timeout: the call fails ("data connection not accepted").
3. Login check: a caller configured to refuse unenciphered sessions (the NR switch on a post
   office peer) with the cipher off → sends bare **8C** and ends the call ("connection to old
   post offices disabled"). A MOBP client does the same when its "refuse unsecure post office" flag
   is 1; what sets that flag is not determined (§9 #5).
4. The old login continues (name, 8B/password, 82/83 + PO name), spec/session-layer.md. Reply
   **9F** after the name → the caller ends the call with the same "old post offices disabled"
   meaning. Known answerers never send 9F; which peers send it is not determined.

Fallback that keeps old answerers working: the caller accepts a plain **81** to its `80` and
ignores every other byte. An old answerer therefore works if it drops the stray `B0` and answers
the `80`.

### 2.2 Answerer

| input | action |
|---|---|
| `80` (no B0 before) | old login: drain input raw, send 81. See router-answer.md 1.2 for the 5.12 s silence rule at > 2400 bps raw |
| `B0` | wait for the next byte, within the TIMEOUT/ budget of the sniff phase (the clock is not restarted) |
| `B0` + not `80` | both bytes dropped; the peer's negotiated character-set values cleared; sniffing goes on |
| `B0 80` | if no packets yet and speed index > 2: needs **512 cs (5.12 s) of silence**, and any byte in that time drops the pair. A MOBP client as answerer waits 3F2h (1010) ticks of its timer; the unit is not determined. Then send **`AE`** in clear, mark the session "negotiated", and run the answer loops (§2.4). They return 0 → **the call ends**. They return 1 → back to sniffing |
| `80` after a negotiation | "negotiated" set → drain raw, send `81` (enciphered if on), old login |

There is no "older reply" case on this side: a caller that does not send B0 is an old caller and
gets the old login. **An answerer configured with NR refuses it with bare 8C after its name**,
because the check is "NR set and cipher off", i.e. on the **cipher flag**, not on "negotiated". A
negotiation without type 6 (for example a MOBP client configured with encryption off) is
refused under NR too.

### 2.3 Packet format

```
off 0  AF            magic
off 1  01            version
off 2  type   u16    request type; reply = type | 8000h
off 4  status u16    0 ok, 1 counter-offer (data carries A's value), 3 unknown id, 7 unknown type, 9 refused
off 6  len    u16    data length
off 8  data[len]     d0..d3 = dword / id, d4..d5 = word value, d6.. = payload (offset 14 of the packet)
```

- The reader reads 8 bytes, then requires `AF 01` (else "not a packet"), then reads `len` bytes.
  Known answerers read `len` into a 128-byte buffer **without a bound check**. Keep `len` ≤ 120.
- The caller's reader does **not** read data when status = 7, and returns the status only if the
  type matches the one expected, else "not a packet".
- `len` is set from the type (and status) only. Real sizes: type 1, 19, 21, 22, 24 = 6; 6 = 96
  (60h); 18 = 10; 23 = 8; 8, 9 = 0 (and status forced 0). Replies 8001h, 8013h, 8016h, 8018h = 6
  if status 1, else 0; 8006h, 8015h = 0; 8012h = 10; 8017h = 8 (the same on both peer kinds). For
  any other reply type the field is **left as received**, and a status-7 reply then carries a
  stale `len` with no data.
- Replies are built **in the request buffer**: header rewritten, data kept. So a reply echoes the
  request's d0..d5 except for the fields the handler overwrites. The caller also reuses one buffer,
  so its d0..d3 (and d4..d5 when not set) are **stale bytes from the previous exchange**, normally
  the id from the hello (see §6).

### 2.4 Request types: answerer handling (post office peer; MOBP client as noted)

| type | request data | answerer | reply |
|---|---|---|---|
| 1 hello | d0..d3 id, d4 u16 version | "NMTP": sync mode off; version 100 → status 0, else status 1 with d4 = 100. "MOBP": version ≥ 200 → **sync mode** on; version 100 or 200 → status 0, else status 1 with d4 = 200. Other id → status 3 | `AF 01 01 80 st 00 len 00 [id ver]` |
| 6 key | d0..d3 stale, d4 u16 = 1, d6..d95 key[90] | d4 = 1: store the key, run the key schedule, **cipher on**, reply status 0, which already goes **enciphered**. d4 ≠ 1: reply status 9; if that send succeeds, a second reply type 8015h status 0 follows and the flag is left as it was. Only a failed send clears the flag | 8 bytes |
| 8 end | none | ends the loop; the end loop answers with **type 9** (not 8009h) | `AF 01 09 00 00 00 00 00` |
| 9 | none | ends the loop, no reply | — |
| 18 id | d0..d5 stale, d6 u32 | store the caller's u32 as the **peer id**; d6 = own 32-bit id (a new-format post office value whose meaning is not determined, §9 #3; 0 on an old-format post office; old/new format as in router-to-router.md) | len 10, status 0 |
| 19 | d4 u16 | 1 → status 0; else status 1 with d4 = 1. No state | |
| 20 | — | status 9 | 8014h has no `len` case, so its `len` is stale |
| 21 | d4 u16 | status 0, no state | len 0 |
| 22 sync flags | d0 u32 flags, d4 u16 | store d0 as the **sync flags**; status 1 with d4 = **101** | len 6 |
| 23 char set | d0..d5 stale, d6 u16 | store the caller's value as the **peer character set**; d6 = own value (the post office database's character set; 0 on an old-format post office) | len 8, status 0 |
| 24 ext fields | d4 u16 | 100 → **extended fields** on, status 0; else status 1 with d4 = 100 | |
| other | — | status 7, keep going | 8 bytes, stale len |

Loops: the first loop handles packets until a **type 1** arrives (other types before it are
served), then the end loop handles packets until **type 8** and answers type 9. Any non-`AF 01`
header, a read timeout, or a failed send ends the loop with 0, and the call ends (§2.2). A mobile
client as answerer handles every type the same way, except that it has **no case 24** (it falls
to status 7).

### 2.5 Caller sequence (post office peer; MOBP client as noted)

| # | send | then |
|---|---|---|
| 1 | type 1: post office peer `"NMTP"` + 100; MOBP client `"MOBP"` + 200 | reply status not 0/1 → **fail**. MOBP client: status 1 with version 100 (an older MOBP answerer) → clears its sync-related flags (including the type-21 and mailbox-sync flags) |
| 1a | MOBP client only: configured with encryption off → skip 2–4 | |
| 2 | type 19, d4 = 2 | `v1` = (status ≠ 9). Known answerers answer status 1, so `v1` = 1 |
| 3 | type 19, d4 = 1 | status ≠ 0 → no cipher, skip to 5 |
| 4 | type 6: d4 = 1 (left from 3), key (§3.4) at d6; **cipher on after the send**, key schedule | reply 8006h status ≠ 0 → **fail with the cipher left on** |
| 5 | type 18: d6 = own 32-bit id (old format: 0) | status 0 → peer id = A's value, else 0 |
| 6 | only if `v1`: type 23, d6 = own character set | status 0 → peer character set = A's value, else 0 |
| 7 | post office peer only, if `v1` and extended fields are not forced by configuration (EXTFIELD switch): type 24, d4 = 100 | extended fields = (status = 0) |
| 7a | MOBP client only, if its type-21 flag is set: type 21, d4 = 100 | status ≠ 0 → flag cleared |
| 7b | MOBP client only, if its mailbox-sync flag is set: type 22, d0 = flags, d4 = 100 | status 1 + d4 = 101 → keep; **status 0** → the client reports "mailbox synchronization refused" and clears the flag; other → flag cleared |
| 8 | type 8 | next packet: type 9 → success; another AF 01 packet → fail; non-packet or read failure → result of the type-8 send, i.e. success |

A MOBP client with encryption off skips step 2, so its `v1` stays 1 and it sends 23.

## 3. Enciphering

### 3.1 What is covered, and from when

- One cipher flag per session (on every known peer). When it is 1, **every session byte read or
  written** goes through the keystream XOR.
- The cipher sits **above the link layer**: frames, CRCs, acks and control codes are not
  enciphered. The data bytes inside them are.
- **One keystream for both directions.** There is a single cipher state, used by reads and writes
  alike. Each side advances it once per byte it sends **or** receives, in session order. This
  works only because the session is strictly half-duplex. Any overlap of directions would
  desynchronize it. Example: 91h keepalives are sent enciphered from many places; in the one
  examined, the peer is waiting. Whether every place, or any real pairing, overlaps the two
  directions is not determined (§9 #8).
- Partial writes: before a write the state is saved. After the link takes `k` of `n` bytes, the
  state is restored and re-advanced over exactly the `k` bytes that left; the unsent tail is
  restored to plaintext. Net: the keystream advances only per byte actually sent. Chunking does
  not matter (verified: 1+5+26 bytes = one 32-byte call, §3.5).
- **Raw drains bypass the cipher.** The direct drains of the input (answerer before 81, caller
  before `B0 80`) do not advance the keystream. Bytes the caller sends after its enciphered `80`
  and before it reads 81 would be lost unaccounted, and the stream would desync. A caller must
  send `80` and then wait.
- **Switch-on points.** Caller: after its type-6 send (sent in clear, then flag on, then key
  schedule). Answerer: after reading type 6 (key schedule, flag on), so its **8006h reply is the
  first enciphered byte string**. Everything after that is enciphered: remaining packets, the
  `80`/`81`, name, password, message exchange, `88`.
- A status-9 refusal of type 6 is sent after the answerer has switched nothing on, but by then the
  caller already enciphers. So the caller cannot read it, and it fails anyway. The only clean
  "no cipher" answer is a non-zero status to **type 19 value 1**.
- **Off again** at every session start and at session teardown. **Suspended** during mailbox-sync
  file transfer: the flag is saved, set to 0 around the file transfer and the `A8` marker exchange
  (sent and awaited in clear), then restored. The keystream does **not** advance while suspended.

### 3.2 Key schedule (`seed`, `key`)

The seed is 0 on every known peer.

1. `v = (u16)(-15203 * (u16)(seed >> 9) + 1)` (multiply by 0C49Dh, add 1) = 1 for seed 0.
2. `s[0..89]` = key as 45 u16 words, each XOR `v`, i.e. with seed 0 every even-offset byte has
   bit 0 flipped.
3. `r = (u16)((seed >> 16) ^ v) % 89`; `j = r + 1`; `k = r + 1 - 51`, and if `k ≤ 0` then
   `k += 89`. Seed 0: j = 2, k = 40. Both stay in 1..89, so **`s[0]` is never used**.
4. Generator step: `s[j] += s[k]` (mod 256), output `s[j]`; `j--`, 0 → 89; `k--`, 0 → 89.
   Lags j − k ≡ 51 (mod 89) over 89 cells.
5. Fill `t[0..255]` with 256 generator outputs; `last = t[255]`.

### 3.3 Keystream

Per byte: `i = last; last = t[i]; t[i] = next generator output; byte ^= last`.
This is a Bays–Durham shuffle of the lagged additive generator above.

### 3.4 Key generation (caller only, non-normative)

The answerer accepts any 90 bytes. Existing callers make the key this way: 92 bytes of C
`rand()` after `srand(centiseconds of day)`, then:
`out[0..1] = in[0..1]; out[2] = 0; x = in[0x18]*in[0x37]`; for d = 88..0: `x = x*41C64E6Dh +
3039h`, `out[3+d] = x >> 24`; for d = 63..0: `out[3+d] ^= in[2+d]`; for d = 63..0:
`out[28+d] ^= in[2+d]`; then a mixing pass over p = out+2: 7921 times
`p[a] += p[b] + 1; a--, 0→89; b--, 0→89`, a from 89, b from 38. Key = `out[2..91]` (the copy into
the key buffer drops 2 bytes), so **key[0] = 0 always**. `os.urandom(90)` is just as good for our
calling side.

### 3.5 Reference implementation and test vectors

```python
class Cipher:
    """Session cipher: key schedule + keystream.
    One instance per session; feed every session byte, both directions, in order."""
    def __init__(self, key: bytes, seed: int = 0):
        assert len(key) == 90
        v = ((-15203 * ((seed >> 9) & 0xFFFF)) + 1) & 0xFFFF
        s = bytearray(90)
        for w in range(45):
            x = (key[2*w] | key[2*w+1] << 8) ^ v
            s[2*w], s[2*w+1] = x & 0xFF, x >> 8
        r = (((seed >> 16) & 0xFFFF) ^ v) % 89
        self.s, self.j, self.k = s, r + 1, r + 1 - 51
        if self.k <= 0:
            self.k += 89
        self.t = bytearray(self._next() for _ in range(256))
        self.last = self.t[255]

    def _next(self) -> int:
        s = self.s
        s[self.j] = (s[self.j] + s[self.k]) & 0xFF
        v = s[self.j]
        self.j = self.j - 1 or 89
        self.k = self.k - 1 or 89
        return v

    def crypt(self, data: bytes) -> bytes:   # same call enciphers and deciphers
        out = bytearray(data)
        for n in range(len(out)):
            i = self.last
            self.last = self.t[i]
            self.t[i] = self._next()
            out[n] ^= self.last
        return bytes(out)


def keygen(rnd92: bytes) -> bytes:
    """Key generation of existing callers (non-normative): 92 random bytes -> 90-byte key."""
    a, out = rnd92, bytearray(92)
    out[0], out[1], out[2] = a[0], a[1], 0
    x = a[0x18] * a[0x37]
    for d in range(88, -1, -1):
        x = (x * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        out[3 + d] = x >> 24
    for d in range(63, -1, -1):
        out[3 + d] ^= a[2 + d]
    for d in range(63, -1, -1):
        out[28 + d] ^= a[2 + d]
    p, i, j = out[2:], 89, 38
    for _ in range(7921):
        p[i] = (p[i] + p[j] + 1) & 0xFF
        i = i - 1 or 89
        j = j - 1 or 89
    return bytes(p)
```

Vectors (verified; the Python above gives the same output). "ks" = keystream = `crypt(00 × n)`.

| # | input | output |
|---|---|---|
| TV1 | key = 90 × `00`, seed 0; ks[0..31] | `01 00 02 01 11 01 10 01 10 11 11 11 12 01 10 11 10 12 12 11 11 11 12 12 18 01 11 11 12 11 17 01` |
| TV2 | key[i] = i (`00 01 … 59`); ks[0..31] | `50 b8 31 99 27 5d 03 7e d2 38 83 b0 16 58 98 31 43 63 e5 64 df bb 09 72 c2 2c a7 80 14 5c 07 76` |
| TV3a | keygen(in[i] = i, 92 bytes) | `00 e9 b7 8b d8 ee 87 09 16 85 db 50 ba 46 bc ef e4 a1 f9 74 09 b7 9c 44 c3 e7 8c 53 95 f4 ea ed 33 0a e1 7d e5 c6 dd 35 18 1a a4 82 bf 30 d0 56 42 eb 30 ba 82 e1 d3 0f 76 a1 e1 11 cb a8 2b 01 f1 c3 c9 41 ca c4 42 1b 6b 19 2c cf 7f 4f 1d fc 54 60 b4 d6 6d fa 61 c2 21 bd` |
| TV3b | key = TV3a; ks[0..31] | `15 b7 e5 bd e5 3f 4b 42 a3 38 33 88 ab c0 31 ee 58 35 41 c3 79 86 ea 67 9f 65 db b5 61 f1 9d 42` |
| TV4 | TV2 key, pieces of 1, 5, 26 bytes | identical to TV2 (state carries across calls) |

## 4. What is negotiated and what it changes

| item | packet | result | effect later |
|---|---|---|---|
| protocol id + version | 1 | sync mode = 1 for MOBP ≥ 200 | **mailbox-sync mode** on the answer side: outbox first, tag 32 (router-answer.md §2); the peer id (type 18) is recorded on synced items. NMTP: none |
| cipher | 19 (=1), 6 | cipher flag | every later session byte enciphered (§3); passes the NR check |
| "type 19 value 2" probe | 19 (=2) | caller `v1` | status 9 → caller skips 23 and 24. Meaning not determined; no known answerer answers 9 |
| 32-bit id | 18 | peer id | sync mode: recorded on synced items and matched against them. What the value identifies: not determined |
| character set | 23 | peer and own character set | the peer's set is applied **only while the peer's name is read** (answerer: the caller's name; caller: the PO name), then the own set again. When the two differ, that name is converted between them. The values are probably code-page numbers (not determined); 0 = no conversion |
| ADE extended fields | 24 | extended-fields flag | directory (ADE) records with extended fields; a post office peer can also force it on or off by configuration (EXTFIELD switch) |
| type 21 | 21 | MOBP client: type-21 flag | post office answerer: nothing stored. Meaning not determined |
| sync flags | 22 | answerer: sync flags | `\| 2` passed as the options of the A2 file sync. Bits a MOBP client sets from its options: 08h/10h/18h from a three-valued option, 80h or 100h from a two-valued option, and 04h, 40h, 200h from single options. Bit meanings not determined |
| post office identity, passwords, serials, compression | — | — | **not negotiated**: no packet carries them. Identity and password stay in the old login |

Extra commands: the mailbox-sync codes A2/A5 (with replies A1/85/A3/A7/A8) are handled in the
caller's turn. Only a new-format answering post office serves them, independently of the
negotiation. Their protocol is out of
scope here; the cipher is suspended for the file part (§3.1).

## 5. Passwords and authentication

- The negotiation has **no password, challenge or authentication**. The key travels in clear
  (type 6), so the cipher only hides traffic from someone who missed the start of the session.
- A calling post office logs in with the old login (spec/session-layer.md). Name = its own post
  office name. On 8B it sends its **call password** (a separate password used when calling), or
  its post office password if no call password is set, as length byte + NUL-terminated string
  (spec/router-to-router.md §1.3).
- The answerer checks it as in router-answer.md 1.4/1.5. Enciphered or not, the password bytes
  are the same plaintext under the cipher.

## 6. Constructed transcript (NMTP, post office ↔ post office, cipher key = TV2)

Constructed from the rules above, **not captured**. Own values: caller id 12345678h, char set 850;
answerer id 9ABCDEF0h, char set 1252; extended fields not forced. Wire bytes verified. These are
session bytes: in packet mode each line sits in link data frames.

| dir | | plaintext | wire |
|---|---|---|---|
| C→A | clear | `b0 80` | same |
| A→C | clear | `ae` | same |
| C→A | clear | `af 01 01 00 00 00 06 00 4e 4d 54 50 64 00` | same |
| A→C | clear | `af 01 01 80 00 00 00 00` | same |
| C→A | clear | `af 01 13 00 00 00 06 00 4e 4d 54 50 02 00` | same |
| A→C | clear | `af 01 13 80 01 00 06 00 4e 4d 54 50 01 00` | same |
| C→A | clear | `af 01 13 00 00 00 06 00 4e 4d 54 50 01 00` | same |
| A→C | clear | `af 01 13 80 00 00 00 00` | same |
| C→A | clear | `af 01 06 00 00 00 60 00 4e 4d 54 50 01 00` + key `00 01 … 59` | same |
| A→C | enc | `af 01 06 80 00 00 00 00` | `ff b9 37 19 27 5d 03 7e` |
| C→A | enc | `af 01 12 00 00 00 0a 00 4e 4d 54 50 01 00 78 56 34 12` | `7d 39 91 b0 16 58 92 31 0d 2e b1 34 de bb 71 24 f6 3e` |
| A→C | enc | `af 01 12 80 00 00 0a 00 4e 4d 54 50 01 00 f0 de bc 9a` | `08 81 06 dc 07 76 08 80 99 97 71 6a 7c da d9 6f b4 ee` |
| C→A | enc | `af 01 17 00 00 00 08 00 4e 4d 54 50 01 00 52 03` | `a1 69 dc 52 b0 bf f4 17 18 ed 15 39 c6 e6 fa 75` |
| A→C | enc | `af 01 17 80 00 00 08 00 4e 4d 54 50 01 00 e4 04` | `9c 92 27 1b 6f a9 60 9b f5 f6 2f b6 93 38 60 ac` |
| C→A | enc | `af 01 18 00 00 00 06 00 4e 4d 54 50 64 00` | `f3 84 b8 72 5f f9 65 47 19 d3 07 fe 4a a1` |
| A→C | enc | `af 01 18 80 00 00 00 00` | `96 80 d8 c8 53 a9 3d 75` |
| C→A | enc | `af 01 08 00 00 00 00 00` | `a5 71 ab 27 01 28 b3 17` |
| A→C | enc | `af 01 09 00 00 00 00 00` | `4d 7c 0c 7a ea 50 85 9c` |
| C→A | enc | `80` | `e5` |
| A→C | enc | `81` | `5a` |

Then the old login continues enciphered from the same stream position.

Stale bytes: `4e 4d 54 50` ("NMTP") in every caller packet after the hello comes from the hello's
data (the 8001h reply had len 0, so it did not overwrite them). The answerer echoes them back. The
d4 = `01 00` in types 6, 18 and 23 is left from type 19 value 1. A MOBP client has `"MOBP"` and
its own leftovers there. **An implementation must not check d0..d3 except in type 1** (no known
handler reads them, §2.4).

MOBP differences (MOBP client ↔ post office answerer): hello
`af 01 01 00 00 00 06 00 4d 4f 42 50 c8 00` → `af 01 01 80 00 00 00 00` (sync mode on). No type
24. Optional type 21 (`… 15 00 00 00 06 00 <d0..d3> 64 00` → `af 01 15 80 00 00 00 00`). Optional
type 22 (`af 01 16 00 00 00 06 00 <flags u32> 64 00` → `af 01 16 80 01 00 06 00 <flags u32> 65 00`).

## 7. Implementation notes for our server

Answering:
- `B0` then `80` → send `AE` and serve packets per §2.4 until type 8 → type 9. Then expect the
  enciphered `80`, drain, send the enciphered `81`.
- To negotiate **without** the cipher: type 19 value ≠ 1 → status 1, d4 = 1 (as known answerers
  do); type 19 value 1 → any non-zero status (e.g. 9). The caller then skips type 6. Never refuse
  type 6 itself (§3.1). A caller with NR set then refuses us with 8C.
- Declining the follow-on features (all from the caller's rules):
  - MOBP sync mode: answer the MOBP hello with status 1, d4 = 100. The client then clears its
    sync-related flags and sends no 21/22. What the remaining one of those flags gates later in the
    client is not determined.
  - Type 22: status 0 → the client reports "mailbox synchronization refused". Any status other
    than 0, or than 1 with d4 = 101 (e.g. 7), clears the flag silently. Status 1/101 keeps mailbox
    sync on.
  - Type 24: any non-zero status → extended fields off on the caller.
  - Types 18 and 23 with no own value: reply status 0 with value 0, as an old-format post office
    does. The peer then treats its id as 0 and does no character-set conversion.
  - Type 21: status 0 (as a post office answerer does) or 7. Either way nothing is agreed.
- To not negotiate at all: on `B0`, drop it and answer the following `80` with `81`. The caller
  takes 81 as an old answerer. Sending `AE` and then failing ends badly, because a post office
  caller jumps straight into login (§2.1).
- Echo the request's data in replies, and set `len` as in §2.3.

Calling:
- Send `B0 80`, accept `81` (old answerer) or `AE`. After `AE` send §2.5. After type 9 send `80`,
  then read `81` with nothing else sent in between.

Both: one `Cipher` per session, applied to session bytes in send/receive order, switched on per
§3.1, never applied to link framing.

## 8. Post office peer vs MOBP client

| point | post office peer | MOBP client |
|---|---|---|
| B0 80 send | yes | same |
| 81/AE loop | negotiation failure → login without 80 | negotiation failure → the call ends |
| caller packets | §2.5, NMTP/100 | MOBP/200, optional encryption off, no 24, adds 21/22 |
| answer handler | §2.4 | same minus 24 |
| key schedule / cipher / key generation | §3.2 / §3.3 / §3.4 | same |
| raw B0 80 silence before AE | 512 cs | 3F2h timer ticks |
| cipher suspension (sync) | yes | same |

## 9. Not determined

1. Meaning of type 19 value 2 (and which answerer answers it with status 9), type 20, type 21.
2. Bit meanings of the type-22 flags.
3. What the type-18 32-bit id identifies.
4. Which peers send reply 9F after the name.
5. What configures a MOBP client to refuse an unenciphered answerer.
6. Whether every mobile client release uses the MOBP id.
7. Unit of a MOBP client's 3F2h silence wait as answerer.
8. Whether any real pairing sends in both directions at once while enciphered (91h, aborts),
   which would desync the shared keystream. A capture of an enciphered session with a long
   message store would show it.
9. How a peer post office's call password (§5) is set.
