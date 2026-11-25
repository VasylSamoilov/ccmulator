# NAK storm between RCONNECT 1.00 and our server on a noisy line

On a noisy line, a call between the RCONNECT 1.00 client and our server produced long runs of
NAKs. This file explains why, gives the sender rules our server now follows, and lists the
measured results.

The runs used the line simulator `tools/linesim.py` (`--bps 2400 --ber 1e-4 --burst 2e-4 --seed 7`
for the main capture). Two runs of that setting are referred to:
- **run 1**: server log ending 02:26:19.111;
- **run 2**: the main capture, with the line simulator's byte log, the frame list from
  `tools/frames.py`, and the server log.

Arrival times at the client are computed from the line simulator's pacing (when each frame
finished arriving), not taken from the frame list. Link terms (N(S), N(R), window, timers) are
those of `link-layer.md`.

## 1. Summary

- **Cause, part 1: the client's NAK rule.** RCONNECT 1.00 NAKs every sequenced frame whose N(S)
  is not the expected one, including old duplicates outside the window. Other peers (Remote
  3.40B, the post office side) NAK only a new, in-window, out-of-order frame.
- **Cause, part 2: our sender (before the fix).**
  - It answered every NAK with an immediate full copy of N(R)+1.
  - It wrote that copy into a TCP stream. Behind the stream, the line still held several frames
    sent earlier.
  - So copies piled up. Each copy arrived after the receiver had moved on, so the client NAKed
    it. That NAK made another copy.
  - A sender that hands over one frame at a time, and the next only when the previous one has
    left the port, does not get into this (section 4).
- **The "intact retransmission answered with a NAK" is an artefact of the timestamps.**
  - Frame list times are when the line simulator took the bytes in, not when they arrived.
  - Every NAK answers the frame that had just finished arriving, which was a frame queued 3–6
    frames earlier.
  - All 46 NAKs are explained: 7 damaged frames, 3 out-of-order frames ahead in the window, and
    36 stale copies of our own.
  - No NAK answers an intact frame with N(S) = expected.
- **No run shows a permanent deadlock.**
  - Run 1 ends the 86-loop after 5 NAKs with an 87 and "done" at 02:26:19.111.
  - The line simulator logs "call end" in the same second. Run 2 shows the same tail with 6 NAKs.
  - No server log contains an unbounded loop.
  - The loop has to end: each stale copy gives one NAK and one resend, and once N(R)+1 is no
    longer outstanding nothing is resent.
- **Fix.** Act on at most one NAK per sequence number until that frame's retransmit timer next
  fires. This needs no line speed (section 5.1).
- **Second fix, needs the line rate.**
  - The retransmit timer starts when the copy has left the line, not when it is handed over.
  - A NAK that arrives while the copy is still on the line is ignored.
  - Without this, the model predicts a permanent livelock at 300 bps even on a clean line (section 6).

## 2. Observed receiver behaviour of RCONNECT 1.00

| | Remote 3.40B | RCONNECT 1.00 |
|---|---|---|
| NAK for a sequenced frame | only an in-window, not yet held frame with N(S) ≠ expected | **every** frame with N(S) ≠ expected, also outside the window; the frame is stored only if it is in the window and not yet held |
| NAK on a damaged frame | yes | yes |
| NAK on frame-receive timeout | yes | yes |
| NAK cancelled | by an in-order delivery | by an in-order delivery |
| ack after delivery | at once | after 2 ticks (0.11 s) |
| NAK frame | ctl 80h\|N(R), p0 04 | the same |
| send order | NAK, retransmit, data, ack | the same |

The measured ack latency agrees with 2 ticks. Each intact expected arrival is acked 0.07–0.11 s
after it ends (e.g. arrival 156.039 → ack 156.136; 159.773 → 159.872; 162.439 → 162.507).

## 3. Why the storm happens, step by step

### 3.1 What RCONNECT does with one arriving frame

1. Data CRC bad: NAK (unless it is already resynchronising after an earlier error).
2. Sequenced frame with N(S) ≠ expected: NAK. If it is in the window and not yet held, it is
   stored; otherwise it is dropped. The NAK stays pending either way.
3. Acks are processed from N(R).
4. Only an in-order delivery cancels the pending NAK. A stale duplicate is never delivered, so
   its NAK goes out.
5. The NAK carries N(R) = expected−1. It is sent about 10 ms after the frame's last byte.

So, at this client:
- every damaged frame gives one NAK;
- every frame ahead of the gap gives one NAK;
- **every copy of a frame already delivered gives one NAK**;
- only an intact frame with N(S) = expected does not.

### 3.2 Our sender (before the fix)

- A NAK made seq = N(R)+1 due for an immediate resend.
- There was no check that an earlier copy was still on its way.
- Frames were handed to TCP immediately, however many were already queued for the line.
- The line simulator (like any modem or bridge buffer) queues them and clocks them out at 2400
  bps, 0.533 s per 128-byte frame.
- The retransmit timer counted from hand-over, not from when the frame had left the line.

### 3.3 The capture, with arrival times

Times are the line simulator's clock. Damage is from the `BAD DCRC` marks of `tools/frames.py`.

Not every resent copy was intact:
- The originals of seq 4 and seq 5 (sent 153.117 and 153.612) were damaged.
- So were the seq-4 copies sent at 156.749 and 158.882.

| arrives at RCONNECT | our frame (sent) | RCONNECT answers | why (rule) |
|---|---|---|---|
| 153.906 | seq 2 (152.020), damaged | NAK 81 153.915 | CRC |
| 154.439 | seq 3 (152.568) | NAK 81 154.449 | N(S)≠2, stored |
| 154.973 | seq 4 (153.117), damaged | NAK 81 154.984 | CRC |
| 155.506 | seq 5 (153.612), damaged | NAK 81 155.517 | CRC |
| 156.039 | seq 2 copy 1 (154.083) | ack 43 156.136 | delivers 2, 3; 4 and 5 are missing (damaged), so not 45 |
| 156.573 / 157.106 / 157.639 | seq 2 copies 2–4 (154.617 / 155.152 / 155.684) | NAK 83 ×3 | stale: N(S)=2 ≠ 4, outside the window, NAK anyway |
| 158.173 / 158.706 | seq 6, 7 (156.302) | NAK 83 ×2 | ahead in the window, stored |
| 159.239 | seq 4 copy 1 (156.749), damaged | NAK 83 159.251 | CRC |
| 159.773 | seq 4 copy 2 (157.282) | ack 44 159.872 | delivers 4 |
| 160.306 / 160.839 | seq 4 copies 3, 4 | NAK 84 ×2 | stale |
| 161.373 | seq 4 copy 5, damaged | NAK 84 | CRC |
| 161.906 | seq 4 copy 6 | NAK 84 | stale |
| 162.439 | seq 5 timer copy (159.770) | ack 47 162.507 | delivers 5, 6, 7 |

**The feedback loop:**
1. Each of those NAKs reached us while 3–6 frames were still queued ahead on the line.
2. We answered each with one more copy of N(R)+1.
3. That copy arrived after the gap had been filled, so it was stale, so RCONNECT NAKed it.
4. Round 1 had four NAKs. All four asked for seq 2, which really was missing, but only the first
   was needed. The other three produced three surplus copies.
5. Every later round is fed by the previous round's surplus copies:
   - 163.515–166.182: 6 × NAK 80;
   - 168.849–171.516: 6 × NAK 84;
   - 174.182–176.850: 6 × NAK 80;
   - 179.516–182.182: 6 × NAK 84.

Classifying every NAK of the call by its trigger gives:

| NAK trigger | count |
|---|---|
| damaged | 7 |
| ahead in window | 3 |
| stale (our own copies) | 36 |
| N(S) = expected | **0** |
| total | 46 = the server's `naks_rx` |

Each NAK is sent 9–12 ms after the modelled arrival end of its trigger, which supports the arrival model.

Timer-driven copies add to the stale supply:
- At 162.484 (server 02:29:53.871) the 6.15 s timers of seq 6 and 7 fired. They count from
  hand-over (156.302), but RCONNECT had held both frames since 158.17 / 158.71 (stored ahead of
  the missing 4 and 5).
- The copies arrived at 165.639 / 166.173 and drew NAK 80 ×2.
- A sender whose timer starts when the frame has left the line would also resend them, since
  they were unacked, but here about 2 s later.

### 3.4 The "final 1-byte frame" loop (NAK 86 … 87)

- **What was queued.** At 183.277 we send ack 44 and seq 7 (3c, L=1).
  - They are queued behind six copies of seq 5 (2b) sent 179.684–182.350, each in answer to a
    stale-triggered NAK 84.
- **The loop.**
  - Each seq-5 copy arrives (183.631 … 186.298) after seq 5 has been delivered (ack 45 at 182.777).
  - The client expects 7, so each copy draws NAK 86.
  - We answer each with another 6-byte copy of seq 7, queued again behind the rest.
- **The end.**
  - The original 3c arrives at 186.348 and is delivered.
  - The next 3c copy (N(S)=7, expected 0) draws NAK 87 at 186.509.
  - Its N(R)=7 acks seq 7, our outstanding set empties, and the session ends ("done").

A permanent loop is not possible here without new damage:
- an intact copy of seq 7 arriving while 7 is expected is either delivered or dropped with no NAK (already held);
- a NAK needs an arrival with N(S) ≠ expected, a damaged frame, or a frame-receive timeout;
- the stale supply is finite (k copies queued → k NAKs → at most k resends), and it reaches zero
  once nothing is outstanding.

Run 1 shows the same tail: 5 × NAK 86 at 0.53 s intervals, then 87 and "done" at 02:26:19.111,
with no damage after 02:25:59. In run 1 we sent 5 copies of seq 5; in run 2 we sent 6. A loop that
never ends is not in any log (section 8).

## 4. A sender that avoids the storm

- **One frame in flight.** The sender hands a frame to the port only when the previous one has
  completely left it (the output queue is empty).
- **NAK handling.** A NAK retransmits only N(R)+1, not the window, and without waiting for the
  timer. A frame already waiting for retransmission is not queued twice.
- **Retransmit timer from completion.** The timer starts when the frame has left the port, not
  at hand-over (6.2 s).
- Effect: a NAK for a frame whose copy is still being clocked out is a no-op, and a NAK that
  arrives while the **original** is being sent is dropped, because the frame is not yet
  outstanding. A NAK that arrives after the copy has completed queues another copy.
- With RCONNECT on a line whose port rate equals the line rate this gives at most one surplus copy
  per gap. The model's "guard" policy (section 6) is this behaviour.
- With a modem that buffers (port faster than the line, V.42/MNP), "left the port" only means "in
  the modem", so such a sender could still build a backlog (section 8).

## 5. Changes to our sender

Test each change on its own, A/B against the previous behaviour.

### 5.1 Change 1 (do first): one NAK-driven resend per frame per timer period

This does not depend on the line speed. The server does not in general know the line speed, and
the inbound byte rate cannot stand in for it: in run 2 the R> direction arrived at about 33 ms/byte
(≈300 bps) while the line simulator ran at 2400 bps.

- **Bookkeeping.** Each outstanding frame carries a mark "resent because of a NAK since its timer last ran".
- **On a NAK.** After the ack processing of N(R), take seq = (N(R)+1)&7:
  - if seq is outstanding and not marked: mark it, resend it at once and log it;
  - if seq is outstanding and already marked: do nothing, count it in `naks_ignored` and log it at debug level.
  - That copy is still on its way, or it was damaged, in which case the timer recovers it.
- **Timer resend.** A resend driven by the retransmit timer clears the mark before sending, so
  the next NAK after a timer copy is acted on again.
- **On an ack.** The marks of the acked frames go with them.

Reasoning:
- At this client, all NAKs after the first one for a gap come from frames that were already on
  the line (3.1, 3.3). None of them is new information.
- The first NAK always gets the immediate resend, as before.
- Cost: if that resent copy is itself damaged, the frame waits for its 6.15 s timer. The sender of
  section 4 would resend it on the next NAK after the copy completed.
- Model prediction (not a measurement), 2400 bps, 40 frames of 128 bytes, p_byte = 1e-3, 20 seeds:

| policy | mean time | NAKs | retransmits |
|---|---|---|---|
| today | 71.8 s | 103 | 118 |
| change 1 | 28.6 s | 18 | 8 |
| ideal | 21.3 s | | |

- Against a receiver with Remote 3.40B's NAK rule, change 1 does no harm: 32.2 s versus 33.4 s today.

("today" = the sender before the fix.)

### 5.2 Change 2 (separate A/B, only when the line rate is known): timing from the line

Only with a known rate `line_bps`. A configuration value is the only source of it so far (section 8).

- **(a) Virtual line clock.** On every send of n bytes:
  - set `line_free = max(now, line_free) + n*10/line_bps`;
  - store `on_line_until[seq] = line_free` for data, control and retransmit frames.
- **(b) Retransmit timer from completion.** Start the retransmit timer from `on_line_until[seq]`
  instead of the hand-over time.
- **(c) NAK guard.** A NAK for seq is acted on only if `now ≥ on_line_until[seq]` + the time of one
  inbound control frame (6 bytes LSEC / 7 HSEC). This replaces the mark test of 5.1 when the rate is known.
  - It is the rule of section 4 (a NAK for a copy still being clocked out is a no-op), applied to
    the line's queue instead of the port's.
- **(d) Optional: no pacing needed.** Pacing hand-over to `line_free` is not needed for the
  storm. The model's guard does not pace.

Model predictions (not measurements):
- Correct rate: 25.3 s / 16 NAKs / 5.5 retransmits at 2400 bps.
- The guard is sensitive to the assumed rate:
  - assuming 4800 → 50.3 s;
  - assuming 9600 → no gain;
  - assuming 1200 → 42.3 s, because NAKs for damaged copies are ignored and the timer has to recover them.
- That sensitivity is why change 1, not this, is the default.
- (b) matters at low speed: at 300 bps, 4 × 128 bytes take 17 s, longer than the 6.15 s timer.
  - With the timer counted from hand-over, the model livelocks on a clean line with both
    receiver NAK rules, under every NAK policy.
  - With (b) it finishes in the ideal 171 s.

### 5.3 Leave alone

- Our re-acks of duplicates are not involved. RCONNECT treats an ack frame as ack-only.
- Our own NAK generation (bad frame, out-of-order in the window) is not involved.

## 6. The model

The model is an event simulation of the link rules. It covers:
- a paced FIFO line each way;
- per-byte damage;
- RCONNECT's NAK rule (3.1) or Remote 3.40B's;
- a 2-tick ack delay;
- our sender with a window of 4 and a 6.15 s retransmit timer.

Policies:
- `now`: the sender before the fix;
- `guard`: change 2(c);
- `once`: change 1;
- `end`: change 2(b).

## 7. Test plan

**Unit tests** (socketpair peer, no DOSBox; `tests/test_link_nak.py`):
1. Queue 4 data frames. Feed NAK(N(R)=s−1) three times for the same s. Expect exactly one resend of s and `naks_ignored` = 2.
2. With a short `retx_seconds`: after the timer resend, one more NAK for s is acted on.
3. An ack covering s, then a NAK for s+1: acted on at once.
4. A NAK for a seq that is not outstanding: nothing is sent.

**Line simulator A/B** (previous sender versus change 1; RCONNECT client; and REMOTE.EXE as a regression):
- **Noise like run 2:** `--bps 2400 --ber 1e-4 --burst 2e-4`, seeds 7 and 1–5.
  - The same seed is not byte-identical between runs: runs 1 and 2 diverge, and one RNG serves both directions.
  - So judge each run on its own NAK classification, not by matching events.
- **Heavier noise:** `--bps 2400 --ber 3e-4 --burst 5e-4`, seeds 1–5.
- **Lost bytes:** `--bps 2400 --drop 1e-4`, seeds 1–3. This exercises frame-receive-timeout NAKs (0.77 s at 2400).
- **Clean regression:** `--bps 2400 --ber 0 --burst 0`. Expect no NAKs, and the same call time as before.
- **Low speed:** `--bps 300 --ber 0 --burst 0`.
  - The model predicts a livelock for the previous sender and for change 1, from timer copies.
  - Run it with the previous sender first to check that prediction. Judge only change 2(b) there.

For every run, record:
- the server's `link stats` (`naks_rx`, `naks_ignored`, `retransmits`, `crc_errors`) and the call time;
- the classification of every NAK by its trigger (damaged, ahead in window, stale, expected),
  using arrival times from the line simulator's pacing.

For this, the server logs each retransmit with its reason: "retransmit (NAK)" or "retransmit (timer)".

Pass criteria for change 1:
- the call completes;
- server log invariant: at most one "retransmit (NAK)" per seq between two timer events of that seq;
- no growing run of NAKs: the runs of the same N(R) do not lengthen through the call, as they do in
  run 2, where the runs by N(R) are 84×1, 81×4, 83×6, 84×4, 80×6, 84×6, 80×6, 84×6, 86×6, 87×1;
- the stale count is far below the previous one (36 of 46 in run 2).
  - It is not required to be zero. A timer resend clears the mark, so some NAK-driven copies can
    still be surplus (model: 8.3 retransmits for `once` against 5.5 for `guard`).

## 8. Open points

1. Not determined: whether a permanent deadlock occurs at all. No server log contains one, and
   what the client showed afterwards is not known.
   - Settle: a run that hangs, with the line simulator's byte log and the client's screen.
2. Not determined: why the R> direction runs at about 33 ms/byte (≈300 bps) whatever `--bps` is
   set. Possibilities: DOSBox-X softmodem pacing, or the client's port speed from its CONNECT
   parsing (link-layer.md §8, "first '0' ends the number").
   - Settle: the client's port speed at run time, and the DOSBox-X modem pacing.
   - Our guest-side receive is evidently not paced at that rate: NAKs follow the line simulator's
     2400-bps arrival ends by about 10 ms.
3. Not determined: how the server would learn the line rate for change 2 other than by
   configuration. It is not carried in-band; inbound timing is not usable (item 2).
4. Not determined: whether a one-frame-in-flight sender (section 4) plus RCONNECT storms over
   buffering modems.
   - Settle: such a sender plus RCONNECT through the line simulator, with the modem emulation buffering.
5. Not determined: whether the client ever held a frame back for lack of room in these runs. It
   is not visible on the line, and no NAK or ack timing needs it.

## 9. Results

Both changes are in `ccmail/link.py`. Change 1 is always on. Change 2 (the line clock) is on when
the line speed is known: `serve --line-bps N`, or later the modem's CONNECT speed. Unit tests are
in `tests/test_link_nak.py`. All runs used the real RCONNECT 1.00 through `tools/linesim.py` with
an attachment message in each direction. All calls completed, and REXPORT showed every attachment
byte-identical.

| line | code | NAKs from RCONNECT | our retransmits (NAK / timer) | call time |
|---|---|---|---|---|
| 2400, ber 1e-4, burst 2e-4, seed 7 | before | 46 | 48 | 187 s |
| same | change 1 | 5 | 2 | 166 s |
| same | changes 1+2 (`--line-bps 2400`) | 13 | 8 (4 / 4) | 174 s |
| 2400, ber 1e-4, burst 2e-4, seed 1 | change 1 | 9 | 4 | 151 s |
| 2400, drop 1e-4, ber 1e-4, seed 3 | change 1 | 5 | 1 | 135 s |
| 2400, ber 3e-4, burst 5e-4, seed 2 | change 1 | 54 | 44 (18 / 26) | 244 s |
| same | changes 1+2 | 35 | 27 (11 / 16) | 225 s |
| 300, clean | change 1 only | 17 | 72 (10 / 62) | **failed** after 236 s: RCONNECT hung up |
| 300, clean | changes 1+2 (`--line-bps 300`) | 0 | 0 | ok, 3 messages down, 239 s |

Call times are from the server log (connection to link stats). They are not directly comparable
between rows, because the bytes differ from run to run even with the same seed.

At 300 bps the timer must count from when the frame has left the line, as the model predicted (§6).
A server that answers slow lines must be given the line speed.
