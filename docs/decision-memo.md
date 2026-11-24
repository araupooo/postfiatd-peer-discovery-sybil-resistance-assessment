# Decision memo

## Question

Can a postfiatd node at commit
`0085a1ff885d6a446369cf73a4430f75af22be55` be eclipsed or denied peers
by Sybil pressure on its peer-discovery pipeline, and what should an
operator do about it?

## Answer in one paragraph

Yes — by an attacker with many IPs and many keys. The pipeline stops
single-IP floods (S4: 48 of 50 rejected) and duplicate identities
(S3: 66 duplicate-key rejections, 60 bad handshakes rejected), but it
has no defence against distinct IPs with distinct keys arriving first:
in S5 the attacker takes 11 of 11 inbound slots and all 11 honest
peers are rejected, and in S7 a poisoned endpoint cache hands the
attacker 10 of 10 outbound slots. The two CRITICAL findings share one
root cause: no control in the pipeline asks whether a peer is honest,
only whether it arrived first, passed the handshake, and has a fresh
key. The fixes are additive (per-/24 caps, a returning-peer reserve,
mixed dial order) and do not require weakening the controls that work.

## Evidence

- **S5-multi-ip-sybil (CRITICAL):** 40 attacker peers, distinct IPs
  and keys, arrive first; 11 of 11 inbound slots go to the attacker;
  11 of 11 honest peers rejected full. Evidence:
  `outputs/S5-multi-ip-sybil.json`, `.csv`, `.log`.
- **S7-eclipse-isolation (CRITICAL):** 60 attacker endpoints gossiped
  at hops 6 (stored 7) vs 10 honest at hops 1 (stored 2); autoconnect
  dials hops-highest-first, so 10 of 10 outbound slots go to the
  attacker. Evidence: `outputs/S7-eclipse-isolation.json`, `.csv`,
  `.log`.
- **S10-attempt-exhaustion (HIGH):** 300 dead endpoints in the
  bootcache; 240 of 240 attempts wasted over 120 s; 0 honest peers
  reached. Self-healing after ~150 s (15 batches). Evidence:
  `outputs/S10-attempt-exhaustion.json`, `.csv`, `.log`.
- **S6-endpoint-gossip (MEDIUM):** 200 gossiped endpoints; 22 enter
  the caches (11.0%). Evidence: `outputs/S6-endpoint-gossip.json`,
  `.csv`, `.log`.
- **S2-peer-churn (MEDIUM):** 36 churn events; outbound refilled
  perfectly (0 ms below full); inbound drains 11 to 0. Evidence:
  `outputs/S2-peer-churn.json`, `.csv`, `.log`.
- **S3-duplicate-identity, S4-single-ip-flood (LOW):** the identity and
  per-IP controls work as designed. Evidence:
  `outputs/S3-duplicate-identity.json`, `outputs/S4-single-ip-flood.json`.
- **S0-baseline, S1-bootstrap (INFO):** healthy reference — 21 of 21
  slots at 155 ms; cold start to full outbound in 10,100 ms.

All numbers are SIMULATED (harness outputs from a faithful
protocol-level model of the pinned code). No live network was measured.

## What the code says (OBSERVED)

- Slot limits: `defaultMaxPeers` 21, `outPeers` 10, `inPeers` 11
  (`peerfinder/detail/Tuning.h:63`, `PeerfinderConfig.cpp:38-43`).
- `can_activate` returns true for fixed or reserved peers regardless
  of slot counts (`peerfinder/detail/Counts.h:70-83`); cluster/fixed
  peers do not count toward `[peers_max]`
  (`cfg/postfiatd-example.cfg:455-458`).
- `ipLimit` is 2 per public IP, capped at `inPeers / 2`
  (`PeerfinderConfig.cpp:48-62`; enforced `Logic.h:278-283`).
- Duplicate keys are rejected (`Logic.h:416-418`); the handshake
  cookie, Network-ID and proxy checks are in
  `Handshake.cpp:140-165,227-248,325-356`.
- Gossip is truncated to 64 by shuffle (`Logic.h:792-796`), filtered
  by hops, validity and duplicates (`Logic.h:727,757,766-776`), and
  rate-limited to one batch per 151 s (`Logic.h:882`).
- Autoconnect dials fixed peers, then livecache hops-highest-first,
  then bootcache (`Logic.h:493-605`).
- Bootstrap hosts are 4 hard-coded names
  (`OverlayImpl.cpp:499-512`).
- `max_untrusted_count` (1000) bounds unlisted validator manifests,
  not peer connections (`cfg:512`; `Config.cpp:858`); it was not
  exercised (C12 UNMEASURED).

## Recommendation

1. **Ship the P0 fixes** (per-/24 inbound cap + returning-peer
   reserve; mixed livecache dial order) before exposing a node to an
   untrusted network. They address the two CRITICAL findings and are
   additive to the controls that work.
2. **Ship the P1 fixes** (dead-endpoint expiry + bootcache shuffling;
   reservation-table cap + audit) in the next pass. They bound the
   HIGH and MEDIUM findings.
3. **Do not weaken the handshake or ipLimit** in the course of fixing
   S5. They are the controls that work (S3, S4), and the P0 fixes
   build on them.
4. **Treat `[cluster_nodes]`, `[ips_fixed]` and the reservation table
   as privileged configuration** — they are the keys to unbounded
   slots (S8), and a misconfigured list is a silent eclipse vector.
5. **Do not rely on `max_untrusted_count` for peer defence.** It is a
   manifest cache bound, not a peer control.

## What would change this assessment

- A live-network measurement showing that honest peers arrive fast
  enough to win the first-come race in S5, or that gossip from honest
  peers dilutes poisoned endpoints before S7's eclipse completes.
  The simulator models one victim against a scripted population; a
  multi-node measurement could soften the CRITICAL ratings.
- A code change implementing the P0 fixes, re-measured with the same
  harness: S5 and S7 are the acceptance tests (attacker inbound share
  below 50%, attacker outbound share below 50%).
