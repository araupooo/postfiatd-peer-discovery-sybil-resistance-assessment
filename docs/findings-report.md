# Findings report

All numbers below are SIMULATED (harness outputs) unless marked
OBSERVED (read from the pinned source). Evidence is the committed
`outputs/S*.json` / `S*.csv` / `S*.log` triple for each scenario.

## Headline

The peer-discovery pipeline is well defended against single-source and
single-identity abuse, and undefended against multi-IP Sybil pressure.
The resource limits stop every flood; the identity checks stop every
replay. But no control asks whether a peer is *honest* — only whether
it arrived first, passed the handshake, and has a fresh key. An
attacker with many IPs and many keys takes every slot the node has,
and a poisoned endpoint cache hands the attacker the node's outbound
slots as well.

## The matrix (severity-ranked)

| Scenario | Severity | Attack success | Effect |
|---|---|---|---|
| S5-multi-ip-sybil | CRITICAL | 100.0% | 11/11 inbound slots attacker; 11/11 honest rejected full |
| S7-eclipse-isolation | CRITICAL | 100.0% | 10/10 outbound slots attacker; 0 honest |
| S10-attempt-exhaustion | HIGH | 100.0% | 240/240 attempts wasted; 0 honest peers in 120 s |
| S8-fixed-cluster-bypass | MEDIUM | 100.0% | 6 reserved peers activate; total active 27 (by design) |
| S6-endpoint-gossip | MEDIUM | 11.0% | 22 of 200 endpoints cached; 178 dropped |
| S2-peer-churn | MEDIUM | 0.0% outbound loss | 36 churn events; outbound refilled; inbound drains 11 to 0 |
| S9-redirect-abuse | LOW | 60.0% | 30 of 50 redirects accepted; 20 rejected at cap |
| S3-duplicate-identity | LOW | 5.5% | 11 slots filled; 66 duplicate-key, 63 full, 60 handshake rejects |
| S4-single-ip-flood | LOW | 4.0% | 2 of 50 accepted; 48 rejected ipLimit |
| S0-baseline | INFO | 0.0% | 21/21 slots active; 9 overshoot attempts rejected full |
| S1-bootstrap | INFO | 0.0% | first peer 100 ms; full outbound 10,100 ms; 40 endpoints learned |

Full matrix: `outputs/matrix.json`, `outputs/matrix.md`.

## Finding 1 — Multi-IP Sybil takes all inbound slots (S5, CRITICAL)

40 attacker peers with distinct IPs and distinct keys arrive first;
11 honest peers arrive 5 s later. Result: the attacker holds 11 of 11
inbound slots; all 11 honest peers are rejected `slots_full`.
OBSERVED, the inbound limit (`inPeers` 11) bounds the total but the
code has no per-IP or per-identity diversity requirement beyond
`ipLimit` 2 per IP — and 40 distinct IPs sail past it. First-come,
first-served is the vulnerability: the control that should discriminate
(C02) has 0.0% effectiveness as a Sybil defence.

## Finding 2 — A poisoned cache eclipses the outbound side (S7, CRITICAL)

Three attacker peers gossip 60 attacker endpoints (hops 6, stored 7)
and two honest peers gossip 10 honest endpoints (hops 1, stored 2).
Autoconnect hands out livecache endpoints hops-highest-first, so the
victim dials the attacker endpoints first: 10 of 10 outbound slots go
to the attacker, 0 to honest peers. OBSERVED, the livecache ordering
(`Logic.h:551-566`) is the mechanism: hops are a distance measure, not
a trust measure, and the attacker sets them. Combined with Finding 1,
an attacker who wins the gossip can own both directions at once.

## Finding 3 — Dead endpoints burn the whole discovery budget (S10, HIGH)

300 dead endpoints sit in the bootcache ahead of 20 honest ones
(sorted order puts the attacker's range first). Over 120 s the node
runs 12 autoconnect batches — 240 of 240 attempts wasted on dead
endpoints, 0 honest peers reached. The 60 s squelch
(`recentAttemptDuration`) does not help, because each batch finds
*fresh* dead endpoints; the backoff table only slows retries of the
same endpoint. The damage is bounded and self-healing: the 300 dead
endpoints are exhausted after 15 batches (~150 s), after which the
honest endpoints are reached. That is why this is HIGH, not CRITICAL.

## Finding 4 — Reserved peers bypass every public limit (S8, MEDIUM)

With all 21 public slots full, 3 cluster peers, 2 fixed peers and 1
reserved peer all activate — total active 27. OBSERVED, this is the
documented design: `can_activate` returns true for fixed or reserved
peers (`Counts.h:70-83`), and `[peers_max]` says cluster/fixed peers
do not count toward the total (`cfg:455-458`). The exposure is
configuration trust: whoever can get a key into `[cluster_nodes]`,
`[ips_fixed]` or the reservation table gets an unbounded slot. The
reservation table has no size cap in the cited code
(`PeerReservationTable.h/.cpp`).

## Finding 5 — Gossip filters work, but the survivors are trusted (S6, MEDIUM)

One peer sends 200 endpoints: 60 with hops over 6, 40 invalid, 40
valid, 60 duplicates. The pipeline truncates 200 to 64 by shuffle,
then drops 27 (hops), 11 (invalid) and 4 (duplicate). 22 endpoints
enter the livecache and bootcache — 11.0% of what was sent. The
filters work (C07: 21.0% of the 200 dropped by filtering, C08: 68.0%
truncated away). The problem is what happens next: the 22 survivors
are treated exactly like honest endpoints. S7 shows the consequence —
those 22 are enough to eclipse the node.

## Finding 6 — Churn is absorbed outbound, not inbound (S2, MEDIUM)

36 churn events over 12 epochs (3 peers every 10 s). Every dropped
outbound peer is refilled within one autoconnect batch; the node spends
0 ms below full outbound, and the maximum outbound deficit after a
refill is 0. But the 11 dropped inbound peers are never replaced:
autoconnect only dials out, so inbound active falls 11 to 0 over the
run. In a live network new peers dial in, which this scenario does not
model — so the drain is a measured asymmetry of the design, not a
demonstrated outage. An operator should know the inbound side has no
self-healing.

## Finding 7 — The handshake stops every replay and relay (S3, LOW)

200 inbound attempts: 140 valid handshakes reusing 20 keys, 30 with a
bad cookie, 20 with a wrong Network-ID, 10 through a proxy. All 60 bad
handshakes are rejected (C04/C05/C06: 100% each) before any slot is
created. Of the 140 valid ones, 66 repeats are rejected as duplicate
keys and 63 more as slots full; 11 activate (5.5%). The identity
checks do exactly what they claim. What they cannot do is stop 11
*distinct* keys from filling the 11 slots — that is S5's finding, not
a failure of S3's controls.

## Finding 8 — Single-IP floods are contained (S4, LOW)

50 inbound attempts from one public IP: 2 activate (the `ipLimit`),
48 rejected `ipLimitExceeded` (C00: 96.0%). The limit works. Its
weakness is that it is per IP, and IPs are cheap — S5 shows the
multi-IP version of the same flood succeeding completely.

## Finding 9 — Redirects are capped, not closed (S9, LOW)

One peer requests 50 redirects: 30 accepted, 20 rejected at the
`maxRedirects` cap (C09: 40.0% of requests blocked). The cap bounds
the abuse, but the first 30 redirects are an unauthenticated endpoint
feed — 30 batches of 10 endpoints each, handed to any connected peer.

## Finding 10 — Baseline and bootstrap are healthy (S0, S1, INFO)

S0: 30 honest peers, 21 of 21 slots active (10 out + 11 in), 9
overshoot attempts rejected full, full table at 155 ms. S1: cold start
from the 4 bootstrap hosts yields 40 endpoints; first peer at 100 ms,
full outbound at 10,100 ms, 24 attempts used. Nothing here is broken;
these two scenarios exist so the attack scenarios have a healthy
reference to be compared against.

## What was NOT measured

- `max_untrusted_count` (C12): code-verified only. It bounds unlisted
  validator manifests, not peer connections, and no scenario exercises
  manifest handling.
- Live-network behaviour: all numbers are SIMULATED. The model is
  faithful to the pinned code, but it is one node against a scripted
  population, with no real network, no real TLS and no ledger.
