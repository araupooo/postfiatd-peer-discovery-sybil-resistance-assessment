# Remediation report

Prioritised by the severity of the finding each item addresses. Every
recommendation names the code it touches; none of them is implemented
in this pack — this pack measures, it does not patch.

## P0 — Rate-limit inbound slot acquisition per /24 and per key-age (S5)

- **Addresses:** Finding 1 (CRITICAL). The inbound limit does not
  discriminate; whoever arrives first wins.
- **Action:** in `new_inbound_slot` (`Logic.h:263-310`), add a
  per-/24 (or per-ASN) inbound cap alongside the per-IP `ipLimit`,
  and a minimum key-age or proof-of-continuity requirement before a
  new key can take one of the last inbound slots. A cheap version:
  reserve 2-3 inbound slots for peers whose key has been seen before
  (returning peers), so a fresh flood cannot take 11 of 11.
- **Why it works:** S5's attacker wins by arriving first with many
  distinct IPs. A /24 cap raises the cost from "many IPs" to "many
  networks"; a returning-peer reserve keeps honest peers reachable
  during a flood.
- **Risk of the fix:** over-strict caps can lock out honest peers
  behind shared NAT. The cap should be per /24, not per IP, and the
  reserve should be small (2-3 slots).

## P0 — Do not trust gossiped hop counts for dial priority (S7)

- **Addresses:** Finding 2 (CRITICAL). Autoconnect dials livecache
  endpoints hops-highest-first, and the attacker sets the hops.
- **Action:** in `autoconnect` (`Logic.h:493-605`), dial livecache
  endpoints in an order that mixes hop levels (for example, interleave
  or shuffle across levels, or prefer endpoints learned from multiple
  independent peers), and cap the share of one batch that can come
  from a single gossiping peer. Alternatively, treat hops as a hint
  for *which* endpoints to keep, not for dial order.
- **Why it works:** S7's eclipse depends entirely on the ordering:
  attacker endpoints at hops 7 are dialled before honest endpoints
  at hops 2. Any mixing breaks the 10-of-10 result.
- **Risk of the fix:** slower convergence to well-connected peers in
  a healthy network. Measure the bootstrap time (S1: 10,100 ms) before
  and after.

## P1 — Expire dead bootcache endpoints faster, and interleave honest ones (S10)

- **Addresses:** Finding 3 (HIGH). 300 dead endpoints burn 240
  attempts over 120 s because the bootcache is tried in sorted order
  and the squelch only covers retries of the same endpoint.
- **Action:** in `Bootcache.h` / `autoconnect`, drop or deprioritise
  endpoints after a small number of consecutive failures (today the
  failure count only feeds the backoff table), and interleave the
  bootcache order instead of trying it sorted — or shuffle the batch
  so a contiguous block of attacker endpoints cannot monopolise 12
  consecutive batches.
- **Why it works:** S10's damage comes from sorted order plus
  inexhaustible fresh dead endpoints. Shuffling bounds the waste to
  the attacker's share of the cache; a failure cap removes dead
  endpoints instead of re-trying them for 150 s.
- **Risk of the fix:** aggressive expiry can drop honest peers that
  are temporarily unreachable. A 3-failure cap with a long cooldown
  is a safer first step than deletion.

## P1 — Cap the reservation table and audit cluster/fixed lists (S8)

- **Addresses:** Finding 4 (MEDIUM). Reserved peers bypass every
  public limit, and the reservation table has no size cap in the
  cited code.
- **Action:** add a bound to `PeerReservationTable` (insert_or_assign
  currently grows without a cap) and log every reserved activation
  with the key and the list it came from. Audit `[cluster_nodes]`,
  `[ips_fixed]` and `[peer_private]` on a schedule — they are the
  keys to unbounded slots.
- **Why it works:** the bypass is by design, so the fix is
  accountability, not removal: a bounded table cannot be grown
  without limit, and a log makes a misconfigured list visible.
- **Risk of the fix:** a cap set too low can lock out legitimate
  cluster peers. Set it above the largest expected cluster size.

## P2 — Verify gossiped endpoints before caching them (S6)

- **Addresses:** Finding 5 (MEDIUM). 22 of 200 poisoned endpoints
  enter the caches and are then trusted.
- **Action:** before inserting a gossiped endpoint into the livecache
  or bootcache, check it against the node's own connection history
  (has this endpoint ever answered?) or require corroboration from a
  second independent peer. At minimum, do not let one peer's gossip
  fill more than a small share of the livecache in one batch.
- **Why it works:** S6's 22 survivors are the seed for S7's eclipse.
  Corroboration raises the cost from "one malicious peer" to "several
  colluding peers".
- **Risk of the fix:** slower discovery in sparse networks where only
  one peer knows an endpoint. A small per-peer share cap is safer
  than full corroboration as a first step.

## P2 — Re-dial inbound slots, or accept the asymmetry (S2)

- **Addresses:** Finding 6 (MEDIUM). Autoconnect never refills
  inbound slots; inbound active drains 11 to 0 under churn.
- **Action:** either (a) accept the asymmetry and document it for
  operators (inbound recovery depends on others dialling in), or (b)
  add an outbound re-dial of recently-dropped inbound peers — the
  node already knows their endpoints, and dialling them out converts
  a lost inbound slot into an outbound one.
- **Why it works:** option (b) closes the measured gap directly; the
  S2 run shows outbound refill is already perfect, so the machinery
  exists.
- **Risk of the fix:** re-dialling dropped peers can look like
  aggressive behaviour to the network. Rate-limit it to one re-dial
  per dropped peer per epoch.

## P2 — Keep the handshake and ipLimit as they are (S3, S4)

- **Addresses:** Findings 7 and 8 (LOW). The handshake stops every
  replay and relay; `ipLimit` contains single-IP floods.
- **Action:** none. These controls work. The lesson is that they are
  necessary but not sufficient: they stop one identity and one IP,
  and S5's attacker brings many of both. Do not weaken them in the
  course of fixing S5 — the P0 fixes above are additive, not
  replacements.

## P3 — Consider lowering maxRedirects, or authenticating redirects (S9)

- **Addresses:** Finding 9 (LOW). 30 free redirects per connection.
- **Action:** lower `maxRedirects` from 30, or require the redirecting
  peer to have been connected for a minimum time first.
- **Why it works:** the cap already bounds the abuse; this only
  reduces the free allowance.
- **Risk of the fix:** negligible — redirects are a legacy mechanism
  and honest peers rarely need 30 of them.
