# Control inventory

13 controls, inventoried from the pinned source. Effectiveness is
measured from the committed scenario outputs; see
`outputs/control-measurements.json` for the numbers behind each row.
C12 is UNMEASURED (code-verified only).

## C00 — ipLimit (public IPs)

- **What it is:** at most `ipLimit` connections from one public IP.
  Autoconfigured to 2, capped at `inPeers / 2`.
- **Source:** `src/xrpld/peerfinder/detail/PeerfinderConfig.cpp:48-62`;
  enforced in `src/xrpld/peerfinder/detail/Logic.h:278-283`.
- **Measured in:** S4-single-ip-flood.
- **Effectiveness:** 96.0% (48 of 50 single-IP attempts rejected). The 2
  that pass are by design — the limit is 2, not 0.
- **Rating:** works as designed against a single IP.

## C01 — Duplicate identity rejection (key + endpoint)

- **What it is:** a public key may be active once
  (`Logic.h:416-418`); an endpoint may hold one slot
  (`Logic.h:287-293` inbound, `327-333` outbound).
- **Source:** `src/xrpld/peerfinder/detail/Logic.h:287-293,327-333,416-418`.
- **Measured in:** S3-duplicate-identity.
- **Effectiveness:** 33.0% (66 of 200 attempts rejected as duplicate
  keys; 63 more rejected as slots full; 60 rejected at the handshake).
  11 slots still fill — one per distinct key. The control stops
  *repeats*; it cannot stop distinct keys filling the slots (see S5).
- **Rating:** works as designed against key reuse; not a Sybil defence
  on its own.

## C02 — Inbound slot limit (inPeers 11)

- **What it is:** at most 11 inbound peers (`defaultMaxPeers` 21 minus
  `outPeers` 10).
- **Source:** `src/xrpld/peerfinder/detail/PeerfinderConfig.cpp:38-43,100-110`;
  enforced in `src/xrpld/peerfinder/detail/Counts.h:70-83`.
- **Measured in:** S5-multi-ip-sybil.
- **Effectiveness:** 0.0% as a Sybil defence. The limit bounds the
  total (11) but does not discriminate: the attacker takes all 11
  slots and 11 of 11 honest peers are rejected full.
- **Rating:** fails open to whoever arrives first. First-come,
  first-served is the vulnerability, not the number 11.

## C03 — Outbound slot limit (outPeers 10)

- **What it is:** at most 10 outbound peers.
- **Source:** `src/xrpld/peerfinder/detail/PeerfinderConfig.cpp:38-43`;
  enforced in `src/xrpld/peerfinder/detail/Counts.h:70-83`.
- **Measured in:** S0-baseline.
- **Effectiveness:** 100% (9 overshoot attempts, all 9 rejected;
  outbound slots stay at 10). The limit bounds the count, not the
  composition — see S7, where all 10 outbound slots go to the attacker.
- **Rating:** works as a count limit; says nothing about who fills it.

## C04 — Handshake cookie

- **What it is:** the TLS Finished messages of both sides must hash to
  the same cookie, proving a direct TLS session rather than a relayed
  one.
- **Source:** `src/xrpld/overlay/detail/Handshake.cpp:140-165`.
- **Measured in:** S3-duplicate-identity.
- **Effectiveness:** 100% (30 of 30 bad-cookie handshakes rejected
  before any slot is created).
- **Rating:** works as designed.

## C05 — Network-ID handshake check

- **What it is:** the `Network-ID` header must match the node's
  network; otherwise the handshake is rejected.
- **Source:** `src/xrpld/overlay/detail/Handshake.cpp:227-248`.
- **Measured in:** S3-duplicate-identity.
- **Effectiveness:** 100% (20 of 20 wrong-Network-ID handshakes
  rejected).
- **Rating:** works as designed.

## C06 — Proxy / direct-connect rejection

- **What it is:** a `Local-IP` / `Remote-IP` mismatch (the peer is
  behind a proxy that establishes two separate sessions) is rejected.
- **Source:** `src/xrpld/overlay/detail/Handshake.cpp:325-356`.
- **Measured in:** S3-duplicate-identity.
- **Effectiveness:** 100% (10 of 10 proxied handshakes rejected).
- **Rating:** works as designed.

## C07 — Endpoint gossip filters (hops / invalid / duplicate)

- **What it is:** gossiped endpoints with hops over 6 are dropped
  (`Logic.h:727`); invalid addresses (private IP or port 0) are
  dropped when `verify_endpoints` is on (`Logic.h:757`,
  default 1, `cfg/postfiatd-example.cfg:541`); duplicates within a
  message are dropped (`Logic.h:766-776`).
- **Source:** `src/xrpld/peerfinder/detail/Logic.h:719-788`.
- **Measured in:** S6-endpoint-gossip.
- **Effectiveness:** 21.0% (42 of 200 endpoints dropped by the filters:
  27 hops, 11 invalid, 4 duplicate). 136 were truncated before
  filtering (see C08); 22 of 200 still enter the caches.
- **Rating:** the filters work, but they are the last line, not the
  first — most of the protection in S6 comes from truncation luck
  (C08), and anything that survives the filters is trusted.

## C08 — Gossip truncation (numberOfEndpointsMax 64)

- **What it is:** an endpoint list longer than 64 is shuffled and cut
  to 64 (`Logic.h:792-796`).
- **Source:** `src/xrpld/peerfinder/detail/Logic.h:792-796`.
- **Measured in:** S6-endpoint-gossip.
- **Effectiveness:** 68.0% (136 of 200 endpoints truncated away). But
  the truncation is a random shuffle: *which* 64 survive is luck, not
  trust. In this run 22 of the surviving 64 were poisoned endpoints
  that then entered the caches.
- **Rating:** bounds the damage per message; does not distinguish good
  endpoints from bad ones.

## C09 — maxRedirects cap (30)

- **What it is:** at most 30 redirects per connection, 10 endpoints
  each (`Logic.h:477-492`, `Tuning.h:70,120`).
- **Source:** `src/xrpld/peerfinder/detail/Logic.h:477-492`.
- **Measured in:** S9-redirect-abuse.
- **Effectiveness:** 40.0% (20 of 50 redirect requests rejected at the
  cap). The first 30 are free by design.
- **Rating:** bounds the abuse; the first 30 redirects are an
  unauthenticated endpoint feed.

## C10 — Autoconnect refill (churn)

- **What it is:** every 10 s, autoconnect dials up to
  `maxConnectAttempts` 20 minus attempts in flight, from fixed peers,
  then livecache (hops highest first), then bootcache
  (`Logic.h:493-605`).
- **Source:** `src/xrpld/peerfinder/detail/Logic.h:493-605`;
  `src/xrpld/peerfinder/detail/Counts.h:88-92`.
- **Measured in:** S2-peer-churn.
- **Effectiveness:** 100% for outbound refill (all 25 dropped outbound
  peers refilled within one batch; 0 ms below full outbound). The 11
  dropped inbound peers were NOT refilled — autoconnect only dials
  out, so inbound recovery depends on other peers dialling in.
- **Rating:** fully resilient outbound; inbound self-healing is absent
  by design.

## C11 — Bootstrap discovery (4 hosts)

- **What it is:** a cold node starts from 4 hard-coded bootstrap hosts
  (`r.ripple.com`, `sahyadri.isrdc.in`, `hubs.xrpkuwait.com`,
  `hub.xrpl-commons.org`, port 51235) and learns endpoints from them.
- **Source:** `src/xrpld/overlay/detail/OverlayImpl.cpp:499-512`.
- **Measured in:** S1-bootstrap.
- **Effectiveness:** 100% (4 hosts yielded 40 endpoints; first peer at
  100 ms, full outbound at 10,100 ms).
- **Rating:** works, and the bootstrap set is the node's first trust
  decision — whoever controls those hosts shapes the node's first
  peer set.

## C12 — max_untrusted_count (1000)

- **What it is:** a bound on unlisted validator manifests kept and
  shared with peers — NOT a peer-connection control. When full, the
  oldest unlisted manifest is dropped for each new one; listed
  validators are never limited.
- **Source:** `cfg/postfiatd-example.cfg:512-522`;
  `src/xrpld/core/detail/Config.cpp:858`;
  `src/xrpld/app/misc/Manifest.h:279`.
- **Measured in:** none.
- **Effectiveness:** UNMEASURED — code-verified only. No scenario
  exercises manifest handling, and no effectiveness number is claimed.
- **Rating:** out of scope for the peer-discovery scenarios; listed
  here so it is not mistaken for a peer control.
