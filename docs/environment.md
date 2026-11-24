# Environment

## What was tested

A faithful protocol-level simulator of the postfiatd peer-discovery and
connection pipeline, implemented in `scripts/simulator.py` and driven by
`scripts/load_harness.py` through the 11 scenarios in `scenarios/`.
No real postfiatd binary was built: a full build was already shown to be
impractical in the deterministic-build assessment of the same commit
(dependency resolution alone takes hours and needs network access to the
Conan remotes). The simulator is the documented test environment instead,
and every one of its parameters is taken verbatim from the pinned source.

## Pinned source

Commit `0085a1ff885d6a446369cf73a4430f75af22be55`
("Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9",
2026-10-10). All 22 cited files are verified blob-by-blob in
`docs/source-inventory.md`. Line numbers in this pack were read with
`grep -n` on a local checkout of that commit.

## What the simulator models

The simulator reproduces the peer-finder pipeline in the order the code
runs it:

1. **Handshake** — TLS Finished cookie, Network-ID header, Local-IP /
   Remote-IP proxy rejection (`Handshake.cpp:140-165, 227-356`).
2. **Slot creation** — `new_inbound_slot` (`Logic.h:263-310`, ipLimit check
   at 278-283, duplicate-endpoint check at 287-293) and
   `new_outbound_slot` (`Logic.h:320-355`, duplicate-endpoint check at
   327-333).
3. **Connection** — `onConnected` (`Logic.h:358-390`), including the
   self-connect rejection.
4. **Activation** — `activate` (`Logic.h:399-469`): duplicate-key rejection
   (416-418), reserved bypass (`Counts.h:70-83`: fixed or reserved peers
   always activate), slot limits otherwise (427-435).
5. **Endpoint gossip** — `preprocess` (`Logic.h:719-788`: hops over 6
   dropped at 727, invalid addresses dropped when `verifyEndpoints` is on
   at 757, duplicates dropped at 766-776) and `on_endpoints`
   (`Logic.h:789-930`: list truncated to `numberOfEndpointsMax` 64 by
   shuffle at 792-796, one batch per `secondsPerMessage` 151 s at 882).
6. **Autoconnect** — `Logic.h:493-605`: fixed peers first, then livecache
   (hops highest first), then bootcache (stored order); one batch every
   `secondsPerConnect` 10 s; batch size `attempts_needed`
   (`Counts.h:88-92`: `maxConnectAttempts` 20 minus attempts in flight).
7. **Failure handling** — `on_closed` / `on_failure` (`Logic.h:931-1010`):
   failed endpoints are squelched for `recentAttemptDuration` 60 s and
   back off on the `connectionBackoff` table [1,1,2,3,5,8,13,21,34,55].
8. **Redirects** — `redirect` (`Logic.h:477-492`): at most `maxRedirects`
   30 per connection, `redirectEndpointCount` 10 endpoints each.

## Parameters (all verbatim from the pinned code)

| Parameter | Value | Source |
|---|---|---|
| defaultMaxPeers | 21 | `peerfinder/detail/Tuning.h:63` |
| outPercent / minOutCount | 15 / 10 | `Tuning.h:52,59` |
| outPeers / inPeers (derived) | 10 / 11 | `PeerfinderConfig.cpp:38-43,100-110` |
| ipLimit (autoconfigured) | 2 (cap inPeers/2) | `PeerfinderConfig.cpp:48-62` |
| secondsPerConnect | 10 s | `Tuning.h:40` |
| maxConnectAttempts | 20 | `Tuning.h:44` |
| connectionBackoff | [1,1,2,3,5,8,13,21,34,55] s | `Tuning.h:79` |
| maxRedirects | 30 | `Tuning.h:70` |
| bootcacheSize / prune | 1000 / 10% | `Tuning.h:90,94` |
| bootcacheCooldownTime | 60 s | `Tuning.h:101` |
| maxHops | 6 | `Tuning.h:110` |
| numberOfEndpoints / Max | 12 / 64 | `Tuning.h:113,116-117` |
| redirectEndpointCount | 10 | `Tuning.h:120` |
| secondsPerMessage | 151 s | `Tuning.h:124` |
| liveCacheSecondsToLive | 30 s | `Tuning.h:128` |
| recentAttemptDuration | 60 s | `Tuning.h:132` |
| Bootstrap hosts | 4 (r.ripple.com, sahyadri.isrdc.in, hubs.xrpkuwait.com, hub.xrpl-commons.org, port 51235) | `OverlayImpl.cpp:499-512` |
| max_untrusted_count | 1000 (default) | `cfg/postfiatd-example.cfg:512` |
| max_unknown_time | 600 s (300-1800) | `cfg:526` |
| max_diverged_time | 300 s (60-900) | `cfg:534` |
| verify_endpoints | 1 (default) | `cfg:541` |

## Timing model

The simulator runs on a virtual clock. Connection attempts inside one
autoconnect batch resolve concurrently after one connect latency (100 ms
for a live endpoint, 1000 ms for a dead one); batches are one
`secondsPerConnect` tick apart. Inbound attempts arrive 5 ms apart.
This matches the real code, which launches a batch of attempts in
parallel and re-runs autoconnect on a 10 s timer. All timestamps in the
outputs are virtual milliseconds; no wall clock is used anywhere except
the single start line of `outputs/run_all.log`, which is excluded from
digests.

## What is NOT modelled (limitations)

- **No real network, no real cryptography.** Handshakes are modelled as
  pass/fail checks, not TLS sessions. No real keys are generated; peers
  carry synthetic identifiers (`key-h0001`, `key-a0001`) and
  documentation-range IPs (203.0.113.0/24 honest, 198.51.100.0/24 and
  192.0.2.0/24 attacker, 192.0.2.0/24 bootstrap). Nothing here names a
  real host.
- **No inbound re-dialling in the churn scenario.** S2 models peers
  dropping, not new peers arriving. The inbound drain it reports
  (11 to 0 over 12 epochs) is therefore a measured asymmetry of the
  autoconnect design, not a demonstrated outage in a live network
  where new peers dial in.
- **No validator-manifest behaviour.** `max_untrusted_count` (C12) bounds
  unlisted validator manifests, not peer connections; no scenario
  exercises it. It is reported UNMEASURED.
- **No ledger or consensus interaction.** The scenarios measure peer
  discovery and connection management only; they do not measure
  validation, ledger sync, or transaction propagation.
- **Single-node view.** Every scenario runs one victim node against a
  scripted peer population. Multi-node emergent behaviour (e.g. gossip
  spreading across many honest nodes) is not measured.
