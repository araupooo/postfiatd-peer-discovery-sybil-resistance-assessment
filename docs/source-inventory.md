# Source inventory

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55`
("Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9", 2026-10-10).

Every file below was verified blob-by-blob: the local `git hash-object` SHA
and size agree with the GitHub API tree for the pinned commit
(tree not truncated, 1783 blobs). Line numbers in the other documents were
read with `grep -n` on this checkout, never from a raw-file fetch.

| File | Blob SHA | Bytes | Cited for |
|---|---|---|---|
| `src/xrpld/peerfinder/detail/Tuning.h` | `1ba23b1cfe5f668a70216151a1d5a25e09088bfc` | 4525 | All peer-finder tuning constants: defaultMaxPeers 21, outPercent 15, minOutCount 10, secondsPerConnect 10 s, maxConnectAttempts 20, maxRedirects 30, connectionBackoff table, bootcacheSize 1000, bootcachePrunePercent 10, bootcacheCooldownTime 60 s, maxHops 6, numberOfEndpoints 12, numberOfEndpointsMax 64, redirectEndpointCount 10, secondsPerMessage 151 s, liveCacheSecondsToLive 30 s, recentAttemptDuration 60 s. |
| `src/xrpld/peerfinder/detail/PeerfinderConfig.cpp` | `6164a8d7c1144ce06b8003a3eedebe573bf3a5e7` | 4203 | calcOutPeers (outPeers 10 from maxPeers 21, outPercent 15, minOutCount 10); ipLimit autoconfiguration (default 2, capped at inPeers/2). |
| `src/xrpld/peerfinder/detail/Logic.h` | `56077303a3b5deec455018728d54c25551824f0b` | 41768 | The peer-finder state machine: new_inbound_slot, new_outbound_slot, onConnected, activate, redirect, autoconnect, preprocess, on_endpoints, on_closed, on_failure. |
| `src/xrpld/peerfinder/detail/Counts.h` | `a35473ddb5d0d20a550f5a38fa8fbe7c06a9da05` | 9201 | Slot accounting: can_activate (fixed/reserved always true; otherwise slot limits), attempts_needed (maxConnectAttempts minus attempts in flight). |
| `src/xrpld/peerfinder/PeerfinderManager.h` | `db854d8190253c94e70d464f1fadfdfdc1c57d1a` | 10688 | Peer-finder manager interface used by the overlay. |
| `src/xrpld/peerfinder/detail/PeerfinderManager.cpp` | `e7d16c61d1a2af8e503d0f3912b3dbc9ef9c2a76` | 7962 | Manager implementation (slot lifecycle wiring). |
| `src/xrpld/peerfinder/detail/Bootcache.h` | `4a5d95fd4150bbda18f8d67d226473fc804ea3cf` | 5523 | Persistent endpoint cache: size 1000, prune 10 percent, 60 s cooldown. |
| `src/xrpld/peerfinder/detail/Livecache.h` | `503ea0161abe00ae04c164179a6a6ce8f0fea8c5` | 15638 | In-memory endpoint cache with hop counts and 30 s time-to-live. |
| `src/xrpld/overlay/detail/OverlayImpl.cpp` | `291a95bc04f02da00fda5bdca1226c60068f26b5` | 49875 | Reserved-slot decision for cluster members (activate with reserved=true); default bootstrap hosts (r.ripple.com, sahyadri.isrdc.in, hubs.xrpkuwait.com, hub.xrpl-commons.org, port 51235). |
| `src/xrpld/overlay/detail/OverlayImpl.h` | `d6156a6fb78221724938c5f75a11e2fb5dfe3052` | 17408 | Overlay implementation interface. |
| `src/xrpld/overlay/detail/PeerImp.cpp` | `d823bf23a17e62172320628a800fdda92fbb2bcb` | 116691 | Peer connection handling; the `fail` / `Closed` peer states cited in the findings. |
| `src/xrpld/overlay/detail/Handshake.cpp` | `e3617a1d9879b0c6663d91336ff49df57d2e13f2` | 13845 | TLS Finished cookie, Network-ID header check, Local-IP/Remote-IP proxy rejection in verifyHandshake. |
| `src/xrpld/overlay/PeerReservationTable.h` | `ddd65261615864bad58633fccd4651ce3c2ad3d3` | 3455 | Peer reservation table interface (no size cap found in the cited code). |
| `src/xrpld/overlay/detail/PeerReservationTable.cpp` | `1a2842591cdac30c5cffe28d39c6abe65a1b0b33` | 4378 | Reservation table implementation (insert_or_assign). |
| `src/xrpld/overlay/Cluster.h` | `a2fd7f9c53b9e918a52976b7b84c09338b26155a` | 3575 | Cluster membership interface (cluster nodes bypass slot limits). |
| `src/xrpld/overlay/detail/Cluster.cpp` | `b4e5b6fc509d7159974a58edd388d244bdbe1679` | 3703 | Cluster membership implementation. |
| `src/xrpld/overlay/PeerSet.h` | `4ee6b8d7c067dc509f127cb2a8d7d358c9994e41` | 3169 | Peer set interface. |
| `src/xrpld/overlay/detail/Tuning.h` | `706c2459b6befffeef057290601336a407fcf8e2` | 2355 | Overlay tuning constants. |
| `src/xrpld/overlay/Overlay.h` | `33ffb93556c609efb7fa0fd9f0fa6a56da416f83` | 7587 | Overlay interface. |
| `src/xrpld/app/rdb/PeerFinder.h` | `8becd053fbe5008befc2a616624916b962dc62c1` | 2598 | Persistent peer-finder store interface (bootcache persistence). |
| `src/xrpld/app/rdb/detail/PeerFinder.cpp` | `b2eaf3dfe118ac1f76551415ecb4b230172a9146` | 8183 | Persistent peer-finder store implementation. |
| `cfg/postfiatd-example.cfg` | `b569f0f3f33252693968710c90ece5b5a394b1e2` | 57654 | Operator configuration: [ips_fixed], [peer_private], [peers_max] (cluster/fixed peers do not count toward the total), [cluster_nodes], [overlay] (max_untrusted_count 1000, max_unknown_time 600, max_diverged_time 300, verify_endpoints default 1). |

Verified 22/22.
