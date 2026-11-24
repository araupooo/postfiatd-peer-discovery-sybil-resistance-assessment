# Scenario matrix (severity-ranked)

| Scenario | Severity | Attack success | Effect | Evidence |
|---|---|---|---|---|
| S5-multi-ip-sybil | CRITICAL | 100.0% (attacker inbound share; honest blocked) | 11/11 inbound slots attacker; 11/11 honest rejected full | outputs/S5-multi-ip-sybil.json |
| S7-eclipse-isolation | CRITICAL | 100.0% (attacker outbound share) | 10/10 outbound slots attacker; 0 honest | outputs/S7-eclipse-isolation.json |
| S10-attempt-exhaustion | HIGH | 100.0% (attempts wasted; honest peers reached) | 240/240 attempts wasted; 0 honest peers in 120 s | outputs/S10-attempt-exhaustion.json |
| S8-fixed-cluster-bypass | MEDIUM | 100.0% (bypass attempts activated) | 6 reserved peers activate; total active 27 (21 public + 6 reserved) | outputs/S8-fixed-cluster-bypass.json |
| S6-endpoint-gossip | MEDIUM | 11.0% (poisoned endpoints accepted / received) | 22 of 200 endpoints cached; 178 dropped (136 truncated, 27 hops, 11 invalid, 4 duplicate) | outputs/S6-endpoint-gossip.json |
| S2-peer-churn | MEDIUM | 0.0% (outbound availability loss) | 36 churn events; 25 outbound refills within one batch; max outbound deficit 0; inbound drains 11 to 0 | outputs/S2-peer-churn.json |
| S9-redirect-abuse | LOW | 60.0% (redirects accepted / requested) | 30 of 50 redirects accepted; 20 rejected at cap | outputs/S9-redirect-abuse.json |
| S3-duplicate-identity | LOW | 5.5% (activated / attempts_total) | 11 slots filled by 20 reused keys; 60 handshake rejects; 66 duplicate-key rejects; 63 slots-full rejects | outputs/S3-duplicate-identity.json |
| S4-single-ip-flood | LOW | 4.0% (accepted / attempts_total) | 2 of 50 accepted; 48 rejected ipLimitExceeded | outputs/S4-single-ip-flood.json |
| S0-baseline | INFO | 0.0% (reference measurement (no attack)) | 21/21 slots active (10 out + 11 in); 9 overshoot attempts rejected full | outputs/S0-baseline.json |
| S1-bootstrap | INFO | 0.0% (reference measurement (no attack)) | first peer 100 ms; full outbound 10,100 ms; 40 endpoints learned from 4 hosts | outputs/S1-bootstrap.json |

Severity counts: CRITICAL 2, HIGH 1, INFO 2, LOW 3, MEDIUM 3
