# Control measurements

| ID | Control | Scenario | Status | Blocked / attempts | Effectiveness |
|---|---|---|---|---|---|
| C00 | ipLimit (public) | S4-single-ip-flood | MEASURED | 48 / 50 | 96.0% |
| C01 | duplicate-key rejection | S3-duplicate-identity | MEASURED | 66 / 200 | 33.0% |
| C02 | inbound slot limit (inPeers 11) | S5-multi-ip-sybil | MEASURED | 11 / 11 | 0.0% |
| C03 | outbound slot limit (outPeers 10) | S0-baseline | MEASURED | 9 / 9 | 100.0% |
| C04 | handshake cookie | S3-duplicate-identity | MEASURED | 30 / 30 | 100.0% |
| C05 | Network-ID handshake check | S3-duplicate-identity | MEASURED | 20 / 20 | 100.0% |
| C06 | proxy / direct-connect rejection | S3-duplicate-identity | MEASURED | 10 / 10 | 100.0% |
| C07 | endpoint gossip filters (hops/invalid/duplicate) | S6-endpoint-gossip | MEASURED | 42 / 200 | 21.0% |
| C08 | gossip truncation (numberOfEndpointsMax 64) | S6-endpoint-gossip | MEASURED | 136 / 200 | 68.0% |
| C09 | maxRedirects cap (30) | S9-redirect-abuse | MEASURED | 20 / 50 | 40.0% |
| C10 | autoconnect refill (churn) | S2-peer-churn | MEASURED | 0 / 36 | 100.0% |
| C11 | bootstrap discovery (4 hosts) | S1-bootstrap | MEASURED | 0 / 40 | 100.0% |
| C12 | max_untrusted_count (1000) | — | UNMEASURED | — | UNMEASURED |
