# Postfiatd Peer Discovery and Sybil-Resistance Assessment

A commit-pinned assessment of how postfiatd peer discovery, connection
management and identity controls respond to Sybil and eclipse-style
pressure, measured with a faithful protocol-level simulator.

Pinned commit: `0085a1ff885d6a446369cf73a4430f75af22be55`
("Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9",
2026-10-10). All 22 cited source files are verified blob-by-blob in
`docs/source-inventory.md`.

## Headline result

The pipeline stops single-IP floods and duplicate identities, and
fails open to multi-IP Sybil pressure:

- **S5 (CRITICAL):** 40 distinct-IP attackers take 11 of 11 inbound
  slots; 11 of 11 honest peers rejected.
- **S7 (CRITICAL):** a poisoned endpoint cache hands the attacker
  10 of 10 outbound slots; 0 honest.
- **S10 (HIGH):** 300 dead endpoints waste 240 of 240 attempts over
  120 s; 0 honest peers reached (self-heals after ~150 s).
- **S3/S4 (LOW):** the handshake stops every replay and relay
  (60 of 60 bad handshakes rejected); `ipLimit` contains single-IP
  floods (48 of 50 rejected).
- **S0/S1 (INFO):** healthy baseline — 21 of 21 slots at 155 ms;
  cold start to full outbound in 10,100 ms.

Severity counts: 2 CRITICAL, 1 HIGH, 3 MEDIUM, 3 LOW, 2 INFO.
12 of 13 controls measured; 1 UNMEASURED (`max_untrusted_count`, a
validator-manifest bound, not a peer control).

## Reproduce

```bash
bash scripts/run_all.sh
```

Runs all 11 scenarios, builds the matrix, measures the controls,
writes the manifest, re-runs the harness into a scratch copy and diffs
every output (determinism check), then regenerates and verifies
`SHA256SUMS`. Exit 0 means everything passed. Deterministic: a re-run
produces byte-identical outputs except `outputs/run_all.log` (which
holds the wall-clock start line and is excluded from digests).

```bash
bash scripts/verify_digests.sh   # verify every committed output digest
```

## Layout

- `scenarios/` — 11 scenario definitions (id, title, seed, duration,
  parameters). All seeds are `20261125`; all durations are virtual ms.
- `scripts/` — `simulator.py` (the protocol model),
  `load_harness.py` (11 scenario drivers), `build_matrix.py`,
  `measure_controls.py`, `make_manifest.py`, `run_all.sh`,
  `make_sha256sums.sh`, `verify_digests.sh`.
- `outputs/` — per scenario: `S*.csv` (one row per event), `S*.json`
  (summary + metrics + final state), `S*.log` (unedited run log with
  full SHA-256s). Plus `matrix.json` / `matrix.md` and
  `control-measurements.json` / `control-measurements.md`.
- `docs/` — `source-inventory.md` (22 files, blob SHAs),
  `environment.md` (simulator design + limitations),
  `methodology.md` (labels, determinism, severity rubric),
  `control-inventory.md` (C00-C12 with measurements),
  `findings-report.md`, `remediation-report.md`, `decision-memo.md`.

## Labels

- **OBSERVED** — read directly from the pinned source, with a
  file:line citation.
- **SIMULATED** — produced by the protocol simulator from scripted
  scenarios. Real harness outputs, but they describe the model, not
  a live network.
- **UNMEASURED** — verified in code but not exercised by any scenario.
  No number is claimed.

## Claim-to-evidence index

Every measured claim below links to its script and its unedited output.

| Claim | Evidence |
|---|---|
| S0 fills 21/21 slots; 9 overshoot attempts rejected; full at 155 ms | `scripts/load_harness.py` (run_s0), `outputs/S0-baseline.json`, `.csv`, `.log` |
| S1 first peer 100 ms; full outbound 10,100 ms; 40 endpoints from 4 hosts; 24 attempts | `scripts/load_harness.py` (run_s1), `outputs/S1-bootstrap.json`, `.csv`, `.log` |
| S2 36 churn events; 25 outbound refills; 0 ms below full outbound; inbound 11 to 0 | `scripts/load_harness.py` (run_s2), `outputs/S2-peer-churn.json`, `.csv`, `.log` |
| S3 11 of 200 activate (5.5%); 66 duplicate-key, 63 full, 60 handshake rejects | `scripts/load_harness.py` (run_s3), `outputs/S3-duplicate-identity.json`, `.csv`, `.log` |
| S4 2 of 50 accepted (4.0%); 48 rejected ipLimit | `scripts/load_harness.py` (run_s4), `outputs/S4-single-ip-flood.json`, `.csv`, `.log` |
| S5 11/11 inbound slots attacker; 0/11 honest | `scripts/load_harness.py` (run_s5), `outputs/S5-multi-ip-sybil.json`, `.csv`, `.log` |
| S6 22 of 200 endpoints cached (11.0%); 136 truncated, 27 hops, 11 invalid, 4 duplicate dropped | `scripts/load_harness.py` (run_s6), `outputs/S6-endpoint-gossip.json`, `.csv`, `.log` |
| S7 10/10 outbound slots attacker; 0 honest; caches 60 attacker / 10 honest | `scripts/load_harness.py` (run_s7), `outputs/S7-eclipse-isolation.json`, `.csv`, `.log` |
| S8 6 reserved peers activate while 21 public slots full; total 27 | `scripts/load_harness.py` (run_s8), `outputs/S8-fixed-cluster-bypass.json`, `.csv`, `.log` |
| S9 30 of 50 redirects accepted; 20 rejected at cap | `scripts/load_harness.py` (run_s9), `outputs/S9-redirect-abuse.json`, `.csv`, `.log` |
| S10 240/240 attempts wasted (100%); 0 honest peers in 120 s; 12 batches | `scripts/load_harness.py` (run_s10), `outputs/S10-attempt-exhaustion.json`, `.csv`, `.log` |
| Matrix: 2 CRITICAL, 1 HIGH, 3 MEDIUM, 3 LOW, 2 INFO | `scripts/build_matrix.py`, `outputs/matrix.json`, `outputs/matrix.md` |
| Controls: 12 measured, 1 UNMEASURED (C12) | `scripts/measure_controls.py`, `outputs/control-measurements.json`, `outputs/control-measurements.md` |
| All 22 cited source files verified blob-by-blob | `docs/source-inventory.md` |
| Simulator parameters verbatim from the pinned code | `docs/environment.md`, `scripts/simulator.py` |

## Limitations

No real postfiatd binary was built; the simulator is a protocol-level
model with scripted peers, documentation-range IPs, synthetic keys and
a virtual clock. It does not measure live-network behaviour, real TLS,
validator manifests, or ledger/consensus interaction. See
`docs/environment.md` for the full list.
