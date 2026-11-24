# Methodology

## Labels

Every measured claim in this pack carries one of three labels:

- **OBSERVED** — read directly from the pinned source (a constant, a
  check, a code path), with a file:line citation.
- **SIMULATED** — produced by the protocol simulator from scripted
  scenarios. The numbers are real outputs of the harness, but they
  describe the model, not a live network.
- **UNMEASURED** — verified in code but not exercised by any scenario.
  No number is claimed for it.

No claim in this pack is presented as a measurement of a live postfiatd
network.

## How a scenario is built

1. The scenario file (`scenarios/S*.json`) declares an id, a title, a
   fixed seed and a duration in virtual milliseconds, plus
   scenario-specific parameters (peer counts, attacker counts, endpoint
   counts, churn settings).
2. `scripts/load_harness.py` runs the scenario against
   `scripts/simulator.py`, which implements the pipeline in
   `docs/environment.md`. The driver records every event (handshake,
   slot creation, activation, rejection, disconnect, gossip, redirect,
   autoconnect batch) with its virtual timestamp, actor, IP, key,
   endpoint, direction, control and outcome.
3. Per scenario the harness writes three files under `outputs/`:
   `S*.csv` (one row per event), `S*.json` (outcome/control counts,
   scenario metrics, final peer-finder state, per-actor breakdown) and
   `S*.log` (unedited run log, including the full SHA-256 of the
   scenario file, the simulator and the harness, and the summary
   numbers).
4. `scripts/build_matrix.py` reads the 11 summary JSON files and builds
   the severity-ranked matrix (`outputs/matrix.json`, `outputs/matrix.md`).
5. `scripts/measure_controls.py` reads the same summaries and measures
   each control's effectiveness (`outputs/control-measurements.json`,
   `outputs/control-measurements.md`).
6. `scripts/make_manifest.py` writes `manifest.json` (SHA-256 per file).
7. `scripts/run_all.sh` runs steps 2-6, then re-runs the harness into a
   scratch copy and diffs every committed output (determinism check),
   regenerates `SHA256SUMS` and verifies it.

## Determinism

The harness uses a virtual clock and fixed seeds (`20261125` for every
scenario). No wall clock, no network, no randomness outside the seeded
generator. Re-running `bash scripts/run_all.sh` produces byte-identical
outputs except `outputs/run_all.log`, which holds the wall-clock start
line and is excluded from digests. The determinism check in `run_all.sh`
verifies this on every run by diffing a second run in a scratch
directory.

## Severity rubric

The matrix percentage is a measurement; the severity is a judgment on
whether the attacker's goal was achieved:

| Severity | Meaning |
|---|---|
| CRITICAL | The attack achieves its goal (success at or near 100%), with no effective control in the way. |
| HIGH | The attack mostly succeeds (success >= 50%), or causes a severe but bounded and self-healing availability loss. |
| MEDIUM | The attack has a measurable but bounded effect (success >= 10%), or the behaviour is by design and the exposure is configuration trust rather than a control failure, or the run exposes a real asymmetry that needs an operator's attention. |
| LOW | The attack is contained by a control (success < 10%), or the control bounds the abuse even though the pre-cap share looks high. |
| INFO | No attack in this scenario (baseline / reference measurement). |

Counts in this pack: 2 CRITICAL, 1 HIGH, 3 MEDIUM, 3 LOW, 2 INFO.

## Control effectiveness

Effectiveness is the share of attack attempts a control stopped, counted
from the committed scenario outputs. Where a control was not the binding
constraint (for example the inbound slot limit in S5, which bounds the
total but does not discriminate), the effectiveness is 0% and the note
says why. A control no scenario exercised is UNMEASURED, never assigned
a number.

## What changed between runs (model fixes found during verification)

The first harness run exposed four model bugs, all fixed in the
simulator and harness before the numbers in this pack were produced:

1. **Failed activations left stale slots.** `activate()` returned
   `duplicatePeer` / `full` without removing the slot, so the slot,
   the IP connection count and the in-flight attempt count leaked.
   The real code destroys the slot on activation failure. Fixed:
   failed activations now remove the slot.
2. **Autoconnect starved after the first batch.** An `attempts_in_flight`
   guard blocked every later batch while any attempt was counted in
   flight. The real code sizes batches by `attempts_needed()`, which
   already subtracts in-flight attempts. Fixed: guard removed.
3. **S3 conflated two controls.** The duplicate-identity flood reused
   the same IP per key, so `ipLimit` rejected 100 of 200 attempts
   before the duplicate-key check ran. Fixed: every (key, round) now
   gets a distinct IP, so the duplicate-key control is what is
   measured.
4. **Sequential instead of concurrent batch timing.** Attempts in one
   batch were charged latency one after another, so S10 burned only
   100 attempts in 120 s. The real code launches a batch in parallel.
   Fixed: a batch resolves together after one latency; batches are one
   `secondsPerConnect` tick apart.

The numbers in this pack are from the fixed model. The fixes are
recorded here so a reviewer can see what the first run got wrong.
