#!/usr/bin/env bash
# run_all.sh — run the full peer-discovery / Sybil assessment end to end.
#
# Usage:
#   bash scripts/run_all.sh
#
# Steps:
#   1. load_harness.py  — run all 11 scenarios (deterministic, virtual clock)
#   2. build_matrix.py  — severity-ranked scenario matrix
#   3. measure_controls.py — per-control effectiveness measurements
#   4. make_manifest.py — pack manifest (SHA-256 per file)
#   5. determinism check — re-run the harness into a scratch copy and
#      diff every committed output (excluding outputs/run_all.log, which
#      holds the wall-clock start line)
#   6. make_sha256sums.sh — regenerate SHA256SUMS
#   7. verify_digests.sh — verify every committed output digest
#
# Exit code is non-zero on any failure. All outputs are deterministic:
# the harness uses a virtual clock and fixed seeds, so a re-run produces
# byte-identical files.
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
export LC_ALL=C
export TZ=UTC

PACK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK_DIR"

# The wall-clock start line is the only non-deterministic output; it is
# excluded from digests by make_sha256sums.sh.
echo "run started at $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee outputs/run_all.log
echo "pinned commit: 0085a1ff885d6a446369cf73a4430f75af22be55" | tee -a outputs/run_all.log

python3 scripts/load_harness.py | tee -a outputs/run_all.log
python3 scripts/build_matrix.py | tee -a outputs/run_all.log
python3 scripts/measure_controls.py | tee -a outputs/run_all.log
python3 scripts/make_manifest.py | tee -a outputs/run_all.log

# Determinism check: re-run the harness into a scratch copy and compare.
SCRATCH="$(mktemp -d /tmp/pf-rerun-check.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT
mkdir -p "$SCRATCH/outputs"
cp scenarios/*.json "$SCRATCH/" 2>/dev/null || true
mkdir -p "$SCRATCH/scenarios" "$SCRATCH/scripts"
cp scenarios/*.json "$SCRATCH/scenarios/"
cp scripts/simulator.py scripts/load_harness.py "$SCRATCH/scripts/"
cd "$SCRATCH"
PYTHONDONTWRITEBYTECODE=1 python3 scripts/load_harness.py > /dev/null
cd "$PACK_DIR"
DIFF_OK=1
for f in outputs/S*.csv outputs/S*.json outputs/S*.log; do
    if ! diff -q "$f" "$SCRATCH/outputs/$(basename "$f")" > /dev/null; then
        echo "DETERMINISM FAIL: $f differs between runs" | tee -a outputs/run_all.log
        DIFF_OK=0
    fi
done
if [ "$DIFF_OK" -eq 1 ]; then
    echo "DETERMINISM OK: all scenario outputs byte-identical across runs" | tee -a outputs/run_all.log
else
    echo "DETERMINISM FAILED" | tee -a outputs/run_all.log
    exit 1
fi

bash scripts/make_sha256sums.sh | tee -a outputs/run_all.log
bash scripts/verify_digests.sh | tee -a outputs/run_all.log
echo "run_all.sh: OK" | tee -a outputs/run_all.log
