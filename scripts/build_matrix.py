#!/usr/bin/env python3
"""build_matrix.py — build the severity-ranked scenario matrix from the
per-scenario summary JSON files in outputs/.

Usage:
    python3 scripts/build_matrix.py

Writes outputs/matrix.json and outputs/matrix.md.

Severity rubric (fixed, documented here and in docs/findings-report.md):
  CRITICAL  attack achieves its goal with a success rate >= 90%
            (or availability loss >= 90% of the target metric)
  HIGH      success rate >= 50%, or availability loss >= 50%
  MEDIUM    success rate >= 10%, or a measurable but bounded effect
  LOW       success rate < 10%, or the attack is contained by a control
  INFO      no attack in this scenario (baseline / reference measurement)

Each scenario carries its own attack_success_pct derived from its metrics
(see the table in this file). The matrix is a view over the committed
outputs — re-running it from the same outputs/ is deterministic.
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
OUTPUTS_DIR = os.path.join(PACK, "outputs")

# scenario -> (attack success percent, what was measured, rationale)
# The percentage is a measurement; the severity is a judgment on whether
# the attacker's goal was achieved. A control that bounds an attack (cap,
# slot limit, filter) keeps the severity low even when the pre-cap share
# is high; a by-design bypass (S8) is MEDIUM because the exposure is
# configuration trust, not a control failure; a self-healing delay (S10)
# is HIGH, not CRITICAL, because the node recovers on its own.
SUCCESS = {
    "S0-baseline": (0.0, "reference measurement (no attack)",
                    "Baseline fills all 21 slots; no attack present."),
    "S1-bootstrap": (0.0, "reference measurement (no attack)",
                     "Cold start reaches full outbound in 10.1 s; "
                     "no attack present."),
    "S2-peer-churn": (0.0, "outbound availability loss",
                      "Outbound availability loss is 0%: every dropped "
                      "outbound peer is refilled within one batch and the "
                      "node spends 0 ms below full outbound. The MEDIUM "
                      "rating is for the asymmetry the run exposes: "
                      "autoconnect never refills INBOUND slots, so inbound "
                      "active drains 11 to 0 over 12 epochs. In a live "
                      "network new peers dial in (which this scenario does "
                      "not model), so the drain is a measured asymmetry, "
                      "not a demonstrated outage."),
    "S3-duplicate-identity": (5.5, "activated / attempts_total",
                              "11 of 200 attempts activate (the 11 inbound "
                              "slots); 66 repeat attempts are rejected as "
                              "duplicate keys, 63 more as slots full."),
    "S4-single-ip-flood": (4.0, "accepted / attempts_total",
                           "2 of 50 attempts activate (ipLimit 2); the "
                           "flood is contained to 2 slots."),
    "S5-multi-ip-sybil": (100.0, "attacker inbound share; honest blocked",
                          "11 of 11 inbound slots go to the attacker; "
                          "all 11 honest peers are rejected full."),
    "S6-endpoint-gossip": (11.0, "poisoned endpoints accepted / received",
                           "22 of 200 gossiped endpoints enter the caches "
                           "(livecache + bootcache); 178 are dropped by "
                           "truncation, hops, invalid and duplicate "
                           "filters. The 22 survivors are the seed for "
                           "the S7 eclipse."),
    "S7-eclipse-isolation": (100.0, "attacker outbound share",
                             "10 of 10 outbound slots go to the attacker; "
                             "0 honest outbound peers."),
    "S8-fixed-cluster-bypass": (100.0, "bypass attempts activated",
                                "6 of 6 reserved peers activate while all "
                                "21 public slots are full. By design "
                                "(fixed/cluster peers do not count toward "
                                "limits); the exposure is configuration "
                                "trust, not a control failure."),
    "S9-redirect-abuse": (60.0, "redirects accepted / requested",
                          "30 of 50 redirects accepted; the cap stops "
                          "the remaining 20, so the attacker's goal of "
                          "unbounded abuse is not achieved."),
    "S10-attempt-exhaustion": (100.0, "attempts wasted; honest peers reached",
                               "240 of 240 attempts wasted on dead "
                               "endpoints; 0 honest peers in 120 s. "
                               "Self-healing: the 300 dead endpoints are "
                               "exhausted after 15 batches (~150 s), so "
                               "the delay is bounded, not permanent."),
}

SEVERITY = {
    "S0-baseline": "INFO",
    "S1-bootstrap": "INFO",
    "S2-peer-churn": "MEDIUM",
    "S3-duplicate-identity": "LOW",
    "S4-single-ip-flood": "LOW",
    "S5-multi-ip-sybil": "CRITICAL",
    "S6-endpoint-gossip": "MEDIUM",
    "S7-eclipse-isolation": "CRITICAL",
    "S8-fixed-cluster-bypass": "MEDIUM",
    "S9-redirect-abuse": "LOW",
    "S10-attempt-exhaustion": "HIGH",
}

# Human-readable effect per scenario, keyed from the summary metrics.
EFFECT = {
    "S0-baseline": "21/21 slots active (10 out + 11 in); 9 overshoot "
                   "attempts rejected full",
    "S1-bootstrap": "first peer 100 ms; full outbound 10,100 ms; "
                    "40 endpoints learned from 4 hosts",
    "S2-peer-churn": "36 churn events; 25 outbound refills within one "
                     "batch; max outbound deficit 0; inbound drains 11 to 0",
    "S3-duplicate-identity": "11 slots filled by 20 reused keys; 60 "
                             "handshake rejects; 66 duplicate-key rejects; "
                             "63 slots-full rejects",
    "S4-single-ip-flood": "2 of 50 accepted; 48 rejected ipLimitExceeded",
    "S5-multi-ip-sybil": "11/11 inbound slots attacker; 11/11 honest "
                         "rejected full",
    "S6-endpoint-gossip": "22 of 200 endpoints cached; 178 dropped "
                     "(136 truncated, 27 hops, 11 invalid, 4 duplicate)",
    "S7-eclipse-isolation": "10/10 outbound slots attacker; 0 honest",
    "S8-fixed-cluster-bypass": "6 reserved peers activate; total active "
                               "27 (21 public + 6 reserved)",
    "S9-redirect-abuse": "30 of 50 redirects accepted; 20 rejected at cap",
    "S10-attempt-exhaustion": "240/240 attempts wasted; 0 honest peers "
                              "in 120 s",
}


def severity_rank(sev):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[sev]


def main():
    rows = []
    for sid in sorted(SUCCESS):
        with open(os.path.join(OUTPUTS_DIR, sid + ".json")) as f:
            summary = json.load(f)
        success, measured, rationale = SUCCESS[sid]
        sev = SEVERITY[sid]
        rows.append({
            "scenario": sid,
            "title": summary["title"],
            "severity": sev,
            "attack_success_pct": success,
            "measured_as": measured,
            "rationale": rationale,
            "effect": EFFECT[sid],
            "total_events": summary["total_events"],
            "activated": summary["activated"],
            "evidence": "outputs/%s.json, outputs/%s.csv, outputs/%s.log"
                        % (sid, sid, sid),
        })
    rows.sort(key=lambda r: (severity_rank(r["severity"]),
                             -r["attack_success_pct"], r["scenario"]))
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    with open(os.path.join(OUTPUTS_DIR, "S0-baseline.json")) as f:
        pinned = json.load(f)["pinned_commit"]
    matrix = {
        "pinned_commit": pinned,
        "severity_counts": dict(sorted(counts.items())),
        "rows": rows,
    }
    with open(os.path.join(OUTPUTS_DIR, "matrix.json"), "w") as f:
        json.dump(matrix, f, indent=2, sort_keys=True)
        f.write("\n")

    lines = ["# Scenario matrix (severity-ranked)", "",
             "| Scenario | Severity | Attack success | Effect | Evidence |",
             "|---|---|---|---|---|"]
    for r in rows:
        lines.append("| %s | %s | %.1f%% (%s) | %s | outputs/%s.json |"
                     % (r["scenario"], r["severity"], r["attack_success_pct"],
                        r["measured_as"], r["effect"], r["scenario"]))
    lines.append("")
    lines.append("Severity counts: %s"
                 % ", ".join("%s %d" % (k, v)
                             for k, v in sorted(counts.items())))
    with open(os.path.join(OUTPUTS_DIR, "matrix.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("matrix: %s" % json.dumps(counts, sort_keys=True))
    for r in rows:
        print("  %s %s %.1f%%" % (r["scenario"], r["severity"],
                                  r["attack_success_pct"]))


if __name__ == "__main__":
    main()
