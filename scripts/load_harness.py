#!/usr/bin/env python3
"""load_harness.py — run peer-discovery / Sybil scenarios against the
protocol simulator (scripts/simulator.py).

Usage:
    python3 scripts/load_harness.py [SCENARIO_ID ...]
    (no arguments: run every scenario in scenarios/*.json)

For each scenario this script writes, under outputs/:
    S0-baseline.csv   — per-event log (one row per simulator event, virtual time)
    S0-baseline.json  — summary: outcome/control counts, scenario metrics,
                        final peer-finder state, per-actor breakdown
    S0-baseline.log   — unedited run log, including the full SHA-256 of the
                        scenario file and of scripts/simulator.py, and the
                        summary numbers
(the same three files exist for every scenario id S0-baseline .. S10-attempt-exhaustion)

All outputs are deterministic: virtual clock, fixed seeds, no wall clock,
no network. Re-running produces byte-identical files (verified by
run_all.sh, which diffs a second run).

Scenario file format (scenarios/S0-baseline.json and likewise):
    id, title, seed, duration_ms, and scenario-specific parameters
    (peer counts, attacker counts, endpoint counts, churn settings).
"""

import csv
import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from simulator import (Peer, PeerFinderSim, CONTROL_PARAMS, PINNED_COMMIT,  # noqa: E402
                       BOOTSTRAP_HOSTS, CONNECT_LATENCY_MS,
                       DEAD_ENDPOINT_LATENCY_MS, DEFAULT_PEER_PORT)

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
SCENARIOS_DIR = os.path.join(PACK, "scenarios")
OUTPUTS_DIR = os.path.join(PACK, "outputs")

SECONDS_PER_CONNECT_MS = CONTROL_PARAMS["secondsPerConnect"][0] * 1000


def time_to_full_outbound_ms(sim):
    """First virtual time at which outbound active slots reach out_max."""
    out = 0
    for r in sorted(sim.records, key=lambda x: (x["t_ms"], x["actor"],
                                                x["event"])):
        if r["direction"] != "out":
            continue
        if r["outcome"] == "activated":
            out += 1
        elif (r["event"] == "disconnect"
              and "(was active)" in r["detail"]):
            # Only a disconnect of an ACTIVE slot frees an outbound slot;
            # disconnects of failed activations (was connect/accept) do not.
            out -= 1
        if out >= sim.out_max:
            return r["t_ms"]
    return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Peer factories. IPs use the documentation ranges; no real host is named.
# ---------------------------------------------------------------------------
def honest_peer(i, port=DEFAULT_PEER_PORT):
    return Peer("h-%03d" % i, "key-h%04d" % i, "203.0.113.%d" % (10 + i),
                port=port, kind="honest")


def attacker_peer(i, port=DEFAULT_PEER_PORT):
    return Peer("a-%03d" % i, "key-a%04d" % i, "198.51.100.%d" % (10 + i),
                port=port, kind="attacker")


def dead_peer(i):
    return Peer("d-%03d" % i, "key-d%04d" % i, "198.51.100.%d" % (100 + i),
                kind="attacker")


# ---------------------------------------------------------------------------
# Attempt helpers — the exact pipeline order of the real code:
# handshake -> slot -> onConnected -> activate.
# ---------------------------------------------------------------------------
def attempt_inbound(sim, peer, cookie_ok=True, network_id_ok=True,
                    proxy_ok=True):
    """One inbound connection attempt. Returns the activate result."""
    ok, _ = sim.handshake(peer, cookie_ok, network_id_ok, proxy_ok)
    if not ok:
        return "handshake_rejected"
    slot, result = sim.new_inbound_slot(peer)
    if slot is None:
        return result
    reserved = (peer.key in sim.cluster_keys
                or peer.key in sim.reservation_keys)
    return sim.activate(slot, peer.key, reserved)


def attempt_outbound(sim, peer, live=True, cookie_ok=True,
                     network_id_ok=True, proxy_ok=True):
    """One outbound connection attempt. Returns the activate result.
    Live endpoints answer; dead ones time out and the attempt is
    squelched. No clock advance here: attempts in one batch resolve
    concurrently, so the caller advances the clock once per batch."""
    ok, _ = sim.handshake(peer, cookie_ok, network_id_ok, proxy_ok)
    if not ok:
        return "handshake_rejected"
    slot, result = sim.new_outbound_slot(peer)
    if slot is None:
        return result
    if not live:
        sim.backoff_failures[peer.endpoint] += 1
        sim.squelch_address(peer.ip)
        sim.bootcache_on_failure(peer.endpoint)
        sim.disconnect_slot(slot, "connect failed: endpoint dead "
                            "(backoff %d s, squelch %d s)"
                            % (sim.backoff_seconds(peer.endpoint),
                               CONTROL_PARAMS["recentAttemptDuration"][0]))
        return "connect_failed"
    if not sim.on_connected(slot, "127.0.0.1:51235"):
        sim.disconnect_slot(slot, "self-connect")
        return "self_connect"
    reserved = (peer.key in sim.cluster_keys
                or peer.key in sim.reservation_keys)
    return sim.activate(slot, peer.key, reserved)


def fill_outbound(sim, registry, until_ms, batch_gap_ms=SECONDS_PER_CONNECT_MS):
    """Autoconnect loop: run batches until outbound slots are full, no
    candidates remain, or the virtual clock passes until_ms. Returns the
    number of batches run."""
    batches = 0
    while sim.now_ms <= until_ms:
        if sim.out_active >= sim.out_max:
            break
        endpoints, source = sim.autoconnect()
        if not endpoints:
            break
        batches += 1
        batch_start = sim.now_ms
        # The whole batch resolves together after one connect latency
        # (concurrent attempts); the next batch is one tick later.
        sim.now_ms = batch_start + CONNECT_LATENCY_MS
        for ep in endpoints:
            peer = registry.get(ep)
            if peer is None:
                # Unknown endpoint (e.g. a bootstrap host address): treat
                # as a live honest peer.
                ip, _, port = ep.rpartition(":")
                peer = Peer("x-" + ip, "key-x-" + ip.replace(".", "-"),
                            ip, port=int(port) if port else DEFAULT_PEER_PORT,
                            kind="honest")
                registry[ep] = peer
            attempt_outbound(sim, peer, live=True)
        sim.now_ms = batch_start + batch_gap_ms
    return batches


# ---------------------------------------------------------------------------
# Scenario drivers
# ---------------------------------------------------------------------------
def run_s0(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    registry = {}
    honest = [honest_peer(i) for i in range(sc["honest_peers"])]
    for p in honest:
        registry[p.endpoint] = p
        sim.bootcache_insert(p.endpoint)
    # 11 honest peers arrive inbound first.
    for p in honest[:11]:
        attempt_inbound(sim, p)
        sim.now_ms += 5
    batches = fill_outbound(sim, registry, sc["duration_ms"])
    return sim, {
        "honest_peers_available": len(honest),
        "autoconnect_batches": batches,
        "time_to_full_ms": time_to_full_outbound_ms(sim),
        "overshoot_rejected_full": sum(
            1 for r in sim.records if r["outcome"] == "rejected_slots_full"
            and r["direction"] == "out"),
    }


def run_s1(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    registry = {}
    # Cold start: only the 4 default bootstrap hosts are known.
    bootstrap = [Peer("boot-%d" % i, "key-boot%04d" % i, ip,
                      kind="honest") for i, (_, ip) in enumerate(BOOTSTRAP_HOSTS)]
    for p in bootstrap:
        registry[p.endpoint] = p
        sim.bootcache_insert(p.endpoint)
    first_peer_ms = None
    attempts_used = 0
    endpoints_learned = 0
    # Bootstrap hosts answer together after one connect latency and gossip
    # 10 honest endpoints each.
    sim.now_ms = CONNECT_LATENCY_MS
    for p in bootstrap:
        result = attempt_outbound(sim, p, live=True)
        attempts_used += 1
        if result == "success" and first_peer_ms is None:
            first_peer_ms = sim.now_ms
        # The bootstrap host shares its neighbours (hops 1 in the message).
        for j in range(10):
            hp = honest_peer(100 + len(registry) - 4 + j)
            registry[hp.endpoint] = hp
            sim.livecache[hp.endpoint] = 2
            sim.bootcache_insert(hp.endpoint)
            endpoints_learned += 1
        # Bootstrap hosts are not kept as peers in this model: they served
        # their purpose (discovery) and disconnect.
        slot = sim.slots.get(p.endpoint)
        if slot is not None:
            sim.disconnect_slot(slot, "bootstrap host disconnected after "
                                "sharing endpoints")
    # The next autoconnect batch is at the next secondsPerConnect tick.
    sim.now_ms = SECONDS_PER_CONNECT_MS
    batches = fill_outbound(sim, registry, sc["duration_ms"])
    return sim, {
        "bootstrap_hosts": len(BOOTSTRAP_HOSTS),
        "endpoints_learned": endpoints_learned,
        "time_to_first_peer_ms": first_peer_ms,
        "time_to_full_outbound_ms": time_to_full_outbound_ms(sim),
        "attempts_used": sum(
            1 for r in sim.records if r["event"] == "new_outbound_slot"),
        "autoconnect_batches": batches,
    }


def run_s2(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    rng = random.Random(sc["seed"])
    registry = {}
    honest = [honest_peer(i) for i in range(sc["honest_peers"])]
    for p in honest:
        registry[p.endpoint] = p
        sim.bootcache_insert(p.endpoint)
    for p in honest[:11]:
        attempt_inbound(sim, p)
        sim.now_ms += 5
    fill_outbound(sim, registry, 10000)
    epochs = sc["epochs"]
    churn_per_epoch = sc["churn_per_epoch"]
    total_churned = 0
    total_refilled = 0
    max_out_deficit = 0
    time_below_full_ms = 0
    epoch_ms = sc["duration_ms"] // epochs
    for epoch in range(epochs):
        active = [s for s in list(sim.slots.values())
                  if s.state == "active" and not s.fixed]
        rng.shuffle(active)
        for slot in active[:churn_per_epoch]:
            sim.disconnect_slot(slot, "churn: peer dropped (epoch %d)" % epoch)
            total_churned += 1
        deficit_start = sim.now_ms
        before = sim.out_active
        fill_outbound(sim, registry, sim.now_ms + epoch_ms)
        total_refilled += sim.out_active - before
        if sim.out_active < sim.out_max:
            time_below_full_ms += sim.now_ms - deficit_start
        max_out_deficit = max(max_out_deficit, sim.out_max - sim.out_active)
        sim.now_ms = max(sim.now_ms, (epoch + 1) * epoch_ms)
    return sim, {
        "epochs": epochs,
        "churn_per_epoch": churn_per_epoch,
        "total_churned": total_churned,
        "total_refilled": total_refilled,
        "max_outbound_deficit": max_out_deficit,
        "time_below_full_outbound_ms": time_below_full_ms,
        "inbound_active_start": 11,
        "inbound_active_end": sim.in_active,
        "inbound_lost": 11 - sim.in_active,
    }


def run_s3(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    # 140 valid handshakes reusing 20 keys (7 endpoints each), then 30 bad
    # cookie, 20 wrong Network-ID, 10 proxy attempts.
    attempts = []
    for round_no in range(7):
        for k in range(20):
            # Distinct IP per (key, round): ipLimit (2 per IP) must not
            # mask the duplicate-key control being measured. Rounds 0-3
            # use 198.51.100.0/24, rounds 4-6 use 192.0.2.0/24.
            if round_no < 4:
                ip = "198.51.100.%d" % (20 + k + 40 * round_no)
            else:
                ip = "192.0.2.%d" % (10 + k + 20 * (round_no - 4))
            p = Peer("a-dup-%d-%d" % (k, round_no), "key-dup%04d" % k,
                     ip, port=51235 + round_no, kind="attacker")
            attempts.append((p, True, True, True))
    for i in range(30):
        attempts.append((attacker_peer(200 + i), False, True, True))
    for i in range(20):
        attempts.append((attacker_peer(230 + i), True, False, True))
    for i in range(10):
        attempts.append((attacker_peer(250 + i), True, True, False))
    for p, cookie_ok, net_ok, proxy_ok in attempts:
        attempt_inbound(sim, p, cookie_ok, net_ok, proxy_ok)
        sim.now_ms += 5
    activated = sum(1 for r in sim.records if r["outcome"] == "activated")
    return sim, {
        "attempts_total": len(attempts),
        "distinct_keys": 20,
        "handshake_rejected_cookie": sim.handshake_rejects["cookie"],
        "handshake_rejected_network_id": sim.handshake_rejects["network_id"],
        "handshake_rejected_proxy": sim.handshake_rejects["proxy"],
        "activated": activated,
        "duplicate_key_rejections": sum(
            1 for r in sim.records
            if r["outcome"] == "rejected_duplicate_key"),
        "slots_full_rejections": sum(
            1 for r in sim.records
            if r["outcome"] == "rejected_slots_full"),
        "attacker_success_pct": round(100.0 * activated / len(attempts), 2),
    }


def run_s4(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    ip = sc["attacker_ip"]
    for i in range(sc["attempts"]):
        p = Peer("a-ip-%02d" % i, "key-ip%04d" % i, ip,
                 port=51235 + i, kind="attacker")
        attempt_inbound(sim, p)
        sim.now_ms += 5
    accepted = sum(1 for r in sim.records if r["outcome"] == "activated")
    return sim, {
        "attacker_ip": ip,
        "attempts_total": sc["attempts"],
        "accepted": accepted,
        "rejected_ip_limit": sum(
            1 for r in sim.records
            if r["outcome"] == "rejected_ip_limit"),
        "attacker_success_pct": round(100.0 * accepted / sc["attempts"], 2),
    }


def run_s5(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    attackers = [attacker_peer(i) for i in range(sc["attacker_peers"])]
    for p in attackers:
        attempt_inbound(sim, p)
        sim.now_ms += 5
    sim.now_ms = 5000
    honest = [honest_peer(i) for i in range(sc["honest_peers"])]
    honest_activated = 0
    for p in honest:
        if attempt_inbound(sim, p) == "success":
            honest_activated += 1
        sim.now_ms += 5
    attacker_activated = sum(
        1 for r in sim.records
        if r["outcome"] == "activated" and r["actor"].startswith("a-"))
    return sim, {
        "attacker_peers": len(attackers),
        "attacker_activated": attacker_activated,
        "attacker_rejected_full": sum(
            1 for r in sim.records
            if r["outcome"] == "rejected_slots_full"
            and r["actor"].startswith("a-")),
        "honest_peers": len(honest),
        "honest_activated": honest_activated,
        "honest_rejected_full": sum(
            1 for r in sim.records
            if r["outcome"] == "rejected_slots_full"
            and r["actor"].startswith("h-")),
        "inbound_saturation_pct": round(
            100.0 * attacker_activated / sim.in_max, 2),
    }


def run_s6(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    attacker = attacker_peer(0)
    attempt_inbound(sim, attacker)
    slot = sim.slots.get(attacker.endpoint)
    # One malicious peer gossips 200 endpoints: 60 with hops > 6, 40
    # invalid (private IP or port 0), 30 duplicates of valid ones, 70 valid.
    endpoints = []
    for i in range(60):
        endpoints.append(("198.51.100.%d:51235" % (150 + i), 7 + (i % 3), True))
    for i in range(40):
        if i % 2 == 0:
            endpoints.append(("10.0.0.%d:51235" % (i + 1), 2, False))
        else:
            endpoints.append(("198.51.100.%d:0" % (200 + i), 2, False))
    valid = [("198.51.100.%d:51235" % (50 + i), 1 + (i % 3), True)
             for i in range(40)]
    endpoints.extend(valid)
    # 60 duplicates: every valid value appears 2-3 times in the list, so
    # the duplicate filter is exercised whatever the shuffle samples.
    endpoints.extend(valid)
    endpoints.extend(valid[:20])
    stats = sim.on_endpoints(slot, endpoints)
    return sim, {
        "endpoints_received": stats["received"],
        "endpoints_truncated": stats["truncated"],
        "dropped_hops": stats["dropped_hops"],
        "dropped_invalid": stats["dropped_invalid"],
        "dropped_duplicate": stats["dropped_duplicate"],
        "accepted_livecache": stats["accepted_livecache"],
        "accepted_bootcache": stats["accepted_bootcache"],
        "livecache_entries": len(sim.livecache),
        "bootcache_entries": len(sim.bootcache),
    }


def run_s7(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    registry = {}
    # Three attacker peers gossip attacker endpoints at hops 6 (stored 7);
    # two honest peers gossip honest endpoints at hops 1 (stored 2).
    gossip_attackers = [attacker_peer(300 + i) for i in range(3)]
    for gi, p in enumerate(gossip_attackers):
        attempt_inbound(sim, p)
        slot = sim.slots.get(p.endpoint)
        eps = [("198.51.100.%d:51235" % (60 + gi * 20 + i), 6, True)
               for i in range(20)]
        sim.on_endpoints(slot, eps)
        sim.now_ms += 5
    gossip_honest = [honest_peer(300 + i) for i in range(2)]
    for gi, p in enumerate(gossip_honest):
        attempt_inbound(sim, p)
        slot = sim.slots.get(p.endpoint)
        eps = [("203.0.113.%d:51235" % (60 + gi * 5 + i), 1, True)
               for i in range(5)]
        sim.on_endpoints(slot, eps)
        sim.now_ms += 5
    # The victim now autoconnects its 10 outbound slots from the poisoned
    # caches: livecache first (hops highest first), then bootcache.
    for ep in list(sim.livecache):
        ip, _, port = ep.rpartition(":")
        kind = "attacker" if ip.startswith("198.51.100.") else "honest"
        n = int(ip.split(".")[2]) * 100 + int(ip.split(".")[3])
        registry[ep] = Peer("g-" + ip, "key-g%04d" % n, ip,
                            port=int(port) if port else DEFAULT_PEER_PORT,
                            kind=kind)
    for ep in sorted(sim.bootcache):
        if ep not in registry:
            ip, _, port = ep.rpartition(":")
            kind = "attacker" if ip.startswith("198.51.100.") else "honest"
            n = int(ip.split(".")[2]) * 100 + int(ip.split(".")[3])
            registry[ep] = Peer("g-" + ip, "key-g%04d" % n, ip,
                                port=int(port) if port else DEFAULT_PEER_PORT,
                                kind=kind)
    # The gossip peers themselves disconnect; the victim keeps only the
    # autoconnected outbound slots for the measurement.
    for p in gossip_attackers + gossip_honest:
        slot = sim.slots.get(p.endpoint)
        if slot is not None:
            sim.disconnect_slot(slot, "gossip peer disconnected")
    batches = fill_outbound(sim, registry, sc["duration_ms"])
    attacker_out = sum(
        1 for s in sim.slots.values()
        if s.state == "active" and not s.inbound()
        and s.peer.kind == "attacker")
    honest_out = sum(
        1 for s in sim.slots.values()
        if s.state == "active" and not s.inbound()
        and s.peer.kind == "honest")
    return sim, {
        "livecache_attacker_endpoints": sum(
            1 for ep in sim.livecache if ep.startswith("198.51.100.")),
        "livecache_honest_endpoints": sum(
            1 for ep in sim.livecache if ep.startswith("203.0.113.")),
        "bootcache_attacker_endpoints": sum(
            1 for ep in sim.bootcache if ep.startswith("198.51.100.")),
        "bootcache_honest_endpoints": sum(
            1 for ep in sim.bootcache if ep.startswith("203.0.113.")),
        "autoconnect_batches": batches,
        "attacker_outbound_slots": attacker_out,
        "honest_outbound_slots": honest_out,
        "attacker_outbound_share_pct": round(
            100.0 * attacker_out / max(1, attacker_out + honest_out), 2),
    }


def run_s8(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    registry = {}
    honest = [honest_peer(i) for i in range(sc["honest_peers"])]
    for p in honest:
        registry[p.endpoint] = p
        sim.bootcache_insert(p.endpoint)
    for p in honest[:11]:
        attempt_inbound(sim, p)
        sim.now_ms += 5
    fill_outbound(sim, registry, 10000)
    assert sim.in_active == sim.in_max and sim.out_active == sim.out_max
    # Public slots are now full. Cluster, fixed and reserved peers arrive.
    cluster_peers = []
    for i in range(sc["cluster_peers"]):
        p = Peer("c-%02d" % i, "key-c%04d" % i, "203.0.113.%d" % (200 + i),
                 kind="cluster", cluster=True)
        sim.add_cluster_key(p.key)
        cluster_peers.append(p)
    fixed_peers = []
    for i in range(sc["fixed_peers"]):
        p = Peer("f-%02d" % i, "key-f%04d" % i, "203.0.113.%d" % (210 + i),
                 kind="fixed", fixed=True)
        sim.add_fixed_peer(p)
        fixed_peers.append(p)
    reserved_peer = Peer("r-00", "key-r0000", "203.0.113.220",
                         kind="reserved", reserved=True)
    sim.add_reservation(reserved_peer.key)
    activated = 0
    for p in cluster_peers + fixed_peers + [reserved_peer]:
        if attempt_inbound(sim, p) == "success":
            activated += 1
        sim.now_ms += 5
    return sim, {
        "public_slots_before": 21,
        "cluster_peers": len(cluster_peers),
        "fixed_peers": len(fixed_peers),
        "reserved_peers": 1,
        "bypass_activated": activated,
        "total_active_after": sim.snapshot()["total_active"],
        "public_in_active": sim.in_active,
        "public_out_active": sim.out_active,
    }


def run_s9(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    attacker = attacker_peer(0)
    attempt_inbound(sim, attacker)
    slot = sim.slots.get(attacker.endpoint)
    # Seed the livecache so redirects have endpoints to hand out.
    for i in range(10):
        sim.livecache["203.0.113.%d:51235" % (40 + i)] = 2
    accepted = 0
    rejected = 0
    for _ in range(sc["redirect_requests"]):
        _, ok = sim.redirect(slot)
        if ok:
            accepted += 1
        else:
            rejected += 1
        sim.now_ms += 5
    return sim, {
        "redirect_requests": sc["redirect_requests"],
        "redirects_accepted": accepted,
        "redirects_rejected_cap": rejected,
        "max_redirects": CONTROL_PARAMS["maxRedirects"][0],
    }


def run_s10(sc):
    sim = PeerFinderSim(seed=sc["seed"])
    registry = {}
    dead = [dead_peer(i) for i in range(sc["dead_endpoints"])]
    honest = [honest_peer(i) for i in range(sc["honest_endpoints"])]
    for p in dead + honest:
        registry[p.endpoint] = p
        sim.bootcache_insert(p.endpoint)
    attempts_wasted = 0
    attempts_total = 0
    first_honest_ms = None
    batches = 0
    while sim.now_ms < sc["duration_ms"]:
        if sim.out_active >= sim.out_max:
            break
        endpoints, source = sim.autoconnect()
        if not endpoints:
            break
        batches += 1
        batch_start = sim.now_ms
        # The whole batch resolves together after one dead-endpoint
        # timeout (concurrent attempts); the next batch is one tick later.
        sim.now_ms = batch_start + DEAD_ENDPOINT_LATENCY_MS
        for ep in endpoints:
            peer = registry[ep]
            attempts_total += 1
            live = peer.kind == "honest"
            result = attempt_outbound(sim, peer, live=live)
            if not live:
                attempts_wasted += 1
            elif result == "success" and first_honest_ms is None:
                first_honest_ms = sim.now_ms
        sim.now_ms = batch_start + SECONDS_PER_CONNECT_MS
    return sim, {
        "dead_endpoints": len(dead),
        "honest_endpoints": len(honest),
        "autoconnect_batches": batches,
        "attempts_total": attempts_total,
        "attempts_wasted_dead": attempts_wasted,
        "attempts_wasted_pct": round(
            100.0 * attempts_wasted / max(1, attempts_total), 2),
        "honest_outbound_slots": sim.out_active,
        "time_to_first_honest_peer_ms": first_honest_ms,
    }


DRIVERS = {
    "S0-baseline": run_s0,
    "S1-bootstrap": run_s1,
    "S2-peer-churn": run_s2,
    "S3-duplicate-identity": run_s3,
    "S4-single-ip-flood": run_s4,
    "S5-multi-ip-sybil": run_s5,
    "S6-endpoint-gossip": run_s6,
    "S7-eclipse-isolation": run_s7,
    "S8-fixed-cluster-bypass": run_s8,
    "S9-redirect-abuse": run_s9,
    "S10-attempt-exhaustion": run_s10,
}


# ---------------------------------------------------------------------------
# Runner: CSV / JSON / log per scenario
# ---------------------------------------------------------------------------
def run_scenario(scenario_path):
    with open(scenario_path, "rb") as f:
        scenario_bytes = f.read()
    scenario_sha = hashlib.sha256(scenario_bytes).hexdigest()
    sc = json.loads(scenario_bytes.decode("utf-8"))
    sid = sc["id"]
    sim, metrics = DRIVERS[sid](sc)

    rows = sorted(sim.records,
                  key=lambda r: (r["t_ms"], r["actor"], r["event"]))
    csv_path = os.path.join(OUTPUTS_DIR, sid + ".csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "t_ms", "actor", "ip", "key", "endpoint", "direction", "event",
            "control", "outcome", "detail"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    outcomes = {}
    controls = {}
    for r in sim.records:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        controls[r["control"]] = controls.get(r["control"], 0) + 1
    per_actor = {}
    for r in sim.records:
        pa = per_actor.setdefault(r["actor"], {"events": 0, "activated": 0,
                                               "rejected": 0})
        pa["events"] += 1
        if r["outcome"] == "activated":
            pa["activated"] += 1
        elif r["outcome"].startswith("rejected"):
            pa["rejected"] += 1
    total = len(sim.records)
    activated = outcomes.get("activated", 0)
    summary = {
        "scenario": sid,
        "title": sc.get("title", ""),
        "pinned_commit": PINNED_COMMIT,
        "simulated": True,
        "duration_ms": sc["duration_ms"],
        "total_events": total,
        "activated": activated,
        "rejected": sum(v for k, v in outcomes.items()
                        if k.startswith("rejected")),
        "outcomes": dict(sorted(outcomes.items())),
        "controls": dict(sorted(controls.items())),
        "metrics": metrics,
        "final_state": sim.snapshot(),
        "per_actor": dict(sorted(per_actor.items())),
        "handshake_rejects": dict(sorted(sim.handshake_rejects.items())),
        "endpoint_stats": dict(sorted(sim.endpoint_stats.items())),
        "gossip_events": sim.gossip_events,
    }
    json_path = os.path.join(OUTPUTS_DIR, sid + ".json")
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")

    sim_path = os.path.join(HERE, "simulator.py")
    log_lines = [
        "scenario: %s" % sid,
        "title: %s" % sc.get("title", ""),
        "pinned_commit: %s" % PINNED_COMMIT,
        "scenario_file: scenarios/%s.json" % sid,
        "scenario_sha256: %s" % scenario_sha,
        "simulator_file: scripts/simulator.py",
        "simulator_sha256: %s" % sha256_file(sim_path),
        "harness_file: scripts/load_harness.py",
        "harness_sha256: %s" % sha256_file(os.path.abspath(__file__)),
        "duration_ms: %d" % sc["duration_ms"],
        "total_events: %d" % total,
        "activated: %d" % activated,
        "outcomes: %s" % json.dumps(summary["outcomes"], sort_keys=True),
        "controls: %s" % json.dumps(summary["controls"], sort_keys=True),
        "metrics: %s" % json.dumps(metrics, sort_keys=True),
        "final_state: %s" % json.dumps(summary["final_state"], sort_keys=True),
        "csv_file: outputs/%s.csv" % sid,
        "csv_sha256: %s" % sha256_file(csv_path),
        "json_file: outputs/%s.json" % sid,
        "json_sha256: %s" % sha256_file(json_path),
    ]
    log_path = os.path.join(OUTPUTS_DIR, sid + ".log")
    with open(log_path, "w") as f:
        f.write("\n".join(log_lines) + "\n")
    print("scenario %s: events=%d activated=%d metrics=%s" % (
        sid, total, activated, json.dumps(metrics, sort_keys=True)))
    return summary


def main(argv):
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    if argv:
        wanted = argv
    else:
        wanted = sorted(
            f[:-5] for f in os.listdir(SCENARIOS_DIR) if f.endswith(".json"))
    for sid in wanted:
        path = os.path.join(SCENARIOS_DIR, sid + ".json")
        if not os.path.exists(path):
            raise SystemExit("scenario file not found: %s" % path)
        run_scenario(path)


if __name__ == "__main__":
    main(sys.argv[1:])
