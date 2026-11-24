#!/usr/bin/env python3
"""simulator.py — faithful protocol-level model of the postfiatd peer-finder
and overlay handshake pipeline, at pinned commit
0085a1ff885d6a446369cf73a4430f75af22be55.

SIMULATED, not a live node. Every control parameter below is taken VERBATIM
from the pinned source; each entry cites the exact file and line numbers
(verified against a local checkout of the pinned commit and the GitHub API
blob SHA/size for every cited file — see docs/source-inventory.md).

Modelled pipeline, in the order the real code applies it
(src/xrpld/peerfinder/detail/Logic.h, src/xrpld/overlay/detail/OverlayImpl.cpp,
src/xrpld/overlay/detail/Handshake.cpp):

  1. Handshake identity (Handshake.cpp:227-356): the peer presents a TLS
     security cookie (hash of both TLS Finished messages, :140-165), a
     Network-ID header that must match the local network (:241-248), and
     Local-IP / Remote-IP headers that reject proxying (:325-356).
     A failed handshake never reaches the slot logic.
  2. Inbound slot (Logic.h:263-310): for a public remote address, the count
     of already-connected addresses from that IP plus one must not exceed
     config_.ipLimit, else Result::ipLimitExceeded (:274-285). A duplicate
     remote endpoint is rejected as Result::duplicatePeer (:289-296).
  3. Outbound slot (Logic.h:320-355): a duplicate remote endpoint is
     rejected as Result::duplicatePeer (:326-333).
  4. Self-connect (Logic.h:358-390): onConnected drops the attempt when the
     local endpoint is already in the slot table.
  5. Activation (Logic.h:399-469): a duplicate public key is rejected as
     Result::duplicatePeer (:415-418). Fixed or reserved slots always
     activate (Counts.h:70-83); otherwise an inbound slot needs
     in_active < in_max and an outbound slot needs out_active < out_max,
     else Result::full (:427-435). A failed outbound activation still
     records bootcache success (:429-430).
  6. Endpoint gossip (Logic.h:719-882): on_endpoints first truncates an
     oversized list to numberOfEndpointsMax (64) by seeded shuffle
     (:792-796), then preprocess drops entries with hops > maxHops (6)
     (:727), invalid addresses when verifyEndpoints is on (:757), and
     duplicates (:766-776). Accepted endpoints enter the livecache and the
     bootcache (:879-880); new endpoints are accepted at most once per
     secondsPerMessage (151 s) per peer (:882).
  7. Autoconnect (Logic.h:493-605): batches are built from fixed peers
     first, then the livecache (hops iterated highest-first), then the
     bootcache. At most maxConnectAttempts (20) may be in flight
     (Counts.h:88-92); batches are spaced secondsPerConnect (10 s) apart.
     A failed attempt is squelched for recentAttemptDuration (60 s) and
     retried with the connectionBackoff table [1,1,2,3,5,8,13,21,34,55] s.
  8. Redirects (Logic.h:1274): at most maxRedirects (30) redirect handouts
     are accepted from one connection.
  9. Bootcache (Bootcache.h, Tuning.h:90-101): at most bootcacheSize (1000)
     entries; above the threshold bootcachePrunePercent (10%) are pruned;
     database updates are cooled down for bootcacheCooldownTime (60 s).
 10. Cluster / reservations (OverlayImpl.cpp:264-267): a peer in the local
     cluster, or holding a reservation, gets a reserved slot and bypasses
     the public slot cap at activation.

MODEL ASSUMPTIONS (labelled, not measured node behaviour):
  * Connection-attempt latency is a simulator constant (100 ms for a live
    endpoint, 1000 ms for a dead endpoint). No live node was dialled; a real
    postfiatd build was out of scope for this pack, so latencies are model
    parameters, not measurements. All conclusions that depend on them are
    labelled SIMULATED.
  * Time is virtual (milliseconds since scenario start). The simulation is
    fully deterministic: fixed seeds, no wall clock, no network, no threads.
    Re-running a scenario produces byte-identical outputs.
  * IP addresses use the documentation ranges 203.0.113.0/24 (honest),
    198.51.100.0/24 (attacker) and 192.0.2.0/24 (bootstrap hosts). No real
    host is named or contacted.

Usage: imported by load_harness.py. Not a standalone CLI.
"""

import random
from collections import Counter, OrderedDict

PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"

# ---------------------------------------------------------------------------
# Verbatim control parameters from the pinned commit.
# Each value cites the exact file:line it was taken from.
# ---------------------------------------------------------------------------
CONTROL_PARAMS = {
    # src/xrpld/peerfinder/detail/Tuning.h
    "secondsPerConnect": (10, "src/xrpld/peerfinder/detail/Tuning.h:40"),
    "maxConnectAttempts": (20, "src/xrpld/peerfinder/detail/Tuning.h:44"),
    "outPercent": (15, "src/xrpld/peerfinder/detail/Tuning.h:52"),
    "minOutCount": (10, "src/xrpld/peerfinder/detail/Tuning.h:59"),
    "defaultMaxPeers": (21, "src/xrpld/peerfinder/detail/Tuning.h:63"),
    "maxRedirects": (30, "src/xrpld/peerfinder/detail/Tuning.h:70"),
    "connectionBackoff": ([1, 1, 2, 3, 5, 8, 13, 21, 34, 55],
                          "src/xrpld/peerfinder/detail/Tuning.h:79-80"),
    "bootcacheSize": (1000, "src/xrpld/peerfinder/detail/Tuning.h:90"),
    "bootcachePrunePercent": (10, "src/xrpld/peerfinder/detail/Tuning.h:94"),
    "bootcacheCooldownTime": (60, "src/xrpld/peerfinder/detail/Tuning.h:101"),
    "maxHops": (6, "src/xrpld/peerfinder/detail/Tuning.h:110"),
    "numberOfEndpoints": (12, "src/xrpld/peerfinder/detail/Tuning.h:113"),
    "numberOfEndpointsMax": (64, "src/xrpld/peerfinder/detail/Tuning.h:116-117"),
    "redirectEndpointCount": (10, "src/xrpld/peerfinder/detail/Tuning.h:120"),
    "secondsPerMessage": (151, "src/xrpld/peerfinder/detail/Tuning.h:124"),
    "liveCacheSecondsToLive": (30, "src/xrpld/peerfinder/detail/Tuning.h:128"),
    "recentAttemptDuration": (60, "src/xrpld/peerfinder/detail/Tuning.h:132"),
    # src/xrpld/peerfinder/detail/PeerfinderConfig.cpp — derived defaults
    # (maxPeers 21 -> outPeers 10, inPeers 11, ipLimit 2; see applyTuning)
    "derived_outPeers": (10, "src/xrpld/peerfinder/detail/PeerfinderConfig.cpp:41,96-110"),
    "derived_inPeers": (11, "src/xrpld/peerfinder/detail/PeerfinderConfig.cpp:109-110"),
    "derived_ipLimit": (2, "src/xrpld/peerfinder/detail/PeerfinderConfig.cpp:48-62"),
    # cfg/postfiatd-example.cfg — [overlay] defaults
    "max_untrusted_count": (1000, "cfg/postfiatd-example.cfg:515-524"),
    "max_unknown_time": (600, "cfg/postfiatd-example.cfg:526-534"),
    "max_diverged_time": (300, "cfg/postfiatd-example.cfg:536-544"),
    "verify_endpoints_default": (1, "cfg/postfiatd-example.cfg:546-556"),
    # src/xrpld/overlay/detail/Tuning.h
    "overlay_maxQueryDepth": (3, "src/xrpld/overlay/detail/Tuning.h:61"),
}

# Simulator constants (MODEL parameters, not pinned-code values).
CONNECT_LATENCY_MS = 100      # live endpoint answers
DEAD_ENDPOINT_LATENCY_MS = 1000  # dead endpoint times out
DEFAULT_PEER_PORT = 51235     # OverlayImpl.cpp: default peer port

# Default bootstrap hosts from the pinned code
# (OverlayImpl.cpp:499-512 — used only when no [ips] / [ips_fixed] is set).
BOOTSTRAP_HOSTS = [
    ("r.ripple.com", "192.0.2.1"),
    ("sahyadri.isrdc.in", "192.0.2.2"),
    ("hubs.xrpkuwait.com", "192.0.2.3"),
    ("hub.xrpl-commons.org", "192.0.2.4"),
]


def is_public_ip(ip):
    """beast::IP::is_public analogue: RFC1918 / loopback / link-local are
    not public, so the per-IP limit does not apply to them (Logic.h:274)."""
    if ip.startswith("10.") or ip.startswith("127."):
        return False
    if ip.startswith("192.168."):
        return False
    if ip.startswith("169.254."):
        return False
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
        except ValueError:
            return True
        if 16 <= second <= 31:
            return False
    return True


def is_valid_address(endpoint):
    """is_valid_address analogue for endpoint gossip (Logic.h:757):
    the address must be publicly routable and the port non-zero."""
    ip, _, port = endpoint.rpartition(":")
    if not is_public_ip(ip):
        return False
    try:
        return int(port) != 0
    except ValueError:
        return False


class Peer:
    """One network participant: an identity (public key) plus an endpoint."""

    def __init__(self, pid, key, ip, port=DEFAULT_PEER_PORT,
                 kind="honest", fixed=False, cluster=False, reserved=False):
        self.id = pid
        self.key = key
        self.ip = ip
        self.port = port
        self.kind = kind  # honest | attacker | cluster | fixed | reserved
        self.fixed = fixed
        self.cluster = cluster
        self.reserved = reserved

    @property
    def endpoint(self):
        return "%s:%d" % (self.ip, self.port)


class Slot:
    """One PeerFinder slot (Logic.h SlotImp)."""

    def __init__(self, peer, direction, fixed=False):
        self.peer = peer
        self.direction = direction  # "in" | "out"
        self.fixed = fixed
        self.reserved = False
        self.state = "accept" if direction == "in" else "connect"
        self.key = None
        self.when_accept_endpoints_ms = 0

    @property
    def endpoint(self):
        return self.peer.endpoint

    def inbound(self):
        return self.direction == "in"


class PeerFinderSim:
    """Deterministic model of PeerFinder::Logic + the overlay handshake."""

    def __init__(self, node_config=None, seed=20261125):
        cfg = node_config or {}
        self.max_peers = cfg.get("max_peers", CONTROL_PARAMS["defaultMaxPeers"][0])
        out = max((self.max_peers * CONTROL_PARAMS["outPercent"][0] + 50) // 100,
                  CONTROL_PARAMS["minOutCount"][0])
        self.out_max = cfg.get("out_peers", out)
        self.in_max = cfg.get("in_peers", self.max_peers - self.out_max)
        self.verify_endpoints = cfg.get(
            "verify_endpoints", CONTROL_PARAMS["verify_endpoints_default"][0]) == 1
        self.want_incoming = cfg.get("want_incoming", True)
        self.auto_connect = cfg.get("auto_connect", True)
        # PeerfinderConfig.cpp:48-62 — autoconfigured ipLimit.
        ip_limit = cfg.get("ip_limit", 0)
        if ip_limit == 0:
            ip_limit = 2
            if self.in_max > CONTROL_PARAMS["defaultMaxPeers"][0]:
                ip_limit += min(5, self.in_max // CONTROL_PARAMS["defaultMaxPeers"][0])
        self.ip_limit = max(1, min(ip_limit, self.in_max // 2))
        self.rng = random.Random(seed)
        self.now_ms = 0
        self.slots = {}            # endpoint -> Slot
        self.keys = set()          # activated public keys
        self.connected = Counter()  # ip -> number of connected addresses
        self.in_active = 0
        self.out_active = 0
        self.fixed_active = 0
        self.reserved_active = 0
        self.attempts = 0          # outbound attempts in flight
        self.fixed_peers = []      # Peer objects from [ips_fixed]
        self.cluster_keys = set()
        self.reservation_keys = set()
        self.bootcache = OrderedDict()   # endpoint -> {"static": bool, "fails": int}
        self.livecache = {}        # endpoint -> hops
        self.squelch = {}          # address -> until_ms
        self.redirects_used = 0
        self.backoff_failures = Counter()  # endpoint -> consecutive failures
        self.records = []          # event rows
        self.gossip_events = []    # endpoint-gossip detail rows
        self.handshake_rejects = Counter()
        self.endpoint_stats = Counter()

    # -- event log -----------------------------------------------------------
    def record(self, actor, event, outcome, control, detail,
               ip="", key="", endpoint="", direction=""):
        self.records.append({
            "t_ms": self.now_ms, "actor": actor, "ip": ip, "key": key,
            "endpoint": endpoint, "direction": direction, "event": event,
            "control": control, "outcome": outcome, "detail": detail,
        })

    # -- configuration -------------------------------------------------------
    def add_fixed_peer(self, peer):
        self.fixed_peers.append(peer)

    def add_cluster_key(self, key):
        self.cluster_keys.add(key)

    def add_reservation(self, key):
        self.reservation_keys.add(key)

    def bootcache_insert(self, endpoint, static=False):
        if endpoint in self.bootcache:
            return False
        if len(self.bootcache) >= CONTROL_PARAMS["bootcacheSize"][0]:
            # Prune bootcachePrunePercent of entries (Tuning.h:90-94).
            n = max(1, len(self.bootcache)
                    * CONTROL_PARAMS["bootcachePrunePercent"][0] // 100)
            for _ in range(n):
                victim = next(iter(self.bootcache))
                del self.bootcache[victim]
                self.record("node", "bootcache_prune", "pruned",
                            "bootcache",
                            "bootcache at %d entries; pruned %s" % (
                                CONTROL_PARAMS["bootcacheSize"][0], victim))
        self.bootcache[endpoint] = {"static": static, "fails": 0}
        return True

    def bootcache_on_success(self, endpoint):
        if endpoint in self.bootcache:
            self.bootcache[endpoint]["fails"] = 0

    def bootcache_on_failure(self, endpoint):
        if endpoint in self.bootcache:
            self.bootcache[endpoint]["fails"] += 1

    # -- handshake (Handshake.cpp:227-356) ------------------------------------
    def handshake(self, peer, cookie_ok=True, network_id_ok=True,
                  proxy_ok=True):
        """verifyHandshake model. Returns (ok, reason)."""
        if not cookie_ok:
            self.handshake_rejects["cookie"] += 1
            self.record(peer.id, "handshake", "rejected_cookie", "C04_handshake_cookie",
                        "TLS Finished cookie mismatch (Handshake.cpp:140-165)",
                        ip=peer.ip, key=peer.key, endpoint=peer.endpoint)
            return False, "cookie"
        if not network_id_ok:
            self.handshake_rejects["network_id"] += 1
            self.record(peer.id, "handshake", "rejected_network_id", "C05_network_id",
                        "Network-ID header mismatch (Handshake.cpp:241-248)",
                        ip=peer.ip, key=peer.key, endpoint=peer.endpoint)
            return False, "network_id"
        if not proxy_ok:
            self.handshake_rejects["proxy"] += 1
            self.record(peer.id, "handshake", "rejected_proxy", "C06_proxy_rejection",
                        "Local-IP/Remote-IP mismatch: proxy attempt rejected "
                        "(Handshake.cpp:325-356)",
                        ip=peer.ip, key=peer.key, endpoint=peer.endpoint)
            return False, "proxy"
        self.record(peer.id, "handshake", "verified", "handshake",
                    "cookie, Network-ID and Local/Remote-IP checks passed",
                    ip=peer.ip, key=peer.key, endpoint=peer.endpoint)
        return True, ""

    # -- slots (Logic.h:263-390) ----------------------------------------------
    def new_inbound_slot(self, peer):
        """Logic.h:263-310. Returns (slot, result)."""
        if is_public_ip(peer.ip):
            count = self.connected[peer.ip]
            if count + 1 > self.ip_limit:
                self.record(peer.id, "new_inbound_slot", "rejected_ip_limit",
                            "C00_ip_limit",
                            "IP %s already has %d connections; ipLimit %d "
                            "exceeded (Logic.h:274-285)"
                            % (peer.ip, count, self.ip_limit),
                            ip=peer.ip, key=peer.key, endpoint=peer.endpoint,
                            direction="in")
                return None, "ipLimitExceeded"
        if peer.endpoint in self.slots:
            self.record(peer.id, "new_inbound_slot", "rejected_duplicate_endpoint",
                        "C01_duplicate_identity",
                        "endpoint already in slot table (Logic.h:289-296)",
                        ip=peer.ip, key=peer.key, endpoint=peer.endpoint,
                        direction="in")
            return None, "duplicatePeer"
        slot = Slot(peer, "in", fixed=peer.fixed)
        self.slots[peer.endpoint] = slot
        self.connected[peer.ip] += 1
        self.record(peer.id, "new_inbound_slot", "slot_created", "C02_inbound_slots",
                    "inbound slot created; connected from %s: %d"
                    % (peer.ip, self.connected[peer.ip]),
                    ip=peer.ip, key=peer.key, endpoint=peer.endpoint,
                    direction="in")
        return slot, "success"

    def new_outbound_slot(self, peer):
        """Logic.h:320-355. Returns (slot, result)."""
        if peer.endpoint in self.slots:
            self.record(peer.id, "new_outbound_slot", "rejected_duplicate_endpoint",
                        "C01_duplicate_identity",
                        "endpoint already in slot table (Logic.h:326-333)",
                        ip=peer.ip, key=peer.key, endpoint=peer.endpoint,
                        direction="out")
            return None, "duplicatePeer"
        slot = Slot(peer, "out", fixed=peer.fixed)
        self.slots[peer.endpoint] = slot
        self.connected[peer.ip] += 1
        self.attempts += 1
        self.record(peer.id, "new_outbound_slot", "slot_created", "C03_outbound_slots",
                    "outbound slot created; attempts in flight %d (max %d)"
                    % (self.attempts, CONTROL_PARAMS["maxConnectAttempts"][0]),
                    ip=peer.ip, key=peer.key, endpoint=peer.endpoint,
                    direction="out")
        return slot, "success"

    def on_connected(self, slot, local_endpoint):
        """Logic.h:358-390 — self-connect check by address."""
        if local_endpoint in self.slots:
            self.record(slot.peer.id, "on_connected", "rejected_self_connect",
                        "C01_duplicate_identity",
                        "local endpoint already in slot table: self-connect "
                        "(Logic.h:382-390)",
                        ip=slot.peer.ip, key=slot.peer.key,
                        endpoint=slot.peer.endpoint, direction="out")
            return False
        slot.state = "connected"
        return True

    def can_activate(self, slot):
        """Counts.h:70-83."""
        if slot.fixed or slot.reserved:
            return True
        if slot.inbound():
            return self.in_active < self.in_max
        return self.out_active < self.out_max

    def activate(self, slot, key, reserved):
        """Logic.h:399-469. Returns result string."""
        if key in self.keys:
            self.record(slot.peer.id, "activate", "rejected_duplicate_key",
                        "C01_duplicate_identity",
                        "public key already active (Logic.h:415-418)",
                        ip=slot.peer.ip, key=key, endpoint=slot.peer.endpoint,
                        direction=slot.direction)
            self.disconnect_slot(slot, "activate failed: duplicatePeer")
            return "duplicatePeer"
        slot.reserved = reserved
        if not self.can_activate(slot):
            if not slot.inbound():
                self.bootcache_on_success(slot.peer.endpoint)
            result = ("inboundDisabled" if slot.inbound() and self.in_max == 0
                      else "full")
            self.record(slot.peer.id, "activate", "rejected_slots_full",
                        "C02_inbound_slots" if slot.inbound()
                        else "C03_outbound_slots",
                        "no %s slot free (%d/%d active); reserved=%s "
                        "(Logic.h:427-435)"
                        % (slot.direction,
                           self.in_active if slot.inbound() else self.out_active,
                           self.in_max if slot.inbound() else self.out_max,
                           reserved),
                        ip=slot.peer.ip, key=key, endpoint=slot.peer.endpoint,
                        direction=slot.direction)
            self.disconnect_slot(slot, "activate failed: %s" % result)
            return result
        slot.key = key
        self.keys.add(key)
        slot.state = "active"
        self.attempts = max(0, self.attempts - (0 if slot.inbound() else 1))
        if slot.fixed:
            self.fixed_active += 1
        elif slot.reserved:
            self.reserved_active += 1
        elif slot.inbound():
            self.in_active += 1
        else:
            self.out_active += 1
        if not slot.inbound():
            self.bootcache_on_success(slot.peer.endpoint)
        self.record(slot.peer.id, "activate", "activated",
                    "reserved_bypass" if reserved else
                    ("C02_inbound_slots" if slot.inbound()
                     else "C03_outbound_slots"),
                    "peer active as %s slot; totals in=%d/%d out=%d/%d "
                    "fixed=%d reserved=%d"
                    % (slot.direction, self.in_active, self.in_max,
                       self.out_active, self.out_max, self.fixed_active,
                       self.reserved_active),
                    ip=slot.peer.ip, key=key, endpoint=slot.peer.endpoint,
                    direction=slot.direction)
        return "success"

    def disconnect_slot(self, slot, reason):
        """Remove a slot (Logic.h:888-990 on_closed / on_failure)."""
        ep = slot.peer.endpoint
        if ep in self.slots:
            del self.slots[ep]
        self.connected[slot.peer.ip] = max(0, self.connected[slot.peer.ip] - 1)
        if slot.key in self.keys:
            self.keys.discard(slot.key)
        # Counts::adjust: a slot in connect/connected state counts as an
        # outbound attempt in flight; removing it frees the attempt.
        if slot.state in ("connect", "connected") and not slot.inbound():
            self.attempts = max(0, self.attempts - 1)
        if slot.state == "active":
            if slot.fixed:
                self.fixed_active = max(0, self.fixed_active - 1)
            elif slot.reserved:
                self.reserved_active = max(0, self.reserved_active - 1)
            elif slot.inbound():
                self.in_active = max(0, self.in_active - 1)
            else:
                self.out_active = max(0, self.out_active - 1)
        self.record(slot.peer.id, "disconnect", "disconnected", "peer_lifecycle",
                    "removed %s slot (was %s): %s"
                    % (slot.direction, slot.state, reason),
                    ip=slot.peer.ip, key=slot.key or slot.peer.key,
                    endpoint=ep, direction=slot.direction)
        return slot.peer

    # -- endpoint gossip (Logic.h:719-882) ------------------------------------
    def on_endpoints(self, slot, endpoints):
        """endpoints: list of (endpoint, hops, valid). Returns stats dict."""
        stats = {"received": len(endpoints), "truncated": 0,
                 "dropped_hops": 0, "dropped_invalid": 0,
                 "dropped_duplicate": 0, "dropped_rate_limit": 0,
                 "accepted_livecache": 0, "accepted_bootcache": 0}
        # Rate limit: at most one endpoints batch per secondsPerMessage.
        if self.now_ms < slot.when_accept_endpoints_ms:
            stats["dropped_rate_limit"] = len(endpoints)
            self.record(slot.peer.id, "on_endpoints", "rate_limited",
                        "C07_gossip_filters",
                        "%d endpoints dropped: within secondsPerMessage 151 s "
                        "window (Logic.h:820-822)" % len(endpoints),
                        ip=slot.peer.ip, key=slot.key or slot.peer.key,
                        endpoint=slot.peer.endpoint, direction=slot.direction)
            return stats
        # Truncate oversized lists to numberOfEndpointsMax by seeded shuffle.
        work = list(endpoints)
        if len(work) > CONTROL_PARAMS["numberOfEndpointsMax"][0]:
            self.rng.shuffle(work)
            stats["truncated"] = len(work) - CONTROL_PARAMS["numberOfEndpointsMax"][0]
            work = work[:CONTROL_PARAMS["numberOfEndpointsMax"][0]]
            self.record(slot.peer.id, "on_endpoints", "truncated",
                        "C08_gossip_truncation",
                        "list of %d endpoints shuffled and truncated to %d "
                        "(Logic.h:792-796)"
                        % (stats["received"],
                           CONTROL_PARAMS["numberOfEndpointsMax"][0]),
                        ip=slot.peer.ip, key=slot.key or slot.peer.key,
                        endpoint=slot.peer.endpoint, direction=slot.direction)
        # preprocess: hop limit, invalid addresses, duplicates; hops++.
        kept = []
        seen = set()
        for endpoint, hops, valid in work:
            if hops > CONTROL_PARAMS["maxHops"][0]:
                stats["dropped_hops"] += 1
                continue
            if (not valid or not is_valid_address(endpoint)) \
                    and self.verify_endpoints:
                stats["dropped_invalid"] += 1
                continue
            if endpoint in seen:
                stats["dropped_duplicate"] += 1
                continue
            seen.add(endpoint)
            kept.append((endpoint, hops + 1))
        for endpoint, hops in kept:
            self.livecache[endpoint] = hops
            stats["accepted_livecache"] += 1
            if self.bootcache_insert(endpoint):
                stats["accepted_bootcache"] += 1
        slot.when_accept_endpoints_ms = (
            self.now_ms + CONTROL_PARAMS["secondsPerMessage"][0] * 1000)
        self.record(slot.peer.id, "on_endpoints", "processed",
                    "C07_gossip_filters",
                    "received=%d truncated=%d dropped_hops=%d "
                    "dropped_invalid=%d dropped_duplicate=%d "
                    "accepted_livecache=%d accepted_bootcache=%d"
                    % (stats["received"], stats["truncated"],
                       stats["dropped_hops"], stats["dropped_invalid"],
                       stats["dropped_duplicate"],
                       stats["accepted_livecache"],
                       stats["accepted_bootcache"]),
                    ip=slot.peer.ip, key=slot.key or slot.peer.key,
                    endpoint=slot.peer.endpoint, direction=slot.direction)
        self.gossip_events.append(dict(stats))
        for k, v in stats.items():
            self.endpoint_stats[k] += v
        return stats

    # -- autoconnect (Logic.h:493-605) -----------------------------------------
    def attempts_needed(self):
        """Counts.h:88-92."""
        if self.attempts >= CONTROL_PARAMS["maxConnectAttempts"][0]:
            return 0
        return CONTROL_PARAMS["maxConnectAttempts"][0] - self.attempts

    def autoconnect(self):
        """Return the next batch of endpoints to try, in the code's
        priority order: fixed, then livecache (hops highest first),
        then bootcache. Returns (endpoints, source)."""
        if not self.auto_connect:
            return [], "disabled"
        if self.out_active >= self.out_max:
            return [], "out_slots_full"
        needed = self.attempts_needed()
        if needed == 0:
            return [], "attempts_exhausted"
        # 1. Fixed peers.
        fixed = [p.endpoint for p in self.fixed_peers
                 if p.endpoint not in self.slots
                 and self.squelch.get(p.ip, 0) <= self.now_ms]
        if fixed:
            batch = fixed[:needed]
            self.record("node", "autoconnect", "batch_fixed", "C10_autoconnect",
                        "%d fixed endpoints handed out (Logic.h:523-532)"
                        % len(batch))
            return batch, "fixed"
        # 2. Livecache, hops highest first, shuffled within each hop level.
        if self.livecache:
            by_hops = {}
            for ep, hops in self.livecache.items():
                by_hops.setdefault(hops, []).append(ep)
            batch = []
            for hops in sorted(by_hops, reverse=True):
                group = list(by_hops[hops])
                self.rng.shuffle(group)
                for ep in group:
                    if len(batch) >= needed:
                        break
                    ip = ep.rpartition(":")[0]
                    if ep in self.slots or self.squelch.get(ip, 0) > self.now_ms:
                        continue
                    batch.append(ep)
                if len(batch) >= needed:
                    break
            if batch:
                self.record("node", "autoconnect", "batch_livecache",
                            "C10_autoconnect",
                            "%d livecache endpoints handed out, hops "
                            "highest-first (Logic.h:551-566)" % len(batch))
                return batch, "livecache"
        # 3. Bootcache, in stored (sorted) order.
        batch = []
        for ep in sorted(self.bootcache):
            if len(batch) >= needed:
                break
            ip = ep.rpartition(":")[0]
            if ep in self.slots or self.squelch.get(ip, 0) > self.now_ms:
                continue
            batch.append(ep)
        if batch:
            self.record("node", "autoconnect", "batch_bootcache",
                        "C10_autoconnect",
                        "%d bootcache endpoints handed out (Logic.h:588-600)"
                        % len(batch))
            return batch, "bootcache"
        return [], "no_candidates"

    def squelch_address(self, ip):
        """recentAttemptDuration (60 s) squelch after a failed attempt
        (Logic.h:710). Backoff delay from the connectionBackoff table."""
        self.squelch[ip] = (self.now_ms
                            + CONTROL_PARAMS["recentAttemptDuration"][0] * 1000)

    def backoff_seconds(self, endpoint):
        """connectionBackoff table, indexed by consecutive failures."""
        table = CONTROL_PARAMS["connectionBackoff"][0]
        n = self.backoff_failures[endpoint]
        return table[min(n, len(table) - 1)]

    # -- redirects (Logic.h:1274) ----------------------------------------------
    def redirect(self, slot):
        """Return redirectEndpointCount endpoints, up to maxRedirects total
        per connection. Returns (endpoints, accepted)."""
        if self.redirects_used >= CONTROL_PARAMS["maxRedirects"][0]:
            self.record(slot.peer.id, "redirect", "rejected_cap",
                        "C09_redirect_cap",
                        "maxRedirects 30 already used on this connection "
                        "(Logic.h:1274)",
                        ip=slot.peer.ip, key=slot.key or slot.peer.key,
                        endpoint=slot.peer.endpoint, direction=slot.direction)
            return [], False
        self.redirects_used += 1
        endpoints = []
        for ep in sorted(self.livecache):
            if len(endpoints) >= CONTROL_PARAMS["redirectEndpointCount"][0]:
                break
            endpoints.append(ep)
        self.record(slot.peer.id, "redirect", "redirected",
                    "C09_redirect_cap",
                    "redirect %d/%d handed out %d endpoints"
                    % (self.redirects_used,
                       CONTROL_PARAMS["maxRedirects"][0], len(endpoints)),
                    ip=slot.peer.ip, key=slot.key or slot.peer.key,
                    endpoint=slot.peer.endpoint, direction=slot.direction)
        return endpoints, True

    # -- state snapshot ---------------------------------------------------------
    def snapshot(self):
        return {
            "in_active": self.in_active, "in_max": self.in_max,
            "out_active": self.out_active, "out_max": self.out_max,
            "fixed_active": self.fixed_active,
            "reserved_active": self.reserved_active,
            "total_active": (self.in_active + self.out_active
                             + self.fixed_active + self.reserved_active),
            "attempts_in_flight": self.attempts,
            "slots": len(self.slots),
            "keys_active": len(self.keys),
            "bootcache_entries": len(self.bootcache),
            "livecache_entries": len(self.livecache),
            "ip_limit": self.ip_limit,
        }
