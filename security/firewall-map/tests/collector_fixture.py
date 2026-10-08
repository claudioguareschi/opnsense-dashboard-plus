#!/usr/local/bin/python3

# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Collector-shaped test responses, built from unshipped semantic fixture oracles.

This stand-in exercises production adapter/orchestration without any PF access.
The real collector protocol, history and snapshot worker have separate C tests.
"""

import ipaddress
import time
from types import SimpleNamespace

from support import COLLECTOR, COMMON, PF, REFERENCE, REFERENCE_THREATS


def address(value):
    parsed = ipaddress.ip_address(value)
    return bytes([parsed.version]) + parsed.packed.ljust(16, b"\0")


def protocol(value):
    return {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58, "sctp": 132}[value]


def aggregate(flows, count=0, threat_entries=None):
    """Encode presented fixture flows as collector-selected aggregate rows."""
    rows, candidates = [], []
    for pair, flow in flows:
        flow = dict(flow)
        row = {"key": pair, "states": flow["states"], "delta_bytes_from_remote": 0, "delta_bytes_to_remote": 0,
               "delta_packets": 0,
               "bytes_from_remote": flow["transferred"][0], "bytes_to_remote": flow["transferred"][1],
               "remote_initiated_weight": int(flow["initiated"] == "remote"),
               "local_initiated_weight": int(flow["initiated"] != "remote"), "oldest": flow["age"],
               "rate_from_remote": flow["rate_in"], "rate_to_remote": flow["rate_out"],
               "packet_rate": flow["packet_rate"], "activity": 1.0, "score": max(flow["rate"], 1.0)}
        index = len(rows)
        rows.append(row)

        def candidate(kind, value, association=0):
            candidates.append((index, kind, len(candidates), 1, association, value))
        for name in flow["protocols"]:
            candidate(1, bytes([protocol(name)]))
        for inside in flow["inside"]:
            candidate(2, address(inside))
        if flow["egress"]:
            candidate(3, flow["egress"].encode())
        for service in flow["services"]:
            label = flow["service_ports"].get(service, "0/tcp")
            port, proto = label.split("/")
            candidate(4, b"", (protocol(proto) << 16) | int(port))
        for target in flow["targets"]:
            proto, host, port = target.split("|")
            candidate(5, bytes([protocol(proto)]) + address(host) + int(port or 0).to_bytes(2, "big"))
        if flow["rule"]:
            candidate(6, flow["rule"].encode())
    remotes, threat_candidates = [], []
    for remote, entry in (threat_entries or {}).items():
        index = len(remotes)
        remotes.append({"address": remote, "bytes": entry["bytes"], "youngest": entry["youngest"],
                        "remote_initiated_states": entry["inbound"],
                        "local_initiated_states": entry["outbound"]})
        for kind, field in ((2, "inside"), (4, "services"), (5, "targets")):
            for item in entry[field]:
                association = 0
                if kind == 2:
                    value = address(item)
                elif kind == 4:
                    port, proto = entry["service_ports"].get(item, "0/tcp").split("/")
                    association = (protocol(proto) << 16) | int(port)
                    value = b""
                else:
                    proto, host, port = item.split("|")
                    value = bytes([protocol(proto)]) + address(host) + int(port or 0).to_bytes(2, "big")
                threat_candidates.append((index, kind, len(threat_candidates), association, value))
    return {"flows": rows, "candidates": candidates, "matches": {},
            "threat_remotes": remotes, "threat_candidates": threat_candidates,
            "counts": {"states": count, "flows": len(flows)}, "threat_summary": True,
            "baseline": False, "refused": None, "telemetry": {"interval": 2.0, "sequence": 1}}


class CollectorFixture:
    def __init__(self, records):
        self.records = records
        self.process = None
        self.snapshot_open = False
        self.tracker = REFERENCE.FlowTracker()
        self.snapshot_flows = None
        self.current_records = []
        # one entry per request: True when it was the helper's baseline (first) sample
        self.baselines = []
        # the ranking profile it was started with, and how often a new one restarted it
        self.profile, self.restarts, self.starts = None, 0, 0
        # PF tables the fixture classifies with, {table: [network...]}, like the helper's own
        self.tables = {}

    def close(self):
        self.process = None
        self.snapshot_open = False

    def set_profile(self, profile):
        """Like the engine: another UUID or definition (fingerprint) restarts it (counted), the same
        one changes nothing."""
        key = COLLECTOR.state_collector.CollectorEngine._profile_key
        if key(profile) == key(self.profile):
            self.profile = profile
            return False
        if self.profile is not None:
            self.restarts += 1
        self.profile = profile
        self.close()
        return True

    def sample(self, local, networks, assigned, wan, memory=None, evidence=(), correlation=True, **options):
        # what the service asked for (CARP mirroring and the like)
        self.last_options = options
        """Like the helper: the first sample of a new process is a baseline (no rates)."""
        baseline = self.process is None
        self.baselines.append(baseline)
        if baseline:
            self.process = SimpleNamespace(poll=lambda: None)
            self.tracker = REFERENCE.FlowTracker()
        records = self.current_records = self.records()
        now = time.monotonic()
        self.tracker.update(records, local, now, networks, interface_addresses=assigned, primary_wan_device=wan)
        selected = [(tuple(row[1:3]), row[3]) for row in self.tracker.visible(now)]
        # like the helper, the threat summary covers only evidence and threat-listed remotes
        sets = (options.get("classification") or (None, []))[1]
        evidence = set(evidence)
        threat = sum(1 << bit for bit, (category, _table) in enumerate(sets) if category == "T")
        threat_entries = REFERENCE_THREATS.observe(
            records, lambda remote: ["fixture"] if remote in evidence or self.mask(remote, sets) & threat else [],
            local, networks)
        result = aggregate(selected, len(records), threat_entries)
        result["counts"]["flows"] = self.tracker.total_flows
        result["baseline"] = baseline
        result["telemetry"] = {"interval": -1.0 if baseline else 2.0, "sequence": len(self.baselines)}
        self.snapshot_open = options.get("snapshot", False)
        self.classify(result, options.get("classification"), options.get("classify", ()))
        # a sample opening a snapshot session lists what it may capture (here every flow, by rate)
        result["snapshot_candidates"] = [
            {"local": local, "remote": remote, "evidence": 0, "security_class": "S0",
             "score": max(flow["rate"], 1.0), "order": index, "states": flow["states"]}
            for index, ((local, remote), flow) in enumerate(self.tracker.flows.items())
        ] if options.get("snapshot") else []
        return result

    def mask(self, value, sets):
        parsed = ipaddress.ip_address(value)
        return sum(1 << bit for bit, (_category, table) in enumerate(sets)
                   if any(parsed in ipaddress.ip_network(network, strict=False)
                          for network in self.tables.get(table, ())))

    def classify(self, result, classification, addresses):
        """Set masks as the helper reports them: flow and threat remotes, requested addresses."""
        sets = classification[1] if classification else []

        def mask(value):
            return self.mask(value, sets)
        for row in result["flows"]:
            row["classes"] = mask(row["key"][1])
        for remote in result["threat_remotes"]:
            remote["classes"] = mask(remote["address"])
        result["classified"] = {address: mask(address) for address in addresses if mask(address)}
        result["remotes"] = {address: {"classes": mask(address), "evidence": 0, "security_class": "S0", "states": 0}
                             for address in addresses if mask(address)}
        result["class_sets"] = [{"id": bit, "category": category,
                                 "status": "ok" if table in self.tables else "missing",
                                 "entries": len(self.tables.get(table, ()))}
                                for bit, (category, table) in enumerate(sets)]

    def snapshot_selection(self, identities):
        flows = self.snapshot_flows if self.snapshot_flows is not None else self.tracker.flows
        return aggregate([((local, remote), flows[(local, remote)]) for local, remote, _required in identities])

    def snapshot_detail(self, identities, byte_limit, state_limit):
        pairs = {(local, remote) for local, remote, _required in identities}
        rows = {}
        for record in self.current_records:
            pair = PF.flow_endpoints(record, {"1.2.3.163"})
            if pair not in pairs:
                continue
            nat = record.nat
            rows.setdefault(pair[1], []).append({
                "proto": record.protocol, "src_addr": record.src.address, "dst_addr": record.dst.address,
                "src_port": record.src.port, "dst_port": record.dst.port, "state": record.state,
                "nat": COMMON.host_port(nat.address, nat.port) if nat else None,
            })
        included = sum(map(len, rows.values()))
        self.snapshot_open = False
        return rows, {"scope": "retained_logical_flows", "available": included, "captured": included,
                      "matched": included, "included": included, "omitted": 0, "complete": True,
                      "truncated": False, "atomic": False, "generation": 1, "omission_reasons": []}

    def snapshot_cancel(self):
        self.snapshot_open = False
