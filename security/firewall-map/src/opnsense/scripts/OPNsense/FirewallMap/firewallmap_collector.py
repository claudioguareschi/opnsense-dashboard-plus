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

"""Persistent PF state sampler for Firewall Map+.

Samples the PF state table every 2 seconds, keeps per-state byte/packet counters
between samples and aggregates counter deltas into public (firewall, remote)
flows. Only a compact, capped, geo-enriched summary is written to disk for the
dashboard API to read; the browser never triggers a PF walk or a GeoIP lookup.

A flow is active only while its counters advance. Idle flows fade out over
FADE_SECONDS and a flow is dropped as soon as its last PF state disappears.
All geolocation lookups are local: the installed MaxMind or DB-IP database, read in process (lib/mmdb.py).

This module is the orchestrator; parsing, caches, threat lists, names, blocks and
Suricata correlation live in the lib/ modules next to it.

    firewallmap_collector.py           run the collector (started by rc.d/firewallmap)
    firewallmap_collector.py tables    JSON threat list candidates for the settings page
    firewallmap_collector.py ensure    start the collector when background recording is wanted
    firewallmap_collector.py reload    ask a running collector to re-read its settings

A map snapshot (the camera button) is a request file in SNAPSHOT_REQUEST_DIR: the next sample
writes bounded incident detail beyond the live summary, plus PF rows and capture coverage.
"""

import json
import ipaddress
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from heapq import nsmallest

import firewallmap_geodb as geodb
import firewallmap_threats as threats
from lib.blocklists import (
    REPUTATION_LIST, BlocklistIndex, Reputation, chosen_threat_lists, tables_report, threat_fields,
    threat_lists_for,
)
from lib.blocks import BlockTracker, FilterLogTail, block_event_time, block_summary, parse_block
from lib.cache import GEO_LOOKUPS_PER_SAMPLE, CacheStore, GeoCache
from lib.common import (
    COLLECTOR_TIMINGS, HOSTNAME_MARKER, OUTPUT_FILE, RC_SCRIPT, REQUEST_MARKER, RUN_DIR, SNAPSHOT_DIR,
    SNAPSHOT_REQUEST_DIR, connection_target, host_port, log_error, log_notice, log_warning, private_ip, public_ip,
    requested, secure_umask, service_name, service_port_label, write_json,
    write_text,
)
from lib.config import interface_names, settings, topology, widget_in_use
from lib.ids import (
    ALERT_BACKLOG_BYTES, EVE_LOG, AlertTracker, Correlator, alert_summary, connection_keys, connection_summary, firewall_blocks,
    ips_drops,
)
from lib.leases import (
    INSIDE_HOSTNAME_TTL, INSIDE_NEGATIVE_TTL, HostnameResolver, describe_inside, describe_target, host_names,
    lease_names,
)
from firewallmap_snapshots import (
    MAX_DOCUMENT_BYTES, DocumentBudget, SnapshotTooLarge, json_size, valid_id as snapshot_valid_id,
)
from lib.pf import (
    SAMPLE_TIMEOUT, StateFacts, TooManyStates, _Record, flow_endpoints, host_info, port_forwards, rule_descriptions, sample_states,
)
from lib.native import NativeEngine, NativeError, available as native_available


EXTERNAL_IP_URL = "https://api.ipify.org"
EXTERNAL_IP_TIMEOUT = 3
EXTERNAL_IP_MAX_AGE = 24 * 3600
EXTERNAL_IP_RETRY_SECONDS = 15 * 60


def discover_external_ipv4(fetch=None):
    """The caller's public IPv4, or None. This is optional map-anchor metadata, never flow identity."""
    if fetch is None:
        def fetch():
            request = urllib.request.Request(EXTERNAL_IP_URL, headers={"User-Agent": "OPNsense-FirewallMap"})
            with urllib.request.urlopen(request, timeout=EXTERNAL_IP_TIMEOUT) as response:
                return response.read(128)
    try:
        value = fetch()
        address = str(ipaddress.ip_address(value.decode("ascii", "ignore").strip() if isinstance(value, bytes) else value))
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return address if public_ip(address) and ":" not in address else None


HOSTNAME_REQUEST_SECONDS = 30
IDLE_SECONDS = 300
ACTIVE_VIEWER_SECONDS = 10
IDLE_INTERVAL = 5.0
# with nobody watching, threat history is still fed from a slow sample (states outlive this)
BACKGROUND_INTERVAL = 20.0
THREAT_RECORD_SECONDS = 20.0
THREAT_PRUNE_SECONDS = 3600.0
MAX_FAILURE_BACKOFF = 30.0
# While the table is too large to walk, only the cheap ``pfctl -si`` count runs. Refresh its
# status before flow_summary.sh's nine-second fast-summary window expires, or viewers see a
# misleading "Starting flow collector…" between honest too-many-states notices.
TOO_MANY_STATES_INTERVAL = 5.0
COLLECTOR_LOCK = f"{RUN_DIR}/collector.lock"
# the last sample's timings are written at most this often
TIMINGS_WRITE_SECONDS = 10.0
RELOAD_MARKER = f"{RUN_DIR}/reload"
# rule descriptions, interface names, DHCP names and port forwards
METADATA_REFRESH_SECONDS = 60
# threat intelligence: pf tables behind URL/external aliases and well-known feed tables
BLOCKLIST_REFRESH_SECONDS = 300
SETTINGS_REFRESH_SECONDS = 30
# one PF walk every 2 s: the dashboard polls every 2 s, so faster sampling only costs CPU
INTERVAL = 2.0
FADE_SECONDS = 20.0
MAX_FLOWS = 150
RATE_SMOOTHING = 0.5
HOST_REFRESH_SECONDS = 30.0
MAX_SERVICES = 4
MAX_INSIDE = 3
# PF states kept with a saved snapshot, per remote address and in all
SNAPSHOT_STATES_PER_ADDRESS = 50
SNAPSHOT_STATES_TOTAL = 5000
# Snapshot-specific budgets: neither live visualization nor PF admission limits.
SNAPSHOT_FLOWS = 5000
SNAPSHOT_BYTES = MAX_DOCUMENT_BYTES


def _ranked(counts, limit=None):
    """Keys of {key: weight}, heaviest first (equal weights in the order they were added)."""
    if limit == 1:
        return [max(counts, key=counts.get)] if counts else []
    ranked = sorted(counts, key=counts.get, reverse=True)
    return ranked[:limit] if limit is not None else ranked


class _Flow(_Record):
    """Persistent flow history and current metadata; the public payload is built separately."""
    __slots__ = ("rate", "rate_in", "rate_out", "packet_rate", "last_active", "first_seen", "states",
                 "protocols", "services", "service_ports", "age", "transferred", "rule", "inside", "egress",
                 "initiated", "targets")

    def __init__(self, first_seen):
        self.rate = self.rate_in = self.rate_out = self.packet_rate = 0.0
        self.last_active = None
        self.first_seen = first_seen
        # The remaining slots are filled by _update_flow() before the flow is read.


class _FlowTotals(_Record):
    """One sample's aggregate, with the same ordered weighted counts as before."""
    __slots__ = ("toward", "away", "packets", "states", "protocols", "services", "inside", "egress",
                 "remote_started", "local_started", "targets", "ports", "oldest", "bytes_toward", "bytes_away",
                 "rules")

    def __init__(self):
        self.toward = self.away = self.packets = self.states = 0
        self.protocols = set()
        self.services = {}
        self.inside = {}
        self.egress = {}
        self.remote_started = self.local_started = 0
        self.targets = {}
        self.ports = {}
        self.oldest = self.bytes_toward = self.bytes_away = 0
        self.rules = {}


def _native_address(value):
    if len(value) != 17 or value[0] not in (4, 6):
        raise NativeError("invalid native address in aggregate")
    return str(ipaddress.ip_address(value[1:5] if value[0] == 4 else value[1:]))


class FlowTracker:
    """Turn successive PF state samples into per-flow byte rates with activity fading."""

    def __init__(self, fade_seconds=FADE_SECONDS, smoothing=RATE_SMOOTHING):
        self.fade_seconds = fade_seconds
        self.smoothing = smoothing
        self.counters = {}
        self.flows = {}
        self.sampled_at = None
        self.total_flows = 0
        self.native_visible = None

    def _totals(self, records, local_addresses, elapsed, networks=None, sample=None,
                interface_addresses=None, primary_wan_device=None):
        """{(local, remote): totals} for this sample, and the counters to diff the next one against.

        sample: StateFacts.view() of these records, when the caller already has it. This runs for
        every state of every sample, so each state is folded into its flow's totals in place.
        """
        counters = {}
        totals = {}
        previous_counters = self.counters
        views, lan_rules = sample if sample is not None else StateFacts().view(
            records, local_addresses, networks, interface_addresses, primary_wan_device)
        for record, facts in views:
            pair = facts.pair
            state_id = record.id
            if pair is None or state_id is None:
                continue
            if facts.src_is_remote:
                toward, away = record.bytes_in, record.bytes_out
            else:
                toward, away = record.bytes_out, record.bytes_in
            packets = record.packets_in + record.packets_out
            counters[state_id] = current = (toward, away, packets)
            age = record.age
            # what the state moved since the previous sample
            previous = previous_counters.get(state_id)
            if previous is not None:
                delta = (max(0, toward - previous[0]), max(0, away - previous[1]), max(0, packets - previous[2]))
            elif elapsed is not None and age is not None and age <= 2 * elapsed:
                # a state created since the previous sample: everything it counted is new
                delta = current
            else:
                delta = (0, 0, 0)
            total = totals.get(pair)
            if total is None:
                total = totals[pair] = _FlowTotals()
            # PF counts initiator->responder first; src is the initiator in parse_states()
            weight = delta[0] + delta[1] + 1
            if facts.remote_started:
                total.remote_started += weight
                # what the remote side connected to: a port-forward target or the firewall itself
                counts, key = total.targets, facts.target
                counts[key] = counts.get(key, 0) + weight
            else:
                total.local_started += weight
            if facts.inside:
                counts, key = total.inside, facts.inside.address
                counts[key] = counts.get(key, 0) + weight
            key = record.origif
            if key:
                counts = total.egress
                counts[key] = counts.get(key, 0) + weight
            service = facts.service
            counts = total.services
            counts[service] = counts.get(service, 0) + weight
            total.ports.setdefault(service, facts.port_label)
            if age is not None and age > total.oldest:
                total.oldest = age
            # bytes moved so far by the connections open now, and the rules that let them through
            total.bytes_toward += toward
            total.bytes_away += away
            rule = (lan_rules.get(facts.rule_key) if facts.rule_key is not None and lan_rules else None) \
                or record.rule
            if rule:
                counts = total.rules
                counts[rule] = counts.get(rule, 0) + 1
            total.toward += delta[0]
            total.away += delta[1]
            total.packets += delta[2]
            total.states += 1
            total.protocols.add(record.protocol)
        return totals, counters

    def _update_flow(self, flow, total, elapsed, now):
        if isinstance(flow, dict):
            # Some callers inject dict-shaped flows. Keep their object and mutate it as before;
            # production flows use attributes directly, without a per-field adapter.
            compact = _Flow(flow["first_seen"])
            for key in compact.keys():
                if key in flow:
                    compact[key] = flow[key]
            self._update_flow(compact, total, elapsed, now)
            flow.update(dict(compact))
            return
        flow.rate_in = self.smoothing * (total.toward / elapsed if elapsed else 0.0) + (1 - self.smoothing) * flow.rate_in
        flow.rate_out = self.smoothing * (total.away / elapsed if elapsed else 0.0) + (1 - self.smoothing) * flow.rate_out
        flow.packet_rate = self.smoothing * (total.packets / elapsed if elapsed else 0.0) + (1 - self.smoothing) * flow.packet_rate
        flow.rate = flow.rate_in + flow.rate_out
        flow.states = total.states
        flow.protocols = sorted(total.protocols)
        flow.services = _ranked(total.services, MAX_SERVICES)
        flow.service_ports = {name: total.ports[name] for name in flow.services if total.ports.get(name)}
        # how long the oldest connection behind this flow has been open
        flow.age = total.oldest
        flow.transferred = (total.bytes_toward, total.bytes_away)
        flow.rule = (_ranked(total.rules, 1) or [None])[0]
        flow.inside = _ranked(total.inside, MAX_INSIDE)
        flow.egress = (_ranked(total.egress, 1) or [None])[0]
        started = total.remote_started + total.local_started
        share = total.remote_started / started if started else 0.0
        flow.initiated = "remote" if share >= 0.75 else "local" if share <= 0.25 else "both"
        flow.targets = _ranked(total.targets, MAX_INSIDE)
        if total.toward + total.away > 0:
            flow.last_active = now

    def update(self, records, local_addresses, now, networks=None, sample=None,
               interface_addresses=None, primary_wan_device=None):
        elapsed = (now - self.sampled_at) if self.sampled_at is not None else None
        totals, self.counters = self._totals(records, local_addresses, elapsed, networks, sample,
                                             interface_addresses, primary_wan_device)
        self.sampled_at = now
        self.total_flows = len(totals)
        self.native_visible = None
        # a flow disappears together with its last PF state
        for pair in list(self.flows):
            if pair not in totals:
                del self.flows[pair]
        for pair, total in totals.items():
            flow = self.flows.setdefault(pair, _Flow(now))
            self._update_flow(flow, total, elapsed, now)

    def update_aggregate(self, aggregate, now, reset_history=False):
        """Ingest only the native top-K aggregates; rates and ordering are already final."""
        self.counters = {}
        totals = {}
        rows_by_pair = {}
        protocols = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp"}
        self.total_flows = aggregate["counts"]["flows"]
        for row in aggregate["flows"]:
            total = _FlowTotals()
            total.states = row["states"]
            total.toward, total.away, total.packets = row["toward"], row["away"], row["packets"]
            total.bytes_toward, total.bytes_away = row["bytes_toward"], row["bytes_away"]
            total.remote_started, total.local_started = row["remote_started"], row["local_started"]
            total.oldest = row["oldest"]
            totals[row["key"]] = total
            rows_by_pair[row["key"]] = row
        for flow_id, kind, _sequence, weight, association, value in sorted(
                aggregate["candidates"], key=lambda candidate: candidate[2]):
            row = aggregate["flows"][flow_id]
            total = totals[row["key"]]
            if kind == 1:
                number = value[0]
                proto = protocols.get(number)
                if proto is None:
                    try:
                        proto = common.protocol_name(number)
                    except (OSError, ValueError):
                        proto = str(number)
                    protocols[number] = proto
                total.protocols.add(proto)
            elif kind == 2:
                address = _native_address(value)
                total.inside[address] = total.inside.get(address, 0) + weight
            elif kind == 3:
                device = value.decode("ascii")
                total.egress[device] = total.egress.get(device, 0) + weight
            elif kind == 4:
                number, port = (association >> 16) & 255, association & 65535
                proto = protocols.get(number, str(number))
                name = service_name(proto, str(port) if port else None)
                total.services[name] = total.services.get(name, 0) + weight
                total.ports.setdefault(name, service_port_label(proto, str(port) if port else None))
            elif kind == 5:
                proto = protocols.get(value[0], str(value[0]))
                address = _native_address(value[1:18])
                port = int.from_bytes(value[18:20], "big")
                target = connection_target(proto, address, str(port) if port else None)
                total.targets[target] = total.targets.get(target, 0) + weight
            elif kind == 6:
                rule = value.decode("utf-8")
                total.rules[rule] = total.rules.get(rule, 0) + weight
        self.sampled_at = now
        previous_flows = self.flows
        current_flows = {}
        visible = []
        for pair, total in totals.items():
            row = rows_by_pair[pair]
            flow = previous_flows[pair] if pair in previous_flows else _Flow(now)
            flow.rate_in, flow.rate_out = row["rate_in"], row["rate_out"]
            flow.packet_rate = row["packet_rate"]
            flow.rate = flow.rate_in + flow.rate_out
            flow.states = total.states
            flow.protocols = sorted(total.protocols)
            flow.services = _ranked(total.services, MAX_SERVICES)
            flow.service_ports = {name: total.ports[name] for name in flow.services if total.ports.get(name)}
            flow.age = total.oldest
            flow.transferred = (total.bytes_toward, total.bytes_away)
            flow.rule = (_ranked(total.rules, 1) or [None])[0]
            flow.inside = _ranked(total.inside, MAX_INSIDE)
            flow.egress = (_ranked(total.egress, 1) or [None])[0]
            started = total.remote_started + total.local_started
            share = total.remote_started / started if started else 0.0
            flow.initiated = "remote" if share >= 0.75 else "local" if share <= 0.25 else "both"
            flow.targets = _ranked(total.targets, MAX_INSIDE)
            flow.last_active = now - (1.0 - row["activity"]) * self.fade_seconds
            current_flows[pair] = flow
            visible.append((row["score"], pair[0], pair[1], flow, row["activity"]))
        self.flows = current_flows
        # The native order is already the stable FlowTracker ranking. No Python re-sort.
        self.native_visible = visible

    def activity(self, flow, now):
        last_active = flow.last_active if isinstance(flow, _Flow) else flow["last_active"]
        if last_active is None:
            return 0.0
        return max(0.0, 1.0 - (now - last_active) / self.fade_seconds)

    def visible(self, now, limit=MAX_FLOWS):
        """Active or fading flows, strongest first, capped before they reach the browser (None: all)."""
        ranked = []
        for (local, remote), flow in self.flows.items():
            activity = self.activity(flow, now)
            if activity > 0:
                rate = flow.rate if isinstance(flow, _Flow) else flow["rate"]
                ranked.append((max(rate, 1.0) * activity, local, remote, flow, activity))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return ranked if limit is None else ranked[:limit]


def _flow_entry(local, remote, flow, activity, local_addresses, context, wall_time):
    names = context.get("names", {})
    networks = context.get("networks", [])
    interfaces = context.get("interfaces", {})
    alerts = context.get("alerts")
    entry = {
        "origin": local,
        "dest": remote,
        "count": max(1, int(flow["rate"])),
        "rate": round(flow["rate"], 1),
        "rate_in": round(flow["rate_in"], 1),
        "rate_out": round(flow["rate_out"], 1),
        "packet_rate": round(flow["packet_rate"], 2),
        "activity": round(activity, 3),
        "states": flow["states"],
        "protocols": flow["protocols"],
        "services": flow.get("services", []),
        "inside": [describe_inside(address, names, networks, interfaces) for address in flow.get("inside", [])],
        "egress": interfaces.get(flow.get("egress"), flow.get("egress")),
        **threat_fields(remote, context.get("blocklists"), context.get("reputation")),
        "ids": alerts.summary(remote, wall_time) if alerts is not None else None,
        "initiated": flow.get("initiated", "local"),
        "targets": [describe_target(target, names, networks, interfaces, local_addresses)
                    for target in flow.get("targets", [])],
        "service_ports": flow.get("service_ports", {}),
        "age": flow.get("age"),
        "transferred": flow.get("transferred"),
        "rule": context.get("descriptions", {}).get(flow.get("rule") or "", "") or None,
    }
    # a permitted flow to a listed address is what deserves attention, not background scans
    entry["threat"] = bool(entry["lists"])
    return entry


def _location_entry(address, location, local_addresses):
    entry = {
        "id": address,
        "name": ", ".join(
            part for part in (location.get("city") or location.get("region"), location.get("country")) if part
        ) or address,
        "city": location.get("city"),
        "region": location.get("region"),
        "accuracy_km": location.get("accuracy_km"),
        "country": location.get("country_name") or location.get("country"),
        "country_code": location.get("country"),
        "lat": location["lat"],
        "lon": location["lon"],
        "local": address in local_addresses,
    }
    if location.get("asn"):
        entry["asn"] = location["asn"]
        entry["as_org"] = location.get("as_org")
    return entry


def summarize_flows(tracker, geo, local_addresses, role, now, wall_time, hostnames=None, context=None, limit=MAX_FLOWS,
                    anchor=None, visible=None):
    context = context or {}
    if visible is None:
        visible = tracker.visible(now, limit)
        geo.resolve([address for _, local, remote, _, _ in visible for address in (remote, local) if public_ip(address)])
    # Explicit candidates are already resolved by snapshot selection. Do not trigger a cache
    # eviction between counting their geographic availability and serializing those flows.
    flows = []
    locations = {}
    for _, local, remote, flow, activity in visible:
        remote_location = geo.get(remote)
        if remote_location is None:
            continue
        locations[remote] = _location_entry(remote, remote_location, local_addresses)
        local_location = geo.get(local)
        if anchor is not None:
            locations[local] = {"id": local, "name": anchor.get("name") or "Firewall",
                                "lat": anchor["lat"], "lon": anchor["lon"], "local": True}
        elif local_location is not None:
            locations[local] = _location_entry(local, local_location, local_addresses)
        flows.append(_flow_entry(local, remote, flow, activity, local_addresses, context, wall_time))
    resolved = {}
    if hostnames is not None:
        remotes = [flow["dest"] for flow in flows]
        known = context.get("names", {})
        inside = []
        for flow in flows:
            inside.extend(item["ip"] for item in flow["inside"] if not item.get("name"))
            inside.extend(item["ip"] for item in flow["targets"]
                          if not item.get("firewall") and not item.get("name"))
        # The existing opt-in covers every host name visible in a flow.  The resolver's one
        # shared budget prevents internal PTRs from adding unbounded DNS work.
        hostnames.update(
            [(address, INSIDE_HOSTNAME_TTL, INSIDE_NEGATIVE_TTL) for address in inside if address not in known] + remotes,
            now,
        )
        addresses = set(remotes) | set(inside)
        resolved = {address: hostnames.get(address) for address in addresses if hostnames.get(address)}
    return {
        "status": "ok",
        "sampled_at": datetime.fromtimestamp(wall_time, timezone.utc).isoformat(),
        "interval": INTERVAL,
        "carp": role,
        "tracked_flows": getattr(tracker, "total_flows", len(tracker.flows)),
        "flows": flows,
        "locations": [locations[address] for address in sorted(locations)],
        "hostnames": resolved,
    }


def recording_wanted(values=None):
    """Record threats for review while the widget is in use, unless switched off."""
    values = values if values is not None else settings()
    return values.get("record_threats", "1") != "0" and widget_in_use()


class ThreatRecorder:
    """Feeds threat history; a database problem never stops the collector.

    Reads what it needs from the running Collector (threat lists, reputation, geolocation,
    host names, Suricata history and names), so a new source of facts needs no new parameter.
    """

    def __init__(self, path=threats.DATABASE):
        self.path = path
        self.db = None
        # a database problem is logged once, then again when recording works
        self.failing = False
        self.recorded = None
        self.pruned = None
        self.last_wall = 0.0

    def due(self, now):
        return self.recorded is None or now - self.recorded >= THREAT_RECORD_SECONDS

    def _identity(self, address, collector):
        """Who the address belongs to, kept with the entry: the map forgets it once the flow ends."""
        location = (collector.geo.get(address) if collector.geo is not None else None) or {}
        name = collector.hostnames.names.get(address) if collector.hostnames is not None else None
        return {key: value for key, value in {
            "hostname": name[0] if name else None,
            "asn": location.get("asn"),
            "org": location.get("as_org"),
            "country": location.get("country_name") or location.get("country"),
            "country_code": location.get("country"),
            "city": location.get("city"),
        }.items() if value}

    def update(self, records, collector, now, sample=None, native=None):
        """sample: StateFacts.view() of records, when the caller already has it."""
        if not self.due(now):
            return
        self.recorded = now
        blocklists, reputation, correlator = collector.blocklists, collector.reputation, collector.correlator
        try:
            if self.db is None:
                self.db = threats.connect(self.path)

            def lists_for(address):
                return threat_lists_for(address, blocklists, reputation, correlator)

            seen = threats.observe_aggregates(native, lists_for) if native is not None else threats.observe(
                records, lists_for, collector.local_addresses, collector.networks, sample)
            seen.update(ips_drops(correlator, seen, self.last_wall, blocklists, reputation))
            seen.update(firewall_blocks(correlator, seen, self.last_wall, blocklists, reputation))
            if collector.geo is not None and seen:
                collector.geo.resolve(list(seen))
            index = connection_keys(correlator) if seen else None
            names = collector.host_names() if seen else {}
            for address, entry in seen.items():
                entry["remote"] = self._identity(address, collector)
                entry["ids"] = collector.alerts.summary(address)
                entry["connections"] = connection_summary(address, correlator, names, collector.interfaces,
                                                          index=index)
            self.last_wall = time.time()
            threats.record(self.db, seen)
            if self.failing:
                log_notice("threat recording works again")
                self.failing = False
            # hourly by age; at once when a burst of flagged addresses overfills history
            over = self.db.execute("SELECT count(*) FROM threats").fetchone()[0] > threats.KEEP_ROWS + threats.KEEP_TOUCHED
            if over or self.pruned is None or now - self.pruned >= THREAT_PRUNE_SECONDS:
                threats.prune(self.db)
                self.pruned = now
        except sqlite3.Error as error:
            if not self.failing:
                log_error(f"threat recording failed: {error}")
                self.failing = True
            # reconnect on the next recording, without leaving the failed connection open
            try:
                self.db.close()
            except (AttributeError, sqlite3.Error):
                pass
            self.db = None


def idle(started, now=None, marker=REQUEST_MARKER, idle_seconds=IDLE_SECONDS):
    """True once no dashboard has read the summary for idle_seconds (with a start-up grace period)."""
    now = time.time() if now is None else now
    if now - started < idle_seconds:
        return False
    try:
        return now - os.stat(marker).st_mtime >= idle_seconds
    except OSError:
        return True


def database_state(values):
    """Return (city path, asn path, problem) for the provider in effect."""
    provider = geodb.lookup_provider(values)
    paths = geodb.DATABASES[provider]
    if os.path.exists(paths["city"]):
        return paths["city"], paths["asn"], None
    if provider.startswith("maxmind") and geodb.license_key(values)[0] is None:
        return paths["city"], paths["asn"], "maxmind_key_missing"
    return paths["city"], paths["asn"], "database_missing"


def acquire_lock(path=COLLECTOR_LOCK):
    """Only one collector may run; a second one started concurrently exits at once."""
    import fcntl
    os.makedirs(os.path.dirname(path), exist_ok=True)
    handle = open(path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


def reload_token(path=RELOAD_MARKER):
    """Opaque token changed by the settings API when the live collector must reload."""
    try:
        with open(path, encoding="ascii") as handle:
            return handle.read(64)
    except OSError:
        return None


def request_reload(path=RELOAD_MARKER):
    """Atomically notify a running collector without losing its in-memory flow history."""
    write_text(path, str(time.time_ns()))


class SampleTimer:
    """Where one sample's time went: seconds per phase (wall time; "parse" is the CPU time spent
    reading pfctl's output during the walk), and the whole sample's wall and CPU time (the
    collector's own plus that of the programs it ran: pfctl, ifconfig). The Status page shows it,
    so anyone can check the cost on their own hardware."""

    def __init__(self):
        self.phases = {}
        self.started = time.perf_counter()
        self.cpu = time.process_time()
        self.children = self._children()
        self.mark = self.started

    @staticmethod
    def _children():
        times = os.times()
        return times.children_user + times.children_system

    def phase(self, name):
        """The time since the previous phase ended goes to `name`."""
        now = time.perf_counter()
        self.phases[name] = self.phases.get(name, 0.0) + now - self.mark
        self.mark = now

    def report(self, states, background):
        programs = self._children() - self.children
        return {
            "at": time.time(), "states": states, "background": background,
            "wall": round(time.perf_counter() - self.started, 4),
            "cpu": round(time.process_time() - self.cpu + programs, 4), "programs": round(programs, 4),
            "phases": {name: round(value, 4) for name, value in self.phases.items()},
        }


def status_document(status, **fields):
    return {"status": status, **fields, "sampled_at": datetime.now(timezone.utc).isoformat(),
            "flows": [], "locations": []}


class Collector:
    """The sampling loop, one iteration at a time.

    Each iteration refreshes what is due (host addresses, settings, metadata, threat lists),
    then either feeds threat history only (nobody is watching: background) or also writes
    the map summary. Both paths share the same ingest and record steps.
    """

    def __init__(self, store=None, started_at=None):
        self.started_at = time.time() if started_at is None else started_at
        self.store = store if store is not None else CacheStore()
        self.tracker = FlowTracker()
        self.hostnames = HostnameResolver(store=self.store)
        self.blocks = BlockTracker()
        self.log = FilterLogTail()
        self.eve = FilterLogTail(EVE_LOG)
        self.backlog_loaded = False
        self.eve_loaded = False
        self.alerts = AlertTracker()
        self.correlator = Correlator()
        self.blocklists = BlocklistIndex()
        self.reputation = Reputation(self.store)
        self.recorder = ThreatRecorder()
        self.facts = StateFacts()
        self.native_engine = NativeEngine()
        self.engine_mode = None
        self.native_last_at = None
        self.native_visible = False
        self.native_failure_logged = False
        # the last sample's timings (SampleTimer.report) and when they were last written
        self.timings = None
        self.timings_written = None
        # Sample fields describe the last successfully published revision, never an attempt.
        # Phase fields describe this process now; payloads freeze their own copy at publication.
        self.collector_status = {
            "generation": uuid.uuid4().hex, "revision": 0, "state_count": None,
            "engine": None,
            "sample_started_at": None, "sample_completed_at": None, "sample_duration": None,
            "effective_sample_interval": None, "next_sample_due": None,
            "phase": "starting", "phase_started_at": self.started_at,
            "phase_deadline": None, "heartbeat_at": time.time(),
        }
        self._status_lock = threading.RLock()
        self._diagnostic_timings = {}
        self._sample_started = None
        self._sample_revision = None
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread = None
        self.descriptions, self.interfaces, self.leases = {}, {}, {}
        self.local_addresses, self.role, self.networks, self.interface_addresses = set(), None, [], {}
        self.primary_wan_device = None
        self.location_settings = {"discover_external_ip": False, "latitude": None, "longitude": None}
        self.external_ip, self.external_ip_key, self.external_ip_checked = None, None, None
        self.values = {}
        self.recording = False
        self.provider = "maxmind"
        self.geo = None
        self.problem = None
        self.failures = 0
        self.too_many_states = False
        self.background = False
        self.checked = {"host": None, "settings": None, "metadata": None, "blocklists": None}
        self.reload_seen = reload_token()

    def _due(self, name, now, every):
        return self.checked[name] is None or now - self.checked[name] >= every

    def refresh_settings(self, now):
        token = reload_token()
        if token != self.reload_seen:
            self.reload_seen = token
            self.checked["settings"] = self.checked["blocklists"] = self.checked["metadata"] = None
            log_notice("settings changed: reloading them")
        if self._due("host", now, HOST_REFRESH_SECONDS):
            self.local_addresses, self.role, self.networks, self.interface_addresses = host_info()
            self.checked["host"] = now
        if self._due("settings", now, SETTINGS_REFRESH_SECONDS):
            self.values = settings()
            self.recording = recording_wanted(self.values)
            # DB-IP while it stands in for a failing MaxMind download (its credit is then shown)
            self.provider = geodb.lookup_provider(self.values)
            city, asn, problem = database_state(self.values)
            if problem != self.problem:
                if problem:
                    log_warning(f"no geolocation database ({problem}): the map waits until one is downloaded")
                elif self.problem:
                    log_notice("geolocation database available")
                self.problem = problem
            # a new provider or a refreshed database invalidates cached locations
            if self.geo is None or self.geo.database != city or self.geo.database_mtime != self.geo._database_mtime():
                if self.geo is not None:
                    self.geo.save(force=True)
                self.geo = GeoCache(store=self.store, database=city, asn_database=asn)
                self.geo.forget_old_databases()
            self.checked["settings"] = now

    def refresh_metadata(self, now):
        """Rule descriptions, interface and DHCP names and port forwards, in both modes: a collector
        kept alive in the background must not record queue entries with stale names."""
        if self._due("metadata", now, METADATA_REFRESH_SECONDS):
            self.descriptions, self.interfaces, self.leases = rule_descriptions(), interface_names(), lease_names()
            self.location_settings = topology()
            self.primary_wan_device = self.location_settings["primary_wan_device"]
            self.correlator.forwards = port_forwards()
            self.checked["metadata"] = now
        if self._due("blocklists", now, BLOCKLIST_REFRESH_SECONDS):
            if self.blocklists.refresh(chosen_threat_lists(self.values.get("threat_lists"))):
                self.checked["blocklists"] = now
        self.reputation.refresh(now)

    def ingest(self, records, now, wall, foreground, sample=None, native=None):
        """Feed one sample to the trackers: states, blocked attempts from the log, Suricata alerts.
        sample: StateFacts.view() of records, when the caller already has it."""
        lines = self.log.lines()
        if foreground and not self.backlog_loaded:
            # the 10-minute hit window starts full
            self.backlog_loaded = True
            lines = self.log.backlog() + lines
        for line in lines:
            event = parse_block(line)
            # only connection attempts aimed at this firewall's own public addresses; blocked
            # forwarded traffic (e.g. another host's outbound packets) is not an inbound probe
            if not event or event["destination"] not in self.local_addresses:
                continue
            if foreground:
                at = block_event_time(line, now, wall)
                if at is None:
                    continue
                self.blocks.add(event, at)
            # blocked attempts stay matchable for late alerts even with no map open
            self.correlator.observe_block(event, wall, self.descriptions)
        if native is None:
            self.correlator.observe_states(records, self.local_addresses, wall, self.descriptions, self.networks, sample)
        else:
            self.correlator.observe_native_matches(native["matches"], wall, self.descriptions)
        if foreground and not self.eve_loaded:
            self.eve_loaded = True
            # older alerts can only be address history: their connections are not indexed yet
            self.alerts.feed(self.eve.backlog(ALERT_BACKLOG_BYTES), self.local_addresses, networks=self.networks)
        self.alerts.feed(self.eve.lines(), self.local_addresses, self.correlator, wall, self.networks)
        if native is None:
            self.correlator.resolve(self.local_addresses, wall, self.networks)
        else:
            self.correlator.resolve_native(native["matches"], self.local_addresses, wall, self.networks)
        self.alerts.expire(wall)

    def map_anchor(self, now):
        """Coordinates for rendering a private-WAN origin, never an address substituted into a flow."""
        latitude, longitude = self.location_settings["latitude"], self.location_settings["longitude"]
        if latitude is not None and longitude is not None:
            return {"lat": latitude, "lon": longitude, "name": "Firewall"}
        device = self.primary_wan_device
        addresses = self.interface_addresses.get(device, set())
        # A public WAN remains on its existing local-GeoIP path even when CARP or an alias adds
        # private addresses. No individual private address is the WAN's semantic identity.
        private_ipv4 = any(private_ip(address) and ":" not in address for address in addresses)
        if not self.location_settings["discover_external_ip"] or not device or not private_ipv4 \
                or any(public_ip(address) for address in addresses):
            return None
        key = device
        if key != self.external_ip_key:
            self.external_ip, self.external_ip_key, self.external_ip_checked = None, key, None
        if self.external_ip is None and (self.external_ip_checked is None or now - self.external_ip_checked >= EXTERNAL_IP_RETRY_SECONDS):
            self.external_ip_checked = now
            self.external_ip = self.store.get("external-ip-v1", key, max_age=EXTERNAL_IP_MAX_AGE)
            if self.external_ip is None:
                self.external_ip = discover_external_ipv4()
                if self.external_ip:
                    self.store.put_many("external-ip-v1", [(key, self.external_ip)])
        if not self.external_ip:
            return None
        self.geo.resolve([self.external_ip])
        location = self.geo.get(self.external_ip)
        return {"lat": location["lat"], "lon": location["lon"], "name": "Firewall"} if location else None

    def host_names(self):
        """Configured DHCP names override the short-lived PTR fallback."""
        return host_names(self.leases, self.store)

    def build_payload(self, now, limit=MAX_FLOWS, visible=None, snapshot=False):
        """The map document: flows (the strongest `limit`, None for all), blocked sources, alerts."""
        resolver = self.hostnames if requested(HOSTNAME_MARKER, HOSTNAME_REQUEST_SECONDS) else None
        geo = self.geo
        if visible is None and not snapshot and self.engine_mode == "native" and self.tracker.native_visible is not None:
            visible = self.tracker.native_visible
            geo.resolve(address for _, local, remote, _, _ in visible for address in (remote, local)
                        if public_ip(address))
        context = {
            "names": self.host_names(), "networks": self.networks, "interfaces": self.interfaces,
            "blocklists": self.blocklists, "reputation": self.reputation, "alerts": self.alerts,
            "descriptions": self.descriptions,
        }
        payload = summarize_flows(self.tracker, geo, self.local_addresses, self.role, now, time.time(), resolver, context,
                                  limit, self.map_anchor(now), visible)
        origin = next((location["id"] for location in payload["locations"] if location["local"]), None)
        if origin is None and self.local_addresses:
            origin = sorted(self.local_addresses)[0]
            geo.resolve([origin])
        payload["blocks"] = block_summary(
            self.blocks, geo, self.local_addresses, origin, now, self.descriptions, self.interfaces,
            self.blocklists, self.reputation, self.alerts,
        )
        shown = {flow["dest"] for flow in payload["flows"]} | {block["source"] for block in payload["blocks"]}
        if snapshot:
            # Keep address-alert evidence independently of ordinary flow byte selection.
            shown = {block["source"] for block in payload["blocks"]}
        payload["alerts"] = alert_summary(self.alerts, geo, origin, shown, self.blocklists, self.reputation)
        payload["ids_flows"] = self.correlator.summary(geo, origin, self.host_names(), self.networks, self.interfaces,
                                                       self.blocklists, self.reputation)
        # which lists are consulted, so the details can show "not listed" per list
        # every configured interface, so the interface filter lists the quiet ones too
        # (not loopback or the IPsec encapsulation device: no inside host lives behind them)
        payload["interfaces"] = sorted({name for device, name in self.interfaces.items()
                                        if not re.match(r"^(lo|enc)\d+$", device)}, key=str.lower)
        payload["threat_lists"] = list(self.blocklists.names) + ([REPUTATION_LIST] if self.reputation.scores else [])
        if origin and geo.get(origin) and not any(location["id"] == origin for location in payload["locations"]):
            location = geo.get(origin)
            payload["locations"].append({
                "id": origin, "name": origin, "lat": location["lat"], "lon": location["lon"], "local": True,
            })
        payload["provider"] = self.provider
        payload["collector"] = self.timing_status()
        return payload

    def timing_status(self):
        with self._status_lock:
            return dict(self.collector_status)

    def heartbeat(self):
        """Atomic liveness update in the existing diagnostic file, not a data revision."""
        with self._status_lock:
            self.collector_status["heartbeat_at"] = time.time()
            try:
                write_json(COLLECTOR_TIMINGS, {**self._diagnostic_timings, "collector": self.timing_status()})
            except OSError:
                pass  # diagnostics must not prevent sampling when their file cannot be written

    def start_heartbeat(self):
        """Daemon-only instrumentation; never wakes or schedules the sampling loop."""
        if self._heartbeat_thread is not None:
            return

        def beat():
            while not self._heartbeat_stop.wait(TIMINGS_WRITE_SECONDS):
                self.heartbeat()

        self._heartbeat_thread = threading.Thread(target=beat, name="firewallmap-heartbeat", daemon=True)
        self._heartbeat_thread.start()

    def set_phase(self, phase, deadline=None, next_due=None):
        with self._status_lock:
            self.collector_status.update(phase=phase, phase_started_at=time.time(), phase_deadline=deadline,
                                         next_sample_due=next_due)
            self.heartbeat()

    def complete_sample(self, states, payload=None):
        """Commit sample identity only after atomic publication succeeds.

        Completion is the publication preparation boundary (after payload construction, before
        its atomic write); duration covers PF acquisition through that boundary. Background
        samples publish timing/queue progress, not a new live-map file. The two files need not
        match: each carries its own generation/revision and immutable sample fields.
        """
        with self._status_lock:
            completed = time.time()
            status = {**self.collector_status, "revision": self.collector_status["revision"] + 1,
                      "state_count": states, "sample_started_at": self._sample_started[0],
                      "sample_completed_at": completed,
                      "sample_duration": max(0.0, time.monotonic() - self._sample_started[1]),
                      "heartbeat_at": completed}
            if payload is not None:
                payload["collector"] = status
                write_json(OUTPUT_FILE, payload)
            else:
                try:
                    write_json(COLLECTOR_TIMINGS, {**self._diagnostic_timings, "collector": status})
                except OSError:
                    return
            self.collector_status = dict(status)
            self._sample_revision = status["revision"]

    def publish_summary(self, now, timer=None, states=None):
        payload = self.build_payload(now)
        if timer:
            timer.phase("payload")
        self.complete_sample(states, payload)
        if timer:
            timer.phase("write")

    def save_timings(self, timer, states, background, now):
        """Keep the sample's timings; the Status page reads them from a file written every few seconds."""
        self.timings = timer.report(states, background)
        # Cost diagnostics retain their existing 10 s refresh. Their identity is explicit,
        # because the current liveness/sample record may already describe a newer revision.
        self.timings.update(generation=self.collector_status["generation"], revision=self._sample_revision)
        if self.timings_written is None or now - self.timings_written >= TIMINGS_WRITE_SECONDS:
            with self._status_lock:
                self._diagnostic_timings = self.timings
                self.timings_written = now

    def state_rows(self, records, remotes, coverage=None, budget=None):
        """The PF states behind the given remote addresses, as the map page's States dialog lists them."""
        rows, total = {}, 0
        for record in records:
            if total >= SNAPSHOT_STATES_TOTAL and coverage is None:
                break
            pair = flow_endpoints(record, self.local_addresses, self.networks, self.interface_addresses,
                                  self.primary_wan_device)
            if pair is None or pair[1] not in remotes:
                continue
            if coverage is not None:
                coverage["available"] += 1
            listed = rows.get(pair[1], [])
            if total >= SNAPSHOT_STATES_TOTAL or len(listed) >= SNAPSHOT_STATES_PER_ADDRESS:
                continue
            nat = record.get("nat")
            row = {
                "interface": self.interfaces.get(record.get("interface"), record.get("interface")),
                "proto": record.get("protocol"),
                "src_addr": record["src"]["address"], "src_port": record["src"]["port"],
                "dst_addr": record["dst"]["address"], "dst_port": record["dst"]["port"],
                "nat": host_port(nat["address"], nat["port"]) if nat and nat.get("address") else None,
                "state": record.get("state"),
                "bytes": (record.get("bytes_in") or 0) + (record.get("bytes_out") or 0),
                "age": record.get("age"),
            }
            if budget is not None and not budget.take({pair[1]: [row]}):
                coverage["omitted_bytes"] += 1
                continue
            rows.setdefault(pair[1], []).append(row)
            total += 1
        if coverage is not None:
            coverage["captured"] = total
            coverage["truncated"] = total < coverage["available"]
        return rows

    def build_snapshot_payload(self, records, now):
        """Bounded incident-first detail. Scan candidates, but never build an uncapped document."""
        native_snapshot = records is None and self.engine_mode == "native"
        # Resolve through the existing per-sample lookup budget, without an O(F) address list.
        if not native_snapshot:
            self.geo.resolve(address for (local, remote), flow in self.tracker.flows.items()
                             if self.tracker.activity(flow, now) > 0
                             for address in (remote, local) if public_ip(address))
        evidence = set(self.alerts.sources) | {key[3] for key in self.correlator.flows}
        coverage = {"candidates": 0, "available": 0, "captured": 0, "limit": SNAPSHOT_FLOWS,
                    "selection": "incident_then_traffic_v1", "omitted_limit": 0, "omitted_bytes": 0, "omitted_geo": 0}

        def candidates():
            for (local, remote), flow in self.tracker.flows.items():
                activity = self.tracker.activity(flow, now)
                if activity <= 0:
                    continue
                coverage["candidates"] += 1
                if self.geo.get(remote) is None:
                    coverage["omitted_geo"] += 1
                    continue
                coverage["available"] += 1
                incident = remote in evidence or bool(threat_lists_for(remote, self.blocklists, self.reputation))
                rank = max(flow["rate"], 1.0) * activity
                yield incident, rank, local, remote, flow, activity

        if native_snapshot:
            evidence.update(self.blocks.sources)

            def native_candidates():
                required, lookup_budget = 0, GEO_LOOKUPS_PER_SAMPLE
                for page in self.native_engine.snapshot_pages():
                    addresses = list(dict.fromkeys(address for local, remote, _rank, _order in page
                                                   for address in (remote, local) if public_ip(address)))
                    unknown = sum(address not in self.geo.entries for address in addresses)
                    if lookup_budget:
                        self.geo.resolve(addresses, budget=lookup_budget)
                        lookup_budget -= min(lookup_budget, unknown)
                    for local, remote, rank, order in page:
                        incident = remote in evidence or bool(threat_lists_for(remote, self.blocklists, self.reputation))
                        if rank <= 0 and not incident:
                            continue
                        coverage["candidates"] += 1
                        if self.geo.get(remote) is None:
                            coverage["omitted_geo"] += 1
                            continue
                        coverage["available"] += 1
                        required += int(incident)
                        if required > SNAPSHOT_FLOWS:
                            raise SnapshotTooLarge("required incident flows exceed snapshot flow ceiling")
                        yield incident, rank, order, local, remote

            identities = nsmallest(SNAPSHOT_FLOWS, native_candidates(),
                                   key=lambda item: (not item[0], -item[1], item[2]))
            aggregate = self.native_engine.snapshot_selection([(local, remote, incident)
                                                               for incident, _rank, _order, local, remote in identities])
            tracker = FlowTracker()
            tracker.update_aggregate(aggregate, now)
            selected = [(identity[0], *row) for identity, row in zip(identities, tracker.native_visible)]
        else:
            selected = nsmallest(SNAPSHOT_FLOWS, candidates(), key=lambda item: (not item[0], -item[1]))
        coverage["omitted_limit"] = coverage["available"] - len(selected)
        visible = [item[1:] for item in selected]
        payload = self.build_payload(now, visible=visible, snapshot=True)
        flows, locations, names = payload["flows"], payload["locations"], payload["hostnames"]
        payload["flows"] = []
        payload["locations"] = [location for location in locations if location["local"]]
        payload["hostnames"] = {}
        payload["states"], payload["full"] = {}, True
        states = {"scope": "captured_flow_block_and_ids_remotes", "available": 0, "captured": 0,
                  "per_remote_limit": SNAPSHOT_STATES_PER_ADDRESS, "total_limit": SNAPSHOT_STATES_TOTAL,
                  "omitted_bytes": 0, "truncated": False}
        if native_snapshot:
            states = {"scope": "retained_logical_flows", "available": 0, "captured": 0,
                      "total_limit": SNAPSHOT_STATES_TOTAL, "truncated": False, "complete": False}
        payload["capture"] = {"version": 1, "source": "collector", "detail_status": "complete",
                              "encoded_limit": SNAPSHOT_BYTES, "flows": coverage, "states": states}
        budget = DocumentBudget(payload, SNAPSHOT_BYTES)
        locations = {location["id"]: location for location in locations}
        kept_locations = {location["id"] for location in payload["locations"]}
        required_pairs = {(item[2], item[3]) for item in selected if item[0]}
        for flow in flows:
            places = [locations[address] for address in dict.fromkeys((flow["origin"], flow["dest"]))
                      if address in locations and address not in kept_locations]
            addresses = {flow["dest"]} | {item["ip"] for field in ("inside", "targets") for item in flow[field]}
            hostnames = {address: names[address] for address in sorted(addresses)
                         if address in names and address not in payload["hostnames"]}
            # The wrapper overhead is conservative; no full document is encoded to test a fit.
            if not budget.take({"flow": flow, "locations": places, "hostnames": hostnames}):
                if native_snapshot and (flow["origin"], flow["dest"]) in required_pairs:
                    raise SnapshotTooLarge("required incident flow evidence exceeds snapshot byte ceiling")
                coverage["omitted_bytes"] += 1
                continue
            payload["flows"].append(flow)
            payload["locations"].extend(places)
            kept_locations.update(place["id"] for place in places)
            payload["hostnames"].update(hostnames)
        payload["locations"].sort(key=lambda location: location["id"])
        coverage["captured"] = len(payload["flows"])
        remotes = {flow["dest"] for flow in payload["flows"]} | {block["source"] for block in payload["blocks"]}
        remotes.update(flow["dest"] for flow in payload["ids_flows"])
        if native_snapshot:
            identities = [(flow["origin"], flow["dest"], (flow["origin"], flow["dest"]) in required_pairs)
                          for flow in payload["flows"]]
            payload["states"], states = self.native_engine.snapshot_detail(
                identities, max(0, budget.remaining), SNAPSHOT_STATES_TOTAL)
            payload["capture"]["states"] = states
            payload["capture"]["source"] = "native_collector"
        else:
            payload["states"] = self.state_rows(records, remotes, states, budget)
        if coverage["captured"] < coverage["candidates"] or states["truncated"]:
            payload["capture"]["detail_status"] = "truncated"
        if json_size(payload, SNAPSHOT_BYTES) > SNAPSHOT_BYTES:
            raise SnapshotTooLarge("snapshot exceeds byte limit")
        return payload

    def save_requested_snapshots(self, records, now):
        """Write a full snapshot for each camera request waiting in SNAPSHOT_REQUEST_DIR."""
        try:
            names = sorted(os.listdir(SNAPSHOT_REQUEST_DIR))
        except OSError:
            return
        requests = [name[:-len(".request")] for name in names if name.endswith(".request")]
        if not requests:
            return
        try:
            payload = self.build_snapshot_payload(records, now)
        except SnapshotTooLarge as error:
            if records is None:
                self.native_engine.close()
            payload = {"status": "snapshot_too_large", "error": str(error)}
        except NativeError as error:
            self.native_engine.close()
            payload = {"status": "snapshot_failed", "error": str(error)}
        for snapshot_id in requests:
            if snapshot_valid_id(snapshot_id):
                write_json(f"{SNAPSHOT_DIR}/{snapshot_id}.json", payload)
            try:
                os.remove(f"{SNAPSHOT_REQUEST_DIR}/{snapshot_id}.request")
            except OSError:
                pass

    @staticmethod
    def snapshot_requested():
        try:
            return any(name.endswith(".request") for name in os.listdir(SNAPSHOT_REQUEST_DIR))
        except OSError:
            return False

    def rest_status(self, rest, failed=False):
        """Describe the already chosen rest, without changing the scheduler's decision."""
        wall = time.time()
        phase = "retrying" if failed or self.failures or self.too_many_states or self.problem else (
            "background" if self.background else "sleeping")
        self.set_phase(phase, wall + rest, next_due=wall + rest)

    def step(self):
        self.set_phase("preparing")
        try:
            rest = self._step()
        except Exception:
            self.set_phase("failed")
            raise
        if rest is None:
            self.set_phase("idle")
        else:
            self.rest_status(rest)
        return rest

    def _step(self):
        """One iteration. Returns the seconds to rest before the next, or None to stop."""
        started = time.monotonic()
        timer = SampleTimer()
        self.refresh_settings(started)
        timer.phase("settings")
        background = idle(self.started_at)
        if background != self.background:
            log_notice("no map open: recording threats in the background" if background and self.recording
                       else "no map open" if background else "a map is open: sampling every 2 seconds")
            self.background = background
        with self._status_lock:
            # Target at this sampling opportunity, not an adaptive interval or the rest floor.
            # next_sample_due separately describes the chosen slow-sample/backoff rest.
            self.collector_status["effective_sample_interval"] = (
                BACKGROUND_INTERVAL if background else INTERVAL if requested(REQUEST_MARKER, ACTIVE_VIEWER_SECONDS)
                else IDLE_INTERVAL)
        if background and not self.recording:
            log_notice("collector stopping: no map open and background recording is off")
            return None
        if not background and self.problem:
            self.set_phase("failed")
            write_json(OUTPUT_FILE, status_document("no_database", reason=self.problem,
                                                    error=geodb.read_status().get("last_error"),
                                                    collector=self.timing_status()))
            # re-check within a few seconds, the database may be downloading; only move the
            # next check earlier, never later, or repeated passes would postpone it forever
            self.checked["settings"] = min(self.checked["settings"], started - SETTINGS_REFRESH_SECONDS + 5)
            return self._rest(started, background)
        self.refresh_metadata(started)
        timer.phase("metadata")
        walk_cpu = time.process_time()
        self._sample_started = (time.time(), time.monotonic())
        self._sample_revision = None
        self.set_phase("collecting", self._sample_started[0] + SAMPLE_TIMEOUT + 10)
        try:
            native = None
            records = None
            engine = "python"
            reset_history = self.engine_mode != "native" or self.native_last_at is None
            if native_available():
                try:
                    native_start = time.perf_counter()
                    elapsed = -1 if reset_history or self.native_last_at is None else started - self.native_last_at
                    native = self.native_engine.sample(
                        self.local_addresses, self.networks, self.interface_addresses,
                        self.primary_wan_device, elapsed, threat_summary=self.recorder.due(started),
                        event_queries=self.correlator.native_queries(self.local_addresses, self.networks),
                        snapshot=not background and self.snapshot_requested())
                    timer.phases["native"] = time.perf_counter() - native_start
                    engine = "native"
                    self.native_failure_logged = False
                except NativeError as error:
                    self.native_engine.close()
                    self.native_last_at = None
                    reset_history = True
                    if not self.native_failure_logged:
                        log_warning(f"native PF sample failed; using pfctl fallback: {error}")
                        self.native_failure_logged = True
            if native is None:
                if self.engine_mode == "native":
                    self.tracker.counters = {}
                    self.tracker.sampled_at = None
                self.native_engine.close()
                self.native_last_at = None
                records = sample_states()
        except TooManyStates as error:
            self.set_phase("failed")
            if not background:
                write_json(OUTPUT_FILE, status_document("too_many_states", count=error.count, limit=error.limit,
                                                        slow=error.slow, collector=self.timing_status()))
            if not self.too_many_states:
                log_warning(f"sampling paused: {error}")
            self.too_many_states = True
            return TOO_MANY_STATES_INTERVAL
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
            self.set_phase("failed")
            if not self.failures:
                log_error(f"reading the firewall states failed: {error}")
            self.failures += 1
            if not background:
                write_json(OUTPUT_FILE, status_document("failed", error=str(error), collector=self.timing_status()))
            return self._rest(started, background)
        if self.failures:
            log_notice(f"reading the firewall states works again, after {self.failures} failed attempts")
        if self.too_many_states:
            log_notice("sampling resumed: the state table is below the limit again")
        self.failures = 0
        self.too_many_states = False
        if records is not None:
            # pfctl output is parsed as it is read; this includes the parser's CPU time.
            timer.phases["parse"] = time.process_time() - walk_cpu
        timer.phase("walk")
        self.set_phase("processing")
        now = time.monotonic()
        wall = time.time()
        sample = None
        if records is not None:
            sample = self.facts.view(records, self.local_addresses, self.networks, self.interface_addresses,
                                     self.primary_wan_device)
            timer.phase("facts")
        if not background:
            if native is not None:
                self.tracker.update_aggregate(native, now, reset_history)
            else:
                self.tracker.update(records, self.local_addresses, now, self.networks, sample,
                                    self.interface_addresses, self.primary_wan_device)
            timer.phase("tracker")
        self.ingest(records, now, wall, foreground=not background, sample=sample, native=native)
        timer.phase("ingest")
        # while the map is open the queue is always fed; the setting and the widget only decide
        # whether recording continues in the background
        self.recorder.update(records, self, now, sample, native=native)
        timer.phase("threats")
        state_count = native["counts"]["states"] if native is not None else len(records)
        with self._status_lock:
            self.collector_status["engine"] = engine
        if engine == "native":
            self.engine_mode = "native"
            # Rate deltas span sample starts, avoiding dependence on the previous
            # sample's PF dump duration when the current dump has not completed yet.
            self.native_last_at = started
            self.native_visible = not background
        else:
            self.engine_mode = "python"
            self.native_visible = False
        if not background:
            self.publish_summary(now, timer, state_count)
            if records is not None or self.native_engine.snapshot_open:
                self.save_requested_snapshots(records, now)
            if native is not None:
                self.native_engine.snapshot_cancel()
        else:
            self.complete_sample(state_count)
        # locations resolved for the queue in the background are saved too (at most once a minute)
        self.geo.save()
        timer.phase("other")
        if native is not None:
            timer.phases["native_states"] = native["counts"]["states"]
            timer.phases["native_flows"] = native["counts"]["flows"]
        self.save_timings(timer, state_count, background, now)
        return self._rest(started, background)

    def _rest(self, started, background):
        took = time.monotonic() - started
        if background:
            return max(BACKGROUND_INTERVAL - took, 0.05)
        # a viewer polls every 2 s; when polls stop (background tab, closed page) sample slowly
        # until the collector's idle timeout ends it
        interval = INTERVAL if requested(REQUEST_MARKER, ACTIVE_VIEWER_SECONDS) else IDLE_INTERVAL
        # never run back to back: rest at least as long as a slow sample took, and back off
        # exponentially while sampling keeps failing
        rest = max(interval - took, took, 0.05)
        if self.failures:
            rest = max(rest, min(MAX_FAILURE_BACKOFF, 2.0 ** self.failures))
        return rest

    def close(self):
        self._heartbeat_stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join()
        self.native_engine.close()
        self.set_phase("stopped")
        if self.geo is not None:
            self.geo.save(force=True)


def sleep_until_viewer(seconds):
    """Sleep, but wake at once when a viewer opens the map (not at the end of a slow interval)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if requested(REQUEST_MARKER, 2):
            return
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))


def stop_on_signal(number, _frame):
    raise SystemExit(f"signal {signal.Signals(number).name}")


def run():
    lock = acquire_lock()
    if lock is None:
        return
    # the service stop (SIGTERM) ends the loop through its finally, which saves the caches
    signal.signal(signal.SIGTERM, stop_on_signal)
    log_notice("collector started: " + ("a map is open" if requested(REQUEST_MARKER, IDLE_SECONDS)
                                        else "recording threats in the background"))
    collector = Collector()
    collector.start_heartbeat()
    errors = 0
    try:
        while True:
            try:
                rest = collector.step()
                if errors:
                    log_notice(f"collector works again, after {errors} failed iterations")
                errors = 0
            except Exception:
                # any bug in one iteration is logged (once, with its traceback) and retried with
                # backoff; the daemon must not die silently and stop recording threats
                if not errors:
                    log_error("collector iteration failed: " + " | ".join(traceback.format_exc().strip().splitlines()))
                errors += 1
                rest = min(MAX_FAILURE_BACKOFF, 2.0 ** errors)
                collector.rest_status(rest, failed=True)
            if rest is None:
                return
            if collector.background:
                sleep_until_viewer(rest)
            else:
                time.sleep(rest)
    except SystemExit as reason:
        log_notice(f"collector stopped ({reason})")
    finally:
        collector.close()


def main(arguments):
    secure_umask()
    if arguments == ["tables"]:
        print(json.dumps(tables_report()))
    elif arguments == ["ensure"]:
        # periodic (cron) and after boot: keep threat history fed while the widget is in use
        if recording_wanted():
            subprocess.run([RC_SCRIPT, "onestart"], capture_output=True, check=False, timeout=10)
    elif arguments == ["reload"]:
        request_reload()
    else:
        try:
            run()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main(sys.argv[1:])
