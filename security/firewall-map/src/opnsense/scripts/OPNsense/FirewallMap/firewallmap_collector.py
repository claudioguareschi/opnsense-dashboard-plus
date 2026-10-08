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

"""Persistent PF collector orchestrator for Firewall Map+.

The required state collector (firewallmap-collector) samples PF, keeps counter
history, aggregates and ranks flows, and returns only bounded mechanical results.
Python applies policy and enrichment, then writes a compact, capped summary for
the dashboard API; the browser never triggers a PF walk or a GeoIP lookup.

A flow is active only while its counters advance. Idle flows fade out over
FADE_SECONDS and a flow is dropped as soon as its last PF state disappears.
All geolocation lookups are local: the installed MaxMind or DB-IP database, read in process (lib/mmdb.py).

This module is the orchestrator; caches, threat lists, names, blocks and
Suricata policy live in the lib/ modules next to it.

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
    REPUTATION_LIST, Reputation, ThreatClassification, chosen_threat_lists, tables_report, threat_fields,
    threat_lists_for,
)
from lib import profiles as ranking_profiles
from lib.blocks import BlockTracker, FilterLogTail, block_event_time, block_summary, parse_block
from lib.cache import GEO_LOOKUPS_PER_SAMPLE, CacheStore, GeoCache
from lib.common import (
    COLLECTOR_TIMINGS, HOSTNAME_MARKER, OUTPUT_FILE, RC_SCRIPT, REQUEST_MARKER, RUN_DIR, SNAPSHOT_DIR,
    SNAPSHOT_REQUEST_DIR, connection_target, log_error, log_notice, log_warning, private_ip, public_ip,
    protocol_name, requested, secure_umask, service_name, service_port_label, write_json,
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
    _Record, host_info, port_forwards, rule_descriptions,
)
from lib import collector as state_collector
from lib.collector import CollectorEngine, CollectorError, PROTOCOL_VERSION, READ_TIMEOUT, memory_budget


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
# while the collector is incompatible the service re-evaluates this rarely; each re-evaluation
# only checks whether the collector binary (or, for a PF ABI mismatch, the kernel) changed
INCOMPATIBLE_RETRY_SECONDS = 300.0
COLLECTOR_LOCK = f"{RUN_DIR}/collector.lock"
# the last sample's timings are written at most this often
TIMINGS_WRITE_SECONDS = 10.0
RELOAD_MARKER = f"{RUN_DIR}/reload"
# rule descriptions, interface names, DHCP names and port forwards
METADATA_REFRESH_SECONDS = 60
# threat intelligence: pf tables behind URL/external aliases and well-known feed tables
BLOCKLIST_REFRESH_SECONDS = 60
SETTINGS_REFRESH_SECONDS = 30
# one PF walk every 2 s: the dashboard polls every 2 s, so faster sampling only costs CPU
INTERVAL = 2.0
FADE_SECONDS = 20.0
MAX_FLOWS = 150
HOST_REFRESH_SECONDS = 30.0
MAX_SERVICES = 4
MAX_INSIDE = 3
# PF states kept with a saved snapshot, per remote address and in all
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
        # Remaining presentation fields are filled by update_aggregate().


class _FlowTotals(_Record):
    """One sample's aggregate, with the same ordered weighted counts as before."""
    __slots__ = ("states", "protocols", "services", "inside", "egress",
                 "remote_started", "local_started", "targets", "ports", "oldest", "bytes_from_remote",
                 "bytes_to_remote", "rules")

    def __init__(self):
        self.states = 0
        self.protocols = set()
        self.services = {}
        self.inside = {}
        self.egress = {}
        self.remote_started = self.local_started = 0
        self.targets = {}
        self.ports = {}
        self.oldest = self.bytes_from_remote = self.bytes_to_remote = 0
        self.rules = {}


def _collector_address(value):
    if len(value) != 17 or value[0] not in (4, 6):
        raise CollectorError("invalid collector address in aggregate")
    return str(ipaddress.ip_address(value[1:5] if value[0] == 4 else value[1:]))


class FlowTracker:
    """Adapt collector-selected aggregates to the existing bounded flow presentation."""

    def __init__(self, fade_seconds=FADE_SECONDS):
        self.fade_seconds = fade_seconds
        self.flows = {}
        self.total_flows = 0
        # the collector's quality axes for the last sample (CONTRACTS.md) and whether the flow
        # total is an estimate (bounded discovery)
        self.total_estimated = False
        self.quality = None
        # per enabled profile, its selection as (local, remote) pairs in rank order
        self.selections = []
        self.collector_visible = []

    def update_aggregate(self, aggregate, now):
        """Ingest only the collector's top-K aggregates; rates and ordering are already final."""
        totals = {}
        rows_by_pair = {}
        protocols = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp"}
        self.total_flows = aggregate["counts"]["flows"]
        self.total_estimated = aggregate["counts"].get("flows_estimated", False)
        self.quality = aggregate.get("quality")
        self.selections = [[aggregate["flows"][index]["key"] for index, _score in rows]
                           for rows in aggregate.get("selections") or ()]
        for row in aggregate["flows"]:
            total = _FlowTotals()
            total.states = row["states"]
            total.bytes_from_remote, total.bytes_to_remote = row["bytes_from_remote"], row["bytes_to_remote"]
            total.remote_started, total.local_started = row["remote_initiated_weight"], row["local_initiated_weight"]
            total.oldest = row["oldest"]
            totals[row["key"]] = total
            rows_by_pair[row["key"]] = row
        for flow_id, kind, _sequence, weight, association, value in sorted(
                aggregate["candidates"], key=lambda candidate: candidate[2]):
            row = aggregate["flows"][flow_id]
            total = totals[row["key"]]
            if kind == state_collector.PROTOCOL:
                number = value[0]
                proto = protocols.get(number)
                if proto is None:
                    try:
                        proto = protocol_name(number)
                    except (OSError, ValueError):
                        proto = str(number)
                    protocols[number] = proto
                total.protocols.add(proto)
            elif kind == state_collector.INSIDE_HOST:
                address = _collector_address(value)
                total.inside[address] = total.inside.get(address, 0) + weight
            elif kind == state_collector.EGRESS_INTERFACE:
                device = value.decode("ascii", "replace")
                total.egress[device] = total.egress.get(device, 0) + weight
            elif kind == state_collector.SERVICE:
                number, port = (association >> 16) & 255, association & 65535
                proto = protocols.get(number, str(number))
                name = service_name(proto, str(port) if port else None)
                total.services[name] = total.services.get(name, 0) + weight
                total.ports.setdefault(name, service_port_label(proto, str(port) if port else None))
            elif kind == state_collector.REMOTE_TARGET:
                proto = protocols.get(value[0], str(value[0]))
                address = _collector_address(value[1:18])
                port = int.from_bytes(value[18:20], "big")
                target = connection_target(proto, address, str(port) if port else None)
                total.targets[target] = total.targets.get(target, 0) + weight
            elif kind == state_collector.RULE_LABEL:
                # PF truncates labels at 63 bytes, possibly inside a UTF-8 sequence
                rule = value.decode("utf-8", "replace")
                total.rules[rule] = total.rules.get(rule, 0) + weight
        previous_flows = self.flows
        current_flows = {}
        visible = []
        for pair, total in totals.items():
            row = rows_by_pair[pair]
            flow = previous_flows[pair] if pair in previous_flows else _Flow(now)
            # rate_in/rate_out are the external names of rate from/to the remote
            flow.rate_in, flow.rate_out = row["rate_from_remote"], row["rate_to_remote"]
            flow.packet_rate = row["packet_rate"]
            flow.rate = flow.rate_in + flow.rate_out
            flow.states = total.states
            flow.protocols = sorted(total.protocols)
            flow.services = _ranked(total.services, MAX_SERVICES)
            flow.service_ports = {name: total.ports[name] for name in flow.services if total.ports.get(name)}
            flow.age = total.oldest
            flow.transferred = (total.bytes_from_remote, total.bytes_to_remote)
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
        # The collector's order is already the stable FlowTracker ranking. No Python re-sort.
        self.collector_visible = visible


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
        visible = tracker.collector_visible
        geo.resolve(address for _, local, remote, _, _ in visible for address in (remote, local) if public_ip(address))
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
        "tracked_flows_estimated": getattr(tracker, "total_estimated", False),
        "quality": getattr(tracker, "quality", None),
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
        # when the last recording was persisted (monotonic), and the wall-clock cut-off up to
        # which firewall blocks and IPS drops were recorded: both advance only after the
        # recording is committed, so a failed one is retried with the same evidence window
        self.recorded = None
        self.retry_at = None
        self.pruned = None
        self.last_wall = 0.0

    def due(self, now):
        if self.retry_at is not None and now < self.retry_at:
            return False
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

    def update(self, sample, collector, now, cutoff=None):
        """Record the collector's mechanical summaries using Python threat policy.

        cutoff: the wall-clock time evidence up to which this recording covers (default: now). The
        service passes the sample's start: that sample classified every evidence remote known then,
        and later evidence is classified by the next sample, before the next recording reads it."""
        if not self.due(now) or not sample.get("threat_summary"):
            return
        blocklists, reputation, correlator = collector.blocklists, collector.reputation, collector.correlator
        # the cut-off of this recording: evidence after it belongs to the next one
        wall = time.time() if cutoff is None else cutoff
        try:
            if self.db is None:
                self.db = threats.connect(self.path)

            def lists_for(address):
                return threat_lists_for(address, blocklists, reputation, correlator)

            seen = threats.observe_aggregates(sample, lists_for)
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
            threats.record(self.db, seen)
            # hourly by age; at once when a burst of flagged addresses overfills history
            over = self.db.execute("SELECT count(*) FROM threats").fetchone()[0] > threats.KEEP_ROWS + threats.KEEP_TOUCHED
            if over or self.pruned is None or now - self.pruned >= THREAT_PRUNE_SECONDS:
                threats.prune(self.db)
                self.pruned = now
        except sqlite3.Error as error:
            if not self.failing:
                log_error(f"threat recording failed: {error}")
                self.failing = True
            # reconnect on the next attempt, without leaving the failed connection open
            try:
                self.db.close()
            except (AttributeError, sqlite3.Error):
                pass
            self.db = None
            self.retry_at = now + THREAT_RECORD_SECONDS
            return
        # committed: only now does the evidence window move on
        self.recorded, self.last_wall, self.retry_at = now, wall, None
        if self.failing:
            log_notice("threat recording works again")
            self.failing = False


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
    """Where one sample's time went: wall seconds per collector phase ("state_collector" is the
    whole state collector request, PF traversal included), and the whole sample's wall and CPU
    time (the service's own plus that of the programs it ran, such as ifconfig; the persistent
    state collector reports its own CPU in its telemetry). The Status page shows it, so anyone
    can check the cost on their own hardware."""

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


def incompatibility(error):
    """What makes the state collector unusable on this installation, or None for any other
    failure: another protocol (the package's components come from different versions; protocol
    None when the collector named none), or a PF state ABI it was not built for (it speaks this
    protocol but cannot read this kernel's states)."""
    if getattr(error, "failure_class", None) != "incompatible":
        return None
    reason = getattr(error, "reason", "pf_abi")
    incompatible = {"reason": reason, "protocol": error.protocol if reason == "protocol" else PROTOCOL_VERSION,
                    "expected_protocol": PROTOCOL_VERSION, "error": str(error)}
    if reason == "pf_abi":
        incompatible.update(collector_pf_state_version=getattr(error, "collector_pf_state_version", None),
                            running_pf_state_version=getattr(error, "running_pf_state_version", None))
    return incompatible


def incompatibility_message(incompatible):
    if incompatible["reason"] == "protocol":
        protocol = "unknown" if incompatible["protocol"] is None else incompatible["protocol"]
        return ("Firewall Map collector incompatible: the Firewall Map application and its state collector "
                f"use incompatible protocols (collector protocol {protocol}, expected "
                f"{incompatible['expected_protocol']}). Reinstall or upgrade the Firewall Map package so "
                "both components come from the same version.")
    return f"the state collector is incompatible with this firewall: {incompatible['error']}"


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
        # threat lists: PF tables the state collector classifies with (lookups answer from the last sample)
        self.blocklists = ThreatClassification()
        self.reputation = Reputation(self.store)
        self.recorder = ThreatRecorder()
        # Flow Ranking Profiles: the collector selects for each; a viewer's Focus picks one
        self.profiles = ranking_profiles.enabled()
        self.collector_engine = CollectorEngine()
        # set while the state collector is incompatible (another protocol, or a PF ABI it was not
        # built for): explicit status and slow pacing; the engine does not run the same binary again
        # (for a PF ABI mismatch: on the same running kernel)
        self.collector_incompatible = None
        # unsupported states the last accepted sample skipped, by reason
        self.sample_skipped = {}
        # per-source counts of log lines rejected by per-line containment, and the last reason
        self.ingest_rejected = {"filterlog": 0, "eve": 0}
        self.ingest_last_rejection = None
        # the last sample's timings (SampleTimer.report) and when they were last written
        self.timings = None
        self.timings_written = None
        # Sample fields describe the last successfully published revision, never an attempt.
        # Phase fields describe this process now; payloads freeze their own copy at publication.
        self.collector_status = {
            "generation": uuid.uuid4().hex, "revision": 0, "state_count": None,
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
            tables, unavailable = chosen_threat_lists(self.values.get("threat_lists"))
            self.blocklists.configure(tables, now, unavailable)
            self.checked["blocklists"] = now
        self.reputation.refresh(now)

    def ingest(self, sample, now, wall, foreground):
        """Feed collector matches, blocked attempts and Suricata alerts to Python policy.

        Log lines are contained one by one: a malformed or failing line is counted and skipped,
        never allowed to abort the iteration (its offset has already been consumed).
        """
        lines = self.log.lines()
        if foreground and not self.backlog_loaded:
            # the 10-minute hit window starts full
            self.backlog_loaded = True
            lines = self.log.backlog() + lines
        for line in lines:
            try:
                self._ingest_block(line, now, wall, foreground)
            except Exception as error:  # noqa: BLE001 - per-line containment, counted below
                self.ingest_rejected["filterlog"] += 1
                self.ingest_last_rejection = f"filterlog: {type(error).__name__}: {error}"
        self.correlator.observe_collector_matches(sample["matches"], wall, self.descriptions)
        rejected = 0
        if foreground and not self.eve_loaded:
            self.eve_loaded = True
            # older alerts can only be address history: their connections are not indexed yet
            rejected += self.alerts.feed(self.eve.backlog(ALERT_BACKLOG_BYTES), self.local_addresses,
                                         networks=self.networks)
        rejected += self.alerts.feed(self.eve.lines(), self.local_addresses, self.correlator, wall, self.networks)
        if rejected:
            self.ingest_rejected["eve"] += rejected
            self.ingest_last_rejection = f"eve: {self.alerts.last_rejection}"
        self.correlator.resolve_collector_matches(sample["matches"], self.local_addresses, wall, self.networks)
        self.alerts.expire(wall)

    def _ingest_block(self, line, now, wall, foreground):
        event = parse_block(line)
        # only connection attempts aimed at this firewall's own public addresses; blocked
        # forwarded traffic (e.g. another host's outbound packets) is not an inbound probe
        if not event or event["destination"] not in self.local_addresses:
            return
        if foreground:
            at = block_event_time(line, now, wall)
            if at is None:
                return
            self.blocks.add(event, at)
        # blocked attempts stay matchable for late alerts even with no map open
        self.correlator.observe_block(event, wall, self.descriptions)

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
        if visible is None and not snapshot:
            visible = self.tracker.collector_visible
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
        if not snapshot:
            self.add_focus(payload)
        payload["provider"] = self.provider
        payload["collector"] = self.timing_status()
        if self.sample_skipped:
            # states the engine recognized but does not model (counted by reason): the map is
            # complete for everything else
            payload["incomplete"] = {"skipped_states": dict(self.sample_skipped)}
        return payload

    def add_focus(self, payload):
        """Each enabled profile's selection as positions in the payload's flows (their union):
        the API returns only the Focus a viewer asked for (FlowSummary.php)."""
        position = {(flow["origin"], flow["dest"]): index for index, flow in enumerate(payload["flows"])}
        selections = self.tracker.selections or [[(flow["origin"], flow["dest"]) for flow in payload["flows"]]]
        payload["profiles"] = ranking_profiles.descriptor(self.profiles)
        payload["focus"] = {profile["key"]: [position[pair] for pair in pairs if pair in position]
                            for profile, pairs in zip(self.profiles, selections)}
        default = self.values.get("focus") or ranking_profiles.DEFAULT_FOCUS
        payload["focus_default"] = default if default in payload["focus"] else self.profiles[0]["key"]

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

    def build_snapshot_payload(self, now):
        """Bounded incident-first detail. Scan candidates, but never build an uncapped document."""
        evidence = set(self.alerts.sources) | {key[3] for key in self.correlator.flows}
        # Truncation never fails a snapshot: what was left out is counted here, and required
        # (incident) evidence that did not fit makes required_evidence_complete false.
        coverage = {"candidates": 0, "available": 0, "captured": 0, "limit": SNAPSHOT_FLOWS,
                    "selection": "incident_then_traffic_v1", "omitted_limit": 0, "omitted_bytes": 0, "omitted_geo": 0,
                    "required": 0, "omitted_required": 0}

        evidence.update(self.blocks.sources)

        def ranked_candidates():
            lookup_budget = GEO_LOOKUPS_PER_SAMPLE
            for page in self.collector_engine.snapshot_pages():
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
                    coverage["required"] += int(incident)
                    yield incident, rank, order, local, remote

        identities = nsmallest(SNAPSHOT_FLOWS, ranked_candidates(),
                               key=lambda item: (not item[0], -item[1], item[2]))
        aggregate = self.collector_engine.snapshot_selection(
            [(local, remote, incident) for incident, _rank, _order, local, remote in identities])
        tracker = FlowTracker()
        tracker.update_aggregate(aggregate, now)
        selected = [(identity[0], *row) for identity, row in zip(identities, tracker.collector_visible)]
        coverage["omitted_limit"] = coverage["available"] - len(selected)
        visible = [item[1:] for item in selected]
        payload = self.build_payload(now, visible=visible, snapshot=True)
        flows, locations, names = payload["flows"], payload["locations"], payload["hostnames"]
        payload["flows"] = []
        payload["locations"] = [location for location in locations if location["local"]]
        payload["hostnames"] = {}
        payload["states"], payload["full"] = {}, True
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
                coverage["omitted_bytes"] += 1
                if (flow["origin"], flow["dest"]) in required_pairs:
                    coverage["omitted_required"] += 1
                continue
            payload["flows"].append(flow)
            payload["locations"].extend(places)
            kept_locations.update(place["id"] for place in places)
            payload["hostnames"].update(hostnames)
        payload["locations"].sort(key=lambda location: location["id"])
        coverage["captured"] = len(payload["flows"])
        # required flows beyond the flow ceiling were never selected
        coverage["omitted_required"] += coverage["required"] - len(required_pairs)
        identities = [(flow["origin"], flow["dest"], (flow["origin"], flow["dest"]) in required_pairs)
                      for flow in payload["flows"]]
        payload["states"], states = self.collector_engine.snapshot_detail(
            identities, max(0, budget.remaining), SNAPSHOT_STATES_TOTAL)
        payload["capture"]["states"] = states
        payload["capture"]["source"] = "state_collector"
        payload["capture"]["required_evidence_complete"] = (
            not coverage["omitted_required"] and states.get("required_evidence_complete", True))
        if coverage["captured"] < coverage["candidates"] or states["truncated"]:
            payload["capture"]["detail_status"] = "truncated"
        if json_size(payload, SNAPSHOT_BYTES) > SNAPSHOT_BYTES:
            raise SnapshotTooLarge("snapshot exceeds byte limit")
        return payload

    def save_requested_snapshots(self, now):
        """Answer every camera request waiting in SNAPSHOT_REQUEST_DIR, from the open session.

        Every request found here gets a document, the snapshot or an error, and its request file
        is removed, whatever happens. A failure the protocol survives (raised between commands)
        ends the session with CANCEL and keeps the helper; CollectorEngine closes the helper itself
        when a request failed mid-stream.
        """
        try:
            names = sorted(os.listdir(SNAPSHOT_REQUEST_DIR))
        except OSError:
            return
        requests = [name[:-len(".request")] for name in names if name.endswith(".request")]
        if not requests:
            return
        payload = {"status": "snapshot_failed", "error": "collector iteration failed"}
        try:
            payload = self.build_snapshot_payload(now)
        except SnapshotTooLarge as error:
            payload = {"status": "snapshot_too_large", "error": str(error)}
        except CollectorError as error:
            payload = {"status": "snapshot_failed", "error": str(error)}
        finally:
            self.collector_engine.snapshot_cancel()
            self._answer_snapshot_requests(requests, payload)

    @staticmethod
    def _answer_snapshot_requests(requests, payload):
        for snapshot_id in requests:
            try:
                if snapshot_valid_id(snapshot_id):
                    write_json(f"{SNAPSHOT_DIR}/{snapshot_id}.json", payload, durable=True)
            except OSError as error:
                log_warning(f"snapshot {snapshot_id} could not be saved: {error}")
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
        phase = "retrying" if failed or self.failures or self.problem else (
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
        """One iteration: prepare, acquire, apply, publish, then post-commit work.

        Commit point: publication. In the foreground that is the atomic write of flows.json (or of
        a refusal status); in the background, and for a baseline sample (which must not replace a
        still-fresh map), it is the diagnostics record. Before it, a failure leaves the previous
        publication untouched; after it (snapshots, cache saves, timings) nothing is unpublished.

        The state collector keeps its own timing and history, so a Python failure after a complete
        collector response does not invalidate it. The collector is closed only when a request to
        it failed or was interrupted (CollectorEngine), never for downstream Python errors.
        """
        started = time.monotonic()
        timer = SampleTimer()
        proceed, rest = self._prepare(started, timer)
        if not proceed:
            return rest
        background = self.background
        sample = self._acquire(started, background, timer)
        if sample is None:
            return self._rest(started, background)
        snapshot_due = self.collector_engine.snapshot_open and not sample["baseline"]
        try:
            self.set_phase("processing")
            now = time.monotonic()
            wall = time.time()
            self._apply(sample, now, wall, background, timer)
            self._publish(sample, now, background, timer)
            if snapshot_due:
                self.save_requested_snapshots(now)
        finally:
            # never leave a session open into the next request, and never leave a request
            # unanswered after its session failed
            self.collector_engine.snapshot_cancel()
            if snapshot_due:
                self._answer_snapshot_requests(self._pending_snapshot_requests(),
                                               {"status": "snapshot_failed",
                                                "error": "collector iteration failed"})
        self._post_commit(sample, now, background, timer)
        return self._rest(started, background)

    @staticmethod
    def _pending_snapshot_requests():
        try:
            names = os.listdir(SNAPSHOT_REQUEST_DIR)
        except OSError:
            return []
        return [name[:-len(".request")] for name in sorted(names) if name.endswith(".request")]

    def _prepare(self, started, timer):
        """Settings, metadata and mode. Returns (proceed, rest when not proceeding)."""
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
            return False, None
        if not background and self.problem:
            self.set_phase("failed")
            write_json(OUTPUT_FILE, status_document("no_database", reason=self.problem,
                                                    error=geodb.read_status().get("last_error"),
                                                    collector=self.timing_status()))
            # re-check within a few seconds, the database may be downloading; only move the
            # next check earlier, never later, or repeated passes would postpone it forever
            self.checked["settings"] = min(self.checked["settings"], started - SETTINGS_REFRESH_SECONDS + 5)
            return False, self._rest(started, background)
        self.refresh_metadata(started)
        timer.phase("metadata")
        return True, None

    def _acquire(self, started, background, timer):
        """The complete state collector response, or None when the request failed."""
        self._sample_started = (time.time(), time.monotonic())
        self._sample_revision = None
        timeout = getattr(self.collector_engine, "read_timeout", READ_TIMEOUT)
        self.set_phase("collecting", self._sample_started[0] + timeout)
        collector_start = time.perf_counter()
        threat_due = self.recorder.due(started)
        queries = self.correlator.collector_queries(self.local_addresses, self.networks)
        # evidence remotes are classified on every sample: alerts, blocks and history name them
        evidence = self.evidence_remotes()
        try:
            sample = self.collector_engine.sample(
                self.local_addresses, self.networks, self.interface_addresses, self.primary_wan_device,
                threat_summary=threat_due, event_queries=queries,
                snapshot=not background and self.snapshot_requested(),
                memory=memory_budget(self.values.get("helper_memory")),
                evidence=evidence if threat_due else (),
                correlation=bool(queries) or os.path.exists(EVE_LOG),
                classification=self.blocklists.request(), classify=evidence,
                profiles=ranking_profiles.request_rows(self.profiles))
        except CollectorError as error:
            self.collector_engine.close()
            self.set_phase("failed")
            if not self.failures:
                log_error(f"reading the firewall states failed: {error}")
            self.failures += 1
            incompatible = incompatibility(error)
            if incompatible and self.collector_incompatible is None:
                log_error(incompatibility_message(incompatible))
            self.collector_incompatible = incompatible
            self._record_collector(error=error)
            if incompatible and not background:
                write_json(OUTPUT_FILE, status_document("collector_incompatible", **incompatible,
                                                        collector=self.timing_status()))
            # Preserve the last successful document and its mtime. Existing API
            # freshness expires it naturally; liveness diagnostics report failure.
            return None
        timer.phases["state_collector"] = time.perf_counter() - collector_start
        timer.mark = time.perf_counter()
        if self.failures:
            log_notice(f"reading the firewall states works again, after {self.failures} failed attempts")
        self.failures = 0
        self.collector_incompatible = None
        if not sample["refused"]:
            skipped = sample.get("skipped") or {}
            if skipped and not self.sample_skipped:
                log_notice("some PF states are not mapped: " + ", ".join(
                    f"{count} {reason.replace('_', ' ')}" for reason, count in skipped.items()))
            self.sample_skipped = skipped
        self.blocklists.observe(sample)
        self._record_collector(sample=sample)
        return sample

    def evidence_remotes(self):
        """Remotes the threat summary keeps first: IDS, reputation and blocked-attempt evidence."""
        evidence = set(self.alerts.sources) | {key[3] for key in self.correlator.flows}
        evidence.update(key[3] for key in self.correlator.blocked)
        evidence.update(self.blocks.sources)
        evidence.update(self.reputation.flagged)
        return evidence

    def _record_collector(self, sample=None, error=None):
        """The state collector's own view of the last request, for diagnostics; logs state changes once."""
        with self._status_lock:
            current = dict(self.collector_status.get("state_collector") or {})
            if sample is not None:
                telemetry = sample["telemetry"] or {}
                refused = sample["refused"]
                omitted = telemetry.get("threat_remotes_omitted") or 0
                if refused and refused != current.get("refused"):
                    log_warning("sample refused: {reason} ({kind}{actual} over the limit of {limit})".format(
                        reason=refused["reason"], kind=f"{refused['kind']} rows: " if refused["kind"] else "",
                        actual=refused["actual"], limit=refused["limit"]))
                elif current.get("refused") and not refused:
                    log_notice("samples are accepted again")
                if omitted and not current.get("threat_remotes_omitted"):
                    log_warning(f"threat recording incomplete: {omitted} remotes over the summary budget")
                current.update(helper=sample.get("helper"), telemetry=telemetry or None,
                               baseline=sample["baseline"], refused=refused, states=sample["counts"]["states"],
                               threat_remotes_omitted=omitted, last_sample_at=time.time(),
                               state_limit=telemetry.get("state_limit", current.get("state_limit")))
            if error is not None:
                current.update(last_error=str(error), last_error_class=getattr(error, "failure_class", None),
                               last_error_at=time.time())
            current["incompatible"] = self.collector_incompatible
            current["classification"] = self.blocklists.report()
            current["ingest_rejected"] = dict(self.ingest_rejected)
            current["ingest_last_rejection"] = self.ingest_last_rejection
            self.collector_status["state_collector"] = current

    def _apply(self, sample, now, wall, background, timer):
        """Python policy over an accepted sample: presentation state, evidence, threat history."""
        if sample["refused"]:
            return
        if not background and not sample["baseline"]:
            self.tracker.update_aggregate(sample, now)
            timer.phase("tracker")
        self.ingest(sample, now, wall, foreground=not background)
        timer.phase("ingest")
        self.recorder.update(sample, self, now, cutoff=self._sample_started[0] if self._sample_started else None)
        timer.phase("threats")
        self._record_collector()

    def _publish(self, sample, now, background, timer):
        """The commit point (see _step)."""
        states = sample["counts"]["states"]
        refused = sample["refused"]
        if refused and not background:
            self.complete_sample(states, self.refusal_document(sample))
        elif background or refused or sample["baseline"]:
            # a baseline has no rates yet: the previous map stays until it expires or is replaced
            self.complete_sample(states)
        else:
            self.publish_summary(now, timer, states)

    @staticmethod
    def refusal_document(sample):
        """What the map shows for a refused sample. Too many states and an exhausted memory
        budget are the same condition for the viewer: the table is larger than this firewall's
        budget maps (the map's too_many_states message, with the derived limit)."""
        refused = sample["refused"]
        if refused["reason"] in ("refused_states", "refused_memory"):
            limit = (sample["telemetry"] or {}).get("state_limit") or refused["limit"]
            count = refused["actual"] if refused["reason"] == "refused_states" else sample["counts"]["states"]
            return status_document("too_many_states", count=count, limit=limit, reason=refused["reason"],
                                   collector=None)
        return status_document("refused", **refused, collector=None)

    def _post_commit(self, sample, now, background, timer):
        self.geo.save()
        timer.phase("other")
        timer.phases["collector_states"] = sample["counts"]["states"]
        timer.phases["collector_flows"] = sample["counts"]["flows"]
        self.save_timings(timer, sample["counts"]["states"], background, now)

    def _rest(self, started, background):
        took = time.monotonic() - started
        if background:
            rest = max(BACKGROUND_INTERVAL - took, 0.05)
            return max(rest, INCOMPATIBLE_RETRY_SECONDS) if self.collector_incompatible is not None else rest
        interval = INTERVAL if requested(REQUEST_MARKER, ACTIVE_VIEWER_SECONDS) else IDLE_INTERVAL
        with self._status_lock:
            # samples slower than the interval: the map updates at the rest floor below instead
            self.collector_status["slow_sampling"] = took > interval
        rest = max(interval - took, took, 0.05)
        if self.failures:
            rest = max(rest, min(MAX_FAILURE_BACKOFF, 2.0 ** self.failures))
        if self.collector_incompatible is not None:
            rest = max(rest, INCOMPATIBLE_RETRY_SECONDS)
        return rest

    def close(self):
        self._heartbeat_stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join()
        self.collector_engine.close()
        self.set_phase("stopped")
        if self.geo is not None:
            self.geo.save(force=True)


def sleep_until_viewer(seconds):
    """Sleep, but wake at once when a viewer opens the map."""
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
