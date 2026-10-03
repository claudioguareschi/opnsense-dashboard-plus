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

Samples the PF state table every second, keeps per-state byte/packet counters
between samples and aggregates counter deltas into public (firewall, remote)
flows. Only a compact, capped, geo-enriched summary is written to disk for the
dashboard API to read; the browser never triggers a PF walk or a GeoIP lookup.

A flow is active only while its counters advance. Idle flows fade out over
FADE_SECONDS and a flow is dropped as soon as its last PF state disappears.
All GeoLite lookups are local (mmdblookup against the installed database).

This module is the orchestrator; parsing, caches, threat lists, names, blocks and
Suricata correlation live in the fwmap_* modules next to it.

    firewallmap_collector.py           run the collector (started by rc.d/firewallmap)
    firewallmap_collector.py tables    JSON threat list candidates for the settings dialog
    firewallmap_collector.py ensure    start the collector when background recording is wanted
    firewallmap_collector.py reload    ask a running collector to re-read its settings
"""

import base64
import binascii
import json
import os
import sqlite3
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import firewallmap_geodb as geodb  # noqa: E402
import firewallmap_threats as threats  # noqa: E402
from fwmap_blocklists import (  # noqa: E402
    REPUTATION_LIST, BlocklistIndex, Reputation, chosen_threat_lists, tables_report, threat_fields,
    threat_lists_for,
)
from fwmap_blocks import BlockTracker, FilterLogTail, block_event_time, block_snapshot, parse_block  # noqa: E402
from fwmap_cache import CacheStore, GeoCache  # noqa: E402
from fwmap_common import (  # noqa: E402
    CONFIG_XML, HOSTNAME_MARKER, OUTPUT_FILE, RC_SCRIPT, REQUEST_MARKER, RUN_DIR, remote_target, requested,
    secure_umask, service_name, service_port_label, write_json, write_text,
)
from fwmap_ids import (  # noqa: E402
    ALERT_BACKLOG_BYTES, EVE_LOG, AlertTracker, Correlator, alert_snapshot, connection_snapshot, firewall_blocks,
    ips_drops,
)
from fwmap_leases import HostnameResolver, describe_inside, describe_target, lease_names  # noqa: E402
from fwmap_pf import (  # noqa: E402
    TooManyStates, flow_endpoints, host_info, inside_endpoint, interface_names, lan_rule_index, orientation,
    port_forwards, rule_descriptions, rule_for, sample_states,
)


HOSTNAME_REQUEST_SECONDS = 30
IDLE_SECONDS = 300
ACTIVE_VIEWER_SECONDS = 10
IDLE_INTERVAL = 5.0
# with nobody watching, threat history is still fed from a slow sample (states outlive this)
BACKGROUND_INTERVAL = 20.0
THREAT_RECORD_SECONDS = 20.0
THREAT_PRUNE_SECONDS = 3600.0
MAX_FAILURE_BACKOFF = 30.0
# while the state table is too large to walk, check its size this often
TOO_MANY_STATES_INTERVAL = 30.0
COLLECTOR_LOCK = f"{RUN_DIR}/collector.lock"
# files earlier versions wrote that nothing reads any more
LEGACY_FILES = (f"{RUN_DIR}/ids_stats.json", "/var/db/firewallmap/geo.json")
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


def _ranked(counts, limit=None):
    """Keys of {key: weight}, heaviest first."""
    ranked = [key for key, _ in sorted(counts.items(), key=lambda item: -item[1])]
    return ranked[:limit] if limit is not None else ranked


def _bump(counts, key, weight):
    counts[key] = counts.get(key, 0) + weight


class FlowTracker:
    """Turn successive PF state samples into per-flow byte rates with activity fading."""

    def __init__(self, fade_seconds=FADE_SECONDS, smoothing=RATE_SMOOTHING):
        self.fade_seconds = fade_seconds
        self.smoothing = smoothing
        self.counters = {}
        self.flows = {}
        self.sampled_at = None

    def _delta(self, record, current, elapsed):
        """Bytes and packets this state moved since the previous sample."""
        previous = self.counters.get(record["id"])
        if previous is not None:
            return tuple(max(0, now_value - before) for now_value, before in zip(current, previous))
        if elapsed is not None and record.get("age") is not None and record["age"] <= 2 * elapsed:
            # a state created since the previous sample: everything it counted is new
            return current
        return (0, 0, 0)

    @staticmethod
    def _add(total, record, pair, current, delta, rule, networks=None, local_addresses=None):
        """Fold one state into its flow's totals for this sample."""
        # PF counts initiator->responder first; src is the initiator in parse_states()
        remote_initiated, service_port = orientation(record, pair[1], networks, local_addresses)
        weight = delta[0] + delta[1] + 1
        inside_side = inside_endpoint(record, networks, local_addresses)
        if remote_initiated:
            total["remote_started"] += weight
            # what the remote side connected to: a port-forward target or the firewall itself
            _bump(total["targets"], remote_target(record, pair[1], pair[0], inside_side, service_port), weight)
        else:
            total["local_started"] += weight
        if inside_side:
            _bump(total["inside"], inside_side["address"], weight)
        if record.get("origif"):
            _bump(total["egress"], record["origif"], weight)
        service = service_name(record["protocol"], service_port)
        _bump(total["services"], service, weight)
        total["ports"].setdefault(service, service_port_label(record["protocol"], service_port))
        if record.get("age") is not None and record["age"] > total["oldest"]:
            total["oldest"] = record["age"]
        # bytes moved so far by the connections open now, and the rules that let them through
        total["bytes_toward"] += current[0]
        total["bytes_away"] += current[1]
        if rule:
            _bump(total["rules"], rule, 1)
        total["toward"] += delta[0]
        total["away"] += delta[1]
        total["packets"] += delta[2]
        total["states"] += 1
        total["protocols"].add(record["protocol"])

    def _totals(self, records, local_addresses, elapsed, networks=None):
        """{(local, remote): totals} for this sample, and the counters to diff the next one against."""
        counters = {}
        totals = {}
        lan_rules = lan_rule_index(records)
        for record in records:
            pair = flow_endpoints(record, local_addresses, networks)
            if pair is None or record.get("id") is None:
                continue
            src_is_remote = record["src"]["address"] == pair[1]
            toward, away = (
                (record["bytes_in"], record["bytes_out"]) if src_is_remote
                else (record["bytes_out"], record["bytes_in"])
            )
            current = (toward, away, record["packets_in"] + record["packets_out"])
            counters[record["id"]] = current
            total = totals.setdefault(pair, {
                "toward": 0, "away": 0, "packets": 0, "states": 0, "protocols": set(), "services": {},
                "inside": {}, "egress": {}, "remote_started": 0, "local_started": 0, "targets": {},
                "ports": {}, "oldest": 0, "bytes_toward": 0, "bytes_away": 0, "rules": {},
            })
            self._add(total, record, pair, current, self._delta(record, current, elapsed),
                      rule_for(record, pair, lan_rules, networks, local_addresses), networks, local_addresses)
        return totals, counters

    def _update_flow(self, flow, total, elapsed, now):
        for key, value in (("rate_in", total["toward"]), ("rate_out", total["away"]), ("packet_rate", total["packets"])):
            current_rate = value / elapsed if elapsed else 0.0
            flow[key] = self.smoothing * current_rate + (1 - self.smoothing) * flow[key]
        flow["rate"] = flow["rate_in"] + flow["rate_out"]
        flow["states"] = total["states"]
        flow["protocols"] = sorted(total["protocols"])
        flow["services"] = _ranked(total["services"], MAX_SERVICES)
        flow["service_ports"] = {name: total["ports"][name] for name in flow["services"] if total["ports"].get(name)}
        # how long the oldest connection behind this flow has been open
        flow["age"] = total["oldest"]
        flow["transferred"] = (total["bytes_toward"], total["bytes_away"])
        flow["rule"] = (_ranked(total["rules"], 1) or [None])[0]
        flow["inside"] = _ranked(total["inside"], MAX_INSIDE)
        flow["egress"] = (_ranked(total["egress"], 1) or [None])[0]
        started = total["remote_started"] + total["local_started"]
        share = total["remote_started"] / started if started else 0.0
        flow["initiated"] = "remote" if share >= 0.75 else "local" if share <= 0.25 else "both"
        flow["targets"] = _ranked(total["targets"], MAX_INSIDE)
        if total["toward"] + total["away"] > 0:
            flow["last_active"] = now

    def update(self, records, local_addresses, now, networks=None):
        elapsed = (now - self.sampled_at) if self.sampled_at is not None else None
        totals, self.counters = self._totals(records, local_addresses, elapsed, networks)
        self.sampled_at = now
        # a flow disappears together with its last PF state
        for pair in list(self.flows):
            if pair not in totals:
                del self.flows[pair]
        for pair, total in totals.items():
            flow = self.flows.setdefault(pair, {
                "rate": 0.0, "rate_in": 0.0, "rate_out": 0.0, "packet_rate": 0.0,
                "last_active": None, "first_seen": now,
            })
            self._update_flow(flow, total, elapsed, now)

    def activity(self, flow, now):
        if flow["last_active"] is None:
            return 0.0
        return max(0.0, 1.0 - (now - flow["last_active"]) / self.fade_seconds)

    def visible(self, now, limit=MAX_FLOWS):
        """Active or fading flows, strongest first, capped before they reach the browser."""
        ranked = []
        for (local, remote), flow in self.flows.items():
            activity = self.activity(flow, now)
            if activity > 0:
                ranked.append((max(flow["rate"], 1.0) * activity, local, remote, flow, activity))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return ranked[:limit]


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


def snapshot(tracker, geo, local_addresses, role, now, wall_time, hostnames=None, context=None):
    context = context or {}
    visible = tracker.visible(now)
    geo.resolve([address for _, local, remote, _, _ in visible for address in (local, remote)])
    flows = []
    location_ids = set()
    for _, local, remote, flow, activity in visible:
        if geo.get(local) is None or geo.get(remote) is None:
            continue
        location_ids.update((local, remote))
        flows.append(_flow_entry(local, remote, flow, activity, local_addresses, context, wall_time))
    resolved = {}
    if hostnames is not None:
        remotes = [flow["dest"] for flow in flows]
        hostnames.update(remotes, now)
        resolved = {address: hostnames.get(address) for address in remotes if hostnames.get(address)}
    return {
        "status": "ok",
        "sampled_at": datetime.fromtimestamp(wall_time, timezone.utc).isoformat(),
        "interval": INTERVAL,
        "carp": role,
        "tracked_flows": len(tracker.flows),
        "flows": flows,
        "locations": [_location_entry(address, geo.get(address), local_addresses) for address in sorted(location_ids)],
        "hostnames": resolved,
    }


def widget_in_use(path=CONFIG_XML):
    """True when any user's dashboard contains the Firewall Map widget."""
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError):
        return False
    for node in root.iterfind("./system/user/dashboard"):
        try:
            dashboard = json.loads(base64.b64decode(node.text or "").decode("utf-8", "replace"))
        except (ValueError, binascii.Error):
            continue
        if not isinstance(dashboard, dict):
            continue
        if any(isinstance(widget, dict) and widget.get("id") == "firewallmap" for widget in dashboard.get("widgets") or []):
            return True
    return False


def recording_wanted(values=None, path=CONFIG_XML):
    """Record threats for review while the widget is in use, unless switched off."""
    values = values if values is not None else geodb.settings(path)
    return values.get("record_threats", "1") != "0" and widget_in_use(path)


class ThreatRecorder:
    """Feeds threat history; a database problem never stops the collector.

    Reads what it needs from the running Collector (threat lists, reputation, geolocation,
    host names, Suricata history and names), so a new source of facts needs no new parameter.
    """

    def __init__(self, path=threats.DATABASE):
        self.path = path
        self.db = None
        self.recorded = None
        self.pruned = None
        self.last_wall = 0.0

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

    def update(self, records, collector, now):
        if self.recorded is not None and now - self.recorded < THREAT_RECORD_SECONDS:
            return
        self.recorded = now
        blocklists, reputation, correlator = collector.blocklists, collector.reputation, collector.correlator
        try:
            if self.db is None:
                self.db = threats.connect(self.path)
            seen = threats.observe(records, lambda address: threat_lists_for(address, blocklists, reputation, correlator),
                                   collector.local_addresses, collector.networks)
            seen.update(ips_drops(correlator, seen, self.last_wall, blocklists, reputation))
            seen.update(firewall_blocks(correlator, seen, self.last_wall, blocklists, reputation))
            if collector.geo is not None and seen:
                collector.geo.resolve(list(seen))
            for address, entry in seen.items():
                entry["remote"] = self._identity(address, collector)
                entry["ids"] = collector.alerts.summary(address)
                entry["connections"] = connection_snapshot(address, correlator, collector.leases, collector.interfaces)
            self.last_wall = time.time()
            threats.record(self.db, seen)
            # hourly by age; at once when a burst of flagged addresses overfills history
            over = self.db.execute("SELECT count(*) FROM threats").fetchone()[0] > threats.KEEP_ROWS
            if over or self.pruned is None or now - self.pruned >= THREAT_PRUNE_SECONDS:
                threats.prune(self.db)
                self.pruned = now
        except sqlite3.Error as error:
            print(f"firewallmap: threat recording failed: {error}", file=sys.stderr)
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
    provider = geodb.effective_provider(values)
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
        self.descriptions, self.interfaces, self.leases = {}, {}, {}
        self.local_addresses, self.role, self.networks = set(), None, []
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
            self.checked["settings"] = self.checked["blocklists"] = None
        if self._due("host", now, HOST_REFRESH_SECONDS):
            self.local_addresses, self.role, self.networks = host_info()
            self.checked["host"] = now
        if self._due("settings", now, SETTINGS_REFRESH_SECONDS):
            self.values = geodb.settings()
            self.recording = recording_wanted(self.values)
            self.provider = geodb.effective_provider(self.values)
            city, asn, self.problem = database_state(self.values)
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
            self.correlator.forwards = port_forwards()
            self.checked["metadata"] = now
        if (self._due("blocklists", now, BLOCKLIST_REFRESH_SECONDS)
                and self.blocklists.refresh(chosen_threat_lists(self.values.get("threat_lists")))):
            self.checked["blocklists"] = now
        self.reputation.refresh(now)

    def ingest(self, records, now, wall, foreground):
        """Feed one sample to the trackers: states, blocked attempts from the log, Suricata alerts."""
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
        self.correlator.observe_states(records, self.local_addresses, wall, self.descriptions, self.networks)
        if foreground and not self.eve_loaded:
            self.eve_loaded = True
            # older alerts can only be address history: their connections are not indexed yet
            self.alerts.feed(self.eve.backlog(ALERT_BACKLOG_BYTES), self.local_addresses, networks=self.networks)
        self.alerts.feed(self.eve.lines(), self.local_addresses, self.correlator, wall, self.networks)
        self.correlator.resolve(self.local_addresses, wall, self.networks)
        self.alerts.expire(wall)

    def publish_snapshot(self, now):
        resolver = self.hostnames if requested(HOSTNAME_MARKER, HOSTNAME_REQUEST_SECONDS) else None
        geo = self.geo
        context = {
            "names": self.leases, "networks": self.networks, "interfaces": self.interfaces,
            "blocklists": self.blocklists, "reputation": self.reputation, "alerts": self.alerts,
            "descriptions": self.descriptions,
        }
        payload = snapshot(self.tracker, geo, self.local_addresses, self.role, now, time.time(), resolver, context)
        origin = next((location["id"] for location in payload["locations"] if location["local"]), None)
        if origin is None and self.local_addresses:
            origin = sorted(self.local_addresses)[0]
            geo.resolve([origin])
        payload["blocks"] = block_snapshot(
            self.blocks, geo, self.local_addresses, origin, now, self.descriptions, self.interfaces,
            self.blocklists, self.reputation, self.alerts,
        )
        shown = {flow["dest"] for flow in payload["flows"]} | {block["source"] for block in payload["blocks"]}
        payload["alerts"] = alert_snapshot(self.alerts, geo, origin, shown, self.blocklists, self.reputation)
        payload["ids_flows"] = self.correlator.snapshot(geo, origin, self.leases, self.networks, self.interfaces,
                                                        self.blocklists, self.reputation)
        # which lists are consulted, so the details can show "not listed" per list
        payload["threat_lists"] = list(self.blocklists.index[0]) + ([REPUTATION_LIST] if self.reputation.scores else [])
        if origin and geo.get(origin) and not any(location["id"] == origin for location in payload["locations"]):
            location = geo.get(origin)
            payload["locations"].append({
                "id": origin, "name": origin, "lat": location["lat"], "lon": location["lon"], "local": True,
            })
        payload["provider"] = self.provider
        write_json(OUTPUT_FILE, payload)

    def step(self):
        """One iteration. Returns the seconds to rest before the next, or None to stop."""
        started = time.monotonic()
        self.refresh_settings(started)
        background = self.background = idle(self.started_at)
        if background and not self.recording:
            return None
        if not background and self.problem:
            write_json(OUTPUT_FILE, status_document("no_database", reason=self.problem,
                                                    error=geodb.read_status().get("last_error")))
            # re-check within a few seconds, the database may be downloading; only move the
            # next check earlier, never later, or repeated passes would postpone it forever
            self.checked["settings"] = min(self.checked["settings"], started - SETTINGS_REFRESH_SECONDS + 5)
            return self._rest(started, background)
        try:
            records = sample_states()
        except TooManyStates as error:
            if not background:
                write_json(OUTPUT_FILE, status_document("too_many_states", count=error.count, limit=error.limit))
            if not self.too_many_states:
                print(f"firewallmap: sampling paused: {error}", file=sys.stderr)
            self.too_many_states = True
            return TOO_MANY_STATES_INTERVAL
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
            self.failures += 1
            print(f"firewallmap: sample failed: {error}", file=sys.stderr)
            if not background:
                write_json(OUTPUT_FILE, status_document("failed", error=str(error)))
            return self._rest(started, background)
        self.failures = 0
        self.too_many_states = False
        now = time.monotonic()
        wall = time.time()
        self.refresh_metadata(now)
        if not background:
            self.tracker.update(records, self.local_addresses, now, self.networks)
        self.ingest(records, now, wall, foreground=not background)
        # while the map is open the queue is always fed; the setting and the widget only decide
        # whether recording continues in the background
        self.recorder.update(records, self, now)
        if not background:
            self.publish_snapshot(now)
        # locations resolved for the queue in the background are saved too (at most once a minute)
        self.geo.save()
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
        if self.geo is not None:
            self.geo.save(force=True)


def sleep_until_viewer(seconds):
    """Sleep, but wake at once when a viewer opens the map (not at the end of a slow interval)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if requested(REQUEST_MARKER, 2):
            return
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))


def run():
    lock = acquire_lock()
    if lock is None:
        return
    for path in LEGACY_FILES:
        try:
            os.remove(path)
        except OSError:
            pass
    collector = Collector()
    errors = 0
    try:
        while True:
            try:
                rest = collector.step()
                errors = 0
            except Exception:
                # any bug in one iteration is logged and retried with backoff; the daemon must
                # not die silently and stop recording threats until someone opens a map
                errors += 1
                print(f"firewallmap: collector iteration failed:\n{traceback.format_exc()}", file=sys.stderr)
                rest = min(MAX_FAILURE_BACKOFF, 2.0 ** errors)
            if rest is None:
                return
            if collector.background:
                sleep_until_viewer(rest)
            else:
                time.sleep(rest)
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
