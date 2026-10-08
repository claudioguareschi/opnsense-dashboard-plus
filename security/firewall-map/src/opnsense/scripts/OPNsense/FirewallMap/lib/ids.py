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

"""Suricata alerts for Firewall Map+: EVE parsing, per-address history and connection matching."""

import json
import time
from collections import deque
from datetime import datetime
from heapq import nsmallest
from itertools import islice

from .collector import EVENT_MATCH_CURRENT
from .blocklists import IDS_LIST, threat_fields, threat_lists_for
from .blocks import MAX_BLOCK_SOURCES
from .common import (connection_target, host_port, location_fields, normalize_ip, public_ip,
                     service_name, service_port_label, split_host_port)
from .leases import describe_inside
from .pf import forward_target, inside_address, outside_key


# Suricata's alert log (EVE JSON); read locally, only alert events
EVE_LOG = "/var/log/suricata/eve.json"
# alerts are remembered this long per remote address; severity 1-2 flags the address as a threat
ALERT_WINDOW_SECONDS = 3600
ALERT_FLAG_SEVERITY = 2
MAX_ALERT_SOURCES = 2000
MAX_SIGNATURES_PER_SOURCE = 10
ALERT_BACKLOG_BYTES = 2 * 1024 * 1024


def alert_summary(alerts, geo, origin, shown, blocklists=None, reputation=None, now=None):
    """Alerting addresses with no arc on the map right now (the connection ended or never got one)."""
    if alerts is None:
        return []
    addresses = [address for address in reversed(list(alerts.sources)) if address not in shown][:MAX_BLOCK_SOURCES]
    geo.resolve(addresses)
    result = []
    for address in addresses:
        location = geo.get(address)
        if location is None:
            continue
        result.append({
            "source": address,
            "target": origin,
            **location_fields(location),
            **threat_fields(address, blocklists, reputation),
            "ids": alerts.summary(address, now),
        })
    return result


# how long a closed connection or a blocked attempt stays matchable by a late Suricata alert
CORRELATION_SECONDS = 600
MAX_CORRELATION_KEYS = 20000
# an alert can arrive before the next PF sample sees its connection: retry this long
CORRELATION_RETRY_SECONDS = 15
MAX_PENDING_ALERTS = 2000
# one connection keeps at most this many Suricata flows, each with at most this many signatures
MAX_GROUPS_PER_FLOW = 10
MAX_SIGNATURES_PER_GROUP = 10
# the map receives the most recent correlated connections only
MAX_SNAPSHOT_IDS_FLOWS = 200
MAX_IDS_FLOWS = 500


def make_connection(key, **fields):
    """The one shape every connection takes, whether it comes from a PF state, a blocked attempt in
    the firewall log or a Suricata alert alone. Fields a source cannot know stay None.

    decision: "pass" (a firewall state let it through), "block" (the firewall dropped it) or None
    (only Suricata saw it, e.g. dropped by the IPS before the firewall).
    """
    connection = {
        "key": key,
        "protocol": key[0],
        "public": host_port(key[1], key[2]),
        "remote": host_port(key[3], key[4]),
        "inside": None, "remote_started": None, "bytes_in": None, "bytes_out": None, "age": None,
        "rule": None, "rule_description": None, "interface": None, "state": None, "decision": None,
        "source": None, "seen": None,
        # True when the PF sample behind it skipped unsupported states: another state, not
        # modelled, may share the tuple, so the attribution may be incomplete
        "attribution_incomplete": False,
    }
    connection.update(fields)
    return connection


class Correlator:
    """Joins Suricata alerts to the exact connection that raised them.

    PF states and blocked attempts are indexed by their outside tuple (protocol, public address and
    port, remote address and port). An alert matches an open connection, one seen in the last
    CORRELATION_SECONDS, or a blocked attempt; otherwise it stays address-level history. Alerts on
    the same Suricata flow are grouped. `stats` counts every outcome so the matching can be checked.
    """

    def __init__(self):
        self.current = {}
        self.blocked = {}  # key -> blocked attempt, most recent last
        # alerts waiting for their connection to show up; the oldest drop out first
        self.pending = deque(maxlen=MAX_PENDING_ALERTS)
        self.ambiguous_keys = set()
        self.flows = {}    # key -> {"connection", "kind", "alerts": {flow_id: {...}}}
        # addresses with flagging evidence on their connection, built once per change of flows
        self._flagged = None
        self.stats = {"alerts": 0, "current": 0, "recent": 0, "blocked": 0, "unmatched": 0,
                      "ambiguous": 0, "no_ports": 0, "pending": 0}
        self.unmatched_samples = []
        self.forwards = []
        # Blocked attempts are kept in the order they were seen as long as the clock never went
        # back: expiring them then stops at the first entry still fresh
        self._newest = None
        self._in_order = True

    def _seen(self, at):
        if self._newest is not None and at < self._newest:
            self._in_order = False
        self._newest = at if self._newest is None else max(self._newest, at)

    def collector_queries(self, local_addresses, networks=None, limit=2500):
        """Only tuples needed for pending or already-correlated IDS evidence cross the IPC boundary."""
        keys = dict.fromkeys(self.flows)
        for _received, alert in self.pending:
            if alert.get("src_port") and alert.get("dst_port"):
                keys.setdefault(self.alert_key(alert, local_addresses, networks), None)
        return list(keys)[:limit]

    def observe_collector_matches(self, matches, now, descriptions=None):
        """Refresh current IDS evidence from only the tuple matches requested from the state collector."""
        descriptions = descriptions or {}
        current, ambiguous = {}, set()
        for key, value in matches.items():
            if value["kind"] != EVENT_MATCH_CURRENT:
                continue
            inside = host_port(value["inside"], value["inside_port"]) if value["inside"] else None
            connection = make_connection(
                key, inside=inside, remote_started=value["remote_started"], bytes_in=value["bytes_in"],
                bytes_out=value["bytes_out"], age=value["age"], rule=value["rule"],
                rule_description=descriptions.get(value["rule"] or "", ""), interface=value["interface"],
                state=f"{value['id']}/{value['creator']}", decision="pass", source="state", seen=now,
                attribution_incomplete=bool(value.get("sample_degraded")))
            current[key] = connection
            if value["ambiguous"]:
                ambiguous.add(key)
        self.current = current
        self.ambiguous_keys = ambiguous
        self._flagged = None

    def resolve_collector_matches(self, matches, local_addresses, now, networks=None):
        """Resolve pending IDS alerts using bounded collector tuple matches, then Python block policy."""
        still = []
        for received, alert in self.pending:
            key = self.alert_key(alert, local_addresses, networks)
            matched = matches.get(key)
            if matched:
                if matched["kind"] == 1:
                    kind = "ambiguous" if matched["ambiguous"] else "current"
                else:
                    kind = "recent"
                connection = self.current.get(key)
                if connection is None:
                    inside = host_port(matched["inside"], matched["inside_port"]) if matched["inside"] else None
                    connection = make_connection(
                        key, inside=inside, remote_started=matched["remote_started"],
                        bytes_in=matched["bytes_in"], bytes_out=matched["bytes_out"], age=matched["age"],
                        rule=matched["rule"], interface=matched["interface"],
                        state=f"{matched['id']}/{matched['creator']}", decision="pass", source="state", seen=now)
            elif key in self.blocked:
                kind, connection = "blocked", self.blocked[key]
            elif now - received < CORRELATION_RETRY_SECONDS:
                still.append((received, alert))
                continue
            else:
                self.stats["unmatched"] += 1
                self.unmatched_samples = (self.unmatched_samples + [{
                    "time": alert["time"], "key": list(key), "signature": alert["signature"]}])[-20:]
                kind, connection = "alert", self.alert_connection(key, alert, now)
            if kind != "alert":
                self.stats[kind] += 1
            self._attach(key, kind, connection, alert, now)
        self.pending = deque(still, maxlen=MAX_PENDING_ALERTS)
        self.stats["pending"] = len(still)
        self._expire(now)

    def observe_block(self, event, at, descriptions=None):
        key = outside_key(event["protocol"], event["destination"], event.get("port"), event["source"],
                          event.get("source_port"))
        self.blocked.pop(key, None)
        self._seen(at)
        inside, _ = forward_target(self.forwards, event["protocol"], event.get("port"))
        self.blocked[key] = make_connection(
            key, time=at, seen=at, inside=inside, remote_started=True, decision="block", source="firewall log",
            rule=event.get("rule"), rule_description=(descriptions or {}).get(event.get("rule") or "", ""),
            interface=event.get("interface"))

    def _expire(self, now):
        self._flagged = None
        for store in (self.blocked,):
            expired = []
            for key, item in store.items():
                if now - item.get("seen", item.get("time", now)) > CORRELATION_SECONDS:
                    expired.append(key)
                elif self._in_order:
                    break
            for key in expired:
                del store[key]
            # One traversal of the oldest keys: restarting a dict iterator after every
            # deletion repeatedly scans the growing deleted prefix of a large sample.
            excess = max(0, len(store) - MAX_CORRELATION_KEYS)
            for key in list(islice(store, excess)):
                del store[key]
        for key in [key for key, flow in self.flows.items() if now - flow["last"] > ALERT_WINDOW_SECONDS]:
            del self.flows[key]
        while len(self.flows) > MAX_IDS_FLOWS:
            del self.flows[min(self.flows, key=lambda key: self.flows[key]["last"])]

    @staticmethod
    def alert_key(alert, local_addresses, networks=None):
        src, dst = alert["src"], alert["dst"]
        if inside_address(src, networks, local_addresses):
            return outside_key(alert["protocol"], src, alert["src_port"], dst, alert["dst_port"])
        if inside_address(dst, networks, local_addresses):
            return outside_key(alert["protocol"], dst, alert["dst_port"], src, alert["src_port"])
        if src in local_addresses or not public_ip(src):
            return outside_key(alert["protocol"], src, alert["src_port"], dst, alert["dst_port"])
        return outside_key(alert["protocol"], dst, alert["dst_port"], src, alert["src_port"])

    def alert_connection(self, key, alert, now):
        # The alert's src is the source of the packet that raised it, which is the flow's
        # client only for alerts on client-to-server packets. Whether the installed
        # Suricata reports the flow direction (and in which field) must be verified on the
        # target before byte orientation is derived from it; until then this keeps the
        # packet-source approximation (pending target verification).
        remote_started = alert["src"] == key[3]
        flow = alert.get("flow") or {}
        # Suricata counts to_server/to_client; the map counts bytes from/to the remote side
        to_server, to_client = flow.get("bytes_toserver"), flow.get("bytes_toclient")
        inside, description = forward_target(self.forwards, key[0], key[2]) if remote_started else (None, None)
        started = flow.get("start")
        return make_connection(
            key, inside=inside, remote_started=remote_started,
            bytes_in=to_server if remote_started else to_client, bytes_out=to_client if remote_started else to_server,
            age=round(now - started) if started else None,
            rule_description=f"Port forward: {description}" if description else None,
            decision=None, source="suricata", seen=now)

    def add_alert(self, alert, now):
        self.stats["alerts"] += 1
        if not alert["src_port"] or not alert["dst_port"]:
            self.stats["no_ports"] += 1  # ICMP and other port-less protocols: address history only
            return None
        self.pending.append((now, alert))
        return None

    def _attach(self, key, kind, connection, alert, now):
        self._flagged = None
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = {"key": key, "kind": kind, "connection": connection, "alerts": {},
                                      "first": now, "last": now}
        # a firewall state outranks a blocked attempt, which outranks Suricata's record alone
        rank = {"current": 3, "ambiguous": 3, "recent": 2, "blocked": 1, "alert": 0}
        if rank.get(kind, 0) >= rank.get(flow["kind"], 0):
            flow["kind"], flow["connection"] = kind, connection
        flow["last"] = now
        flow_id = str(alert.get("flow_id") or "-")
        if flow_id not in flow["alerts"] and len(flow["alerts"]) >= MAX_GROUPS_PER_FLOW:
            # a connection that keeps raising alerts on new Suricata flows keeps the latest ones
            del flow["alerts"][next(iter(flow["alerts"]))]
        group = flow["alerts"].setdefault(flow_id, {})
        key = alert["sid"] or alert["signature"]
        if key not in group and len(group) >= MAX_SIGNATURES_PER_GROUP:
            return
        signature = group.setdefault(key, {
            "sid": alert["sid"], "signature": alert["signature"], "category": alert["category"],
            "severity": alert["severity"], "action": alert["action"], "count": 0,
            "first": alert["time"] or now, "last": alert["time"] or now,
        })
        signature["count"] += 1
        signature["last"] = max(signature["last"], alert["time"] or now)
        signature["action"] = alert["action"]
        if alert.get("query"):
            signature["query"] = alert["query"]

    def flags(self, address):
        """Evidence on the connection itself: an allowed connection with a severity 1-2 alert."""
        if self._flagged is None:
            # asked once per address of a sample: one walk of the connections, not one per address
            self._flagged = {key[3] for key, flow in self.flows.items()
                             if flow["kind"] != "blocked" and self._severity(flow) <= ALERT_FLAG_SEVERITY}
        return address in self._flagged

    @staticmethod
    def _severity(flow):
        return min((item["severity"] for item in Correlator._alert_items(flow)), default=3)

    @staticmethod
    def _alert_items(flow):
        return [item for group in flow["alerts"].values() for item in group.values()]

    def _flow_entry(self, key, flow, origin, names, networks, interfaces, now):
        """One correlated connection as the map draws it (without location or threat facts)."""
        active = key in self.current
        # when the connection was last seen open, so the map can let its arc fade out
        if active:
            flow.pop("closed", None)
        else:
            flow.setdefault("closed", now)
        connection = self.current.get(key) or flow["connection"]
        inside = split_host_port(connection.get("inside") or "")[0] if flow["kind"] != "blocked" else ""
        groups = [{"flow_id": flow_id,
                   "signatures": sorted(signatures.values(), key=lambda item: (item["severity"], -item["count"]))[:5]}
                  for flow_id, signatures in flow["alerts"].items()]
        items = self._alert_items(flow)
        return {
            "key": "|".join(key),
            "kind": flow["kind"],
            "active": active,
            "origin": origin,
            "dest": key[3],
            "protocol": key[0],
            "public": host_port(key[1], key[2]),
            "remote": host_port(key[3], key[4]),
            "inside": connection.get("inside"),
            "inside_host": describe_inside(inside, names, networks, interfaces) if inside else None,
            "remote_started": connection.get("remote_started"),
            "bytes_in": connection.get("bytes_in"),
            "bytes_out": connection.get("bytes_out"),
            "age": connection.get("age"),
            "rule": connection.get("rule_description") or connection.get("rule"),
            "interface": interfaces.get(connection.get("interface"), connection.get("interface")),
            "severity": self._severity(flow),
            "count": sum(item["count"] for item in items),
            "last_seconds": round(max(0, now - flow["last"])),
            "closed_seconds": None if active else round(max(0, now - flow["closed"])),
            "groups": groups,
            "ips_dropped": any(item["action"] == "blocked" for item in items),
        }

    def summary(self, geo, origin, names, networks, interfaces, blocklists=None, reputation=None, now=None):
        """Correlated connections for the map: each is drawn as its own arc."""
        now = time.time() if now is None else now
        geo.resolve([key[3] for key in self.flows])
        result = []
        for key, flow in sorted(self.flows.items(), key=lambda item: -item[1]["last"])[:MAX_SNAPSHOT_IDS_FLOWS]:
            location = geo.get(key[3])
            if location is None:
                continue
            result.append({
                **self._flow_entry(key, flow, origin, names, networks, interfaces, now),
                **location_fields(location),
                **threat_fields(key[3], blocklists, reputation),
            })
        return result

    def diagnostics(self):
        stats = dict(self.stats)
        matched = stats["current"] + stats["recent"] + stats["blocked"]
        decided = matched + stats["unmatched"] + stats["ambiguous"]
        stats["correlated_share"] = round(matched / decided, 3) if decided else None
        stats["ids_flows"] = len(self.flows)
        stats["index"] = {"current": len(self.current), "blocked": len(self.blocked)}
        stats["unmatched_samples"] = self.unmatched_samples[-5:]
        return stats


def eve_time(value):
    """Epoch seconds of an EVE timestamp, or None."""
    try:
        return datetime.strptime(value or "", "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        return None


class MalformedAlert(ValueError):
    """An EVE alert line that is not the documented object shape."""


def _object(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise MalformedAlert("expected an object")
    return value


def _port(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise MalformedAlert("invalid port")
    return value


def _address(value):
    if not isinstance(value, str):
        raise MalformedAlert("invalid address")
    return normalize_ip(value)


def _string(value, default=""):
    return value if isinstance(value, str) else default


def parse_alert(line):
    """One Suricata EVE alert, or None for any other event (cheap check before JSON parsing).

    Raises MalformedAlert for an alert line that is not valid JSON of the expected shape;
    the caller counts and skips it.
    """
    if '"event_type":"alert"' not in line and '"event_type": "alert"' not in line:
        return None
    try:
        event = json.loads(line)
    except (ValueError, RecursionError) as error:
        raise MalformedAlert("invalid JSON") from error
    event = _object(event)
    alert, flow, dns = _object(event.get("alert")), _object(event.get("flow")), _object(event.get("dns"))
    queries = dns.get("queries")
    first_query = queries[0] if isinstance(queries, list) and queries and isinstance(queries[0], dict) else {}
    severity = alert.get("severity")
    sid = alert.get("signature_id")
    flow_id = event.get("flow_id")
    return {
        "time": eve_time(_string(event.get("timestamp"))),
        "src": _address(event.get("src_ip")),
        "dst": _address(event.get("dest_ip")),
        "src_port": _port(event.get("src_port")),
        "dst_port": _port(event.get("dest_port")),
        "protocol": _string(event.get("proto")).lower(),
        "sid": sid if isinstance(sid, int) and not isinstance(sid, bool) else None,
        "signature": _string(alert.get("signature")),
        "category": _string(alert.get("category")),
        "severity": severity if isinstance(severity, int) and not isinstance(severity, bool) else 3,
        "action": _string(alert.get("action"), "allowed") or "allowed",
        "flow_id": flow_id if isinstance(flow_id, int) and not isinstance(flow_id, bool) else None,
        "flow": {**{key: (value if isinstance(value, int) and not isinstance(value, bool) else None)
                    for key, value in ((key, flow.get(key)) for key in (
                        "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient"))},
                 "start": eve_time(_string(flow.get("start")))},
        "app_proto": _string(event.get("app_proto"), None),
        # what was asked, for DNS alerts (the name behind "ET DNS Query for .cc TLD")
        "query": _string(first_query.get("rrname"), None) or _string(dns.get("rrname"), None),
    }


class AlertTracker:
    """Suricata alerts per remote address over the last ALERT_WINDOW_SECONDS, bounded in memory."""

    def __init__(self, window=ALERT_WINDOW_SECONDS, max_sources=MAX_ALERT_SOURCES):
        self.last_rejection = None
        self.window = window
        self.max_sources = max_sources
        self.sources = {}

    def add(self, alert, local_addresses, now=None, networks=None):
        at = alert["time"] if alert["time"] is not None else (now or time.time())
        src, dst = alert["src"], alert["dst"]
        # the remote side is the public address that is not this firewall; internal-only alerts
        # have no place on the map
        if inside_address(src, networks, local_addresses) and public_ip(dst):
            remote, local, inbound = dst, src, False
        elif inside_address(dst, networks, local_addresses) and public_ip(src):
            remote, local, inbound = src, dst, True
        elif public_ip(src) and src not in local_addresses:
            remote, local, inbound = src, dst, True
        elif public_ip(dst) and dst not in local_addresses:
            remote, local, inbound = dst, src, False
        else:
            return
        entry = self.sources.pop(remote, None)
        if entry is None:
            if len(self.sources) >= self.max_sources:
                del self.sources[next(iter(self.sources))]
            entry = {"first": at, "last": at, "count": 0, "signatures": {}, "targets": {}, "inbound": False,
                     "outbound": False}
        self.sources[remote] = entry  # most recently alerting last, so eviction drops the stalest
        entry["first"] = min(entry["first"], at)
        entry["last"] = max(entry["last"], at)
        entry["count"] += 1
        entry["inbound" if inbound else "outbound"] = True
        signatures = entry["signatures"]
        key = alert["sid"] or alert["signature"]
        if key in signatures or len(signatures) < MAX_SIGNATURES_PER_SOURCE:
            signature = signatures.setdefault(key, {
                "sid": alert["sid"], "signature": alert["signature"], "category": alert["category"],
                "severity": alert["severity"], "count": 0, "last": at, "action": alert["action"],
            })
            signature["count"] += 1
            signature["last"] = max(signature["last"], at)
            signature["action"] = alert["action"]
        port = alert["dst_port"] if inbound else alert["src_port"]
        target = f'{host_port(local, port)}/{alert["protocol"]}' if port else f'{local}/{alert["protocol"]}'
        if target in entry["targets"] or len(entry["targets"]) < MAX_SIGNATURES_PER_SOURCE:
            entry["targets"][target] = entry["targets"].get(target, 0) + 1

    def expire(self, now):
        for address in [address for address, entry in self.sources.items() if now - entry["last"] > self.window]:
            del self.sources[address]

    def flags(self, address):
        entry = self.sources.get(address)
        if not entry or not entry["signatures"]:
            return False
        return min(item["severity"] for item in entry["signatures"].values()) <= ALERT_FLAG_SEVERITY

    def feed(self, lines, local_addresses, correlator=None, now=None, networks=None):
        """Feed EVE lines; returns how many alert lines were rejected (malformed or failing).

        Each line is contained on its own: one bad line never stops the others.
        """
        rejected = 0
        for line in lines:
            try:
                alert = parse_alert(line)
                if alert:
                    self.add(alert, local_addresses, networks=networks)
                    if correlator is not None:
                        correlator.add_alert(alert, now if now is not None else time.time())
            except Exception as error:  # noqa: BLE001 - per-line containment, counted by the caller
                rejected += 1
                self.last_rejection = f"{type(error).__name__}: {error}"
        return rejected

    def summary(self, address, now=None):
        """What the map shows for an address: count, worst severity and the top signatures."""
        entry = self.sources.get(address)
        if not entry:
            return None
        now = time.time() if now is None else now
        signatures = sorted(entry["signatures"].values(), key=lambda item: (item["severity"], -item["count"]))
        return {
            "count": entry["count"],
            "severity": signatures[0]["severity"] if signatures else 3,
            "signatures": [{key: item[key] for key in ("sid", "signature", "category", "severity", "count", "action")}
                           for item in signatures[:3]],
            "targets": [target for target, _ in sorted(entry["targets"].items(), key=lambda item: -item[1])][:3],
            "inbound": entry["inbound"],
            "outbound": entry["outbound"],
            "first_seconds": round(max(0, now - entry["first"])),
            "last_seconds": round(max(0, now - entry["last"])),
            "minutes": self.window // 60,
        }


MAX_SNAPSHOT_CONNECTIONS = 6


def connection_keys(correlator):
    """{remote address: [connection keys]} over current states, IDS flows and blocked attempts, in
    that order of preference. Built once per recording: walking every state for each flagged
    address cost about 0.5 s at 100,000 states."""
    index = {}
    seen = set()
    for store in (correlator.current, correlator.flows, correlator.blocked):
        for key in store:
            if key not in seen:
                seen.add(key)
                index.setdefault(key[3], []).append(key)
    return index


def connection_summary(address, correlator, names, interfaces, wall=None, index=None):
    """The connections to one flagged address as PF sees them right now (plus any Suricata linked).

    Each carries both sides (inside host, public side, remote), the rule and interface that let it
    through, bytes and age, and the Suricata signatures correlated to that exact connection.
    `index` is connection_keys(correlator), when several addresses are looked up in a row.
    """
    wall = time.time() if wall is None else wall
    keys = (index if index is not None else connection_keys(correlator)).get(address, [])

    def entries():
        for key in keys:
            connection = correlator.current.get(key) or (correlator.flows.get(key) or {}).get("connection") \
                or correlator.blocked[key]
            flow = correlator.flows.get(key)
            inside_ip = split_host_port(connection.get("inside") or "")[0] if connection.get("inside") else ""
            signatures = []
            if flow:
                for group in flow["alerts"].values():
                    for item in group.values():
                        signatures.append({field: item.get(field) for field in ("sid", "signature", "severity", "count", "action", "query")})
            age = connection.get("age")
            yield {
                "key": "|".join(key),
                "open": key in correlator.current,
                "protocol": key[0],
                "inside": connection.get("inside"),
                "inside_name": names.get(inside_ip) if inside_ip else None,
                "public": connection.get("public"),
                "remote": connection.get("remote"),
                "remote_started": connection.get("remote_started"),
                "rule": connection.get("rule_description") or connection.get("rule"),
                "interface": interfaces.get(connection.get("interface"), connection.get("interface")),
                "bytes_in": connection.get("bytes_in"),
                "bytes_out": connection.get("bytes_out"),
                "started": round(wall - age) if age is not None else None,
                "seen": round(wall),
                "kind": flow["kind"] if flow else ("current" if key in correlator.current else "blocked"),
                # the firewall's decision and Suricata's are separate facts
                "decision": connection.get("decision"),
                "ips_dropped": any(item.get("action") == "blocked" for item in signatures),
                "source": connection.get("source"),
                "ids": sorted(signatures, key=lambda item: (item["severity"], -item["count"]))[:3],
            }
    # the busiest first, IDS-linked ones always kept
    # nsmallest preserves the input order of ties, just like the previous stable sort,
    # while retaining only the selected rows instead of every matching connection.
    return nsmallest(MAX_SNAPSHOT_CONNECTIONS, entries(),
                     key=lambda item: (not item["ids"], -((item["bytes_in"] or 0) + (item["bytes_out"] or 0))))


def firewall_blocks(correlator, seen, since, blocklists=None, reputation=None):
    """Flagged sources PF blocked since the last history recording."""
    entries = {}
    for key, connection in correlator.blocked.items():
        remote = key[3]
        if remote in seen or (connection.get("seen") or 0) < since:
            continue
        lists = threat_lists_for(remote, blocklists, reputation)
        if not lists:
            continue
        inside = connection.get("inside")
        inside_ip, inside_port = split_host_port(inside) if inside else (None, "")
        port = inside_port or key[2]
        service = service_name(key[0], port)
        entry = entries.setdefault(remote, {
            "lists": lists, "inbound": 0, "outbound": 0, "targets": [], "inside": [],
            "services": [], "bytes": 0, "youngest": None, "service_ports": {},
            "disposition": "firewall_blocked",
        })
        entry["inbound"] += 1
        target = connection_target(key[0], inside_ip or key[1], port)
        if target not in entry["targets"]:
            entry["targets"].append(target)
        if inside_ip and inside_ip not in entry["inside"]:
            entry["inside"].append(inside_ip)
        if service not in entry["services"]:
            entry["services"].append(service)
            label = service_port_label(key[0], port)
            if label:
                entry["service_ports"][service] = label
    return entries


def ips_drops(correlator, seen, since, blocklists=None, reputation=None):
    """Addresses whose traffic Suricata dropped (IPS) since the last recording, as queue entries.

    They carry the same fields as allowed traffic, so the queue shows them the same way, under
    their own status.
    """
    entries = {}
    for key, flow in correlator.flows.items():
        remote = key[3]
        if remote in seen or flow["last"] < since:
            continue
        if not any(item.get("action") == "blocked" for item in Correlator._alert_items(flow)):
            continue
        connection = flow["connection"]
        inside = connection.get("inside")
        inside_ip, inside_port = split_host_port(inside) if inside else (None, "")
        started_by_remote = bool(connection.get("remote_started"))
        port = (inside_port or key[2]) if started_by_remote else key[4]
        entry = entries.setdefault(remote, {
            "lists": threat_lists_for(remote, blocklists, reputation) + [IDS_LIST],
            "inbound": 0, "outbound": 0, "targets": [], "inside": [], "services": [], "bytes": 0,
            "youngest": None, "service_ports": {}, "disposition": "ips_dropped",
        })
        entry["inbound" if started_by_remote else "outbound"] += 1
        if started_by_remote:
            target = connection_target(key[0], inside_ip or key[1], port)
            if target not in entry["targets"]:
                entry["targets"].append(target)
        elif inside_ip and inside_ip not in entry["inside"]:
            entry["inside"].append(inside_ip)
        service = service_name(key[0], port)
        if service not in entry["services"]:
            entry["services"].append(service)
            label = service_port_label(key[0], port)
            if label:
                entry["service_ports"][service] = label
        entry["bytes"] += (connection.get("bytes_in") or 0) + (connection.get("bytes_out") or 0)
    return entries
