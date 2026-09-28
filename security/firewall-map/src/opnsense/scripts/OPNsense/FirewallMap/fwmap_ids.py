#!/usr/local/bin/python3

"""Suricata alerts for Firewall Map+: EVE parsing, per-address history and connection matching."""

import json
import time
from collections import deque
from datetime import datetime

from fwmap_blocklists import IDS_LIST, threat_fields, threat_lists_for
from fwmap_blocks import MAX_BLOCK_SOURCES
from fwmap_common import connection_target, host_port, split_host_port, location_fields, public_ipv4, service_name, service_port_label
from fwmap_leases import describe_inside
from fwmap_pf import flow_endpoints, forward_target, inside_endpoint, lan_rule_index, orientation, outside_key, rule_for, state_outside


# Suricata's alert log (EVE JSON); read locally, only alert events
EVE_LOG = "/var/log/suricata/eve.json"
# alerts are remembered this long per remote address; severity 1-2 flags the address as a threat
ALERT_WINDOW_SECONDS = 3600
ALERT_FLAG_SEVERITY = 2
MAX_ALERT_SOURCES = 2000
MAX_SIGNATURES_PER_SOURCE = 10
ALERT_BACKLOG_BYTES = 2 * 1024 * 1024


def alert_snapshot(alerts, geo, origin, shown, blocklists=None, reputation=None, now=None):
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
        self.recent = {}   # key -> connection, most recently seen last
        self.blocked = {}  # key -> blocked attempt, most recent last
        # alerts waiting for their connection to show up; the oldest drop out first
        self.pending = deque(maxlen=MAX_PENDING_ALERTS)
        self.ambiguous_keys = set()
        self.flows = {}    # key -> {"connection", "kind", "alerts": {flow_id: {...}}}
        self.stats = {"alerts": 0, "current": 0, "recent": 0, "blocked": 0, "unmatched": 0,
                      "ambiguous": 0, "no_ports": 0, "pending": 0}
        self.unmatched_samples = []
        self.forwards = []

    def observe_states(self, records, local_addresses, now, descriptions=None):
        current = {}
        ambiguous = set()
        lan_rules = lan_rule_index(records)
        for record in records:
            pair = flow_endpoints(record, local_addresses)
            if pair is None:
                continue
            key = state_outside(record, pair)
            if key is None:
                continue
            inside = inside_endpoint(record)
            rule = rule_for(record, pair, lan_rules)
            connection = make_connection(
                key,
                inside=host_port(inside["address"], inside["port"]) if inside else None,
                remote_started=orientation(record, pair[1])[0],
                bytes_in=record.get("bytes_in", 0),
                bytes_out=record.get("bytes_out", 0),
                age=record.get("age"),
                rule=rule,
                rule_description=(descriptions or {}).get(rule or "", ""),
                interface=record.get("origif"),
                state=record.get("state"),
                decision="pass",
                source="state",
                seen=now,
            )
            previous = current.get(key)
            if previous and previous["inside"] != connection["inside"]:
                ambiguous.add(key)
            current[key] = connection
        self.current = current
        self.ambiguous_keys = ambiguous
        for key, connection in current.items():
            self.recent.pop(key, None)
            self.recent[key] = connection
        self._expire(now)

    def observe_block(self, event, at, descriptions=None):
        key = outside_key(event["protocol"], event["destination"], event.get("port"), event["source"],
                          event.get("source_port"))
        self.blocked.pop(key, None)
        inside, _ = forward_target(self.forwards, event["protocol"], event.get("port"))
        self.blocked[key] = make_connection(
            key, time=at, seen=at, inside=inside, remote_started=True, decision="block", source="firewall log",
            rule=event.get("rule"), rule_description=(descriptions or {}).get(event.get("rule") or "", ""),
            interface=event.get("interface"))

    def _expire(self, now):
        for store in (self.recent, self.blocked):
            for key in [key for key, item in store.items() if now - item.get("seen", item.get("time", now)) > CORRELATION_SECONDS]:
                del store[key]
            while len(store) > MAX_CORRELATION_KEYS:
                del store[next(iter(store))]
        for key in [key for key, flow in self.flows.items() if now - flow["last"] > ALERT_WINDOW_SECONDS]:
            del self.flows[key]
        while len(self.flows) > MAX_IDS_FLOWS:
            del self.flows[min(self.flows, key=lambda key: self.flows[key]["last"])]

    @staticmethod
    def alert_key(alert, local_addresses):
        src, dst = alert["src"], alert["dst"]
        if src in local_addresses or not public_ipv4(src):
            return outside_key(alert["protocol"], src, alert["src_port"], dst, alert["dst_port"])
        return outside_key(alert["protocol"], dst, alert["dst_port"], src, alert["src_port"])

    def alert_connection(self, key, alert, now):
        remote_started = alert["src"] == key[3]
        flow = alert.get("flow") or {}
        # Suricata counts to_server/to_client; the map counts toward/away from the remote side
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

    def resolve(self, local_addresses, now):
        """Try pending alerts against what PF and the firewall log have shown; give up after a while."""
        still = []
        for received, alert in self.pending:
            key = self.alert_key(alert, local_addresses)
            if key in self.current:
                kind = "ambiguous" if key in self.ambiguous_keys else "current"
                connection = self.current[key]
            elif key in self.recent:
                kind, connection = "recent", self.recent[key]
            elif key in self.blocked:
                kind, connection = "blocked", self.blocked[key]
            elif now - received < CORRELATION_RETRY_SECONDS:
                still.append((received, alert))
                continue
            else:
                # no firewall state or log entry: Suricata's own record is the connection (an IPS drop
                # never reaches the firewall); a port forward still names the inside target
                self.stats["unmatched"] += 1
                self.unmatched_samples = (self.unmatched_samples + [{
                    "time": alert["time"], "key": list(key), "signature": alert["signature"]}])[-20:]
                kind, connection = "alert", self.alert_connection(key, alert, now)
            if kind != "alert":
                self.stats[kind] += 1
            self._attach(key, kind, connection, alert, now)
        self.pending = deque(still, maxlen=MAX_PENDING_ALERTS)
        self.stats["pending"] = len(still)

    def _attach(self, key, kind, connection, alert, now):
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = {"key": key, "kind": kind, "connection": connection, "alerts": {},
                                      "first": now, "last": now}
        # a firewall state outranks a blocked attempt, which outranks Suricata's record alone
        rank = {"current": 3, "ambiguous": 3, "recent": 2, "blocked": 1, "alert": 0}
        if rank.get(kind, 0) >= rank.get(flow["kind"], 0):
            flow["kind"], flow["connection"] = kind, connection
        flow["last"] = now
        group = flow["alerts"].setdefault(str(alert.get("flow_id") or "-"), {})
        signature = group.setdefault(alert["sid"] or alert["signature"], {
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
        for key, flow in self.flows.items():
            if key[3] == address and flow["kind"] != "blocked" and self._severity(flow) <= ALERT_FLAG_SEVERITY:
                return True
        return False

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
        groups = [{"flow_id": flow_id, "signatures": sorted(
                      signatures.values(), key=lambda item: (item["severity"], -item["count"]))[:5]}
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

    def snapshot(self, geo, origin, names, networks, interfaces, blocklists=None, reputation=None, now=None):
        """Correlated connections for the map: each is drawn as its own arc."""
        now = time.time() if now is None else now
        geo.resolve([key[3] for key in self.flows])
        result = []
        for key, flow in sorted(self.flows.items(), key=lambda item: -item[1]["last"]):
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
        stats["index"] = {"current": len(self.current), "recent": len(self.recent), "blocked": len(self.blocked)}
        stats["unmatched_samples"] = self.unmatched_samples[-5:]
        return stats


def eve_time(value):
    """Epoch seconds of an EVE timestamp, or None."""
    try:
        return datetime.strptime(value or "", "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        return None


def parse_alert(line):
    """One Suricata EVE alert, or None for any other event (cheap check before JSON parsing)."""
    if '"event_type":"alert"' not in line and '"event_type": "alert"' not in line:
        return None
    try:
        event = json.loads(line)
    except ValueError:
        return None
    alert = event.get("alert") or {}
    at = eve_time(event.get("timestamp"))
    return {
        "time": at,
        "src": event.get("src_ip"),
        "dst": event.get("dest_ip"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dest_port"),
        "protocol": str(event.get("proto") or "").lower(),
        "sid": alert.get("signature_id"),
        "signature": alert.get("signature") or "",
        "category": alert.get("category") or "",
        "severity": alert.get("severity") or 3,
        "action": alert.get("action") or "allowed",
        "flow_id": event.get("flow_id"),
        "flow": {**{key: (event.get("flow") or {}).get(key) for key in (
            "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient")},
            "start": eve_time((event.get("flow") or {}).get("start"))},
        "app_proto": event.get("app_proto"),
        # what was asked, for DNS alerts (the name behind "ET DNS Query for .cc TLD")
        "query": ((event.get("dns") or {}).get("queries") or [{}])[0].get("rrname") or (event.get("dns") or {}).get("rrname"),
    }


class AlertTracker:
    """Suricata alerts per remote address over the last ALERT_WINDOW_SECONDS, bounded in memory."""

    def __init__(self, window=ALERT_WINDOW_SECONDS, max_sources=MAX_ALERT_SOURCES):
        self.window = window
        self.max_sources = max_sources
        self.sources = {}

    def add(self, alert, local_addresses, now=None):
        at = alert["time"] if alert["time"] is not None else (now or time.time())
        src, dst = alert["src"], alert["dst"]
        # the remote side is the public address that is not this firewall; internal-only alerts
        # have no place on the map
        if public_ipv4(src) and src not in local_addresses:
            remote, local, inbound = src, dst, True
        elif public_ipv4(dst) and dst not in local_addresses:
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
        target = f'{local}:{port}/{alert["protocol"]}' if port else f'{local}/{alert["protocol"]}'
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

    def feed(self, lines, local_addresses, correlator=None, now=None):
        for line in lines:
            alert = parse_alert(line)
            if alert:
                self.add(alert, local_addresses)
                if correlator is not None:
                    correlator.add_alert(alert, now if now is not None else time.time())

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


def connection_snapshot(address, correlator, names, interfaces, wall=None):
    """The connections to one flagged address as PF sees them right now (plus any Suricata linked).

    Each carries both sides (inside host, public side, remote), the rule and interface that let it
    through, bytes and age, and the Suricata signatures correlated to that exact connection.
    """
    wall = time.time() if wall is None else wall
    keys = [key for key in correlator.current if key[3] == address]
    keys += [key for key in correlator.flows if key[3] == address and key not in correlator.current]
    result = []
    for key in keys:
        connection = correlator.current.get(key) or correlator.flows[key]["connection"]
        flow = correlator.flows.get(key)
        inside_ip = split_host_port(connection.get("inside") or "")[0] if connection.get("inside") else ""
        signatures = []
        if flow:
            for group in flow["alerts"].values():
                for item in group.values():
                    signatures.append({field: item.get(field) for field in ("sid", "signature", "severity", "count", "action", "query")})
        age = connection.get("age")
        result.append({
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
            "kind": flow["kind"] if flow else "current",
            # the firewall's decision and Suricata's are separate facts
            "decision": connection.get("decision"),
            "ips_dropped": any(item.get("action") == "blocked" for item in signatures),
            "source": connection.get("source"),
            "ids": sorted(signatures, key=lambda item: (item["severity"], -item["count"]))[:3],
        })
    # the busiest first, IDS-linked ones always kept
    result.sort(key=lambda item: (not item["ids"], -((item["bytes_in"] or 0) + (item["bytes_out"] or 0))))
    return result[:MAX_SNAPSHOT_CONNECTIONS]


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
            "youngest": None, "service_ports": {}, "status_hint": "dropped",
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
