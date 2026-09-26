#!/usr/local/bin/python3

"""Persistent PF state sampler for Firewall Map+.

Samples the PF state table every second, keeps per-state byte/packet counters
between samples and aggregates counter deltas into public (firewall, remote)
flows. Only a compact, capped, geo-enriched summary is written to disk for the
dashboard API to read; the browser never triggers a PF walk or a GeoIP lookup.

A flow is active only while its counters advance. Idle flows fade out over
FADE_SECONDS and a flow is dropped as soon as its last PF state disappears.
All GeoLite lookups are local (mmdblookup against the installed database).
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ElementTree
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import firewallmap_geodb as geodb  # noqa: E402


PFCTL = "/sbin/pfctl"
IFCONFIG = "/sbin/ifconfig"
MMDBLOOKUP = "/usr/local/bin/mmdblookup"
# database paths follow the provider chosen in the firewall-wide settings (see firewallmap_geodb)
CITY_DATABASE = geodb.DATABASES["maxmind"]["city"]
ASN_DATABASE = geodb.DATABASES["maxmind"]["asn"]
OUTPUT_FILE = "/var/run/firewallmap/flows.json"
# touched by the dashboard API on every read; the collector stops once nobody is watching
REQUEST_MARKER = "/var/run/firewallmap/last_request"
# touched only when a viewer has hostname lookups enabled; reverse DNS runs while it is fresh
HOSTNAME_MARKER = "/var/run/firewallmap/hostnames_request"
HOSTNAME_REQUEST_SECONDS = 30
HOSTNAME_TTL = 6 * 3600
HOSTNAME_LOOKUPS_PER_SAMPLE = 8
IDLE_SECONDS = 300
FILTER_LOG = "/var/log/filter/latest.log"
RULES_DEBUG = "/tmp/rules.debug"
CONFIG_XML = "/conf/config.xml"
# a blocked source fades this long after its last hit and is reported while hit in the last minute;
# hits are counted over a longer window so slow scanners still reach a viewer's display threshold
BLOCK_FADE_SECONDS = 6
BLOCK_SHOW_SECONDS = 60
BLOCK_WINDOW_SECONDS = 600
# a source hitting at least this often per minute is drawn as a threat
THREAT_HITS_PER_MINUTE = 30
MAX_BLOCK_SOURCES = 300
MAX_LOG_LINES_PER_SAMPLE = 5000
BLOCK_REFRESH_SECONDS = 60
SETTINGS_REFRESH_SECONDS = 30
GEO_CACHE_FILE = "/var/db/firewallmap/geo.json"

INTERVAL = 1.0
FADE_SECONDS = 20.0
MAX_FLOWS = 150
RATE_SMOOTHING = 0.5
HOST_REFRESH_SECONDS = 30.0
GEO_CACHE_SAVE_SECONDS = 60.0
GEO_LOOKUPS_PER_SAMPLE = 25
GEO_CACHE_MAX = 20000
GEO_CACHE_VERSION = 2
MAX_SERVICES = 4

SERVICES = {
    ("tcp", "20"): "FTP data", ("tcp", "21"): "FTP", ("tcp", "22"): "SSH", ("tcp", "25"): "SMTP",
    ("udp", "53"): "DNS", ("tcp", "53"): "DNS", ("tcp", "80"): "HTTP", ("udp", "123"): "NTP",
    ("tcp", "143"): "IMAP", ("tcp", "443"): "HTTPS", ("udp", "443"): "QUIC", ("udp", "500"): "IKE",
    ("tcp", "465"): "SMTPS", ("tcp", "587"): "Submission", ("tcp", "853"): "DNS over TLS",
    ("udp", "853"): "DNS over QUIC", ("tcp", "993"): "IMAPS", ("tcp", "995"): "POP3S",
    ("udp", "1194"): "OpenVPN", ("tcp", "1194"): "OpenVPN", ("udp", "3478"): "STUN/TURN",
    ("tcp", "3389"): "RDP", ("udp", "4500"): "IPsec NAT-T", ("tcp", "5223"): "Apple Push",
    ("tcp", "5228"): "Google Push", ("udp", "51820"): "WireGuard", ("tcp", "8080"): "HTTP alt",
    ("tcp", "8443"): "HTTPS alt", ("udp", "19302"): "Google STUN",
}


def service_name(protocol, port):
    """Name the responder side of a connection (the service being used)."""
    if protocol in ("icmp", "ipv6-icmp"):
        return "ICMP"
    if port is None:
        return protocol.upper()
    return SERVICES.get((protocol, port), f"{protocol.upper()}/{port}")

COUNTERS = re.compile(r"(?P<packets_in>\d+):(?P<packets_out>\d+) pkts,\s+(?P<bytes_in>\d+):(?P<bytes_out>\d+) bytes")
AGE = re.compile(r"\bage (?:(?P<days>\d+)d)?(?P<h>\d+):(?P<m>\d+):(?P<s>\d+)")
STATE_ID = re.compile(r"\bid: (?P<id>[0-9a-f]+) creatorid: (?P<creator>[0-9a-f]+)")
ENDPOINT = re.compile(r"^(?P<address>.+?)(?::(?P<port>\d+))?$")
MMDB_KEY = re.compile(r'^"(?P<key>[^"]+)":\s*$')
MMDB_STRING = re.compile(r'^"(?P<value>.*)" <utf8_string>$')
MMDB_NUMBER = re.compile(r"^(?P<value>[-+]?\d+(?:\.\d+)?) <(?:double|float|uint\d+|int\d+)>$")


def endpoint(value):
    """Split a PF endpoint while keeping address parsing deliberately IPv4-only."""
    match = ENDPOINT.match(value.strip("()"))
    if not match:
        return {"address": None, "port": None}
    return {"address": match.group("address"), "port": match.group("port")}


def parse_states(output):
    """Parse `pfctl -vv -s state` using the same endpoint fields as OPNsense's state API."""
    records = []
    header = None
    for line in output.splitlines():
        if not line.startswith((" ", "\t")):
            parts = line.split()
            if len(parts) < 6:
                header = None
                continue
            direction = "out" if parts[-3] == "->" else "in"
            left = endpoint(parts[2])
            right = endpoint(parts[-2])
            header = {
                "interface": parts[0],
                "protocol": parts[1],
                "state": parts[-1],
                "direction": direction,
                "src": left if direction == "out" else right,
                "dst": right if direction == "out" else left,
                "nat": endpoint(parts[3]) if parts[3].startswith("(") else None,
            }
            continue
        state_id = STATE_ID.search(line)
        if state_id and records and records[-1].get("id") is None:
            records[-1]["id"] = f"{state_id.group('id')}/{state_id.group('creator')}"
            continue
        if header is None:
            continue
        counters = COUNTERS.search(line)
        if not counters:
            continue
        age = AGE.search(line)
        records.append({
            **header,
            "id": None,
            "age": (
                int(age.group("days") or 0) * 86400 + int(age.group("h")) * 3600
                + int(age.group("m")) * 60 + int(age.group("s"))
            ) if age else None,
            **{key: int(value) for key, value in counters.groupdict().items()},
        })
        header = None
    return records


def public_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return False
    return address.version == 4 and address.is_global


def flow_endpoints(record, local_addresses):
    """Return (firewall public address, remote address) or None for non-map traffic.

    NAT states carry the firewall's public address explicitly; other states are kept
    only when one endpoint is a public address configured on this firewall.
    """
    src = record["src"]["address"]
    dst = record["dst"]["address"]
    nat = record["nat"]["address"] if record["nat"] else None
    if nat and public_ipv4(nat):
        local = nat
    elif src in local_addresses:
        local = src
    elif dst in local_addresses:
        local = dst
    else:
        return None
    remote = dst if local == src else src
    if not public_ipv4(remote) or remote == local or remote in local_addresses:
        return None
    return local, remote


def parse_mmdb(output):
    """Flatten mmdblookup's annotated dump into {("a", "b"): value} (array indices omitted)."""
    values = {}
    path = []
    pending = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        key = MMDB_KEY.match(line)
        if key:
            pending = key.group("key")
        elif line in ("{", "["):
            path.append(pending)
            pending = None
        elif line in ("}", "]"):
            if path:
                path.pop()
        else:
            match = MMDB_STRING.match(line) or MMDB_NUMBER.match(line)
            if match and pending is not None:
                values[tuple(part for part in path if part is not None) + (pending,)] = match.group("value")
            pending = None
    return values


def mmdb_lookup(database, address):
    try:
        result = subprocess.run(
            [MMDBLOOKUP, "--file", database, "--ip", address],
            capture_output=True, check=False, text=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_mmdb(result.stdout)


def lookup_location(address, city_database=CITY_DATABASE, asn_database=ASN_DATABASE):
    """Resolve one address against the local geolocation databases (never a remote service)."""
    values = mmdb_lookup(city_database, address)
    try:
        latitude = float(values[("location", "latitude")])
        longitude = float(values[("location", "longitude")])
    except (KeyError, ValueError):
        return None
    location = {
        "lat": round(latitude, 4),
        "lon": round(longitude, 4),
        "city": values.get(("city", "names", "en")),
        # GeoLite often knows only the state/province (with a coarse accuracy radius)
        "region": values.get(("subdivisions", "names", "en")),
        "accuracy_km": int(float(values[("location", "accuracy_radius")])) if ("location", "accuracy_radius") in values else None,
        "country": values.get(("country", "iso_code")) or values.get(("registered_country", "iso_code")),
        "country_name": values.get(("country", "names", "en")) or values.get(("registered_country", "names", "en")),
    }
    if os.path.exists(asn_database):
        asn = mmdb_lookup(asn_database, address)
        if ("autonomous_system_number",) in asn:
            location["asn"] = int(asn[("autonomous_system_number",)])
            location["as_org"] = asn.get(("autonomous_system_organization",))
    return location


class GeoCache:
    """IP -> location cache persisted across restarts and invalidated when the MMDB changes."""

    def __init__(self, path=GEO_CACHE_FILE, database=CITY_DATABASE, asn_database=ASN_DATABASE, lookup=None):
        self.path = path
        self.database = database
        self.asn_database = asn_database
        self.lookup = lookup or (lambda address: lookup_location(address, database, asn_database))
        self.entries = {}
        self.dirty = False
        self.saved_at = time.monotonic()
        self.database_mtime = self._database_mtime()
        self._load()

    def _database_mtime(self):
        mtimes = []
        for database in (self.database, self.asn_database):
            try:
                mtimes.append(int(os.stat(database).st_mtime))
            except OSError:
                mtimes.append(None)
        return mtimes

    def _load(self):
        try:
            with open(self.path) as handle:
                cached = json.load(handle)
        except (OSError, ValueError):
            return
        if (cached.get("database_mtime") == self.database_mtime and cached.get("version") == GEO_CACHE_VERSION
                and cached.get("database") == self.database):
            self.entries = cached.get("entries", {})

    def save(self, force=False):
        if not self.dirty or (not force and time.monotonic() - self.saved_at < GEO_CACHE_SAVE_SECONDS):
            return
        if len(self.entries) > GEO_CACHE_MAX:
            self.entries = dict(list(self.entries.items())[-GEO_CACHE_MAX:])
        write_json(self.path, {
            "version": GEO_CACHE_VERSION, "database": self.database,
            "database_mtime": self.database_mtime, "entries": self.entries,
        })
        self.dirty = False
        self.saved_at = time.monotonic()

    def resolve(self, addresses, budget=GEO_LOOKUPS_PER_SAMPLE):
        """Look up at most `budget` unknown addresses; unresolvable ones are cached as null."""
        for address in addresses:
            if budget <= 0:
                break
            if address not in self.entries:
                self.entries[address] = self.lookup(address)
                self.dirty = True
                budget -= 1

    def get(self, address):
        return self.entries.get(address)


def write_json(path, payload):
    """Write atomically so readers never see a partial document."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.{os.getpid()}.tmp"
    with open(temporary, "w") as handle:
        json.dump(payload, handle, separators=(",", ":"))
    os.replace(temporary, path)


def host_info():
    """Return (public IPv4 addresses on this firewall, CARP role or None)."""
    try:
        output = subprocess.run(
            [IFCONFIG, "-a"], capture_output=True, check=False, text=True, timeout=2,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set(), None
    addresses = {address for address in re.findall(r"\binet\s+(\d+(?:\.\d+){3})", output) if public_ipv4(address)}
    roles = set(re.findall(r"\bcarp: (MASTER|BACKUP|INIT)\b", output))
    if not roles:
        role = None
    elif "MASTER" in roles:
        role = "master"
    else:
        role = "backup"
    return addresses, role


class FlowTracker:
    """Turn successive PF state samples into per-flow byte rates with activity fading."""

    def __init__(self, fade_seconds=FADE_SECONDS, smoothing=RATE_SMOOTHING):
        self.fade_seconds = fade_seconds
        self.smoothing = smoothing
        self.counters = {}
        self.flows = {}
        self.sampled_at = None

    def update(self, records, local_addresses, now):
        elapsed = (now - self.sampled_at) if self.sampled_at is not None else None
        first_sample = elapsed is None
        counters = {}
        totals = {}
        for record in records:
            pair = flow_endpoints(record, local_addresses)
            if pair is None or record.get("id") is None:
                continue
            # PF counts initiator->responder first; src is the initiator in parse_states()
            remote_initiated = record["src"]["address"] == pair[1]
            toward, away = (
                (record["bytes_in"], record["bytes_out"]) if remote_initiated
                else (record["bytes_out"], record["bytes_in"])
            )
            current = (toward, away, record["packets_in"] + record["packets_out"])
            counters[record["id"]] = current
            previous = self.counters.get(record["id"])
            if previous is not None:
                delta = tuple(max(0, now_value - before) for now_value, before in zip(current, previous))
            elif not first_sample and record.get("age") is not None and record["age"] <= 2 * (elapsed or INTERVAL):
                # a state created since the previous sample: everything it counted is new
                delta = current
            else:
                delta = (0, 0, 0)
            total = totals.setdefault(pair, {"toward": 0, "away": 0, "packets": 0, "states": 0, "protocols": set(), "services": {}})
            service = service_name(record["protocol"], record["dst"]["port"])
            total["services"][service] = total["services"].get(service, 0) + delta[0] + delta[1] + 1
            total["toward"] += delta[0]
            total["away"] += delta[1]
            total["packets"] += delta[2]
            total["states"] += 1
            total["protocols"].add(record["protocol"])
        self.counters = counters
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
            for key, value in (("rate_in", total["toward"]), ("rate_out", total["away"]), ("packet_rate", total["packets"])):
                current_rate = value / elapsed if elapsed else 0.0
                flow[key] = self.smoothing * current_rate + (1 - self.smoothing) * flow[key]
            flow["rate"] = flow["rate_in"] + flow["rate_out"]
            flow["states"] = total["states"]
            flow["protocols"] = sorted(total["protocols"])
            # busiest services first
            flow["services"] = [name for name, _ in sorted(total["services"].items(), key=lambda item: -item[1])][:MAX_SERVICES]
            if total["toward"] + total["away"] > 0:
                flow["last_active"] = now

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


class HostnameResolver:
    """Reverse DNS for visible endpoints, only while a viewer asked for it; results are cached."""

    def __init__(self, ttl=HOSTNAME_TTL, per_sample=HOSTNAME_LOOKUPS_PER_SAMPLE):
        self.ttl = ttl
        self.per_sample = per_sample
        self.names = {}
        self.pending = {}
        self.pool = ThreadPoolExecutor(max_workers=4)

    @staticmethod
    def _reverse(address):
        try:
            return socket.gethostbyaddr(address)[0]
        except (OSError, UnicodeError):
            return None

    def update(self, addresses, now):
        for address, future in list(self.pending.items()):
            if future.done():
                self.names[address] = (future.result(), now)
                del self.pending[address]
        budget = self.per_sample - len(self.pending)
        for address in addresses:
            if budget <= 0:
                break
            cached = self.names.get(address)
            if address in self.pending or (cached and now - cached[1] < self.ttl):
                continue
            self.pending[address] = self.pool.submit(self._reverse, address)
            budget -= 1

    def get(self, address):
        cached = self.names.get(address)
        return cached[0] if cached else None


def requested(marker, seconds, now=None):
    try:
        return (time.time() if now is None else now) - os.stat(marker).st_mtime < seconds
    except OSError:
        return False


class FilterLogTail:
    """Follow the firewall log from its current end, surviving the daily rotation of latest.log."""

    def __init__(self, path=FILTER_LOG):
        self.path = path
        self.handle = None
        self.inode = None

    def _open(self, at_end):
        try:
            handle = open(self.path, "r", errors="replace")
            inode = os.fstat(handle.fileno()).st_ino
        except OSError:
            return
        if at_end:
            handle.seek(0, os.SEEK_END)
        if self.handle:
            self.handle.close()
        self.handle, self.inode = handle, inode

    def lines(self, limit=MAX_LOG_LINES_PER_SAMPLE):
        if self.handle is None:
            self._open(at_end=True)
            return []
        result = []
        for line in self.handle:
            result.append(line)
            if len(result) >= limit:
                # a burst larger than we can draw: skip ahead instead of falling behind
                self.handle.seek(0, os.SEEK_END)
                break
        try:
            if os.stat(self.path).st_ino != self.inode:
                self._open(at_end=False)
        except OSError:
            pass
        return result


def parse_block(line):
    """Parse an inbound block from an OPNsense filterlog line (CSV after the syslog header)."""
    marker = line.find("] ")
    if " filterlog " not in line or marker < 0:
        return None
    fields = line[marker + 2:].strip().split(",")
    if len(fields) < 20 or fields[6] != "block" or fields[7] != "in":
        return None
    if fields[8] == "4":
        protocol, source, destination = fields[16], fields[18], fields[19]
        ports = fields[20:22] if protocol in ("tcp", "udp") and len(fields) > 21 else [None, None]
    elif fields[8] == "6" and len(fields) > 17:
        protocol, source, destination = fields[12], fields[15], fields[16]
        ports = fields[17:19] if protocol in ("tcp", "udp") and len(fields) > 18 else [None, None]
    else:
        return None
    return {
        "rule": fields[3] or fields[0],
        "interface": fields[4],
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "port": ports[1] or None,
    }


def rule_descriptions(path=RULES_DEBUG):
    """Map rule labels to their descriptions, as the firewall log view does."""
    descriptions = {}
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                if " label " in line:
                    label = line.split(" label ")[-1]
                    if label.count('"') >= 2:
                        descriptions[label.split('"')[1]] = "".join(label.split('"')[2:]).strip().strip("# : ")
    except OSError:
        pass
    return descriptions


def interface_names(path=CONFIG_XML):
    """Map devices (igb1, vlan01, ...) to their configured names (WAN, LAN, ...)."""
    names = {}
    try:
        interfaces = ElementTree.parse(path).getroot().find("interfaces")
    except (OSError, ElementTree.ParseError):
        return names
    for node in list(interfaces) if interfaces is not None else []:
        device = node.findtext("if")
        if device:
            names[device] = (node.findtext("descr") or "").strip() or node.tag.upper()
    return names


class BlockTracker:
    """Inbound firewall blocks per public source: recent hits, ports tried, rule and interface."""

    def __init__(self, fade=BLOCK_FADE_SECONDS, show=BLOCK_SHOW_SECONDS, window=BLOCK_WINDOW_SECONDS):
        self.fade = fade
        self.show = show
        self.window = window
        self.sources = {}

    def add(self, event, now):
        if not public_ipv4(event["source"]):
            return
        entry = self.sources.get(event["source"])
        if entry is None:
            entry = self.sources[event["source"]] = {
                "hits": deque(), "total": 0, "ports": {}, "protocols": set(),
                "destination": event["destination"], "rule": event["rule"], "interface": event["interface"],
            }
        entry["hits"].append(now)
        entry["total"] += 1
        entry["last"] = now
        entry["destination"] = event["destination"]
        entry["rule"] = event["rule"]
        entry["interface"] = event["interface"]
        entry["protocols"].add(event["protocol"])
        port = f'{event["protocol"]}/{event["port"]}' if event["port"] else event["protocol"]
        entry["ports"][port] = entry["ports"].get(port, 0) + 1

    def visible(self, now, limit=MAX_BLOCK_SOURCES):
        """Sources hit within the last `show` seconds, most persistent first."""
        for address in list(self.sources):
            entry = self.sources[address]
            while entry["hits"] and now - entry["hits"][0] > self.window:
                entry["hits"].popleft()
            if not entry["hits"]:
                del self.sources[address]
        recent = [(address, entry) for address, entry in self.sources.items() if now - entry["last"] <= self.show]
        recent.sort(key=lambda item: (-len(item[1]["hits"]), -item[1]["last"]))
        return recent[:limit]

    def per_minute(self, entry, now):
        return sum(1 for hit in entry["hits"] if now - hit <= 60)

    def activity(self, entry, now):
        return max(0.0, 1.0 - (now - entry["last"]) / self.fade)


def block_snapshot(blocks, geo, local_addresses, origin, now, descriptions, interfaces):
    """Map-ready blocked sources; each arc ends at the firewall address that was hit."""
    visible = blocks.visible(now)
    geo.resolve([address for address, _ in visible])
    result = []
    for address, entry in visible:
        location = geo.get(address)
        if location is None:
            continue
        target = entry["destination"]
        per_minute = blocks.per_minute(entry, now)
        result.append({
            "source": address,
            "target": target,
            "activity": round(blocks.activity(entry, now), 3),
            "hits": len(entry["hits"]),
            "window_minutes": blocks.window // 60,
            "hits_per_minute": per_minute,
            "total": entry["total"],
            "threat": per_minute >= THREAT_HITS_PER_MINUTE,
            "ports": [name for name, _ in sorted(entry["ports"].items(), key=lambda item: -item[1])][:5],
            "rule": descriptions.get(entry["rule"], ""),
            "interface": interfaces.get(entry["interface"], entry["interface"]),
            "lat": location["lat"],
            "lon": location["lon"],
            "city": location.get("city") or location.get("region"),
            "country": location.get("country_name") or location.get("country"),
            "accuracy_km": location.get("accuracy_km"),
            "asn": location.get("asn"),
            "as_org": location.get("as_org"),
        })
    return result


def snapshot(tracker, geo, local_addresses, role, now, wall_time, hostnames=None):
    visible = tracker.visible(now)
    geo.resolve([address for _, local, remote, _, _ in visible for address in (local, remote)])
    flows = []
    location_ids = set()
    for _, local, remote, flow, activity in visible:
        if geo.get(local) is None or geo.get(remote) is None:
            continue
        location_ids.update((local, remote))
        flows.append({
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
        })
    locations = []
    for address in sorted(location_ids):
        location = geo.get(address)
        entry = {
            "id": address,
            "name": ", ".join(
                part for part in (location.get("city") or location.get("region"), location.get("country")) if part
            ) or address,
            "city": location.get("city"),
            "region": location.get("region"),
            "accuracy_km": location.get("accuracy_km"),
            "country": location.get("country_name") or location.get("country"),
            "lat": location["lat"],
            "lon": location["lon"],
            "local": address in local_addresses,
        }
        if location.get("asn"):
            entry["asn"] = location["asn"]
            entry["as_org"] = location.get("as_org")
        locations.append(entry)
    names = {}
    if hostnames is not None:
        remotes = [flow["dest"] for flow in flows]
        hostnames.update(remotes, now)
        names = {address: hostnames.get(address) for address in remotes if hostnames.get(address)}
    return {
        "status": "ok",
        "sampled_at": datetime.fromtimestamp(wall_time, timezone.utc).isoformat(),
        "interval": INTERVAL,
        "carp": role,
        "tracked_flows": len(tracker.flows),
        "flows": flows,
        "locations": locations,
        "hostnames": names,
    }


def sample_states():
    result = subprocess.run(
        [PFCTL, "-vv", "-s", "state"], capture_output=True, check=False, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("pfctl failed")
    return parse_states(result.stdout)


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
    """Return (city path, asn path, problem) for the configured provider."""
    paths = geodb.DATABASES[values["provider"]]
    if os.path.exists(paths["city"]):
        return paths["city"], paths["asn"], None
    if values["provider"].startswith("maxmind") and geodb.license_key(values)[0] is None:
        return paths["city"], paths["asn"], "maxmind_key_missing"
    return paths["city"], paths["asn"], "database_missing"


def run():
    started_at = time.time()
    tracker = FlowTracker()
    hostnames = HostnameResolver()
    blocks = BlockTracker()
    log = FilterLogTail()
    descriptions, interfaces, block_meta_checked = {}, {}, None
    geo = None
    problem = None
    local_addresses, role = set(), None
    host_checked = None
    settings_checked = None
    provider = "maxmind"
    while True:
        started = time.monotonic()
        if host_checked is None or started - host_checked >= HOST_REFRESH_SECONDS:
            local_addresses, role = host_info()
            host_checked = started
        if settings_checked is None or started - settings_checked >= SETTINGS_REFRESH_SECONDS:
            values = geodb.settings()
            provider = values["provider"]
            city, asn, problem = database_state(values)
            # a new provider or a refreshed database invalidates cached locations
            if geo is None or geo.database != city or geo.database_mtime != geo._database_mtime():
                if geo is not None:
                    geo.save(force=True)
                geo = GeoCache(database=city, asn_database=asn)
            settings_checked = started
        if problem:
            write_json(OUTPUT_FILE, {
                "status": "no_database",
                "reason": problem,
                "sampled_at": datetime.now(timezone.utc).isoformat(),
                "flows": [],
                "locations": [],
            })
            # re-check soon, the database may be downloading
            settings_checked = started - SETTINGS_REFRESH_SECONDS + 5
        else:
            try:
                records = sample_states()
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                write_json(OUTPUT_FILE, {
                    "status": "failed",
                    "error": str(error),
                    "sampled_at": datetime.now(timezone.utc).isoformat(),
                    "flows": [],
                    "locations": [],
                })
            else:
                now = time.monotonic()
                tracker.update(records, local_addresses, now)
                resolver = hostnames if requested(HOSTNAME_MARKER, HOSTNAME_REQUEST_SECONDS) else None
                for line in log.lines():
                    event = parse_block(line)
                    # only connection attempts aimed at this firewall's own public addresses; blocked
                    # forwarded traffic (e.g. another host's outbound packets) is not an inbound probe
                    if event and event["destination"] in local_addresses:
                        blocks.add(event, now)
                if block_meta_checked is None or started - block_meta_checked >= BLOCK_REFRESH_SECONDS:
                    descriptions, interfaces = rule_descriptions(), interface_names()
                    block_meta_checked = started
                payload = snapshot(tracker, geo, local_addresses, role, now, time.time(), resolver)
                origin = next((location["id"] for location in payload["locations"] if location["local"]), None)
                if origin is None and local_addresses:
                    origin = sorted(local_addresses)[0]
                    geo.resolve([origin])
                payload["blocks"] = block_snapshot(blocks, geo, local_addresses, origin, now, descriptions, interfaces)
                if origin and geo.get(origin) and not any(location["id"] == origin for location in payload["locations"]):
                    location = geo.get(origin)
                    payload["locations"].append({
                        "id": origin, "name": origin, "lat": location["lat"], "lon": location["lon"], "local": True,
                    })
                payload["provider"] = provider
                write_json(OUTPUT_FILE, payload)
                geo.save()
        if idle(started_at):
            if geo is not None:
                geo.save(force=True)
            return
        time.sleep(max(0.05, INTERVAL - (time.monotonic() - started)))


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        sys.exit(0)
