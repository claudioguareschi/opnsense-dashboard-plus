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

import functools
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ElementTree
from array import array
from bisect import bisect_left
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
ACTIVE_VIEWER_SECONDS = 10
IDLE_INTERVAL = 5.0
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
MAX_LOG_BYTES_PER_SAMPLE = 4 * 1024 * 1024
# bounded memory under floods: tracked blocked sources and ports remembered per source
MAX_TRACKED_SOURCES = 5000
MAX_PORTS_PER_SOURCE = 20
BLOCK_BUCKET_SECONDS = 10
MAX_HOSTNAMES = 5000
MAX_FAILURE_BACKOFF = 30.0
COLLECTOR_LOCK = "/var/run/firewallmap/collector.lock"
# read back this much of the log when the collector starts, so the 10-minute hit window is full
BACKLOG_BYTES = 2 * 1024 * 1024
BLOCK_REFRESH_SECONDS = 60
# threat intelligence: pf tables behind URL/external aliases and well-known feed tables
BLOCKLIST_REFRESH_SECONDS = 300
BLOCKLIST_ALIAS_TYPES = {"urltable", "url", "urljson", "external"}
BLOCKLIST_TABLE_PREFIXES = ("crowdsec", "__qfeeds", "qfeeds", "spamhaus", "firehol", "abuse")
BLOCKLIST_MAX_ENTRIES = 500000
BLOCKLIST_MAX_TOTAL = 1000000
CGNAT = ipaddress.ip_network("100.64.0.0/10")
SETTINGS_REFRESH_SECONDS = 30
CACHE_DB = "/var/db/firewallmap/cache.db"

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
MAX_INSIDE = 3

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
ORIGIF = re.compile(r"\borigif: (?P<ifname>\S+)")
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
            arrow = next((index for index, part in enumerate(parts) if part in ("->", "<-")), None)
            if len(parts) < 6 or arrow is None or arrow < 3 or arrow + 1 >= len(parts):
                header = None
                continue
            # "A [(A')] -> B [(B')] STATE": translations follow the endpoint they belong to
            direction = "out" if parts[arrow] == "->" else "in"
            left = endpoint(parts[2])
            right = endpoint(parts[arrow + 1])
            translated = arrow > 3 and parts[3].startswith("(")
            if not translated and not public_ipv4(left["address"]) and not public_ipv4(right["address"]):
                # LAN-internal state (or the LAN side of a NAT pair): never drawn, skip its details
                header = None
                continue
            header = {
                "interface": parts[0],
                "protocol": parts[1],
                "state": parts[-1],
                "direction": direction,
                "src": left if direction == "out" else right,
                "dst": right if direction == "out" else left,
                "nat": endpoint(parts[3]) if arrow > 3 and parts[3].startswith("(") else None,
            }
            continue
        # dispatch on the detail line's first word: running every pattern over every line was
        # the collector's largest CPU cost
        stripped = line.lstrip()
        if stripped.startswith("id:"):
            state_id = STATE_ID.search(stripped)
            if state_id and records and records[-1].get("id") is None:
                records[-1]["id"] = f"{state_id.group('id')}/{state_id.group('creator')}"
            continue
        if stripped.startswith("origif:"):
            if records and records[-1].get("origif") is None:
                # the interface the state was created on: for NAT states, the egress (WAN, VPN, ...)
                records[-1]["origif"] = stripped.split()[1]
            continue
        if header is None or not stripped.startswith("age "):
            continue
        counters = COUNTERS.search(line)
        if not counters:
            continue
        age = AGE.search(line)
        records.append({
            **header,
            "id": None,
            "origif": None,
            "age": (
                int(age.group("days") or 0) * 86400 + int(age.group("h")) * 3600
                + int(age.group("m")) * 60 + int(age.group("s"))
            ) if age else None,
            **{key: int(value) for key, value in counters.groupdict().items()},
        })
        header = None
    return records


@functools.lru_cache(maxsize=65536)
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
    elif nat and private_ipv4(src) and public_ipv4(dst) and local_addresses:
        # outbound NAT to a tunnel address (e.g. a WireGuard or IPsec egress): draw it from the
        # firewall's own location, the egress interface tells which path it took
        local = min(local_addresses)
        return local, dst
    else:
        return None
    remote = dst if local == src else src
    if not public_ipv4(remote) or remote == local or remote in local_addresses:
        return None
    return local, remote


@functools.lru_cache(maxsize=65536)
def private_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return False
    # carrier-grade NAT space (Tailscale, some VPN tunnels) is inside space too
    return address.version == 4 and (address.is_private or address in CGNAT) and not address.is_loopback


def inside_address(record):
    """The LAN host behind a NAT state (the private address among source, destination and NAT)."""
    for side in (record["nat"], record["src"], record["dst"]):
        if side and private_ipv4(side["address"]):
            return side["address"]
    return None


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
    except (OSError, subprocess.TimeoutExpired) as error:
        # a transient failure, not "no data": callers must not cache it
        raise LookupError(str(error)) from error
    if result.returncode == 6 or "Could not find an entry" in result.stderr:
        return {}  # not in the database: a definite miss that is cached
    if result.returncode != 0:
        raise LookupError(result.stderr.strip() or "mmdblookup failed")
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
        try:
            asn = mmdb_lookup(asn_database, address)
        except LookupError:
            asn = {}
        if ("autonomous_system_number",) in asn:
            location["asn"] = int(asn[("autonomous_system_number",)])
            location["as_org"] = asn.get(("autonomous_system_organization",))
    return location


class CacheStore:
    """Small SQLite key/value store with expiry, shared by the collector's caches.

    One file, no service: GeoIP results, reverse DNS names and investigation lookups survive
    restarts, are written incrementally and are pruned by age and count.
    """

    def __init__(self, path=CACHE_DB):
        self.path = path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS cache (kind TEXT, key TEXT, value TEXT, stored REAL, PRIMARY KEY (kind, key))"
        )
        self.lock = threading.Lock()

    def get_all(self, kind, max_age=None, now=None):
        now = time.time() if now is None else now
        with self.lock:
            rows = self.db.execute("SELECT key, value, stored FROM cache WHERE kind = ?", (kind,)).fetchall()
        return {key: json.loads(value) for key, value, stored in rows if max_age is None or now - stored < max_age}

    def get(self, kind, key, max_age=None, now=None):
        now = time.time() if now is None else now
        with self.lock:
            row = self.db.execute("SELECT value, stored FROM cache WHERE kind = ? AND key = ?", (kind, key)).fetchone()
        if row is None or (max_age is not None and now - row[1] >= max_age):
            return None
        return json.loads(row[0])

    def put_many(self, kind, items, now=None):
        now = time.time() if now is None else now
        with self.lock:
            self.db.execute("BEGIN")
            self.db.executemany(
                "INSERT OR REPLACE INTO cache (kind, key, value, stored) VALUES (?, ?, ?, ?)",
                [(kind, key, json.dumps(value), now) for key, value in items],
            )
            self.db.execute("COMMIT")

    def prune(self, kind, max_age=None, keep=None, now=None):
        now = time.time() if now is None else now
        with self.lock:
            if max_age is not None:
                self.db.execute("DELETE FROM cache WHERE kind = ? AND stored < ?", (kind, now - max_age))
            if keep is not None:
                self.db.execute(
                    "DELETE FROM cache WHERE kind = ? AND key NOT IN "
                    "(SELECT key FROM cache WHERE kind = ? ORDER BY stored DESC LIMIT ?)", (kind, kind, keep),
                )

    def clear(self, kind):
        with self.lock:
            self.db.execute("DELETE FROM cache WHERE kind = ?", (kind,))


class GeoCache:
    """IP -> location cache persisted in SQLite and invalidated when the databases change."""

    def __init__(self, store=None, database=CITY_DATABASE, asn_database=ASN_DATABASE, lookup=None, path=None):
        self.store = store if store is not None else CacheStore(path or CACHE_DB)
        self.database = database
        self.asn_database = asn_database
        self.lookup = lookup or (lambda address: lookup_location(address, database, asn_database))
        self.database_mtime = self._database_mtime()
        self.kind = f"geo:{GEO_CACHE_VERSION}:{database}:{self.database_mtime}"
        self.pending = {}
        self.saved_at = time.monotonic()
        self.entries = self.store.get_all(self.kind)

    def _database_mtime(self):
        mtimes = []
        for database in (self.database, self.asn_database):
            try:
                mtimes.append(int(os.stat(database).st_mtime))
            except OSError:
                mtimes.append(None)
        return mtimes

    def save(self, force=False):
        if not self.pending or (not force and time.monotonic() - self.saved_at < GEO_CACHE_SAVE_SECONDS):
            return
        self.store.put_many(self.kind, self.pending.items())
        self.store.prune(self.kind, keep=GEO_CACHE_MAX)
        self.pending = {}
        self.saved_at = time.monotonic()

    def forget_old_databases(self):
        """Drop cached locations from previous database files."""
        with self.store.lock:
            self.store.db.execute("DELETE FROM cache WHERE kind LIKE 'geo:%' AND kind != ?", (self.kind,))

    def resolve(self, addresses, budget=GEO_LOOKUPS_PER_SAMPLE):
        """Look up at most `budget` unknown addresses; unresolvable ones are cached as null."""
        for address in addresses:
            if budget <= 0:
                break
            if address not in self.entries:
                budget -= 1
                try:
                    self.entries[address] = self.pending[address] = self.lookup(address)
                except LookupError:
                    continue  # try again on a later sample
        if len(self.entries) > GEO_CACHE_MAX * 2:
            # keep memory bounded: the store keeps the most recent entries
            self.save(force=True)
            self.entries = self.store.get_all(self.kind)

    def get(self, address):
        return self.entries.get(address)


def write_json(path, payload):
    """Write atomically so readers never see a partial document."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.{os.getpid()}.tmp"
    with open(temporary, "w") as handle:
        json.dump(payload, handle, separators=(",", ":"))
    os.replace(temporary, path)


def interface_networks(output):
    """[(IPv4Network, device)] for every IPv4 address configured on an interface."""
    networks = []
    device = None
    for line in output.splitlines():
        header = re.match(r"^(\S+?):\s+flags=", line)
        if header:
            device = header.group(1)
            continue
        match = re.search(r"\binet\s+(\d+(?:\.\d+){3})\s+netmask\s+(0x[0-9a-fA-F]+)", line)
        if match and device:
            try:
                prefix = bin(int(match.group(2), 16)).count("1")
                networks.append((ipaddress.ip_network(f"{match.group(1)}/{prefix}", strict=False), device))
            except ValueError:
                continue
    # most specific first, so a host matches its own subnet before a wider one
    networks.sort(key=lambda item: -item[0].prefixlen)
    return networks


def host_info():
    """Return (public IPv4 addresses on this firewall, CARP role or None, interface networks)."""
    try:
        output = subprocess.run(
            [IFCONFIG, "-a"], capture_output=True, check=False, text=True, timeout=2,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set(), None, []
    addresses = {address for address in re.findall(r"\binet\s+(\d+(?:\.\d+){3})", output) if public_ipv4(address)}
    roles = set(re.findall(r"\bcarp: (MASTER|BACKUP|INIT)\b", output))
    if not roles:
        role = None
    elif "MASTER" in roles:
        role = "master"
    else:
        role = "backup"
    return addresses, role, interface_networks(output)


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
            total = totals.setdefault(pair, {
                "toward": 0, "away": 0, "packets": 0, "states": 0, "protocols": set(), "services": {},
                "inside": {}, "egress": {},
            })
            weight = delta[0] + delta[1] + 1
            inside = inside_address(record)
            if inside:
                total["inside"][inside] = total["inside"].get(inside, 0) + weight
            if record.get("origif"):
                total["egress"][record["origif"]] = total["egress"].get(record["origif"], 0) + weight
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
            flow["inside"] = [address for address, _ in sorted(total["inside"].items(), key=lambda item: -item[1])][:MAX_INSIDE]
            flow["egress"] = max(total["egress"], key=total["egress"].get) if total["egress"] else None
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


def blocked_rule_tables(path=RULES_DEBUG):
    """Tables referenced by block or reject rules in the running ruleset."""
    tables = set()
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                if line.startswith(("block", "reject")):
                    tables.update(re.findall(r"<([A-Za-z0-9_.-]+)>", line.split(" label ")[0]))
    except OSError:
        pass
    return tables


def blocklist_tables(config=CONFIG_XML, tables=None, blocked=None):
    """Names of pf tables that hold threat lists.

    URL/external aliases count only when a block or reject rule uses them, since the same alias
    types are often allowlists (cloud provider ranges...); feed tables with well-known names
    (CrowdSec, Q-Feeds, Spamhaus...) always count.
    """
    names = set()
    blocked = blocked_rule_tables() if blocked is None else blocked
    try:
        root = ElementTree.parse(config).getroot()
        for alias in root.iterfind(".//OPNsense/Firewall/Alias/aliases/alias"):
            name = alias.findtext("name")
            if alias.findtext("type") in BLOCKLIST_ALIAS_TYPES and alias.findtext("enabled") != "0" and name in blocked:
                names.add(name)
    except (OSError, ElementTree.ParseError):
        pass
    if tables is None:
        try:
            tables = subprocess.run([PFCTL, "-sT"], capture_output=True, check=False, text=True, timeout=10).stdout.split()
        except (OSError, subprocess.TimeoutExpired):
            tables = []
    names.update(table for table in tables if table.lower().startswith(BLOCKLIST_TABLE_PREFIXES))
    return {name for name in names if name and name in tables}


class BlocklistIndex:
    """Longest-prefix lookup of IPv4 addresses in blocklist pf tables.

    Compact: per prefix length a sorted array of network addresses with a parallel array of
    table bitmasks, searched with bisect. Rebuilt in a background thread and swapped in whole,
    so the sampling loop never waits for large tables.
    """

    def __init__(self):
        self.index = ([], {})  # (table names, {prefixlen: (networks, masks)})
        self.refreshing = False

    @staticmethod
    def build(contents, max_total=BLOCKLIST_MAX_TOTAL):
        names = sorted(contents)[:62]
        by_prefix = {}
        total = 0
        for bit, table in enumerate(names):
            for entry in contents[table]:
                entry = entry.strip()
                if not entry or entry.startswith("!") or ":" in entry:
                    continue
                try:
                    network = ipaddress.IPv4Network(entry, strict=False)
                except ValueError:
                    continue
                bucket = by_prefix.setdefault(network.prefixlen, {})
                key = int(network.network_address)
                bucket[key] = bucket.get(key, 0) | (1 << bit)
                total += 1
                if total >= max_total:
                    break
        compact = {}
        for prefixlen, bucket in by_prefix.items():
            keys = sorted(bucket)
            compact[prefixlen] = (array("I", keys), array("Q", (bucket[key] for key in keys)))
        return names, compact

    def load(self, contents):
        self.index = self.build(contents)

    def _refresh(self, tables):
        try:
            contents = {}
            for table in sorted(tables):
                try:
                    output = subprocess.run(
                        [PFCTL, "-t", table, "-T", "show"], capture_output=True, check=False, text=True, timeout=20,
                    ).stdout
                except (OSError, subprocess.TimeoutExpired):
                    continue
                entries = output.split()
                if len(entries) <= BLOCKLIST_MAX_ENTRIES:
                    contents[table] = entries
            self.index = self.build(contents)
        finally:
            self.refreshing = False

    def refresh(self, tables, background=True):
        if self.refreshing:
            return
        self.refreshing = True
        if background:
            threading.Thread(target=self._refresh, args=(tables,), daemon=True).start()
        else:
            self._refresh(tables)

    def lookup(self, address):
        try:
            value = int(ipaddress.IPv4Address(address))
        except ValueError:
            return []
        names, compact = self.index
        mask = 0
        for prefixlen, (networks, masks) in compact.items():
            key = value & ((0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF if prefixlen else 0)
            position = bisect_left(networks, key)
            if position < len(networks) and networks[position] == key:
                mask |= masks[position]
        return [name for bit, name in enumerate(names) if mask & (1 << bit)]


KEA_LEASES = "/var/db/kea/kea-leases4.csv"
DNSMASQ_LEASES = "/var/db/dnsmasq.leases"


def lease_names(kea=KEA_LEASES, dnsmasq=DNSMASQ_LEASES, config=CONFIG_XML, now=None):
    """IPv4 -> hostname from DHCP: Kea reservations win over Kea leases, then dnsmasq leases."""
    now = time.time() if now is None else now
    leases = {}
    try:
        with open(kea, errors="replace") as handle:
            header = handle.readline().strip().split(",")
            column = {name: index for index, name in enumerate(header)}
            for line in handle:
                fields = line.rstrip("\n").split(",")
                try:
                    address = fields[column["address"]]
                    name = fields[column["hostname"]].strip().rstrip(".")
                    expire = int(fields[column["expire"]] or 0)
                except (KeyError, IndexError, ValueError):
                    continue
                # Kea appends lease updates: the latest line for an address wins, and an expired,
                # released or nameless latest line clears the name
                if name and expire >= now:
                    leases[address] = name
                else:
                    leases.pop(address, None)
    except OSError:
        pass
    try:
        with open(dnsmasq, errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 4 and fields[3] != "*" and private_ipv4(fields[2]):
                    leases.setdefault(fields[2], fields[3])
    except OSError:
        pass
    try:
        root = ElementTree.parse(config).getroot()
        for reservation in root.iterfind(".//Kea/dhcp4/reservations/reservation"):
            address, name = reservation.findtext("ip_address"), reservation.findtext("hostname")
            if address and name:
                leases[address.strip()] = name.strip()
    except (OSError, ElementTree.ParseError):
        pass
    return leases


def describe_inside(address, names, networks, interfaces):
    device = next((device for network, device in networks if ipaddress.ip_address(address) in network), None)
    return {
        "ip": address,
        "name": names.get(address),
        "interface": interfaces.get(device, device) if device else None,
    }


class HostnameResolver:
    """Reverse DNS for visible endpoints, only while a viewer asked for it; results are cached."""

    def __init__(self, ttl=HOSTNAME_TTL, per_sample=HOSTNAME_LOOKUPS_PER_SAMPLE, store=None):
        self.ttl = ttl
        self.per_sample = per_sample
        self.store = store
        # (name, monotonic time looked up); names cached in the store survive restarts
        now = time.monotonic()
        wall = time.time()
        self.names = {}
        if store is not None:
            for address, (name, stamp) in store.get_all("hostname", max_age=ttl).items():
                self.names[address] = (name, now - (wall - stamp))
        self.pending = {}
        self.pool = ThreadPoolExecutor(max_workers=4)

    @staticmethod
    def _reverse(address):
        try:
            return socket.gethostbyaddr(address)[0]
        except (OSError, UnicodeError):
            return None

    def update(self, addresses, now):
        resolved = []
        for address, future in list(self.pending.items()):
            if future.done():
                self.names[address] = (future.result(), now)
                resolved.append((address, (future.result(), time.time())))
                del self.pending[address]
        if resolved and self.store is not None:
            self.store.put_many("hostname", resolved)
        for address in [address for address, (_, stamp) in self.names.items() if now - stamp >= self.ttl]:
            del self.names[address]
        while len(self.names) > MAX_HOSTNAMES:
            del self.names[min(self.names, key=lambda address: self.names[address][1])]
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
    """Follow the firewall log from its current end, surviving the daily rotation of latest.log.

    Only complete lines are returned; a line still being written is kept until its newline arrives.
    """

    def __init__(self, path=FILTER_LOG):
        self.path = path
        self.handle = None
        self.inode = None
        self.pending = b""

    def _open(self, at_end):
        try:
            handle = open(self.path, "rb")
            inode = os.fstat(handle.fileno()).st_ino
        except OSError:
            return
        if at_end:
            handle.seek(0, os.SEEK_END)
        if self.handle:
            self.handle.close()
        self.handle, self.inode, self.pending = handle, inode, b""

    def backlog(self, max_bytes=BACKLOG_BYTES):
        """Lines from the end of the current log, used once at start to fill the hit window."""
        self._open(at_end=True)
        if self.handle is None:
            return []
        end = self.handle.tell()
        self.handle.seek(max(0, end - max_bytes))
        data = self.handle.read(end - self.handle.tell())
        if end > max_bytes:
            data = data.split(b"\n", 1)[-1]  # drop the partial first line
        return [line.decode("utf-8", "replace") for line in data.split(b"\n") if line]

    def lines(self, limit_bytes=MAX_LOG_BYTES_PER_SAMPLE):
        if self.handle is None:
            self._open(at_end=True)
            return []
        data = self.handle.read(limit_bytes)
        if len(data) >= limit_bytes:
            # a burst larger than we can draw: skip ahead instead of falling behind, keeping only
            # whole lines (the pending fragment no longer lines up with what follows)
            self.handle.seek(0, os.SEEK_END)
            data = data.split(b"\n", 1)[-1] if self.pending else data
            self.pending = b""
            data = data.rsplit(b"\n", 1)[0] + b"\n"
        parts = (self.pending + data).split(b"\n")
        self.pending = parts.pop()
        try:
            if os.stat(self.path).st_ino != self.inode:
                # rotated: finish the old file, then read the new one from its start
                # (old lines are dropped by their timestamps)
                rest = (self.pending + self.handle.read(limit_bytes)).split(b"\n")
                parts.extend(line for line in rest if line)
                self._open(at_end=False)
        except OSError:
            pass
        return [line.decode("utf-8", "replace") for line in parts if line]


def log_time(line):
    """Wall-clock time of a syslog line (RFC 5424 timestamp, second field)."""
    try:
        return datetime.fromisoformat(line.split(" ", 2)[1]).timestamp()
    except (IndexError, ValueError):
        return None


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
    """Inbound firewall blocks per public source: recent hits, ports tried, rule and interface.

    Memory is bounded even under a spoofed-source flood: hits are kept as 10-second bucket
    counts, ports per source are capped, and the least recently seen sources are evicted.
    """

    def __init__(self, fade=BLOCK_FADE_SECONDS, show=BLOCK_SHOW_SECONDS, window=BLOCK_WINDOW_SECONDS,
                 max_sources=MAX_TRACKED_SOURCES):
        self.fade = fade
        self.show = show
        self.window = window
        self.max_sources = max_sources
        self.sources = {}

    def add(self, event, now):
        if not public_ipv4(event["source"]):
            return
        # dict order doubles as recency order: a hit moves the source to the end, so the least
        # recently hit source is always first and eviction is O(1)
        entry = self.sources.pop(event["source"], None)
        if entry is None:
            if len(self.sources) >= self.max_sources:
                del self.sources[next(iter(self.sources))]
            entry = {"buckets": {}, "total": 0, "ports": {}}
        self.sources[event["source"]] = entry
        bucket = int(now // BLOCK_BUCKET_SECONDS)
        entry["buckets"][bucket] = entry["buckets"].get(bucket, 0) + 1
        entry["total"] += 1
        entry["last"] = max(now, entry.get("last", now))
        entry["destination"] = event["destination"]
        entry["rule"] = event["rule"]
        entry["interface"] = event["interface"]
        port = f'{event["protocol"]}/{event["port"]}' if event["port"] else event["protocol"]
        if port in entry["ports"] or len(entry["ports"]) < MAX_PORTS_PER_SOURCE:
            entry["ports"][port] = entry["ports"].get(port, 0) + 1

    def hits(self, entry):
        return sum(entry["buckets"].values())

    def per_minute(self, entry, now):
        first = int((now - 60) // BLOCK_BUCKET_SECONDS) + 1
        return sum(count for bucket, count in entry["buckets"].items() if bucket >= first)

    def visible(self, now, limit=MAX_BLOCK_SOURCES):
        """Sources hit within the last `show` seconds, most persistent first."""
        oldest_bucket = int((now - self.window) // BLOCK_BUCKET_SECONDS) + 1
        recent = []
        for address in list(self.sources):
            entry = self.sources[address]
            for bucket in [bucket for bucket in entry["buckets"] if bucket < oldest_bucket]:
                del entry["buckets"][bucket]
            if not entry["buckets"]:
                del self.sources[address]
            elif now - entry["last"] <= self.show:
                recent.append((address, entry))
        recent.sort(key=lambda item: (-self.hits(item[1]), -item[1]["last"]))
        return recent[:limit]

    def activity(self, entry, now):
        return max(0.0, 1.0 - (now - entry["last"]) / self.fade)


def block_snapshot(blocks, geo, local_addresses, origin, now, descriptions, interfaces, blocklists=None):
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
            "hits": blocks.hits(entry),
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
            "country_code": location.get("country"),
            "accuracy_km": location.get("accuracy_km"),
            "asn": location.get("asn"),
            "as_org": location.get("as_org"),
            "lists": blocklists.lookup(address) if blocklists else [],
        })
    return result


def snapshot(tracker, geo, local_addresses, role, now, wall_time, hostnames=None, context=None):
    context = context or {}
    names = context.get("names", {})
    networks = context.get("networks", [])
    interfaces = context.get("interfaces", {})
    blocklists = context.get("blocklists")
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
            "inside": [describe_inside(address, names, networks, interfaces) for address in flow.get("inside", [])],
            "egress": interfaces.get(flow.get("egress"), flow.get("egress")),
            "lists": blocklists.lookup(remote) if blocklists else [],
        })
        # a permitted flow to a listed address is what deserves attention, not background scans
        flows[-1]["threat"] = bool(flows[-1]["lists"])
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
            "country_code": location.get("country"),
            "lat": location["lat"],
            "lon": location["lon"],
            "local": address in local_addresses,
        }
        if location.get("asn"):
            entry["asn"] = location["asn"]
            entry["as_org"] = location.get("as_org")
        locations.append(entry)
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
        "locations": locations,
        "hostnames": resolved,
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


def block_event_time(line, now, wall):
    """Monotonic time of a log line from its own timestamp (None when outside the hit window)."""
    stamp = log_time(line)
    if stamp is None:
        return now
    age = wall - stamp
    if age > BLOCK_WINDOW_SECONDS:
        return None
    return now - max(0.0, age)


def run():
    lock = acquire_lock()
    if lock is None:
        return
    started_at = time.time()
    failures = 0
    store = CacheStore()
    try:
        os.remove("/var/db/firewallmap/geo.json")  # the JSON cache used before the SQLite store
    except OSError:
        pass
    tracker = FlowTracker()
    hostnames = HostnameResolver(store=store)
    blocks = BlockTracker()
    log = FilterLogTail()
    backlog_loaded = False
    descriptions, interfaces, leases, block_meta_checked = {}, {}, {}, None
    blocklists, blocklists_checked = BlocklistIndex(), None
    geo = None
    problem = None
    local_addresses, role, networks = set(), None, []
    host_checked = None
    settings_checked = None
    provider = "maxmind"
    while True:
        started = time.monotonic()
        if host_checked is None or started - host_checked >= HOST_REFRESH_SECONDS:
            local_addresses, role, networks = host_info()
            host_checked = started
        if settings_checked is None or started >= settings_checked + SETTINGS_REFRESH_SECONDS:
            values = geodb.settings()
            provider = geodb.effective_provider(values)
            city, asn, problem = database_state(values)
            # a new provider or a refreshed database invalidates cached locations
            if geo is None or geo.database != city or geo.database_mtime != geo._database_mtime():
                if geo is not None:
                    geo.save(force=True)
                geo = GeoCache(store=store, database=city, asn_database=asn)
                geo.forget_old_databases()
            settings_checked = started
        if problem:
            write_json(OUTPUT_FILE, {
                "status": "no_database",
                "reason": problem,
                "error": geodb.read_status().get("last_error"),
                "sampled_at": datetime.now(timezone.utc).isoformat(),
                "flows": [],
                "locations": [],
            })
            # re-check within a few seconds, the database may be downloading; only move the
            # next check earlier, never later, or repeated passes would postpone it forever
            settings_checked = min(settings_checked, started - SETTINGS_REFRESH_SECONDS + 5)
        else:
            try:
                records = sample_states()
                failures = 0
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                failures += 1
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
                wall = time.time()
                lines = log.lines()
                if not backlog_loaded:
                    backlog_loaded = True
                    lines = log.backlog() + lines
                for line in lines:
                    event = parse_block(line)
                    # only connection attempts aimed at this firewall's own public addresses; blocked
                    # forwarded traffic (e.g. another host's outbound packets) is not an inbound probe
                    if event and event["destination"] in local_addresses:
                        at = block_event_time(line, now, wall)
                        if at is not None:
                            blocks.add(event, at)
                if block_meta_checked is None or started - block_meta_checked >= BLOCK_REFRESH_SECONDS:
                    descriptions, interfaces, leases = rule_descriptions(), interface_names(), lease_names()
                    block_meta_checked = started
                if blocklists_checked is None or started - blocklists_checked >= BLOCKLIST_REFRESH_SECONDS:
                    blocklists.refresh(blocklist_tables())
                    blocklists_checked = started
                payload = snapshot(tracker, geo, local_addresses, role, now, time.time(), resolver, {
                    "names": leases, "networks": networks, "interfaces": interfaces, "blocklists": blocklists,
                })
                origin = next((location["id"] for location in payload["locations"] if location["local"]), None)
                if origin is None and local_addresses:
                    origin = sorted(local_addresses)[0]
                    geo.resolve([origin])
                payload["blocks"] = block_snapshot(
                    blocks, geo, local_addresses, origin, now, descriptions, interfaces, blocklists,
                )
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
        # never run back to back: rest at least as long as a slow sample took, and back off
        # exponentially while sampling keeps failing
        took = time.monotonic() - started
        # a viewer polls every 2 s; when polls stop (background tab, closed page) sample slowly
        # until the collector's idle timeout ends it
        interval = INTERVAL if requested(REQUEST_MARKER, ACTIVE_VIEWER_SECONDS) else IDLE_INTERVAL
        rest = max(interval - took, took, 0.05)
        if failures:
            rest = max(rest, min(MAX_FAILURE_BACKOFF, 2.0 ** failures))
        time.sleep(rest)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        sys.exit(0)
