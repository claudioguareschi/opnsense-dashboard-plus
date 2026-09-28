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

import base64
import binascii
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
import firewallmap_threats as threats  # noqa: E402


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
# with nobody watching, the review queue is still fed from a slow sample (states outlive this)
BACKGROUND_INTERVAL = 20.0
THREAT_RECORD_SECONDS = 20.0
THREAT_PRUNE_SECONDS = 3600.0
RC_SCRIPT = "/usr/local/etc/rc.d/firewallmap"
FILTER_LOG = "/var/log/filter/latest.log"
# Suricata's alert log (EVE JSON); read locally, only alert events
EVE_LOG = "/var/log/suricata/eve.json"
IDS_STATS_FILE = "/var/run/firewallmap/ids_stats.json"
IDS_LIST = "Suricata IDS"
# alerts are remembered this long per remote address; severity 1-2 flags the address as a threat
ALERT_WINDOW_SECONDS = 3600
ALERT_FLAG_SEVERITY = 2
MAX_ALERT_SOURCES = 2000
MAX_SIGNATURES_PER_SOURCE = 10
ALERT_BACKLOG_BYTES = 2 * 1024 * 1024
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
RELOAD_MARKER = "/var/run/firewallmap/reload"
# read back this much of the log when the collector starts, so the 10-minute hit window is full
BACKLOG_BYTES = 2 * 1024 * 1024
BLOCK_REFRESH_SECONDS = 60
# threat intelligence: pf tables behind URL/external aliases and well-known feed tables
BLOCKLIST_REFRESH_SECONDS = 300
BLOCKLIST_ALIAS_TYPES = {"urltable", "url", "urljson", "external"}
BLOCKLIST_TABLE_PREFIXES = ("crowdsec", "__qfeeds", "qfeeds", "spamhaus", "firehol", "abuse", "fwmap_")
BLOCKLIST_MAX_ENTRIES = 500000
BLOCKLIST_MAX_TOTAL = 1000000
# addresses an operator marked, and AbuseIPDB's daily blacklist, always count as threats
WATCHLIST_TABLE = "FWMAP_Watchlist"
ABUSEIPDB_BLACKLIST = "/var/db/firewallmap/abuseipdb_blacklist.txt"
ABUSEIPDB_LIST = "AbuseIPDB blacklist"
REPUTATION_LIST = "AbuseIPDB (looked up)"
REPUTATION_THRESHOLD = 75
REPUTATION_MAX_AGE = 30 * 86400
# verdicts from AbuseIPDB lookups, kept longer than the full lookup results
REPUTATION_KIND = "reputation"
REPUTATION_REFRESH_SECONDS = 60
CGNAT = ipaddress.ip_network("100.64.0.0/10")
SETTINGS_REFRESH_SECONDS = 30
CACHE_DB = "/var/db/firewallmap/cache.db"

# one PF walk every 2 s: the dashboard polls every 2 s, so faster sampling only costs CPU
INTERVAL = 2.0
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
    # what scanners knock on most, so blocked attempts read as services too
    ("tcp", "23"): "Telnet", ("tcp", "110"): "POP3", ("tcp", "135"): "MS RPC", ("tcp", "139"): "NetBIOS",
    ("udp", "137"): "NetBIOS", ("tcp", "445"): "SMB", ("udp", "161"): "SNMP", ("tcp", "1433"): "MS SQL",
    ("tcp", "1723"): "PPTP", ("udp", "1900"): "SSDP", ("tcp", "2375"): "Docker API", ("tcp", "3306"): "MySQL",
    ("tcp", "5060"): "SIP", ("udp", "5060"): "SIP", ("tcp", "5432"): "PostgreSQL", ("tcp", "5900"): "VNC",
    ("tcp", "6379"): "Redis", ("tcp", "8291"): "MikroTik Winbox", ("tcp", "9200"): "Elasticsearch",
    ("tcp", "27017"): "MongoDB", ("udp", "11211"): "Memcached", ("tcp", "2222"): "SSH alt",
}


def service_port_label(protocol, port):
    """'443/tcp' for the summary sentence; ICMP has no port."""
    if protocol in ("icmp", "ipv6-icmp") or not port:
        return None
    return f"{port}/{protocol}"


def service_name(protocol, port):
    """Name the responder side of a connection (the service being used)."""
    if protocol in ("icmp", "ipv6-icmp"):
        return "ICMP"
    if port is None:
        return protocol.upper()
    return SERVICES.get((protocol, port), f"{protocol.upper()}/{port}")

COUNTERS = re.compile(r"(?P<packets_in>\d+):(?P<packets_out>\d+) pkts,\s+(?P<bytes_in>\d+):(?P<bytes_out>\d+) bytes")
AGE = re.compile(r"\bage (?:(?P<days>\d+)d)?(?P<h>\d+):(?P<m>\d+):(?P<s>\d+)")
RLABEL = re.compile(r"\brlabel ([^,\s]+)")
STATE_ID = re.compile(r"\bid: (?P<id>[0-9a-f]+) creatorid: (?P<creator>[0-9a-f]+)")
ORIGIF = re.compile(r"\borigif: (?P<ifname>\S+)")
ENDPOINT = re.compile(r"^(?P<address>.+?)(?::(?P<port>\d+))?$")
MMDB_KEY = re.compile(r'^"(?P<key>[^"]+)":\s*$')
MMDB_STRING = re.compile(r'^"(?P<value>.*)" <utf8_string>$')
MMDB_NUMBER = re.compile(r"^(?P<value>[-+]?\d+(?:\.\d+)?) <(?:double|float|uint\d+|int\d+)>$")


def endpoint(value):
    """Split a PF endpoint while keeping address parsing deliberately IPv4-only."""
    value = value.strip("()")
    # fast path for the common "a.b.c.d:port" / "a.b.c.d" forms (no regex: this runs per state)
    if value.count(":") <= 1:
        address, _, port = value.partition(":")
        if address and (not port or port.isdigit()):
            return {"address": address, "port": port or None}
    match = ENDPOINT.match(value)
    if not match:
        return {"address": None, "port": None}
    return {"address": match.group("address"), "port": match.group("port")}


def parse_states(output):
    """Parse `pfctl -vv -s state` using the same endpoint fields as OPNsense's state API."""
    records = []
    header = None
    skipping = False
    for line in output.splitlines():
        if not line.startswith((" ", "\t")):
            parts = line.split()
            arrow = next((index for index, part in enumerate(parts) if part in ("->", "<-")), None)
            if len(parts) < 6 or arrow is None or arrow < 3 or arrow + 1 >= len(parts):
                header = None
                skipping = True
                continue
            # "A [(A')] -> B [(B')] STATE": translations follow the endpoint they belong to
            direction = "out" if parts[arrow] == "->" else "in"
            left = endpoint(parts[2])
            right = endpoint(parts[arrow + 1])
            translated = arrow > 3 and parts[3].startswith("(")
            if not translated and not public_ipv4(left["address"]) and not public_ipv4(right["address"]):
                # LAN-internal state (or the LAN side of a NAT pair): never drawn, skip its details
                header = None
                skipping = True
                continue
            skipping = False
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
        if skipping:
            continue  # detail lines of a skipped state must not attach to the previous record
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
            # the rule that created the state (same label as in the firewall log)
            "rule": (RLABEL.search(line) or [None, None])[1] if "rlabel" in line else None,
        })
        header = None
    return records


@functools.lru_cache(maxsize=65536)
def public_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return False
    # multicast (e.g. CARP advertisements to 224.0.0.18) counts as global in ipaddress, not here
    return address.version == 4 and address.is_global and not address.is_multicast


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


def inside_endpoint(record):
    """The LAN endpoint behind a NAT state (the private one among source, destination and NAT)."""
    for side in (record["nat"], record["src"], record["dst"]):
        if side and private_ipv4(side["address"]):
            return side
    return None


def lan_rule_index(records):
    """Rules of the inside-facing states, keyed by (protocol, inside address:port, remote address:port).

    A NATed connection has two states: the one on the inside interface was created by the rule the
    operator wrote (e.g. "IoT to Internet"), the one on WAN by the automatic outbound rule. The map
    reports the first.
    """
    index = {}
    for record in records:
        rule = record.get("rule")
        if not rule or record["nat"]:
            continue
        src, dst = record["src"], record["dst"]
        if private_ipv4(src["address"]) and public_ipv4(dst["address"]):
            index[(record["protocol"], src["address"], src["port"], dst["address"], dst["port"])] = rule
    return index


def rule_for(record, pair, lan_rules):
    inside = inside_endpoint(record)
    if inside and lan_rules:
        far = record["src"] if record["src"]["address"] == pair[1] else record["dst"]
        rule = lan_rules.get((record["protocol"], inside["address"], inside["port"], far["address"], far["port"]))
        if rule:
            return rule
    return record.get("rule")


def orientation(record, remote):
    """(remote started it, the service's port) for one state.

    A state normally starts at its initiator. When the opening packet passed the other CARP
    node (asymmetric paths), the reply from an inside server creates an "outbound" state from a
    well-known port to an ephemeral one: that connection was really started by the remote side.
    """
    if record["src"]["address"] == remote:
        return True, record["dst"]["port"]
    # behind outbound NAT the source port that matters is the inside host's, not the translated one
    source, target = (inside_endpoint(record) or record["src"])["port"], record["dst"]["port"]
    # the client side must look ephemeral: keeps NFS (reserved port to 2049) and IKE (500 to 4500) outbound
    if (record["protocol"] in ("tcp", "udp") and source and target and source.isdigit() and target.isdigit()
            and int(source) < 1024 and int(target) >= 10000):
        return True, source
    return False, target


def inside_address(record):
    side = inside_endpoint(record)
    return side["address"] if side else None


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
    restarts, are written incrementally and are pruned by age and count. A cache must never
    take the collector down: a damaged file is moved aside, and any later database error
    degrades to "not cached" instead of raising.
    """

    def __init__(self, path=CACHE_DB):
        self.path = path
        self.lock = threading.Lock()
        try:
            self.db = self._open(path)
        except sqlite3.Error:
            try:
                os.replace(path, f"{path}.corrupt")
                self.db = self._open(path)
            except (OSError, sqlite3.Error):
                self.db = self._open(":memory:")

    @staticmethod
    def _open(path):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("CREATE TABLE IF NOT EXISTS cache (kind TEXT, key TEXT, value TEXT, stored REAL, PRIMARY KEY (kind, key))")
        db.execute("SELECT count(*) FROM cache").fetchone()
        return db

    def _query(self, sql, parameters=()):
        try:
            with self.lock:
                return self.db.execute(sql, parameters).fetchall()
        except sqlite3.Error as error:
            print(f"firewallmap: cache query failed: {error}", file=sys.stderr)
            return []

    def get_all(self, kind, max_age=None, now=None):
        now = time.time() if now is None else now
        rows = self._query("SELECT key, value, stored FROM cache WHERE kind = ?", (kind,))
        result = {}
        for key, value, stored in rows:
            if max_age is None or now - stored < max_age:
                try:
                    result[key] = json.loads(value)
                except ValueError:
                    continue
        return result

    def get(self, kind, key, max_age=None, now=None):
        now = time.time() if now is None else now
        rows = self._query("SELECT value, stored FROM cache WHERE kind = ? AND key = ?", (kind, key))
        if not rows or (max_age is not None and now - rows[0][1] >= max_age):
            return None
        try:
            return json.loads(rows[0][0])
        except ValueError:
            return None

    def put_many(self, kind, items, now=None):
        now = time.time() if now is None else now
        rows = [(kind, key, json.dumps(value), now) for key, value in items]
        with self.lock:
            try:
                self.db.execute("BEGIN")
                self.db.executemany("INSERT OR REPLACE INTO cache (kind, key, value, stored) VALUES (?, ?, ?, ?)", rows)
                self.db.execute("COMMIT")
            except sqlite3.Error as error:
                print(f"firewallmap: cache write failed: {error}", file=sys.stderr)
                try:
                    self.db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass

    def prune(self, kind, max_age=None, keep=None, now=None):
        now = time.time() if now is None else now
        if max_age is not None:
            self._query("DELETE FROM cache WHERE kind = ? AND stored < ?", (kind, now - max_age))
        if keep is not None:
            self._query(
                "DELETE FROM cache WHERE kind = ? AND key NOT IN "
                "(SELECT key FROM cache WHERE kind = ? ORDER BY stored DESC LIMIT ?)", (kind, kind, keep),
            )

    def clear(self, kind):
        self._query("DELETE FROM cache WHERE kind = ?", (kind,))


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
        self.store._query("DELETE FROM cache WHERE kind LIKE 'geo:%' AND kind != ?", (self.kind,))

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
        lan_rules = lan_rule_index(records)
        for record in records:
            pair = flow_endpoints(record, local_addresses)
            if pair is None or record.get("id") is None:
                continue
            # PF counts initiator->responder first; src is the initiator in parse_states()
            src_is_remote = record["src"]["address"] == pair[1]
            remote_initiated, service_port = orientation(record, pair[1])
            toward, away = (
                (record["bytes_in"], record["bytes_out"]) if src_is_remote
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
                "inside": {}, "egress": {}, "remote_started": 0, "local_started": 0, "targets": {},
                "ports": {}, "oldest": 0, "bytes_toward": 0, "bytes_away": 0, "rules": {},
            })
            weight = delta[0] + delta[1] + 1
            inside_side = inside_endpoint(record)
            inside = inside_side["address"] if inside_side else None
            if remote_initiated:
                total["remote_started"] += weight
                # what the remote side connected to: a port-forward target (its inside port) or
                # the firewall itself; ICMP ids are not ports
                aimed = inside_side or record["dst"]
                if not src_is_remote:
                    port = service_port or ""  # a reply state: the server's own port
                elif record["protocol"] in ("icmp", "ipv6-icmp"):
                    port = ""
                else:
                    port = aimed["port"] or ""
                target = f'{record["protocol"]}|{inside or pair[0]}|{port}'
                total["targets"][target] = total["targets"].get(target, 0) + weight
            else:
                total["local_started"] += weight
            if inside:
                total["inside"][inside] = total["inside"].get(inside, 0) + weight
            if record.get("origif"):
                total["egress"][record["origif"]] = total["egress"].get(record["origif"], 0) + weight
            service = service_name(record["protocol"], service_port)
            total["services"][service] = total["services"].get(service, 0) + delta[0] + delta[1] + 1
            total["ports"].setdefault(service, service_port_label(record["protocol"], service_port))
            if record.get("age") is not None and record["age"] > total["oldest"]:
                total["oldest"] = record["age"]
            # bytes moved so far by the connections open now, and the rules that let them through
            total["bytes_toward"] += current[0]
            total["bytes_away"] += current[1]
            rule = rule_for(record, pair, lan_rules)
            if rule:
                total["rules"][rule] = total["rules"].get(rule, 0) + 1
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
            flow["service_ports"] = {name: total["ports"][name] for name in flow["services"] if total["ports"].get(name)}
            # how long the oldest connection behind this flow has been open
            flow["age"] = total["oldest"]
            flow["transferred"] = (total["bytes_toward"], total["bytes_away"])
            flow["rule"] = max(total["rules"], key=total["rules"].get) if total["rules"] else None
            flow["inside"] = [address for address, _ in sorted(total["inside"].items(), key=lambda item: -item[1])][:MAX_INSIDE]
            flow["egress"] = max(total["egress"], key=total["egress"].get) if total["egress"] else None
            started = total["remote_started"] + total["local_started"]
            share = total["remote_started"] / started if started else 0.0
            flow["initiated"] = "remote" if share >= 0.75 else "local" if share <= 0.25 else "both"
            flow["targets"] = [target for target, _ in sorted(total["targets"].items(), key=lambda item: -item[1])][:MAX_INSIDE]
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
    aliases = set()
    blocked = blocked_rule_tables() if blocked is None else blocked
    try:
        root = ElementTree.parse(config).getroot()
        for alias in root.iterfind(".//OPNsense/Firewall/Alias/aliases/alias"):
            name = alias.findtext("name")
            aliases.add(name)
            if alias.findtext("type") in BLOCKLIST_ALIAS_TYPES and alias.findtext("enabled") != "0" and name in blocked:
                names.add(name)
    except (OSError, ElementTree.ParseError):
        pass
    if tables is None:
        try:
            tables = subprocess.run([PFCTL, "-sT"], capture_output=True, check=False, text=True, timeout=10).stdout.split()
        except (OSError, subprocess.TimeoutExpired):
            tables = []
    names.update(table for table in tables if is_feed_table(table, aliases))
    return {name for name in names if name and name in tables}


def is_feed_table(table, aliases):
    """Well-known feed tables; this plugin's FWMAP_ feeds only while their alias still exists
    (pf keeps the table of a deleted alias until the next filter reload)."""
    lowered = table.lower()
    if lowered.startswith("fwmap_"):
        return table in aliases
    return lowered.startswith(BLOCKLIST_TABLE_PREFIXES)


# only list-type aliases are sensible threat lists (not LAN host/network aliases)
THREAT_CANDIDATE_TYPES = BLOCKLIST_ALIAS_TYPES

# curated public feeds this plugin can add as daily URL table aliases
FEEDS = [
    {"name": "FWMAP_Spamhaus_DROP", "label": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop.txt",
     "about": "Hijacked and criminal netblocks"},
    {"name": "FWMAP_Feodo", "label": "abuse.ch Feodo Tracker",
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "about": "Botnet command-and-control servers"},
    {"name": "FWMAP_ET_Compromised", "label": "Emerging Threats compromised",
     "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "about": "Hosts known to be compromised"},
    {"name": "FWMAP_FireHOL_L1", "label": "FireHOL level 1",
     "url": "https://iplists.firehol.org/files/firehol_level1.netset",
     "about": "Combined attack sources (DROP, Feodo, DShield...). Also lists private and bogon ranges: "
              "do not use it to block LAN traffic."},
]


def pf_tables():
    try:
        return subprocess.run([PFCTL, "-sT"], capture_output=True, check=False, text=True, timeout=10).stdout.split()
    except (OSError, subprocess.TimeoutExpired):
        return []


def threat_list_candidates(config=CONFIG_XML, tables=None):
    """Tables an administrator may choose as threat lists, with their alias type."""
    tables = pf_tables() if tables is None else tables
    candidates = {}
    aliases = set()
    try:
        root = ElementTree.parse(config).getroot()
        for alias in root.iterfind(".//OPNsense/Firewall/Alias/aliases/alias"):
            name, kind = alias.findtext("name"), alias.findtext("type")
            aliases.add(name)
            if name in tables and kind in THREAT_CANDIDATE_TYPES:
                candidates[name] = {"name": name, "type": kind, "description": alias.findtext("description") or ""}
    except (OSError, ElementTree.ParseError):
        pass
    for table in tables:
        if is_feed_table(table, aliases) and table not in candidates:
            candidates[table] = {"name": table, "type": "feed", "description": ""}
    for feed in FEEDS:
        entry = candidates.setdefault(feed["name"], {"name": feed["name"], "type": "urltable"})
        entry.update({"label": feed["label"], "description": feed["about"], "url": feed["url"],
                      "curated": True, "installed": feed["name"] in aliases})
    return sorted(candidates.values(), key=lambda item: (not item.get("curated"), item["name"].lower()))


def chosen_threat_lists(setting, config=CONFIG_XML):
    """The administrator's choice when set, otherwise the automatic selection."""
    names = {name.strip() for name in (setting or "").split(",") if name.strip()}
    tables = set(pf_tables())
    chosen = (names & tables) if names else blocklist_tables(config, list(tables))
    if WATCHLIST_TABLE in tables:
        chosen.add(WATCHLIST_TABLE)
    return chosen


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
            try:
                with open(ABUSEIPDB_BLACKLIST) as handle:
                    contents[ABUSEIPDB_LIST] = handle.read().split()[:BLOCKLIST_MAX_ENTRIES]
            except OSError:
                pass
            self.index = self.build(contents)
        finally:
            self.refreshing = False

    def refresh(self, tables, background=True):
        if self.refreshing:
            return False
        self.refreshing = True
        if background:
            threading.Thread(target=self._refresh, args=(tables,), daemon=True).start()
        else:
            self._refresh(tables)
        return True

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
            store.prune("hostname", max_age=ttl, keep=MAX_HOSTNAMES)
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
            self.store.prune("hostname", max_age=self.ttl, keep=MAX_HOSTNAMES)
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
        "source_port": ports[0] or None,
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
            entry = {"buckets": {}, "total": 0, "ports": {}, "first": now}
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


def block_snapshot(blocks, geo, local_addresses, origin, now, descriptions, interfaces, blocklists=None,
                   reputation=None, alerts=None):
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
            # the same service names and ports as permitted flows, busiest first
            "services": [{"name": service_name(*(port.split("/", 1) + [None])[:2]),
                          "port": f'{port.split("/", 1)[1]}/{port.split("/", 1)[0]}' if "/" in port else None,
                          "hits": hits}
                         for port, hits in sorted(entry["ports"].items(), key=lambda item: -item[1])][:5],
            "port_count": len(entry["ports"]),
            "seconds": round(now - entry.get("first", now)),
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
            "lists": threat_lists_for(address, blocklists, reputation),
            "abuseipdb": reputation.scores.get(address) if reputation is not None else None,
            "ids": alerts.summary(address) if alerts is not None else None,
        })
    return result


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
            "lat": location["lat"],
            "lon": location["lon"],
            "city": location.get("city") or location.get("region"),
            "country": location.get("country_name") or location.get("country"),
            "country_code": location.get("country"),
            "asn": location.get("asn"),
            "as_org": location.get("as_org"),
            "lists": threat_lists_for(address, blocklists, reputation),
            "abuseipdb": reputation.scores.get(address) if reputation is not None else None,
            "ids": alerts.summary(address, now),
        })
    return result


def describe_target(target, names, networks, interfaces, local_addresses):
    """'tcp|192.168.1.2|443' -> the inside host (or this firewall) a remote connection was aimed at."""
    protocol, address, port = target.split("|")
    service = service_name(protocol, port or None)
    if address in local_addresses:
        return {"ip": address, "port": port, "protocol": protocol, "name": "firewall", "interface": None,
                "service": service, "firewall": True}
    described = describe_inside(address, names, networks, interfaces)
    described.update({"port": port, "protocol": protocol, "service": service})
    return described


def threat_lists_for(address, blocklists, reputation, alerts=None):
    lists = blocklists.lookup(address) if blocklists else []
    if reputation is not None and address in reputation.flagged:
        lists = lists + [REPUTATION_LIST]
    if alerts is not None and alerts.flags(address):
        lists = lists + [IDS_LIST]
    return lists


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
        "public": f"{key[1]}:{key[2]}" if key[2] else key[1],
        "remote": f"{key[3]}:{key[4]}" if key[4] else key[3],
        "inside": None, "remote_started": None, "bytes_in": None, "bytes_out": None, "age": None,
        "rule": None, "rule_description": None, "interface": None, "state": None, "decision": None,
        "source": None, "seen": None,
    }
    connection.update(fields)
    return connection


PORT_FORWARD = re.compile(
    r"^rdr (?:pass )?on (?P<iface>\S+) inet proto (?P<proto>\{[^}]*\}|\S+) from .*? to .*? port \{?(?P<ports>[\d:, ]+)\}?"
    r" -> (?P<target>\S+)(?: port (?P<tport>\d+))?(?:.*?# (?P<descr>.*))?$")


def port_forwards(path=RULES_DEBUG, table_lookup=None):
    """Port forwards from the running ruleset: protocol and public port(s) -> inside host and port."""
    def lookup(name):
        try:
            out = subprocess.run([PFCTL, "-t", name, "-T", "show"], capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.TimeoutExpired):
            return None
        first = out.split()
        return first[0] if first else None
    table_lookup = table_lookup or lookup
    forwards = []
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                if not line.startswith("rdr "):
                    continue
                match = PORT_FORWARD.match(line.strip())
                if not match:
                    continue
                target = match["target"]
                if target.startswith("$"):
                    target = table_lookup(target[1:])
                if not target or not private_ipv4(target):
                    continue  # captive portal and other redirects to the firewall itself
                ports = []
                for part in re.split(r"[ ,]+", match["ports"].strip()):
                    low, _, high = part.partition(":")
                    if low.isdigit():
                        ports.append((int(low), int(high) if high.isdigit() else int(low)))
                forwards.append({
                    "protocols": set(re.findall(r"tcp|udp", match["proto"])),
                    "ports": ports, "target": target, "target_port": match["tport"],
                    "description": (match["descr"] or "").strip(),
                })
    except OSError:
        pass
    return forwards


def forward_target(forwards, protocol, port):
    """(inside host:port, rule description) a port forward sends this public port to, or (None, None)."""
    if not port or not str(port).isdigit():
        return None, None
    port = int(port)
    for forward in forwards or []:
        if protocol in forward["protocols"] and any(low <= port <= high for low, high in forward["ports"]):
            return f'{forward["target"]}:{forward["target_port"] or port}', forward["description"]
    return None, None


def outside_key(protocol, public_ip, public_port, remote_ip, remote_port):
    """The connection as seen outside NAT, which is what Suricata on WAN observes."""
    return (protocol, public_ip, str(public_port or ""), remote_ip, str(remote_port or ""))


def state_outside(record, pair):
    """(outside key, inside endpoint) of a PF state touching a public remote address, else None."""
    local, remote = pair
    nat = record["nat"]
    # pfctl prints the wire side first for outbound states ("wire (original) -> remote") and last
    # for inbound ones ("original (wire) <- remote"); the outbound NAT source port, including the
    # firewall's own randomised DNS ports, is only right on the wire side
    if record["direction"] == "out":
        public = record["src"]
    else:
        public = nat if nat else record["dst"]
    if public["address"] != local:
        return None  # NAT to a tunnel address: Suricata on WAN never sees this tuple
    far = record["src"] if record["src"]["address"] == remote else record["dst"]
    if far["address"] != remote:
        return None
    return outside_key(record["protocol"], local, public["port"], remote, far["port"])


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
        self.pending = []
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
                inside=f'{inside["address"]}:{inside["port"]}' if inside and inside["port"] else
                       (inside["address"] if inside else None),
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

    def alert_connection(self, key, alert, local_addresses, now):
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

    def add_alert(self, alert, local_addresses, now):
        self.stats["alerts"] += 1
        if not alert["src_port"] or not alert["dst_port"]:
            self.stats["no_ports"] += 1  # ICMP and other port-less protocols: address history only
            return None
        if len(self.pending) >= MAX_PENDING_ALERTS:
            self.pending.pop(0)
        self.pending.append((now, alert))
        return None

    def resolve(self, local_addresses, now):
        """Try pending alerts against what PF and the firewall log have shown; give up after a while."""
        still = []
        for received, alert in self.pending:
            key = self.alert_key(alert, local_addresses)
            if key in self.current:
                kind = "ambiguous" if key in getattr(self, "ambiguous_keys", ()) else "current"
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
                kind, connection = "alert", self.alert_connection(key, alert, local_addresses, now)
            if kind != "alert":
                self.stats[kind] += 1
            self._attach(key, kind, connection, alert, now)
        self.pending = still
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
        return min((item["severity"] for group in flow["alerts"].values() for item in group.values()), default=3)

    def snapshot(self, geo, origin, names, networks, interfaces, blocklists=None, reputation=None, now=None):
        """Correlated connections for the map: each is drawn as its own arc."""
        now = time.time() if now is None else now
        geo.resolve([key[3] for key in self.flows])
        result = []
        for key, flow in sorted(self.flows.items(), key=lambda item: -item[1]["last"]):
            location = geo.get(key[3])
            if location is None:
                continue
            active = key in self.current
            # when the connection was last seen open, so the map can let its arc fade out
            if active:
                flow.pop("closed", None)
            else:
                flow.setdefault("closed", now)
            connection = self.current.get(key) or flow["connection"]
            inside = (connection.get("inside") or "").rsplit(":", 1)[0] if flow["kind"] != "blocked" else ""
            groups = []
            for flow_id, signatures in flow["alerts"].items():
                groups.append({"flow_id": flow_id, "signatures": sorted(
                    signatures.values(), key=lambda item: (item["severity"], -item["count"]))[:5]})
            actions = {item["action"] for group in flow["alerts"].values() for item in group.values()}
            result.append({
                "key": "|".join(key),
                "kind": flow["kind"],
                "active": active,
                "origin": origin,
                "dest": key[3],
                "protocol": key[0],
                "public": f"{key[1]}:{key[2]}" if key[2] else key[1],
                "remote": f"{key[3]}:{key[4]}" if key[4] else key[3],
                "inside": connection.get("inside"),
                "inside_host": describe_inside(inside, names, networks, interfaces) if inside else None,
                "remote_started": connection.get("remote_started"),
                "bytes_in": connection.get("bytes_in"),
                "bytes_out": connection.get("bytes_out"),
                "age": connection.get("age"),
                "rule": connection.get("rule_description") or connection.get("rule"),
                "interface": interfaces.get(connection.get("interface"), connection.get("interface")),
                "severity": self._severity(flow),
                "count": sum(item["count"] for group in flow["alerts"].values() for item in group.values()),
                "last_seconds": round(max(0, now - flow["last"])),
                "closed_seconds": None if active else round(max(0, now - flow["closed"])),
                "groups": groups,
                "ips_dropped": "blocked" in actions,
                "lat": location["lat"],
                "lon": location["lon"],
                "city": location.get("city") or location.get("region"),
                "country": location.get("country_name") or location.get("country"),
                "country_code": location.get("country"),
                "asn": location.get("asn"),
                "as_org": location.get("as_org"),
                "lists": threat_lists_for(key[3], blocklists, reputation),
                "abuseipdb": reputation.scores.get(key[3]) if reputation is not None else None,
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
    try:
        at = datetime.strptime(event.get("timestamp", ""), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        at = None
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
                    correlator.add_alert(alert, local_addresses, now if now is not None else time.time())

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


class Reputation:
    """Addresses already found abusive by an AbuseIPDB lookup, read from the investigation cache."""

    def __init__(self, store, threshold=REPUTATION_THRESHOLD):
        self.store = store
        self.threshold = threshold
        self.flagged = set()
        self.scores = {}
        self.checked = None

    def refresh(self, now):
        if self.checked is not None and now - self.checked < REPUTATION_REFRESH_SECONDS:
            return
        self.checked = now
        rows = {}
        if self.store is not None:
            # full lookups cached before verdicts were kept separately still count
            rows.update(self.store.get_all("abuseipdb", max_age=REPUTATION_MAX_AGE))
            rows.update(self.store.get_all(REPUTATION_KIND, max_age=REPUTATION_MAX_AGE))
        self.flagged = {address for address, data in rows.items()
                        if isinstance(data, dict) and (data.get("score") or 0) >= self.threshold}
        # every cached verdict, so the details can say "clean" as well as "listed"
        self.scores = {address: data.get("score") for address, data in rows.items()
                       if isinstance(data, dict) and data.get("score") is not None}


def snapshot(tracker, geo, local_addresses, role, now, wall_time, hostnames=None, context=None):
    context = context or {}
    names = context.get("names", {})
    networks = context.get("networks", [])
    interfaces = context.get("interfaces", {})
    blocklists = context.get("blocklists")
    reputation = context.get("reputation")
    alerts = context.get("alerts")
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
            "lists": threat_lists_for(remote, blocklists, reputation),
            "ids": alerts.summary(remote, wall_time) if alerts is not None else None,
            "initiated": flow.get("initiated", "local"),
            "targets": [describe_target(target, names, networks, interfaces, local_addresses)
                        for target in flow.get("targets", [])],
            "service_ports": flow.get("service_ports", {}),
            "age": flow.get("age"),
            "transferred": flow.get("transferred"),
            "rule": context.get("descriptions", {}).get(flow.get("rule") or "", "") or None,
            "abuseipdb": reputation.scores.get(remote) if reputation is not None else None,
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
        inside_ip = (connection.get("inside") or "").rsplit(":", 1)[0] if connection.get("inside") else ""
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
        signatures = [item for group in flow["alerts"].values() for item in group.values()]
        if not any(item.get("action") == "blocked" for item in signatures):
            continue
        connection = flow["connection"]
        inside = connection.get("inside")
        inside_ip = inside.rsplit(":", 1)[0] if inside else None
        started_by_remote = bool(connection.get("remote_started"))
        port = (inside.rsplit(":", 1)[1] if inside and ":" in inside else key[2]) if started_by_remote else key[4]
        entry = entries.setdefault(remote, {
            "lists": threat_lists_for(remote, blocklists, reputation) + [IDS_LIST],
            "inbound": 0, "outbound": 0, "targets": [], "inside": [], "services": [], "bytes": 0,
            "youngest": None, "service_ports": {}, "status_hint": "dropped",
        })
        entry["inbound" if started_by_remote else "outbound"] += 1
        if started_by_remote:
            target = f"{key[0]}|{inside_ip or key[1]}|{port}"
            if target not in entry["targets"]:
                entry["targets"].append(target)
        elif inside_ip and inside_ip not in entry["inside"]:
            entry["inside"].append(inside_ip)
        service = service_name(key[0], port)
        if service not in entry["services"]:
            entry["services"].append(service)
            entry["service_ports"][service] = f"{port}/{key[0]}"
        entry["bytes"] += (connection.get("bytes_in") or 0) + (connection.get("bytes_out") or 0)
    return entries


class ThreatRecorder:
    """Feeds the review queue; a database problem never stops the collector."""

    def __init__(self, path=threats.DATABASE):
        self.path = path
        self.db = None
        self.recorded = None
        self.pruned = None
        self.last_wall = 0.0

    def update(self, records, local_addresses, blocklists, reputation, now, geo=None, hostnames=None, alerts=None,
               correlator=None, names=None, interfaces=None):
        if self.recorded is not None and now - self.recorded < THREAT_RECORD_SECONDS:
            return
        self.recorded = now
        try:
            if self.db is None:
                self.db = threats.connect(self.path)
            seen = threats.observe(records, flow_endpoints,
                                   lambda address: threat_lists_for(address, blocklists, reputation, correlator),
                                   local_addresses, inside_endpoint, service_name, orientation)
            # who the address belongs to is kept with the entry: the map forgets it once the flow ends
            if geo is not None and seen:
                geo.resolve(list(seen))
            for address, entry in seen.items():
                location = geo.get(address) if geo is not None else None
                name = hostnames.names.get(address) if hostnames is not None else None
                entry["remote"] = {key: value for key, value in {
                    "hostname": name[0] if name else None,
                    "asn": (location or {}).get("asn"),
                    "org": (location or {}).get("as_org"),
                    "country": (location or {}).get("country_name") or (location or {}).get("country"),
                    "country_code": (location or {}).get("country"),
                    "city": (location or {}).get("city"),
                }.items() if value}
            if alerts is not None:
                for address, entry in seen.items():
                    entry["ids"] = alerts.summary(address)
            if correlator is not None:
                seen.update(ips_drops(correlator, seen, self.last_wall, blocklists, reputation))
                for address, entry in seen.items():
                    entry["connections"] = connection_snapshot(address, correlator, names or {}, interfaces or {})
                self.last_wall = time.time()
            threats.record(self.db, seen)
            if self.pruned is None or now - self.pruned >= THREAT_PRUNE_SECONDS:
                threats.prune(self.db)
                self.pruned = now
        except sqlite3.Error as error:
            print(f"firewallmap: threat recording failed: {error}", file=sys.stderr)
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


def block_event_time(line, now, wall):
    """Monotonic time of a log line from its own timestamp (None when outside the hit window)."""
    stamp = log_time(line)
    if stamp is None:
        return now
    age = wall - stamp
    if age > BLOCK_WINDOW_SECONDS:
        return None
    return now - max(0.0, age)


def reload_token(path=RELOAD_MARKER):
    """Opaque token changed by the settings API when the live collector must reload."""
    try:
        with open(path, encoding="ascii") as handle:
            return handle.read(64)
    except OSError:
        return None


def request_reload(path=RELOAD_MARKER):
    """Atomically notify a running collector without losing its in-memory flow history."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.{os.getpid()}"
    with open(temporary, "w", encoding="ascii") as handle:
        handle.write(str(time.time_ns()))
    os.replace(temporary, path)


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
    alerts = AlertTracker()
    correlator = Correlator()
    eve = FilterLogTail(EVE_LOG)
    eve_loaded = False
    descriptions, interfaces, leases, block_meta_checked = {}, {}, {}, None
    blocklists, blocklists_checked = BlocklistIndex(), None
    reputation = Reputation(store)
    recorder = ThreatRecorder()
    recording = False
    geo = None
    problem = None
    local_addresses, role, networks = set(), None, []
    host_checked = None
    settings_checked = None
    reload_checked = reload_token()
    provider = "maxmind"
    while True:
        started = time.monotonic()
        reload_now = reload_token()
        if reload_now != reload_checked:
            reload_checked = reload_now
            settings_checked = None
            blocklists_checked = None
        if host_checked is None or started - host_checked >= HOST_REFRESH_SECONDS:
            local_addresses, role, networks = host_info()
            host_checked = started
        if settings_checked is None or started >= settings_checked + SETTINGS_REFRESH_SECONDS:
            values = geodb.settings()
            recording = recording_wanted(values)
            provider = geodb.effective_provider(values)
            city, asn, problem = database_state(values)
            # a new provider or a refreshed database invalidates cached locations
            if geo is None or geo.database != city or geo.database_mtime != geo._database_mtime():
                if geo is not None:
                    geo.save(force=True)
                geo = GeoCache(store=store, database=city, asn_database=asn)
                geo.forget_old_databases()
            settings_checked = started
        background = idle(started_at)
        if background and not recording:
            if geo is not None:
                geo.save(force=True)
            return
        if background:
            # nobody is watching: only feed the review queue, no map summary, no GeoIP work
            try:
                records = sample_states()
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                print(f"firewallmap: background sample failed: {error}", file=sys.stderr)
            else:
                if ((blocklists_checked is None or started - blocklists_checked >= BLOCKLIST_REFRESH_SECONDS)
                        and blocklists.refresh(chosen_threat_lists(values.get("threat_lists")))):
                    blocklists_checked = started
                reputation.refresh(time.monotonic())
                wall = time.time()
                correlator.observe_states(records, local_addresses, wall, descriptions)
                # blocked attempts stay matchable for late alerts even with no map open
                for line in log.lines():
                    event = parse_block(line)
                    if event and event["destination"] in local_addresses:
                        correlator.observe_block(event, wall, descriptions)
                alerts.feed(eve.lines(), local_addresses, correlator, wall)
                correlator.resolve(local_addresses, wall)
                alerts.expire(wall)
                write_json(IDS_STATS_FILE, correlator.diagnostics())
                recorder.update(records, local_addresses, blocklists, reputation, time.monotonic(), geo, hostnames, alerts,
                                correlator, leases, interfaces)
            # wake at once when a viewer opens the map, not at the end of the slow interval
            while time.monotonic() - started < BACKGROUND_INTERVAL and not requested(REQUEST_MARKER, 2):
                time.sleep(1.0)
            continue
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
                            correlator.observe_block(event, wall, descriptions)
                if block_meta_checked is None or started - block_meta_checked >= BLOCK_REFRESH_SECONDS:
                    descriptions, interfaces, leases = rule_descriptions(), interface_names(), lease_names()
                    correlator.forwards = port_forwards()
                    block_meta_checked = started
                if ((blocklists_checked is None or started - blocklists_checked >= BLOCKLIST_REFRESH_SECONDS)
                        and blocklists.refresh(chosen_threat_lists(values.get("threat_lists")))):
                    blocklists_checked = started
                reputation.refresh(now)
                # while the map is open the queue is always fed; the setting and the widget only
                # decide whether recording continues in the background
                correlator.observe_states(records, local_addresses, wall, descriptions)
                if not eve_loaded:
                    eve_loaded = True
                    # older alerts can only be address history: their connections are not indexed yet
                    alerts.feed(eve.backlog(ALERT_BACKLOG_BYTES), local_addresses)
                alerts.feed(eve.lines(), local_addresses, correlator, wall)
                correlator.resolve(local_addresses, wall)
                alerts.expire(wall)
                write_json(IDS_STATS_FILE, correlator.diagnostics())
                recorder.update(records, local_addresses, blocklists, reputation, now, geo, hostnames, alerts, correlator,
                                leases, interfaces)
                payload = snapshot(tracker, geo, local_addresses, role, now, time.time(), resolver, {
                    "names": leases, "networks": networks, "interfaces": interfaces, "blocklists": blocklists,
                    "reputation": reputation, "alerts": alerts, "descriptions": descriptions,
                })
                origin = next((location["id"] for location in payload["locations"] if location["local"]), None)
                if origin is None and local_addresses:
                    origin = sorted(local_addresses)[0]
                    geo.resolve([origin])
                payload["blocks"] = block_snapshot(
                    blocks, geo, local_addresses, origin, now, descriptions, interfaces, blocklists, reputation,
                    alerts,
                )
                shown = {flow["dest"] for flow in payload["flows"]} | {block["source"] for block in payload["blocks"]}
                payload["alerts"] = alert_snapshot(alerts, geo, origin, shown, blocklists, reputation)
                payload["ids_flows"] = correlator.snapshot(geo, origin, leases, networks, interfaces, blocklists, reputation)
                # which lists are consulted, so the details can show "not listed" per list
                payload["threat_lists"] = list(blocklists.index[0]) + ([REPUTATION_LIST] if reputation.scores else [])
                if origin and geo.get(origin) and not any(location["id"] == origin for location in payload["locations"]):
                    location = geo.get(origin)
                    payload["locations"].append({
                        "id": origin, "name": origin, "lat": location["lat"], "lon": location["lon"], "local": True,
                    })
                payload["provider"] = provider
                write_json(OUTPUT_FILE, payload)
                geo.save()
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
    if sys.argv[1:] == ["tables"]:
        print(json.dumps({"tables": threat_list_candidates(), "automatic": sorted(blocklist_tables())}))
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "ensure":
        # periodic (cron) and after boot: keep the review queue fed while the widget is in use
        if recording_wanted():
            subprocess.run([RC_SCRIPT, "onestart"], capture_output=True, check=False, timeout=10)
        sys.exit(0)
    if sys.argv[1:] == ["reload"]:
        request_reload()
        sys.exit(0)
    try:
        run()
    except KeyboardInterrupt:
        sys.exit(0)
