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
import subprocess
import sys
import time
from datetime import datetime, timezone


PFCTL = "/sbin/pfctl"
IFCONFIG = "/sbin/ifconfig"
MMDBLOOKUP = "/usr/local/bin/mmdblookup"
CITY_DATABASE = "/usr/local/share/GeoIP/GeoLite2-City.mmdb"
OUTPUT_FILE = "/var/run/firewallmap/flows.json"
GEO_CACHE_FILE = "/var/db/firewallmap/geo.json"

INTERVAL = 1.0
FADE_SECONDS = 20.0
MAX_FLOWS = 150
RATE_SMOOTHING = 0.5
HOST_REFRESH_SECONDS = 30.0
GEO_CACHE_SAVE_SECONDS = 60.0
GEO_LOOKUPS_PER_SAMPLE = 25
GEO_CACHE_MAX = 20000

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


def lookup_location(address):
    """Resolve one address against the local GeoLite City database (never a remote service)."""
    try:
        result = subprocess.run(
            [MMDBLOOKUP, "--file", CITY_DATABASE, "--ip", address],
            capture_output=True, check=False, text=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    values = parse_mmdb(result.stdout)
    try:
        latitude = float(values[("location", "latitude")])
        longitude = float(values[("location", "longitude")])
    except (KeyError, ValueError):
        return None
    return {
        "lat": round(latitude, 4),
        "lon": round(longitude, 4),
        "city": values.get(("city", "names", "en")),
        "country": values.get(("country", "iso_code")) or values.get(("registered_country", "iso_code")),
    }


class GeoCache:
    """IP -> location cache persisted across restarts and invalidated when the MMDB changes."""

    def __init__(self, path=GEO_CACHE_FILE, database=CITY_DATABASE, lookup=lookup_location):
        self.path = path
        self.database = database
        self.lookup = lookup
        self.entries = {}
        self.dirty = False
        self.saved_at = time.monotonic()
        self.database_mtime = self._database_mtime()
        self._load()

    def _database_mtime(self):
        try:
            return int(os.stat(self.database).st_mtime)
        except OSError:
            return None

    def _load(self):
        try:
            with open(self.path) as handle:
                cached = json.load(handle)
        except (OSError, ValueError):
            return
        if cached.get("database_mtime") == self.database_mtime:
            self.entries = cached.get("entries", {})

    def save(self, force=False):
        if not self.dirty or (not force and time.monotonic() - self.saved_at < GEO_CACHE_SAVE_SECONDS):
            return
        if len(self.entries) > GEO_CACHE_MAX:
            self.entries = dict(list(self.entries.items())[-GEO_CACHE_MAX:])
        write_json(self.path, {"database_mtime": self.database_mtime, "entries": self.entries})
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
            total = totals.setdefault(pair, {"toward": 0, "away": 0, "packets": 0, "states": 0, "protocols": set()})
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


def snapshot(tracker, geo, local_addresses, role, now, wall_time):
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
        })
    locations = []
    for address in sorted(location_ids):
        location = geo.get(address)
        locations.append({
            "id": address,
            "name": ", ".join(part for part in (location.get("city"), location.get("country")) if part) or address,
            "lat": location["lat"],
            "lon": location["lon"],
            "local": address in local_addresses,
        })
    return {
        "status": "ok",
        "sampled_at": datetime.fromtimestamp(wall_time, timezone.utc).isoformat(),
        "interval": INTERVAL,
        "carp": role,
        "tracked_flows": len(tracker.flows),
        "flows": flows,
        "locations": locations,
    }


def sample_states():
    result = subprocess.run(
        [PFCTL, "-vv", "-s", "state"], capture_output=True, check=False, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError("pfctl failed")
    return parse_states(result.stdout)


def run():
    tracker = FlowTracker()
    geo = GeoCache()
    local_addresses, role = set(), None
    host_checked = None
    while True:
        started = time.monotonic()
        if host_checked is None or started - host_checked >= HOST_REFRESH_SECONDS:
            local_addresses, role = host_info()
            host_checked = started
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
            write_json(OUTPUT_FILE, snapshot(tracker, geo, local_addresses, role, now, time.time()))
            geo.save()
        time.sleep(max(0.05, INTERVAL - (time.monotonic() - started)))


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        sys.exit(0)
