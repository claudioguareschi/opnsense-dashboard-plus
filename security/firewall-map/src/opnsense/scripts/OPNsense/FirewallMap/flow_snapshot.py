#!/usr/local/bin/python3

"""Return a bounded, read-only PF state sample for Firewall Map.

This is intentionally a bootstrap endpoint, not the long-lived collector. The
collector will retain state counters between samples, aggregate eligible public
flows, and emit only map-ready deltas to the browser.
"""

import json
import ipaddress
import re
import subprocess
from datetime import datetime, timezone


PFCTL = "/sbin/pfctl"
MMDBLOOKUP = "/usr/local/bin/mmdblookup"
CITY_DATABASE = "/usr/local/share/GeoIP/GeoLite2-City.mmdb"
MAX_RECORDS = 250
COUNTERS = re.compile(r"(?P<packets_in>\d+):(?P<packets_out>\d+) pkts,\s+(?P<bytes_in>\d+):(?P<bytes_out>\d+) bytes")
ENDPOINT = re.compile(r"^(?P<address>.+?)(?::(?P<port>\d+))?$")
GEO_CACHE = {}


def endpoint(value):
    """Split a PF endpoint while keeping address parsing deliberately IPv4-only."""
    match = ENDPOINT.match(value.strip("()"))
    if not match:
        return {"address": None, "port": None}
    return {"address": match.group("address"), "port": match.group("port")}


def state_snapshot(output, max_records=MAX_RECORDS):
    """Parse the same directional endpoint fields used by OPNsense's state API."""
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
                "nat": endpoint(parts[3]) if len(parts) > 3 and parts[3].startswith("(") else None,
            }
            continue
        if header is None:
            continue
        counters = COUNTERS.search(line)
        if not counters:
            continue
        record = {
            "interface": header["interface"],
            "protocol": header["protocol"],
            "state": header["state"],
            "direction": header["direction"],
            "src": header["src"],
            "dst": header["dst"],
            "nat": header["nat"],
            **{key: int(value) for key, value in counters.groupdict().items()},
        }
        records.append(record)
        header = None
        if len(records) >= max_records:
            break
    return records


def public_ipv4(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and address.is_global


def local_public_addresses():
    """Read public IPv4 addresses directly configured on this firewall."""
    try:
        output = subprocess.run(
            ["/sbin/ifconfig", "-a"], capture_output=True, check=False, text=True, timeout=2,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return {address for address in re.findall(r"\binet\s+(\d+(?:\.\d+){3})", output) if public_ipv4(address)}


def mmdb_value(address, *path):
    try:
        result = subprocess.run(
            [MMDBLOOKUP, "--file", CITY_DATABASE, "--ip", address, *path],
            capture_output=True, check=False, text=True, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"([-+]?\d+(?:\.\d+)?)", result.stdout)
    return float(match.group(1)) if match else None


def geolocate(address):
    """Return only map coordinates; all lookup happens against the local MMDB."""
    if address in GEO_CACHE:
        return GEO_CACHE[address]
    latitude = mmdb_value(address, "location", "latitude")
    longitude = mmdb_value(address, "location", "longitude")
    location = {"id": address, "name": address, "lat": latitude, "lon": longitude} if latitude is not None and longitude is not None else None
    GEO_CACHE[address] = location
    return location


def map_flows(records, local_addresses):
    """Produce Flowmap.gl endpoint pairs only for public firewall traffic.

    PF presents both directions of a state. NAT state records carry the firewall
    public address explicitly; non-NAT states are retained only when one endpoint
    is a public address configured on this firewall. Grouping is intentionally
    bounded and aggregation uses current byte totals until the persistent
    collector replaces this bootstrap snapshot.
    """
    grouped = {}
    for record in records:
        src = record["src"]["address"]
        dst = record["dst"]["address"]
        nat = record["nat"]["address"] if record["nat"] else None
        local = nat if nat and public_ipv4(nat) else (src if src in local_addresses else dst if dst in local_addresses else None)
        remote = dst if local == src else src
        if not local or not public_ipv4(remote) or remote == local or remote in local_addresses:
            continue
        key = (local, remote)
        grouped[key] = grouped.get(key, 0) + record["bytes_in"] + record["bytes_out"]
    return [
        {"origin": local, "dest": remote, "count": max(1, count)}
        for (local, remote), count in sorted(grouped.items(), key=lambda item: item[1], reverse=True)[:50]
    ]


def collect():
    """Run the fixed PF command without a shell and return a safe JSON payload."""
    try:
        result = subprocess.run(
            [PFCTL, "-v", "-s", "state"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "failed", "flows": []}
    if result.returncode != 0:
        return {"status": "failed", "flows": []}
    records = state_snapshot(result.stdout)
    flows = map_flows(records, local_public_addresses())
    location_ids = {flow["origin"] for flow in flows} | {flow["dest"] for flow in flows}
    locations = [location for location in (geolocate(address) for address in location_ids) if location]
    usable_locations = {location["id"] for location in locations}
    flows = [flow for flow in flows if flow["origin"] in usable_locations and flow["dest"] in usable_locations]
    return {
        "status": "ok",
        "sampled_at": datetime.now(timezone.utc).isoformat(),
        "flows": flows,
        "locations": locations,
        "truncated": len(state_snapshot(result.stdout, MAX_RECORDS + 1)) > MAX_RECORDS,
    }


if __name__ == "__main__":
    print(json.dumps(collect(), separators=(",", ":")))
