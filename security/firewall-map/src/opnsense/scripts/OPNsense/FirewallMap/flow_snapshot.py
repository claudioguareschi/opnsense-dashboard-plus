#!/usr/local/bin/python3

"""Return the latest Firewall Map flow summary written by the collector.

The dashboard polls this through configd, so it must stay cheap: it only reads
the compact JSON document the persistent collector rewrites every second, marks
the collector as in use, and starts it if it is not running (it stops by itself
when no dashboard has asked for a while).
"""

import json
import os
import subprocess
import sys
import time


OUTPUT_FILE = "/var/run/firewallmap/flows.json"
REQUEST_MARKER = "/var/run/firewallmap/last_request"
HOSTNAME_MARKER = "/var/run/firewallmap/hostnames_request"
GEODB = "/usr/local/opnsense/scripts/OPNsense/FirewallMap/firewallmap_geodb.py"
RC_SCRIPT = "/usr/local/etc/rc.d/firewallmap"
STALE_SECONDS = 10


def start_collector():
    try:
        subprocess.run([RC_SCRIPT, "onestart"], capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def read_snapshot(path=OUTPUT_FILE, now=None):
    try:
        age = (now or time.time()) - os.stat(path).st_mtime
        with open(path) as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    if age > STALE_SECONDS:
        return None
    payload["age"] = round(max(0.0, age), 1)
    return payload


def mark_request(path=REQUEST_MARKER):
    """Tell the collector a dashboard is watching, so it keeps running."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a"):
            os.utime(path)
    except OSError:
        pass


def fetch_database():
    """A missing database is downloaded in the background (the updater serialises itself)."""
    try:
        subprocess.Popen(
            ["/usr/local/bin/python3", GEODB, "update"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
    except OSError:
        pass


def main(want_hostnames=False):
    mark_request()
    if want_hostnames:
        mark_request(HOSTNAME_MARKER)
    payload = read_snapshot()
    if payload is None:
        start_collector()
        payload = {"status": "starting", "flows": [], "locations": []}
    if payload.get("status") == "no_database" and payload.get("reason") == "database_missing":
        fetch_database()
    if not want_hostnames:
        payload.pop("hostnames", None)
    return payload


if __name__ == "__main__":
    print(json.dumps(main(want_hostnames="hostnames" in sys.argv[1:]), separators=(",", ":")))
