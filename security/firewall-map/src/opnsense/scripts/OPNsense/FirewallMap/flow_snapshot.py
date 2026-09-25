#!/usr/local/bin/python3

"""Return the latest Firewall Map flow summary written by the collector.

The dashboard polls this through configd, so it must stay cheap: it only reads
the compact JSON document the persistent collector rewrites every second, and
starts the collector if it is not running.
"""

import json
import os
import subprocess
import time


OUTPUT_FILE = "/var/run/firewallmap/flows.json"
RC_SCRIPT = "/usr/local/etc/rc.d/firewallmap"
STALE_SECONDS = 10


def start_collector():
    try:
        subprocess.run([RC_SCRIPT, "start"], capture_output=True, check=False, timeout=5)
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


def main():
    payload = read_snapshot()
    if payload is None:
        start_collector()
        payload = {"status": "starting", "flows": [], "locations": []}
    return payload


if __name__ == "__main__":
    print(json.dumps(main(), separators=(",", ":")))
