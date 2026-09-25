#!/usr/local/bin/python3

"""Return a bounded, read-only PF state sample for Firewall Map.

This is intentionally a bootstrap endpoint, not the long-lived collector. The
collector will retain state counters between samples, aggregate eligible public
flows, and emit only map-ready deltas to the browser.
"""

import json
import re
import subprocess
from datetime import datetime, timezone


PFCTL = "/sbin/pfctl"
MAX_RECORDS = 250
HEADER = re.compile(r"^(?P<interface>\S+)\s+(?P<protocol>\S+)\s+(?P<flow>.+?)\s+(?P<state>\S+)$")
COUNTERS = re.compile(r"(?P<packets_in>\d+):(?P<packets_out>\d+) pkts,\s+(?P<bytes_in>\d+):(?P<bytes_out>\d+) bytes")


def state_snapshot(output, max_records=MAX_RECORDS):
    """Parse verbose pfctl records without attempting geo or flow aggregation."""
    records = []
    header = None
    for line in output.splitlines():
        if not line.startswith((" ", "\t")):
            match = HEADER.match(line)
            header = match.groupdict() if match else None
            continue
        if header is None:
            continue
        counters = COUNTERS.search(line)
        if not counters:
            continue
        record = {
            "interface": header["interface"],
            "protocol": header["protocol"],
            "flow": header["flow"],
            "state": header["state"],
            **{key: int(value) for key, value in counters.groupdict().items()},
        }
        records.append(record)
        header = None
        if len(records) >= max_records:
            break
    return records


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
    return {
        "status": "ok",
        "sampled_at": datetime.now(timezone.utc).isoformat(),
        "flows": state_snapshot(result.stdout),
        "truncated": len(state_snapshot(result.stdout, MAX_RECORDS + 1)) > MAX_RECORDS,
    }


if __name__ == "__main__":
    print(json.dumps(collect(), separators=(",", ":")))
