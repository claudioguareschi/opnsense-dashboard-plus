#!/usr/local/bin/python3

"""Daily download of the AbuseIPDB blacklist for Firewall Map+.

    firewallmap_abuseipdb.py update [force]   download when older than a day (needs a key)
    firewallmap_abuseipdb.py status           JSON status (never includes the key)

The list is stored locally and matched by the collector, so flagging needs no per-address
API calls. The free tier returns up to 10,000 addresses at 100% confidence and allows only a
few downloads a day, so an automatic run never repeats within MIN_AGE_SECONDS.
"""

import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import firewallmap_collector as collector  # noqa: E402
import firewallmap_investigate as investigate  # noqa: E402

LIST_FILE = collector.ABUSEIPDB_BLACKLIST
STATUS_FILE = "/var/db/firewallmap/abuseipdb.json"
URL = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=10000"
MIN_AGE_SECONDS = 20 * 3600
TIMEOUT = 60


def read_status(path=None):
    try:
        with open(path or STATUS_FILE) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def write_atomic(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.tmp"
    with open(temporary, "w") as handle:
        handle.write(text)
    os.replace(temporary, path)


def parse_list(text):
    """Keep only valid public IPv4 addresses (the list is plain text, one address per line)."""
    addresses = []
    for line in text.splitlines():
        value = line.strip()
        try:
            address = ipaddress.IPv4Address(value)
        except ValueError:
            continue
        if address.is_global:
            addresses.append(str(address))
    return addresses


def download(key):
    request = urllib.request.Request(URL, headers={"User-Agent": investigate.USER_AGENT, "Accept": "text/plain"})
    request.add_unredirected_header("Key", key)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", "replace")


def update(force=False, key=None, fetch=download, now=None):
    now = time.time() if now is None else now
    key = key if key is not None else investigate.abuseipdb_key()
    if not key:
        return {"result": "skipped", "reason": "no key"}
    status = read_status()
    attempted = status.get("attempted")
    # a timestamp from the future (clock fixed after boot) must not block updates
    if not force and attempted is not None and 0 <= now - attempted < MIN_AGE_SECONDS:
        return {"result": "skipped", "reason": "recent"}
    status["attempted"] = now
    try:
        addresses = parse_list(fetch(key))
        if not addresses:
            raise ValueError("empty list")
        write_atomic(LIST_FILE, "\n".join(addresses) + "\n")
        status.update({"updated": now, "count": len(addresses), "error": None})
        result = {"result": "ok", "count": len(addresses)}
    except urllib.error.HTTPError as error:
        status["error"] = f"HTTP {error.code}"
        result = {"result": "failed", "error": status["error"]}
    except Exception as error:  # network or parse errors; never let the key reach the status file
        status["error"] = str(error).replace(key, "<key>")[:200]
        result = {"result": "failed", "error": status["error"]}
    write_atomic(STATUS_FILE, json.dumps(status))
    return result


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "update":
        print(json.dumps(update(force=len(sys.argv) > 2 and sys.argv[2] == "force")))
    else:
        print(json.dumps(read_status()))
