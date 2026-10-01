#!/usr/local/bin/python3

"""Daily download of the AbuseIPDB blacklist for Firewall Map+.

    firewallmap_abuseipdb.py update [force]   download when older than a day (needs a key)
    firewallmap_abuseipdb.py sync             load the optional FWMAP_AbuseIPDB table from the cache
    firewallmap_abuseipdb.py status           JSON status (never includes the key)

The list is stored locally and matched by the collector, so flagging needs no per-address
API calls. The free tier returns up to 10,000 addresses at 100% confidence and allows only a
few downloads a day, so an automatic run never repeats within MIN_AGE_SECONDS.
"""

import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ElementTree

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import firewallmap_investigate as investigate  # noqa: E402
from fwmap_common import (  # noqa: E402
    ABUSEIPDB_BLACKLIST, CONFIG_XML, PFCTL, STATE_DIR, read_json, secure_umask, write_json, write_text,
)

LIST_FILE = ABUSEIPDB_BLACKLIST
STATUS_FILE = f"{STATE_DIR}/abuseipdb.json"
URL = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=100&limit=10000"
PF_TABLE = "FWMAP_AbuseIPDB"
MIN_AGE_SECONDS = 20 * 3600
TIMEOUT = 60


def read_status(path=None):
    return read_json(path or STATUS_FILE)


def parse_list(text):
    """Keep normalized, unique public IPv4 and IPv6 addresses from the plaintext response."""
    addresses = []
    seen = set()
    for line in text.splitlines():
        value = line.strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        normalized = str(address)
        if address.is_global and not address.is_multicast and normalized not in seen:
            addresses.append(normalized)
            seen.add(normalized)
    return addresses


def download(key):
    # AbuseIPDB documents the omitted ipVersion parameter as a mixed IPv4/IPv6 response.
    request = urllib.request.Request(URL, headers={"User-Agent": investigate.USER_AGENT, "Accept": "text/plain"})
    request.add_unredirected_header("Key", key)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", "replace")


def alias_settings(path=CONFIG_XML):
    """(option on, alias defined) from config.xml; the alias may exist without the option."""
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError):
        return False, False
    enabled = (root.findtext("./OPNsense/FirewallMap/general/blocklist_aliases") or "").strip() == "1"
    defined = any((alias.findtext("name") or "").strip() == PF_TABLE
                  for alias in root.iterfind("./OPNsense/Firewall/Alias/aliases/alias"))
    return enabled, defined


def sync_pf_table(settings=None, run=subprocess.run):
    """Load the FWMAP_AbuseIPDB table from the cached blacklist (the same file the map uses).

    Called after every download, at boot and when the option changes. With the option off the
    table is dropped, unless an alias of that name is still defined (it is then not ours to empty).
    """
    enabled, defined = alias_settings() if settings is None else settings
    if enabled:
        if not os.path.exists(LIST_FILE):
            return {"enabled": True, "loaded": False, "error": "no blacklist downloaded yet"}
        command = [PFCTL, "-t", PF_TABLE, "-T", "replace", "-f", LIST_FILE]
    elif defined:
        return {"enabled": False, "loaded": False}
    else:
        command = [PFCTL, "-q", "-t", PF_TABLE, "-T", "kill"]
    try:
        result = run(command, capture_output=True, check=False, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"enabled": enabled, "loaded": False, "error": str(error)[:200]}
    if not enabled:
        return {"enabled": False, "loaded": False}  # kill fails harmlessly when there is no table
    if result.returncode != 0:
        return {"enabled": True, "loaded": False, "error": (result.stderr.strip() or "pfctl failed")[:200]}
    return {"enabled": True, "loaded": True}


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
        write_text(LIST_FILE, "\n".join(addresses) + "\n")
        counts = {version: 0 for version in (4, 6)}
        for address in addresses:
            counts[ipaddress.ip_address(address).version] += 1
        status.update({"updated": now, "count": len(addresses), "count_v4": counts[4], "count_v6": counts[6],
                       "error": None, "pf": sync_pf_table()})
        result = {"result": "ok", "count": len(addresses)}
    except urllib.error.HTTPError as error:
        status["error"] = f"HTTP {error.code}"
        result = {"result": "failed", "error": status["error"]}
    except Exception as error:  # network or parse errors; never let the key reach the status file
        status["error"] = str(error).replace(key, "<key>")[:200]
        result = {"result": "failed", "error": status["error"]}
    write_json(STATUS_FILE, status)
    return result


if __name__ == "__main__":
    secure_umask()
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "update":
        print(json.dumps(update(force=len(sys.argv) > 2 and sys.argv[2] == "force")))
    elif command == "sync":
        status = read_status()
        status["pf"] = sync_pf_table()
        write_json(STATUS_FILE, status)
        print(json.dumps(status["pf"]))
    else:
        print(json.dumps(read_status()))
