#!/usr/local/bin/python3

"""Daily download of the curated threat feeds for Firewall Map+.

    firewallmap_feeds.py update [force]   download the feeds in use (at most once in MIN_AGE_SECONDS)
    firewallmap_feeds.py status           JSON status per feed

The map matches these local copies, so a feed counts as a threat list whether or not its
FWMAP_* alias exists. The aliases (Maintain blocklist aliases) are URL tables that OPNsense
refreshes on its own schedule.
"""

import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwmap_blocklists import FEEDS, FEED_DIR, feed_file  # noqa: E402
from fwmap_common import CONFIG_XML, STATE_DIR, read_json, secure_umask, write_json, write_text  # noqa: E402
from fwmap_pf import config_aliases  # noqa: E402
from firewallmap_geodb import settings  # noqa: E402

STATUS_FILE = f"{STATE_DIR}/feeds.json"
MIN_AGE_SECONDS = 20 * 3600
TIMEOUT = 60
MAX_BYTES = 32 * 1024 * 1024
USER_AGENT = "OPNsense-FirewallMap"


def feeds_in_use(values=None, config=CONFIG_XML):
    """The curated feeds chosen as threat lists; with none chosen (automatic), those with an alias."""
    values = settings(config) if values is None else values
    chosen = {name.strip() for name in (values.get("threat_lists") or "").split(",") if name.strip()}
    if not chosen:
        chosen = {alias["name"] for alias in config_aliases(config) if alias["enabled"]}
    return [feed for feed in FEEDS if feed["name"] in chosen]


def parse_feed(text):
    """Addresses and networks, one per line; ';' and '#' start comments (Spamhaus, FireHOL, abuse.ch)."""
    entries = []
    seen = set()
    for line in text.splitlines():
        value = line.split(";", 1)[0].split("#", 1)[0].strip().split()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value[0], strict=False)
        except ValueError:
            continue
        text_value = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
        if text_value not in seen:
            seen.add(text_value)
            entries.append(text_value)
    return entries


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read(MAX_BYTES).decode("utf-8", "replace")


def update(force=False, fetch=download, now=None, feeds=None):
    now = time.time() if now is None else now
    feeds = feeds_in_use() if feeds is None else feeds
    status = read_json(STATUS_FILE)
    os.makedirs(FEED_DIR, exist_ok=True)
    results = {}
    for feed in feeds:
        entry = status.get(feed["name"], {})
        attempted = entry.get("attempted")
        fresh = attempted is not None and 0 <= now - attempted < MIN_AGE_SECONDS
        if fresh and not force and os.path.exists(feed_file(feed["name"])):
            results[feed["name"]] = "recent"
            continue
        entry["attempted"] = now
        try:
            entries = parse_feed(fetch(feed["url"]))
            if not entries:
                raise ValueError("empty list")
            write_text(feed_file(feed["name"]), "\n".join(entries) + "\n")
            entry.update({"updated": now, "count": len(entries), "error": None})
            results[feed["name"]] = "ok"
        except urllib.error.HTTPError as error:
            entry["error"] = f"HTTP {error.code}"
            results[feed["name"]] = entry["error"]
        except Exception as error:  # network or parse errors; the previous copy stays in use
            entry["error"] = str(error)[:200]
            results[feed["name"]] = entry["error"]
        status[feed["name"]] = entry
    write_json(STATUS_FILE, status)
    return results


if __name__ == "__main__":
    secure_umask()
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "update":
        print(json.dumps(update(force=len(sys.argv) > 2 and sys.argv[2] == "force")))
    else:
        print(json.dumps(read_json(STATUS_FILE)))
