#!/usr/local/bin/python3

# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

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

from lib.blocklists import BLOCKLIST_MAX_ENTRIES, FEEDS, FEED_DIR, feed_file
from lib.common import (
    FORCED_REPEAT_SECONDS, STATE_DIR, log_notice, log_warning, public_ip, read_json, secure_umask, write_json,
    write_text,
)
from lib.config import aliases, settings

STATUS_FILE = f"{STATE_DIR}/feeds.json"
MIN_AGE_SECONDS = 20 * 3600
TIMEOUT = 60
MAX_BYTES = 32 * 1024 * 1024
USER_AGENT = "OPNsense-FirewallMap"


def feeds_in_use(values=None):
    """The curated feeds chosen as threat lists; with none chosen (automatic), those with an alias."""
    values = settings() if values is None else values
    chosen = {name.strip() for name in (values.get("threat_lists") or "").split(",") if name.strip()}
    if not chosen:
        chosen = {alias["name"] for alias in aliases() if alias["enabled"]}
    return [feed for feed in FEEDS if feed["name"] in chosen]


# Threat-feed policy for downloaded lists (sanity limits, not syntax checks: such an entry is a
# valid network the policy rejects): a feed is third-party data. A network wider than these
# prefixes (a hijacked or broken feed listing 0.0.0.0/0) would flag a large part of the internet;
# networks without a global address cannot name a remote peer; and more entries than the threat
# index takes means the download is not the list it claims to be.
MIN_PREFIX = {4: 8, 6: 16}


def parse_feed(text, max_entries=BLOCKLIST_MAX_ENTRIES):
    """Addresses and networks, one per line; ';' and '#' start comments (Spamhaus, FireHOL, abuse.ch).

    Returns (entries, skipped): entries the threat-feed policy rejects (wider than MIN_PREFIX, or
    entirely outside global address space) are skipped and counted; unparsable lines are ignored.
    More than max_entries usable entries raise ValueError, so the previous copy stays in use.
    """
    entries = []
    seen = set()
    skipped = 0
    for line in text.splitlines():
        value = line.split(";", 1)[0].split("#", 1)[0].strip().split()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value[0], strict=False)
        except ValueError:
            continue
        if network.prefixlen < MIN_PREFIX[network.version] or not (
                public_ip(network.network_address) or public_ip(network.broadcast_address)):
            skipped += 1
            continue
        text_value = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
        if text_value not in seen:
            seen.add(text_value)
            entries.append(text_value)
            if len(entries) > max_entries:
                raise ValueError(f"list has more than {max_entries} entries")
    return entries, skipped


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        data = response.read(MAX_BYTES + 1)
    # a cut list would end in a cut line ("10.20.0.0/16" read as "10.20.0.0/1"): refuse it, and
    # the previous copy stays in use
    if len(data) > MAX_BYTES:
        raise ValueError(f"list larger than {MAX_BYTES // (1024 * 1024)} MB")
    return data.decode("utf-8", "replace")


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
        updated = entry.get("updated")
        just_updated = updated is not None and 0 <= now - updated < FORCED_REPEAT_SECONDS
        if (just_updated if force else fresh) and os.path.exists(feed_file(feed["name"])):
            results[feed["name"]] = "recent"
            continue
        entry["attempted"] = now
        try:
            entries, skipped = parse_feed(fetch(feed["url"]))
            if not entries:
                raise ValueError("empty list")
            write_text(feed_file(feed["name"]), "\n".join(entries) + "\n")
            entry.update({"updated": now, "count": len(entries), "skipped": skipped, "error": None})
            results[feed["name"]] = "ok"
            log_notice(f"threat feed {feed['label']} downloaded: {len(entries)} entries"
                       + (f", {skipped} rejected by the threat-feed policy (wider than IPv4 /8 or IPv6 /16, "
                          "or not global)" if skipped else ""))
        except urllib.error.HTTPError as error:
            entry["error"] = f"HTTP {error.code}"
            results[feed["name"]] = entry["error"]
        except Exception as error:  # network or parse errors; the previous copy stays in use
            entry["error"] = str(error)[:200]
            results[feed["name"]] = entry["error"]
        if entry.get("error"):
            log_warning(f"threat feed {feed['label']} download failed: {entry['error']} (the previous copy stays in use)")
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
