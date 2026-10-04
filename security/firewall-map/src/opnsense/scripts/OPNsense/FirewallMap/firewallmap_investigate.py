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

"""On-demand investigation of one public IPv4 or IPv6 address for Firewall Map+.

    firewallmap_investigate.py <address>

Queries, only when an administrator asks for this address:
  - RDAP (registry whois, via the rdap.org bootstrap): network name, range, owner, abuse contact
  - RIPEstat prefix overview: announced prefix and origin AS
  - AbuseIPDB (only when an API key is configured): abuse confidence and reports

Results are cached in the collector's SQLite store, so repeated clicks do not repeat the
lookups. The AbuseIPDB key comes from the plugin settings file and is never printed.
"""

import ipaddress
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from lib.cache import CacheStore
from lib.common import REPUTATION_KIND, REPUTATION_MAX_AGE, secure_umask
from lib.config import abuseipdb_key

TIMEOUT = 10
# an RDAP, RIPEstat or AbuseIPDB answer is a few kB; anything far larger is not one
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
USER_AGENT = "OPNsense-FirewallMap"
MAX_AGE = {"rdap": 7 * 86400, "ripestat": 86400, "abuseipdb": 6 * 3600}
MAX_ENTRIES = {"rdap": 5000, "ripestat": 5000, "abuseipdb": 5000}


def fetch_json(url, secret_headers=None):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    for name, value in (secret_headers or {}).items():
        # never forwarded if the provider redirects elsewhere
        request.add_unredirected_header(name, value)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("response too large")
    return json.loads(body.decode("utf-8", "replace"))


def vcard(entity):
    """(name, email) from an RDAP entity's jCard."""
    name = email = None
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) >= 4 and item[0] == "fn":
            name = item[3]
        elif len(item) >= 4 and item[0] == "email" and not email:
            email = item[3]
    return name, email


def walk_entities(entities):
    for entity in entities or []:
        yield entity
        yield from walk_entities(entity.get("entities"))


def parse_rdap(data):
    owner = abuse_name = abuse_email = None
    for entity in walk_entities(data.get("entities")):
        roles = entity.get("roles") or []
        name, email = vcard(entity)
        if "abuse" in roles and not abuse_email:
            abuse_name, abuse_email = name, email
        if ("registrant" in roles or "administrative" in roles) and not owner:
            owner = name
    events = {event.get("eventAction"): event.get("eventDate") for event in data.get("events") or []}
    return {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "range": f'{data.get("startAddress")} – {data.get("endAddress")}' if data.get("startAddress") else None,
        "country": data.get("country"),
        "type": data.get("type"),
        "owner": owner,
        "abuse_name": abuse_name,
        "abuse_email": abuse_email,
        "registered": (events.get("registration") or "")[:10] or None,
        "updated": (events.get("last changed") or "")[:10] or None,
        "source": data.get("port43") or "RDAP",
    }


def parse_ripestat(data):
    data = data.get("data") or {}
    return {
        "prefix": data.get("resource"),
        "announced": data.get("announced"),
        "asns": [{"asn": item.get("asn"), "holder": item.get("holder")} for item in data.get("asns") or []],
    }


def parse_abuseipdb(data):
    data = data.get("data") or {}
    return {
        "score": data.get("abuseConfidenceScore"),
        "reports": data.get("totalReports"),
        "reporters": data.get("numDistinctUsers"),
        "last_reported": (data.get("lastReportedAt") or "")[:10] or None,
        "usage": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "tor": data.get("isTor"),
        "whitelisted": data.get("isWhitelisted"),
    }


def lookups(address, key):
    quoted = urllib.parse.quote(address)
    sources = {
        "rdap": lambda: parse_rdap(fetch_json(f"https://rdap.org/ip/{quoted}")),
        "ripestat": lambda: parse_ripestat(fetch_json(
            f"https://stat.ripe.net/data/prefix-overview/data.json?resource={quoted}&sourceapp=opnsense-firewallmap")),
    }
    if key:
        sources["abuseipdb"] = lambda: parse_abuseipdb(fetch_json(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={quoted}&maxAgeInDays=90", {"Key": key}))
    return sources


def investigate(address, store=None, key=None, fetchers=None, now=None, sources=None):
    """Look `address` up in every source, or only in `sources` (e.g. {"abuseipdb"} for the
    Reputation card's check), from the cache where it is fresh."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return {"status": "failed", "error": "not an IP address"}
    if not parsed.is_global or parsed.is_multicast:
        return {"status": "failed", "error": "not a public address"}
    address = str(parsed)
    now = time.time() if now is None else now
    store = store if store is not None else CacheStore()
    fetchers = fetchers if fetchers is not None else lookups(address, key)
    result = {"status": "ok", "address": address, "abuseipdb_configured": "abuseipdb" in fetchers}
    if sources:
        fetchers = {source: fetch for source, fetch in fetchers.items() if source in sources}
    missing = {}
    for source, fetch in fetchers.items():
        cached = store.get(source, address, max_age=MAX_AGE[source], now=now)
        if cached is not None:
            result[source] = {**cached, "cached": True}
        else:
            missing[source] = fetch
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {source: pool.submit(fetch) for source, fetch in missing.items()}
    for source, future in futures.items():
        try:
            data = future.result()
        except urllib.error.HTTPError as error:
            result[source] = {"error": f"HTTP {error.code}"}
            continue
        except Exception as error:  # network errors, bad JSON: report per source, never the key
            message = str(error)
            if key:
                message = message.replace(key, "<key>")
            result[source] = {"error": message[:200]}
            continue
        store.put_many(source, [(address, data)], now=now)
        store.prune(source, max_age=MAX_AGE[source], keep=MAX_ENTRIES[source], now=now)
        if source == "abuseipdb":
            # the verdict flags the address on the map for 30 days; a newer lookup replaces it
            store.put_many(REPUTATION_KIND, [(address, {"score": data.get("score")})], now=now)
            store.prune(REPUTATION_KIND, max_age=REPUTATION_MAX_AGE, keep=20000, now=now)
        result[source] = data
    return result


if __name__ == "__main__":
    secure_umask()
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    # "all", or a comma-separated subset of rdap, ripestat and abuseipdb
    wanted = sys.argv[2] if len(sys.argv) > 2 else "all"
    sources = None if wanted == "all" else set(wanted.split(",")) & set(MAX_AGE)
    print(json.dumps(investigate(target, key=abuseipdb_key(), sources=sources)))
