#!/usr/local/bin/python3

"""On-demand investigation of one public IPv4 address for Firewall Map+.

    firewallmap_investigate.py <address>

Queries, only when an administrator asks for this address:
  - RDAP (registry whois, via the rdap.org bootstrap): network name, range, owner, abuse contact
  - RIPEstat prefix overview: announced prefix and origin AS
  - AbuseIPDB (only when an API key is configured): abuse confidence and reports

Results are cached in the collector's SQLite store, so repeated clicks do not repeat the
lookups. The AbuseIPDB key is read from config.xml and never printed.
"""

import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import firewallmap_collector as collector  # noqa: E402

CONFIG_XML = "/conf/config.xml"
TIMEOUT = 10
USER_AGENT = "OPNsense-FirewallMap"
MAX_AGE = {"rdap": 7 * 86400, "ripestat": 86400, "abuseipdb": 6 * 3600}
MAX_ENTRIES = {"rdap": 5000, "ripestat": 5000, "abuseipdb": 5000}


def abuseipdb_key(path=CONFIG_XML):
    try:
        node = ElementTree.parse(path).getroot().find("./OPNsense/FirewallMap/general/abuseipdb_key")
    except (OSError, ElementTree.ParseError):
        return None
    return node.text.strip() if node is not None and node.text and node.text.strip() else None


def fetch_json(url, secret_headers=None):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    for name, value in (secret_headers or {}).items():
        # never forwarded if the provider redirects elsewhere
        request.add_unredirected_header(name, value)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


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


def investigate(address, store=None, key=None, fetchers=None, now=None):
    try:
        parsed = ipaddress.IPv4Address(address)
    except ValueError:
        return {"status": "failed", "error": "not an IPv4 address"}
    if not parsed.is_global:
        return {"status": "failed", "error": "not a public address"}
    address = str(parsed)
    now = time.time() if now is None else now
    store = store if store is not None else collector.CacheStore()
    fetchers = fetchers if fetchers is not None else lookups(address, key)
    result = {"status": "ok", "address": address, "abuseipdb_configured": "abuseipdb" in fetchers}
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
            store.put_many(collector.REPUTATION_KIND, [(address, {"score": data.get("score")})], now=now)
            store.prune(collector.REPUTATION_KIND, max_age=collector.REPUTATION_MAX_AGE, keep=20000, now=now)
        result[source] = data
    return result


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(investigate(target, key=abuseipdb_key())))
