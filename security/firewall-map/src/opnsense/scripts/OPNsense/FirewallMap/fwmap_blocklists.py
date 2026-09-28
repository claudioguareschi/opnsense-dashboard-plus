#!/usr/local/bin/python3

"""Threat lists for Firewall Map+: blocklist pf tables, curated feeds and AbuseIPDB verdicts."""

import ipaddress
import subprocess
import sys
import threading
from array import array
from bisect import bisect_left

from fwmap_common import ABUSEIPDB_BLACKLIST, CONFIG_XML, PFCTL, REPUTATION_KIND, REPUTATION_MAX_AGE
from fwmap_pf import blocked_rule_tables, config_aliases, pf_tables


IDS_LIST = "Suricata IDS"
BLOCKLIST_ALIAS_TYPES = {"urltable", "url", "urljson", "external"}
BLOCKLIST_TABLE_PREFIXES = ("crowdsec", "__qfeeds", "qfeeds", "spamhaus", "firehol", "abuse", "fwmap_")
BLOCKLIST_MAX_ENTRIES = 500000
BLOCKLIST_MAX_TOTAL = 1000000
# addresses an operator marked, and AbuseIPDB's daily blacklist, always count as threats
WATCHLIST_TABLE = "FWMAP_Watchlist"
ABUSEIPDB_LIST = "AbuseIPDB blacklist"
REPUTATION_LIST = "AbuseIPDB (looked up)"
REPUTATION_THRESHOLD = 75
REPUTATION_REFRESH_SECONDS = 60


def blocklist_tables(config=CONFIG_XML, tables=None, blocked=None, aliases=None):
    """Names of pf tables that hold threat lists.

    URL/external aliases count only when a block or reject rule uses them, since the same alias
    types are often allowlists (cloud provider ranges...); feed tables with well-known names
    (CrowdSec, Q-Feeds, Spamhaus...) always count.
    """
    blocked = blocked_rule_tables() if blocked is None else blocked
    aliases = config_aliases(config) if aliases is None else aliases
    tables = pf_tables() if tables is None else tables
    alias_names = {alias["name"] for alias in aliases}
    names = {alias["name"] for alias in aliases
             if alias["type"] in BLOCKLIST_ALIAS_TYPES and alias["enabled"] and alias["name"] in blocked}
    names.update(table for table in tables if is_feed_table(table, alias_names))
    return {name for name in names if name and name in tables}


def is_feed_table(table, aliases):
    """Well-known feed tables; this plugin's FWMAP_ feeds only while their alias still exists
    (pf keeps the table of a deleted alias until the next filter reload)."""
    lowered = table.lower()
    if lowered.startswith("fwmap_"):
        return table in aliases
    return lowered.startswith(BLOCKLIST_TABLE_PREFIXES)


# curated public feeds this plugin can add as daily URL table aliases
FEEDS = [
    {"name": "FWMAP_Spamhaus_DROP", "label": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop.txt",
     "about": "Hijacked and criminal netblocks"},
    {"name": "FWMAP_Feodo", "label": "abuse.ch Feodo Tracker",
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "about": "Botnet command-and-control servers"},
    {"name": "FWMAP_ET_Compromised", "label": "Emerging Threats compromised",
     "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "about": "Hosts known to be compromised"},
    {"name": "FWMAP_FireHOL_L1", "label": "FireHOL level 1",
     "url": "https://iplists.firehol.org/files/firehol_level1.netset",
     "about": "Combined attack sources (DROP, Feodo, DShield...). Also lists private and bogon ranges: "
              "do not use it to block LAN traffic."},
]


def threat_list_candidates(config=CONFIG_XML, tables=None, aliases=None):
    """Tables an administrator may choose as threat lists, with their alias type.

    Only list-type aliases are sensible threat lists (not LAN host or network aliases).
    """
    tables = pf_tables() if tables is None else tables
    aliases = config_aliases(config) if aliases is None else aliases
    alias_names = {alias["name"] for alias in aliases}
    candidates = {alias["name"]: {"name": alias["name"], "type": alias["type"], "description": alias["description"]}
                  for alias in aliases if alias["name"] in tables and alias["type"] in BLOCKLIST_ALIAS_TYPES}
    for table in tables:
        if is_feed_table(table, alias_names) and table not in candidates:
            candidates[table] = {"name": table, "type": "feed", "description": ""}
    for feed in FEEDS:
        entry = candidates.setdefault(feed["name"], {"name": feed["name"], "type": "urltable"})
        entry.update({"label": feed["label"], "description": feed["about"], "url": feed["url"],
                      "curated": True, "installed": feed["name"] in alias_names})
    return sorted(candidates.values(), key=lambda item: (not item.get("curated"), item["name"].lower()))


def tables_report(config=CONFIG_XML):
    """What the settings dialog lists: candidates and the automatic choice, from one pf and config read."""
    tables = pf_tables()
    aliases = config_aliases(config)
    return {"tables": threat_list_candidates(config, tables, aliases),
            "automatic": sorted(blocklist_tables(config, tables, aliases=aliases))}


def chosen_threat_lists(setting, config=CONFIG_XML):
    """The administrator's choice when set, otherwise the automatic selection."""
    names = {name.strip() for name in (setting or "").split(",") if name.strip()}
    tables = set(pf_tables())
    chosen = (names & tables) if names else blocklist_tables(config, list(tables))
    if WATCHLIST_TABLE in tables:
        chosen.add(WATCHLIST_TABLE)
    return chosen


class BlocklistIndex:
    """Longest-prefix lookup of IPv4 addresses in blocklist pf tables.

    Compact: per prefix length a sorted array of network addresses with a parallel array of
    table bitmasks, searched with bisect. Rebuilt in a background thread and swapped in whole,
    so the sampling loop never waits for large tables.
    """

    def __init__(self):
        self.index = ([], {})  # (table names, {prefixlen: (networks, masks)})
        self.refreshing = False

    # one bit per table in a 64-bit mask
    MAX_TABLES = 62

    @staticmethod
    def build(contents, max_total=BLOCKLIST_MAX_TOTAL):
        names = sorted(contents)
        if len(names) > BlocklistIndex.MAX_TABLES:
            print(f"firewallmap: {len(names) - BlocklistIndex.MAX_TABLES} threat lists ignored "
                  f"(more than {BlocklistIndex.MAX_TABLES}): {', '.join(names[BlocklistIndex.MAX_TABLES:])}",
                  file=sys.stderr)
            names = names[:BlocklistIndex.MAX_TABLES]
        by_prefix = {}
        total = 0
        for bit, table in enumerate(names):
            if total >= max_total:
                print(f"firewallmap: threat lists truncated at {max_total} entries, from {table} on",
                      file=sys.stderr)
                break
            for entry in contents[table]:
                entry = entry.strip()
                if not entry or entry.startswith("!") or ":" in entry:
                    continue
                try:
                    network = ipaddress.IPv4Network(entry, strict=False)
                except ValueError:
                    continue
                bucket = by_prefix.setdefault(network.prefixlen, {})
                key = int(network.network_address)
                bucket[key] = bucket.get(key, 0) | (1 << bit)
                total += 1
                if total >= max_total:
                    break
        compact = {}
        for prefixlen, bucket in by_prefix.items():
            keys = sorted(bucket)
            compact[prefixlen] = (array("I", keys), array("Q", (bucket[key] for key in keys)))
        return names, compact

    def _refresh(self, tables):
        try:
            contents = {}
            for table in sorted(tables):
                try:
                    output = subprocess.run(
                        [PFCTL, "-t", table, "-T", "show"], capture_output=True, check=False, text=True, timeout=20,
                    ).stdout
                except (OSError, subprocess.TimeoutExpired):
                    continue
                entries = output.split()
                if len(entries) <= BLOCKLIST_MAX_ENTRIES:
                    contents[table] = entries
            try:
                with open(ABUSEIPDB_BLACKLIST) as handle:
                    contents[ABUSEIPDB_LIST] = handle.read().split()[:BLOCKLIST_MAX_ENTRIES]
            except OSError:
                pass
            self.index = self.build(contents)
        finally:
            self.refreshing = False

    def refresh(self, tables, background=True):
        if self.refreshing:
            return False
        self.refreshing = True
        if background:
            threading.Thread(target=self._refresh, args=(tables,), daemon=True).start()
        else:
            self._refresh(tables)
        return True

    def lookup(self, address):
        try:
            value = int(ipaddress.IPv4Address(address))
        except ValueError:
            return []
        names, compact = self.index
        mask = 0
        for prefixlen, (networks, masks) in compact.items():
            key = value & ((0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF if prefixlen else 0)
            position = bisect_left(networks, key)
            if position < len(networks) and networks[position] == key:
                mask |= masks[position]
        return [name for bit, name in enumerate(names) if mask & (1 << bit)]


def threat_lists_for(address, blocklists, reputation, alerts=None):
    lists = blocklists.lookup(address) if blocklists else []
    if reputation is not None and address in reputation.flagged:
        lists = lists + [REPUTATION_LIST]
    if alerts is not None and alerts.flags(address):
        lists = lists + [IDS_LIST]
    return lists


def threat_fields(address, blocklists, reputation):
    """The threat facts every map entry carries: the lists naming the address and its AbuseIPDB score."""
    return {
        "lists": threat_lists_for(address, blocklists, reputation),
        "abuseipdb": reputation.scores.get(address) if reputation is not None else None,
    }


class Reputation:
    """Addresses already found abusive by an AbuseIPDB lookup, read from the investigation cache."""

    def __init__(self, store, threshold=REPUTATION_THRESHOLD):
        self.store = store
        self.threshold = threshold
        self.flagged = set()
        self.scores = {}
        self.checked = None

    def refresh(self, now):
        if self.checked is not None and now - self.checked < REPUTATION_REFRESH_SECONDS:
            return
        self.checked = now
        rows = {}
        if self.store is not None:
            # full lookups cached before verdicts were kept separately still count
            rows.update(self.store.get_all("abuseipdb", max_age=REPUTATION_MAX_AGE))
            rows.update(self.store.get_all(REPUTATION_KIND, max_age=REPUTATION_MAX_AGE))
        self.flagged = {address for address, data in rows.items()
                        if isinstance(data, dict) and (data.get("score") or 0) >= self.threshold}
        # every cached verdict, so the details can say "clean" as well as "listed"
        self.scores = {address: data.get("score") for address, data in rows.items()
                       if isinstance(data, dict) and data.get("score") is not None}
