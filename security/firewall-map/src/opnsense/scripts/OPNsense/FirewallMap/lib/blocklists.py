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

"""Threat lists for Firewall Map+: blocklist pf tables, curated feeds and AbuseIPDB verdicts."""

import hashlib
import ipaddress
import os
import subprocess
import threading
from array import array
from bisect import bisect_left

from .common import ABUSEIPDB_BLACKLIST, CONFIG_XML, PFCTL, REPUTATION_KIND, REPUTATION_MAX_AGE, STATE_DIR, log_warning
from .pf import blocked_rule_tables, config_aliases, pf_tables


IDS_LIST = "Suricata IDS"
BLOCKLIST_ALIAS_TYPES = {"urltable", "url", "urljson", "external"}
BLOCKLIST_TABLE_PREFIXES = ("crowdsec", "__qfeeds", "qfeeds", "spamhaus", "firehol", "abuse", "fwmap_")
BLOCKLIST_MAX_ENTRIES = 500000
BLOCKLIST_MAX_TOTAL = 1000000
# addresses an operator marked, and AbuseIPDB's daily blacklist, always count as threats
WATCHLIST_TABLE = "FWMAP_Watchlist"
ABUSEIPDB_LIST = "AbuseIPDB blacklist"
ABUSEIPDB_TABLE = "FWMAP_AbuseIPDB"
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


# curated public feeds: downloaded by firewallmap_feeds.py for the map, and added as daily URL
# table aliases when "Maintain blocklist aliases" is on
FEED_DIR = f"{STATE_DIR}/feeds"
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


FEED_NAMES = {feed["name"] for feed in FEEDS}


def feed_file(name):
    return f"{FEED_DIR}/{name}.txt"


def downloaded_feeds():
    """Curated feeds with a local copy (firewallmap_feeds.py)."""
    return {feed["name"] for feed in FEEDS if os.path.exists(feed_file(feed["name"]))}


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
    """What the settings page lists: candidates and the automatic choice, from one pf and config read."""
    tables = pf_tables()
    aliases = config_aliases(config)
    return {"tables": threat_list_candidates(config, tables, aliases),
            "automatic": sorted(blocklist_tables(config, tables, aliases=aliases))}


def chosen_threat_lists(setting, config=CONFIG_XML):
    """The administrator's choice when set, otherwise the automatic selection."""
    names = {name.strip() for name in (setting or "").split(",") if name.strip()}
    tables = set(pf_tables())
    # a curated feed counts from its downloaded copy, with or without its alias
    available = tables | downloaded_feeds()
    chosen = (names & available) if names else blocklist_tables(config, list(tables))
    # The same cache is indexed below under one stable, friendly badge; reading its PF alias too
    # would duplicate both work and the badge whenever optional alias maintenance is enabled.
    chosen.discard(ABUSEIPDB_TABLE)
    if WATCHLIST_TABLE in tables:
        chosen.add(WATCHLIST_TABLE)
    return chosen


class BlocklistIndex:
    """Longest-prefix lookup of IPv4 and IPv6 addresses in blocklist PF tables.

    Compact: IPv4 uses one 32-bit array per prefix. IPv6 uses parallel 64-bit high/low arrays,
    avoiding Python's much larger arbitrary-precision integers for large feeds. Both carry a
    parallel array of table bitmasks and are searched with bisect. The complete dual-family index
    is rebuilt in a background thread and swapped atomically, so sampling never waits for it.
    """

    def __init__(self):
        self.index = ([], {4: {}, 6: {}})
        self.refreshing = False
        # what the index was built from, so an unchanged set of lists is not parsed again
        self.fingerprint = None
        # lists too large to use, each logged once (the check repeats every few minutes)
        self.oversized = set()

    # one bit per table in a 64-bit mask
    MAX_TABLES = 62

    @staticmethod
    def build(contents, max_total=BLOCKLIST_MAX_TOTAL):
        names = sorted(contents)
        if len(names) > BlocklistIndex.MAX_TABLES:
            log_warning(f"{len(names) - BlocklistIndex.MAX_TABLES} threat lists ignored "
                        f"(more than {BlocklistIndex.MAX_TABLES}): {', '.join(names[BlocklistIndex.MAX_TABLES:])}")
            names = names[:BlocklistIndex.MAX_TABLES]
        by_family = {4: {}, 6: {}}
        total = 0
        for bit, table in enumerate(names):
            if total >= max_total:
                log_warning(f"threat lists truncated at {max_total} entries, from {table} on")
                break
            for entry in contents[table]:
                entry = entry.strip()
                if not entry or entry.startswith("!"):
                    continue
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    continue
                bucket = by_family[network.version].setdefault(network.prefixlen, {})
                key = int(network.network_address)
                bucket[key] = bucket.get(key, 0) | (1 << bit)
                total += 1
                if total >= max_total:
                    break
        compact = {4: {}, 6: {}}
        for prefixlen, bucket in by_family[4].items():
            keys = sorted(bucket)
            compact[4][prefixlen] = (array("I", keys), array("Q", (bucket[key] for key in keys)))
        for prefixlen, bucket in by_family[6].items():
            keys = sorted(bucket)
            compact[6][prefixlen] = (
                array("Q", (key >> 64 for key in keys)),
                array("Q", (key & 0xFFFFFFFFFFFFFFFF for key in keys)),
                array("Q", (bucket[key] for key in keys)),
            )
        return names, compact

    def _refresh(self, tables):
        try:
            contents = {}
            for table in sorted(tables):
                if table in FEED_NAMES:
                    # a curated feed's own download, rather than its alias table (which may not exist)
                    try:
                        with open(feed_file(table)) as handle:
                            contents[table] = handle.read().split()[:BLOCKLIST_MAX_ENTRIES]
                        continue
                    except OSError:
                        pass
                try:
                    output = subprocess.run(
                        [PFCTL, "-t", table, "-T", "show"], capture_output=True, check=False, text=True, timeout=20,
                    ).stdout
                except (OSError, subprocess.TimeoutExpired):
                    continue
                entries = output.split()
                if len(entries) <= BLOCKLIST_MAX_ENTRIES:
                    contents[table] = entries
                    self.oversized.discard(table)
                elif table not in self.oversized:
                    self.oversized.add(table)
                    log_warning(f"threat list {table} has {len(entries)} entries, over {BLOCKLIST_MAX_ENTRIES}: not used")
            try:
                with open(ABUSEIPDB_BLACKLIST) as handle:
                    contents[ABUSEIPDB_LIST] = handle.read().split()[:BLOCKLIST_MAX_ENTRIES]
            except OSError:
                pass
            # parsing every entry is the expensive part: skip it when no list changed since
            digest = hashlib.sha256()
            for name in sorted(contents):
                digest.update(name.encode() + b"\0" + "\n".join(contents[name]).encode() + b"\0")
            fingerprint = digest.digest()
            if fingerprint != self.fingerprint:
                self.index = self.build(contents)
                self.fingerprint = fingerprint
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

    @property
    def names(self):
        """The lists in the index, in their bit order."""
        return self.index[0]

    def lookup(self, address):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return []
        names, compact = self.index
        value = int(parsed)
        mask = 0
        bits = parsed.max_prefixlen
        for prefixlen, bucket in compact.get(parsed.version, {}).items():
            key = value & (((1 << bits) - 1) ^ ((1 << (bits - prefixlen)) - 1) if prefixlen else 0)
            if parsed.version == 4:
                networks, masks = bucket
                position = bisect_left(networks, key)
                if position < len(networks) and networks[position] == key:
                    mask |= masks[position]
            else:
                high, low, masks = bucket
                high_key, low_key = key >> 64, key & 0xFFFFFFFFFFFFFFFF
                start = bisect_left(high, high_key)
                end = bisect_left(high, high_key + 1, lo=start)
                position = bisect_left(low, low_key, lo=start, hi=end)
                if position < end and low[position] == low_key:
                    mask |= masks[position]
        return [name for bit, name in enumerate(names) if mask & (1 << bit)]


def threat_lists_for(address, blocklists, reputation, ids_evidence=None):
    """The threat lists an address is on: chosen lists, the AbuseIPDB verdict and, with
    `ids_evidence` (anything with flags(address): the Correlator, an AlertTracker), IDS alerts."""
    lists = blocklists.lookup(address) if blocklists else []
    if reputation is not None and address in reputation.flagged:
        lists = lists + [REPUTATION_LIST]
    if ids_evidence is not None and ids_evidence.flags(address):
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
