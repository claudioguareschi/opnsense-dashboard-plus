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
import os

from .collector import CLASS_MAX_SETS
from .common import (
    ABUSEIPDB_BLACKLIST, REPUTATION_KIND, REPUTATION_MAX_AGE, log_warning, public_ip,
)
from .config import aliases as configured_aliases
from .pf import blocked_rule_tables, pf_tables


IDS_LIST = "Suricata IDS"
BLOCKLIST_ALIAS_TYPES = {"urltable", "url", "urljson", "external"}
BLOCKLIST_TABLE_PREFIXES = ("crowdsec", "__qfeeds", "qfeeds", "spamhaus", "firehol", "abuse", "fwmap_")
# addresses an operator marked, and AbuseIPDB's daily blacklist, always count as threats
WATCHLIST_TABLE = "FWMAP_Watchlist"
ABUSEIPDB_LIST = "AbuseIPDB blacklist"
ABUSEIPDB_TABLE = "FWMAP_AbuseIPDB"
REPUTATION_LIST = "AbuseIPDB (looked up)"
REPUTATION_THRESHOLD = 75
REPUTATION_REFRESH_SECONDS = 60


def blocklist_tables(tables=None, blocked=None, aliases=None):
    """Names of pf tables that hold threat lists.

    URL/external aliases count only when a block or reject rule uses them, since the same alias
    types are often allowlists (cloud provider ranges...); feed tables with well-known names
    (CrowdSec, Q-Feeds, Spamhaus...) always count.
    """
    blocked = blocked_rule_tables() if blocked is None else blocked
    aliases = configured_aliases() if aliases is None else aliases
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


# curated public feeds: added as daily URL table aliases (FWMAP_*) when "Maintain blocklist
# aliases" is on; PF loads them, and the collector classifies with those tables
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


def threat_list_candidates(tables=None, aliases=None):
    """Tables an administrator may choose as threat lists, with their alias type.

    Only list-type aliases are sensible threat lists (not LAN host or network aliases).
    """
    tables = pf_tables() if tables is None else tables
    aliases = configured_aliases() if aliases is None else aliases
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


def tables_report():
    """What the settings page lists: candidates and the automatic choice, from one pf and alias read."""
    tables = pf_tables()
    aliases = configured_aliases()
    return {"tables": threat_list_candidates(tables, aliases),
            "automatic": sorted(blocklist_tables(tables, aliases=aliases))}


def chosen_threat_lists(setting):
    """(PF tables to classify with, chosen lists without a PF table).

    The administrator's choice when set, otherwise the automatic selection. Only PF tables
    classify: a curated feed counts through its FWMAP_* alias, and the AbuseIPDB blacklist through
    FWMAP_AbuseIPDB (both kept by "Maintain blocklist aliases"); a list with no table is reported,
    never silently replaced by another source."""
    names = {name.strip() for name in (setting or "").split(",") if name.strip()}
    tables = set(pf_tables())
    chosen = (names & tables) if names else blocklist_tables(list(tables))
    unavailable = names - tables
    if ABUSEIPDB_TABLE in tables:
        chosen.add(ABUSEIPDB_TABLE)
    elif os.path.exists(ABUSEIPDB_BLACKLIST):
        unavailable.add(ABUSEIPDB_TABLE)
    if WATCHLIST_TABLE in tables:
        chosen.add(WATCHLIST_TABLE)
    return chosen, unavailable


# PF table identity for the classification generation: OPNsense writes the content digest of
# every URL table alias here, and FWMAP_AbuseIPDB is loaded from the blacklist cache
ALIAS_TABLE_DIR = "/var/db/aliastables"
# PF loads a table after its source file changes, and tables without a source (CrowdSec...) change
# on their own: the collector re-reads every table at least this often
CLASS_REFRESH_SECONDS = 900
CLASS_VOLATILE_REFRESH_SECONDS = 300


def list_label(table):
    """How a threat list is named on the map: FWMAP_AbuseIPDB keeps its historical badge."""
    return ABUSEIPDB_LIST if table == ABUSEIPDB_TABLE else table


class ThreatClassification:
    """Threat lists as the collector classifies them: PF tables, read by the collector itself.

    Python chooses the tables (one set ID each, in name order) and a generation token that changes
    when their sources may have changed; the collector compiles them and reports, per sample, the
    set mask of every flow remote, threat-summary remote and requested address (`wanted`). Lookups
    answer from the last accepted sample, so Python never holds or searches list contents.
    """

    def __init__(self):
        self.tables = []        # PF tables in set-ID order
        self.generation = None
        self.masks = {}         # address -> set mask, from the last accepted sample
        self.status = {}        # table -> {"status", "entries"}, from the last accepted sample
        self.ignored = []       # tables over the set limit
        self.unavailable = []   # chosen lists that have no PF table (not classified)

    def configure(self, tables, now, unavailable=()):
        names = sorted(tables)
        self.ignored = names[CLASS_MAX_SETS:]
        if self.ignored:
            log_warning(f"{len(self.ignored)} threat lists ignored (more than {CLASS_MAX_SETS}): "
                        f"{', '.join(self.ignored)}")
        self.tables = names[:CLASS_MAX_SETS]
        unavailable = sorted(unavailable)
        if unavailable and unavailable != self.unavailable:
            log_warning("threat lists without a PF table are not used (enable Maintain blocklist aliases or "
                        f"create the aliases): {', '.join(unavailable)}")
        self.unavailable = unavailable
        self.generation = self._generation(now)

    def _generation(self, now):
        digest = hashlib.sha256()
        volatile = False
        for table in self.tables:
            digest.update(table.encode() + b"\0")
            try:
                if table == ABUSEIPDB_TABLE:
                    info = os.stat(ABUSEIPDB_BLACKLIST)
                    digest.update(f"{info.st_mtime_ns}:{info.st_size}".encode())
                else:
                    with open(f"{ALIAS_TABLE_DIR}/{table}.md5.txt", "rb") as handle:
                        digest.update(handle.read(64))
            except OSError:
                volatile = True
        period = CLASS_VOLATILE_REFRESH_SECONDS if volatile else CLASS_REFRESH_SECONDS
        digest.update(str(int(now // period)).encode())
        return digest.hexdigest()[:32]

    def request(self):
        """The collector's classification argument: (generation, [(category, table)...])."""
        return (self.generation, [("T", table) for table in self.tables]) if self.tables else None

    def observe(self, sample):
        """Masks and set statuses of an accepted sample (the previous ones stay otherwise)."""
        if sample.get("refused"):
            return
        masks = {flow["key"][1]: flow["classes"] for flow in sample["flows"] if flow.get("classes")}
        masks.update((remote["address"], remote["classes"]) for remote in sample["threat_remotes"]
                     if remote.get("classes"))
        masks.update(sample.get("classified") or {})
        self.masks = masks
        self.status = {self.tables[row["id"]]: {"status": row["status"], "entries": row["entries"]}
                       for row in sample.get("class_sets") or () if row["id"] < len(self.tables)}

    @property
    def names(self):
        """The lists in use, as the map names them."""
        return [list_label(table) for table in self.tables
                if self.status.get(table, {}).get("status", "ok") == "ok"]

    def lookup(self, address):
        mask = self.masks.get(address, 0)
        return [list_label(table) for bit, table in enumerate(self.tables) if mask >> bit & 1]

    def report(self):
        """Status: every list, with what the collector read from its table."""
        return {"lists": [dict(self.status.get(table, {"status": "pending", "entries": 0}), name=table,
                               label=list_label(table)) for table in self.tables],
                "ignored": list(self.ignored), "unavailable": list(self.unavailable)}


def threat_lists_for(address, blocklists, reputation, ids_evidence=None):
    """The threat lists an address is on: chosen lists, the AbuseIPDB verdict and, with
    `ids_evidence` (anything with flags(address): the Correlator, an AlertTracker), IDS alerts.
    Only globally reachable addresses can be threats: lists that also name private or bogon
    space (FireHOL level 1 does) must not flag the site's own or CGNAT/VPN peers."""
    if not public_ip(address):
        return []
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
