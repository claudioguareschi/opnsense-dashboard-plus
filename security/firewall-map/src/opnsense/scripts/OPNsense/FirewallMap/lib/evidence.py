#!/usr/local/bin/python3

# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
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



"""Security evidence for the collector's ranking (collector/evidence.h, CONTRACTS.md "Evidence").

Each source stays its own fact, so a remote can be blocked, IDS-detected and reputation-flagged at
once; the collector adds the threat-list fact from its PF tables and derives the security class
(S0-S3) from all of them. Everything here is read from already bounded trackers: filterlog hits in
the block window, Suricata alerts in the alert window, AbuseIPDB verdicts in the cache.
"""

from .common import public_ip

THREAT_LIST, PF_BLOCKED, IDS, IDS_HIGH, REPUTATION = 1, 2, 4, 8, 16
# what a request may say (THREAT_LIST is the collector's own, from its PF tables)
REQUEST_BITS = PF_BLOCKED | IDS | IDS_HIGH | REPUTATION
COUNT_MAX = 1000000
# Suricata severities run from 1 (highest) to 3: IDS_HIGH is a worst severity of 1 or 2, the map's
# long-standing rule for flagging an address (lib/ids.py ALERT_FLAG_SEVERITY)
IDS_HIGH_SEVERITY = 2
NAMES = {THREAT_LIST: "threat_list", PF_BLOCKED: "pf_blocked", IDS: "ids", IDS_HIGH: "ids_high",
         REPUTATION: "reputation"}


def facts(blocked_hits=0, ids_alerts=0, ids_severity=0, reputation=False):
    """(mask, blocked hits, IDS alerts, IDS worst severity) as an EVIDENCE row carries them."""
    blocked_hits, ids_alerts = min(int(blocked_hits), COUNT_MAX), min(int(ids_alerts), COUNT_MAX)
    mask = PF_BLOCKED if blocked_hits > 0 else 0
    if ids_alerts > 0:
        ids_severity = min(max(int(ids_severity or 3), 1), 3)
        mask |= IDS | (IDS_HIGH if ids_severity <= IDS_HIGH_SEVERITY else 0)
    else:
        ids_severity = 0
    if reputation:
        mask |= REPUTATION
    return mask, blocked_hits, ids_alerts, ids_severity


def gather(alerts=None, correlator=None, blocks=None, reputation=None):
    """{remote: facts} for every public remote with evidence."""
    blocked, ids = {}, {}
    if blocks is not None:
        for address, entry in blocks.sources.items():
            blocked[address] = blocks.hits(entry)
    if correlator is not None:
        # blocked attempts kept for late alerts (also while no map is open)
        for key in correlator.blocked:
            if key[3] not in (blocks.sources if blocks is not None else ()):
                blocked[key[3]] = blocked.get(key[3], 0) + 1
        for key, flow in correlator.flows.items():
            items = correlator._alert_items(flow)
            if items:
                count, worst = ids.get(key[3], (0, 3))
                ids[key[3]] = (count + sum(item["count"] for item in items),
                               min([worst] + [item["severity"] for item in items]))
    if alerts is not None:
        # the alert tracker sees every alert of the window: its count and worst severity win
        for address, entry in alerts.sources.items():
            if entry["signatures"]:
                ids[address] = (entry["count"], min(item["severity"] for item in entry["signatures"].values()))
    flagged = reputation.flagged if reputation is not None else set()
    result = {}
    for address in set(blocked) | set(ids) | set(flagged):
        if not public_ip(address):
            continue
        alerts_count, severity = ids.get(address, (0, 0))
        result[address] = facts(blocked.get(address, 0), alerts_count, severity, address in flagged)
    return result
