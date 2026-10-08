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

"""Security evidence facts (lib/evidence.py) and the EVIDENCE rows the collector receives."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import COLLECTOR  # noqa: E402,F401
from lib import collector, evidence  # noqa: E402


class Blocks:
    def __init__(self, hits):
        self.sources = {address: {"hits": count} for address, count in hits.items()}

    @staticmethod
    def hits(entry):
        return entry["hits"]


class Alerts:
    def __init__(self, entries):
        self.sources = {address: {"count": count, "signatures": {n: {"severity": severity} for n, severity
                                                                    in enumerate(severities)}}
                        for address, (count, severities) in entries.items()}


class Correlator:
    def __init__(self, blocked=(), flows=None):
        self.blocked = {("tcp", "198.51.100.1", "22", address, "5555" + str(n)): {} for n, address in enumerate(blocked)}
        self.flows = flows or {}

    @staticmethod
    def _alert_items(flow):
        return flow["items"]


class Reputation:
    def __init__(self, flagged):
        self.flagged = set(flagged)


class EvidenceFactsTest(unittest.TestCase):
    def test_ids_severity_sets_ids_and_ids_high(self):
        # Suricata severity 1 is the highest; 1 and 2 are high (the map's long-standing rule)
        self.assertEqual(evidence.facts(ids_alerts=3, ids_severity=1), (evidence.IDS | evidence.IDS_HIGH, 0, 3, 1))
        self.assertEqual(evidence.facts(ids_alerts=3, ids_severity=2), (evidence.IDS | evidence.IDS_HIGH, 0, 3, 2))
        self.assertEqual(evidence.facts(ids_alerts=3, ids_severity=3), (evidence.IDS, 0, 3, 3))
        # the severity is kept, not only the bit; without alerts there is no IDS fact
        self.assertEqual(evidence.facts(ids_alerts=0, ids_severity=1), (0, 0, 0, 0))

    def test_counts_are_bounded(self):
        mask, blocked, alerts, _ = evidence.facts(blocked_hits=10 ** 12, ids_alerts=10 ** 9, ids_severity=3)
        self.assertEqual((blocked, alerts), (evidence.COUNT_MAX, evidence.COUNT_MAX))
        self.assertEqual(mask, evidence.PF_BLOCKED | evidence.IDS)

    def test_simultaneous_sources_keep_every_fact(self):
        remote = "45.56.79.9"
        gathered = evidence.gather(
            alerts=Alerts({remote: (7, [3, 2]), "34.1.1.200": (1, [3])}),
            correlator=Correlator(blocked=["45.56.79.50"] * 2),
            blocks=Blocks({remote: 40, "10.0.0.5": 99}),
            reputation=Reputation([remote, "45.56.79.77"]))
        self.assertEqual(gathered[remote], (evidence.PF_BLOCKED | evidence.IDS | evidence.IDS_HIGH | evidence.REPUTATION,
                                            40, 7, 2))
        self.assertEqual(gathered["34.1.1.200"], (evidence.IDS, 0, 1, 3))
        self.assertEqual(gathered["45.56.79.50"], (evidence.PF_BLOCKED, 2, 0, 0))
        self.assertEqual(gathered["45.56.79.77"], (evidence.REPUTATION, 0, 0, 0))
        # only public remotes can be evidence
        self.assertNotIn("10.0.0.5", gathered)

    def test_the_alert_tracker_wins_over_correlated_flows(self):
        remote = "45.56.79.9"
        flows = {("tcp", "198.51.100.1", "443", remote, "5000"): {"items": [{"count": 2, "severity": 3}]},
                 ("tcp", "198.51.100.1", "443", "45.56.79.10", "5000"): {"items": [{"count": 4, "severity": 1}]}}
        gathered = evidence.gather(alerts=Alerts({remote: (9, [2])}), correlator=Correlator(flows=flows))
        self.assertEqual(gathered[remote], (evidence.IDS | evidence.IDS_HIGH, 0, 9, 2))
        self.assertEqual(gathered["45.56.79.10"], (evidence.IDS | evidence.IDS_HIGH, 0, 4, 1))


class EvidenceRowsTest(unittest.TestCase):
    def test_rows_carry_the_facts(self):
        rows = collector._evidence_rows({"45.56.79.9": evidence.facts(40, 7, 2, True)})
        self.assertEqual(rows, ["EVIDENCE 45.56.79.9 30 40 7 2"])

    def test_inconsistent_facts_are_refused(self):
        for facts in ((evidence.IDS_HIGH, 0, 1, 3), (evidence.PF_BLOCKED, 0, 0, 0), (evidence.THREAT_LIST, 0, 0, 0),
                      (evidence.IDS, 0, 0, 2)):
            with self.subTest(facts=facts), self.assertRaises(collector.CollectorError):
                collector._evidence_rows({"45.56.79.9": facts})

    def test_over_the_cap_the_strongest_evidence_is_kept(self):
        facts = {"45.56.79.1": evidence.facts(5), "45.56.79.2": evidence.facts(ids_alerts=1, ids_severity=1),
                 "45.56.79.3": evidence.facts(500), "45.56.79.4": evidence.facts(ids_alerts=1, ids_severity=3)}
        with mock.patch.object(collector, "THREAT_REMOTES", 3):
            rows = collector._evidence_rows(facts)
        self.assertEqual([row.split()[1] for row in rows], ["45.56.79.2", "45.56.79.3", "45.56.79.4"])


if __name__ == "__main__":
    unittest.main()
