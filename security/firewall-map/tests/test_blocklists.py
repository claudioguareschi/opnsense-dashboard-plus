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

"""Unit tests for threat lists (lib/blocklists.py)."""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import BLOCKLISTS, COLLECTOR, PF  # noqa: E402


def alias(name, kind, enabled=True):
    """An alias as the plugin's settings file lists it."""
    return {"name": name, "type": kind, "enabled": enabled, "description": ""}


class BlocklistTest(unittest.TestCase):
    def test_reload_marker_changes_without_restarting_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = os.path.join(directory, "reload")
            self.assertIsNone(COLLECTOR.reload_token(marker))
            COLLECTOR.request_reload(marker)
            first = COLLECTOR.reload_token(marker)
            self.assertTrue(first)
            COLLECTOR.request_reload(marker)
            self.assertNotEqual(COLLECTOR.reload_token(marker), first)

    def test_lookups_answer_from_the_collector_masks(self):
        lists = BLOCKLISTS.ThreatClassification()
        lists.configure({"spamhaus_drop", "crowdsec_blacklists", "FWMAP_AbuseIPDB"}, 0.0)
        generation, sets = lists.request()
        # set IDs follow table names; the AbuseIPDB table keeps its badge
        self.assertEqual(sets, [("T", "FWMAP_AbuseIPDB"), ("T", "crowdsec_blacklists"), ("T", "spamhaus_drop")])
        lists.observe({"refused": None,
                       "flows": [{"key": ("192.168.1.2", "45.56.79.53"), "classes": 0b110}],
                       "threat_remotes": [{"address": "203.0.113.7", "classes": 0b100}],
                       "classified": {"2606:4700:4700::1111": 0b001},
                       "class_sets": [{"id": 0, "status": "ok", "entries": 3},
                                      {"id": 1, "status": "ok", "entries": 2},
                                      {"id": 2, "status": "missing", "entries": 0}]})
        self.assertEqual(lists.lookup("45.56.79.53"), ["crowdsec_blacklists", "spamhaus_drop"])
        self.assertEqual(lists.lookup("203.0.113.7"), ["spamhaus_drop"])
        self.assertEqual(lists.lookup("2606:4700:4700::1111"), ["AbuseIPDB blacklist"])
        self.assertEqual(lists.lookup("10.1.2.3"), [])
        self.assertEqual(lists.names, ["AbuseIPDB blacklist", "crowdsec_blacklists"])
        self.assertEqual([row["status"] for row in lists.report()["lists"]], ["ok", "ok", "missing"])
        # a refused sample keeps the previous answers
        lists.observe({"refused": {"reason": "refused_states"}, "flows": [], "threat_remotes": []})
        self.assertEqual(lists.lookup("203.0.113.7"), ["spamhaus_drop"])

    def test_country_and_operational_sets_describe_without_flagging(self):
        """Country and operational sets follow the threat lists in set-ID order; they describe a
        remote (PF membership, not GeoIP) and never make it a threat. A table chosen twice keeps
        its first category; a set matching most of the ranked flows is reported broad."""
        sets = BLOCKLISTS.ThreatClassification()
        with mock.patch.object(BLOCKLISTS, "log_warning"):
            sets.configure({"spamhaus_drop"}, 0.0, (), {"Country_CN", "Country_US"}, {"Partners", "spamhaus_drop"},
                           {"Country_XX"})
        self.assertEqual(sets.request()[1], [("T", "spamhaus_drop"), ("C", "Country_CN"), ("C", "Country_US"),
                                             ("O", "Partners")])
        flows = [{"key": ("192.168.1.2", f"45.56.79.{n}"), "classes": 0b0100} for n in range(30)]
        flows[0]["classes"] = 0b1011
        sets.observe({"refused": None, "flows": flows, "threat_remotes": [], "classified": {},
                      "class_sets": [{"id": n, "status": "ok", "entries": 10} for n in range(4)]})
        self.assertEqual(sets.lookup("45.56.79.0"), ["spamhaus_drop"])
        self.assertEqual(sets.described("45.56.79.0"), [{"name": "Country_CN", "category": "country"},
                                                       {"name": "Partners", "category": "operational"}])
        self.assertEqual(sets.lookup("45.56.79.1"), [])
        self.assertEqual(sets.described("45.56.79.1"), [{"name": "Country_US", "category": "country"}])
        report = sets.report()
        self.assertEqual([(row["name"], row["category"], row["matched"], row["broad"]) for row in report["sets"]],
                         [("Country_CN", "country", 1, False), ("Country_US", "country", 29, True),
                          ("Partners", "operational", 1, False)])
        self.assertEqual((report["missing"], report["duplicates"], report["ranked"]), (["Country_XX"], ["spamhaus_drop"], 30))
        self.assertEqual([row["name"] for row in report["lists"]], ["spamhaus_drop"])
        fields = BLOCKLISTS.threat_fields("45.56.79.1", sets, None)
        self.assertEqual(fields, {"lists": [], "abuseipdb": None, "sets": [{"name": "Country_US", "category": "country"}]})
        self.assertNotIn("sets", BLOCKLISTS.threat_fields("45.56.79.200", sets, None))

    def test_set_candidates_skip_internal_tables(self):
        aliases = [{"name": "Country_CN", "type": "geoip", "enabled": True, "description": "China"}]
        self.assertEqual(BLOCKLISTS.set_candidates(["__lan_network", "Country_CN", "bogons"], aliases),
                         [{"name": "bogons", "type": "table", "description": ""},
                          {"name": "Country_CN", "type": "geoip", "description": "China"}])

    def test_generation_follows_the_table_sources(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(BLOCKLISTS, "ALIAS_TABLE_DIR", directory), \
                mock.patch.object(BLOCKLISTS, "ABUSEIPDB_BLACKLIST", os.path.join(directory, "abuse.txt")):
            with open(os.path.join(directory, "Drop.md5.txt"), "w") as handle:
                handle.write("a" * 32)
            with open(os.path.join(directory, "abuse.txt"), "w") as handle:
                handle.write("203.0.113.7\n")
            lists = BLOCKLISTS.ThreatClassification()
            lists.configure({"Drop", "FWMAP_AbuseIPDB"}, 0.0)
            first = lists.generation
            lists.configure({"Drop", "FWMAP_AbuseIPDB"}, 10.0)
            self.assertEqual(lists.generation, first)
            with open(os.path.join(directory, "Drop.md5.txt"), "w") as handle:
                handle.write("b" * 32)
            lists.configure({"Drop", "FWMAP_AbuseIPDB"}, 10.0)
            self.assertNotEqual(lists.generation, first)
            changed = lists.generation
            # tables with a known source are still re-read periodically (PF loads them after the file)
            lists.configure({"Drop", "FWMAP_AbuseIPDB"}, BLOCKLISTS.CLASS_REFRESH_SECONDS)
            self.assertNotEqual(lists.generation, changed)
            # a table without a source (CrowdSec...) is re-read more often
            lists.configure({"crowdsec_blacklists"}, 0.0)
            volatile = lists.generation
            lists.configure({"crowdsec_blacklists"}, BLOCKLISTS.CLASS_VOLATILE_REFRESH_SECONDS)
            self.assertNotEqual(lists.generation, volatile)
        self.assertIsNone(BLOCKLISTS.ThreatClassification().request())

    def test_more_lists_than_sets_are_reported(self):
        lists = BLOCKLISTS.ThreatClassification()
        with mock.patch.object(BLOCKLISTS, "log_warning") as warning:
            lists.configure({f"list{n:02}" for n in range(70)}, 0.0)
        self.assertEqual(len(lists.request()[1]), 64)
        self.assertEqual(lists.report()["ignored"], [f"list{n:02}" for n in range(64, 70)])
        warning.assert_called_once()

    def test_selects_feed_tables(self):
        aliases = [alias("Drop", "urltable"), alias("Office", "host"), alias("Off", "url", enabled=False)]
        tables = ["Drop", "Office", "Off", "crowdsec_blacklists", "bogons"]
        self.assertEqual(BLOCKLISTS.blocklist_tables(tables, blocked={"Drop", "Off"}, aliases=aliases),
                         {"Drop", "crowdsec_blacklists"})
        # a leftover FWMAP_ table whose alias was deleted is ignored
        self.assertEqual(BLOCKLISTS.blocklist_tables(tables + ["FWMAP_Old"], blocked=set(), aliases=aliases),
                         {"crowdsec_blacklists"})
        # a URL alias used only by pass rules (an allowlist) is not a threat list
        self.assertEqual(BLOCKLISTS.blocklist_tables(tables, blocked=set(), aliases=aliases), {"crowdsec_blacklists"})

    def test_only_pf_tables_classify(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(BLOCKLISTS, "ABUSEIPDB_BLACKLIST", os.path.join(directory, "abuse.txt")):
            with mock.patch.object(BLOCKLISTS, "pf_tables", return_value=["FWMAP_AbuseIPDB", "Other", "FWMAP_Watchlist"]), \
                    mock.patch.object(BLOCKLISTS, "blocklist_tables", return_value={"Other"}):
                self.assertEqual(BLOCKLISTS.chosen_threat_lists(""),
                                 ({"FWMAP_AbuseIPDB", "Other", "FWMAP_Watchlist"}, set()))
            # a chosen feed without its alias, and the AbuseIPDB blacklist without its table, are
            # reported rather than read from their downloads
            with open(os.path.join(directory, "abuse.txt"), "w") as handle:
                handle.write("203.0.113.7\n")
            with mock.patch.object(BLOCKLISTS, "pf_tables", return_value=["Other"]):
                self.assertEqual(BLOCKLISTS.chosen_threat_lists("FWMAP_Feodo,Other"),
                                 ({"Other"}, {"FWMAP_Feodo", "FWMAP_AbuseIPDB"}))

    def test_threat_list_candidates_offer_feeds_not_lan_aliases(self):
        aliases = [alias("Drop", "urltable"), alias("RFC1918", "network"), alias("FWMAP_Feodo", "urltable")]
        candidates = BLOCKLISTS.threat_list_candidates(["Drop", "RFC1918", "FWMAP_Feodo", "crowdsec_blacklists"], aliases)
        names = [item["name"] for item in candidates]
        self.assertNotIn("RFC1918", names)
        self.assertIn("Drop", names)
        self.assertIn("crowdsec_blacklists", names)
        feeds = {item["name"]: item for item in candidates if item.get("curated")}
        self.assertEqual(len(feeds), len(BLOCKLISTS.FEEDS))
        self.assertTrue(feeds["FWMAP_Feodo"]["installed"])
        self.assertFalse(feeds["FWMAP_Spamhaus_DROP"]["installed"])

    def test_reads_block_rule_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            rules = os.path.join(directory, "rules.debug")
            with open(rules, "w") as handle:
                handle.write('block in log quick from {<Drop>} to {any} label "abc" # <NotThis>\n'
                             'pass in quick from {<Allow>} to {any} label "def"\n')
            self.assertEqual(PF.blocked_rule_tables(rules), {"Drop"})


if __name__ == "__main__":
    unittest.main()
