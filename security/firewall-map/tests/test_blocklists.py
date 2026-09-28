"""Unit tests for threat lists (fwmap_blocklists)."""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import BLOCKLISTS, COLLECTOR, PF  # noqa: E402


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

    def test_longest_prefix_lookup_across_tables(self):
        index = BLOCKLISTS.BlocklistIndex()
        index.index = BLOCKLISTS.BlocklistIndex.build({
            "spamhaus_drop": ["45.56.0.0/16", "   203.0.113.7", "!10.0.0.0/8", "2001:db8::/32"],
            "crowdsec_blacklists": ["45.56.79.53"],
        })
        self.assertEqual(index.lookup("45.56.79.53"), ["crowdsec_blacklists", "spamhaus_drop"])
        self.assertEqual(index.lookup("203.0.113.7"), ["spamhaus_drop"])
        self.assertEqual(index.lookup("10.1.2.3"), [])
        self.assertEqual(index.lookup("not-an-ip"), [])

    def test_busy_blocklist_refresh_is_retried(self):
        index = BLOCKLISTS.BlocklistIndex()
        index.refreshing = True
        self.assertFalse(index.refresh(set()))
        index.refreshing = False
        self.assertTrue(index.refresh(set(), background=False))

    def test_selects_feed_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            config = os.path.join(directory, "config.xml")
            with open(config, "w") as handle:
                handle.write("<opnsense><OPNsense><Firewall><Alias><aliases>"
                             "<alias><name>Drop</name><type>urltable</type><enabled>1</enabled></alias>"
                             "<alias><name>Office</name><type>host</type><enabled>1</enabled></alias>"
                             "<alias><name>Off</name><type>url</type><enabled>0</enabled></alias>"
                             "</aliases></Alias></Firewall></OPNsense></opnsense>")
            tables = ["Drop", "Office", "Off", "crowdsec_blacklists", "bogons"]
            self.assertEqual(BLOCKLISTS.blocklist_tables(config, tables, blocked={"Drop", "Off"}),
                             {"Drop", "crowdsec_blacklists"})
            # a leftover FWMAP_ table whose alias was deleted is ignored
            self.assertEqual(BLOCKLISTS.blocklist_tables(config, tables + ["FWMAP_Old"], blocked=set()),
                             {"crowdsec_blacklists"})
            # a URL alias used only by pass rules (an allowlist) is not a threat list
            self.assertEqual(BLOCKLISTS.blocklist_tables(config, tables, blocked=set()), {"crowdsec_blacklists"})

    def test_threat_list_candidates_offer_feeds_not_lan_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            config = os.path.join(directory, "config.xml")
            with open(config, "w") as handle:
                handle.write("<opnsense><OPNsense><Firewall><Alias><aliases>"
                             "<alias><name>Drop</name><type>urltable</type><enabled>1</enabled></alias>"
                             "<alias><name>RFC1918</name><type>network</type><enabled>1</enabled></alias>"
                             "<alias><name>FWMAP_Feodo</name><type>urltable</type><enabled>1</enabled></alias>"
                             "</aliases></Alias></Firewall></OPNsense></opnsense>")
            candidates = BLOCKLISTS.threat_list_candidates(config, ["Drop", "RFC1918", "FWMAP_Feodo", "crowdsec_blacklists"])
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
