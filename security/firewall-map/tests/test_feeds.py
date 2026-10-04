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

"""Unit tests for the plugin's own download of the curated threat feeds."""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import BLOCKLISTS, FEEDS  # noqa: E402

SPAMHAUS = "; Spamhaus DROP List\n1.10.16.0/20 ; SBL256894\n2001:db8::/32 ; SBL1\n"
FIREHOL = "# firehol_level1\n#\n0.0.0.0/8\n192.0.2.7\n192.0.2.7\nnot-a-network\n"


class FeedTest(unittest.TestCase):
    def test_parses_comments_networks_and_addresses(self):
        self.assertEqual(FEEDS.parse_feed(SPAMHAUS), ["1.10.16.0/20", "2001:db8::/32"])
        self.assertEqual(FEEDS.parse_feed(FIREHOL), ["0.0.0.0/8", "192.0.2.7"])

    def test_feeds_in_use(self):
        chosen = {"threat_lists": "FWMAP_Feodo,Other"}
        self.assertEqual([feed["name"] for feed in FEEDS.feeds_in_use(chosen)], ["FWMAP_Feodo"])
        # automatic: the feeds that already have an alias
        with mock.patch.object(FEEDS, "aliases", return_value=[{"name": "FWMAP_FireHOL_L1", "enabled": True}]):
            self.assertEqual([feed["name"] for feed in FEEDS.feeds_in_use({"threat_lists": ""})], ["FWMAP_FireHOL_L1"])

    def test_update_downloads_once_a_day_and_keeps_the_last_copy(self):
        feed = next(item for item in BLOCKLISTS.FEEDS if item["name"] == "FWMAP_Spamhaus_DROP")
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(FEEDS, "FEED_DIR", directory), \
                mock.patch.object(BLOCKLISTS, "FEED_DIR", directory), \
                mock.patch.object(FEEDS, "STATUS_FILE", os.path.join(directory, "feeds.json")):
            calls = []

            def fetch(url):
                calls.append(url)
                return SPAMHAUS

            self.assertEqual(FEEDS.update(fetch=fetch, now=1000.0, feeds=[feed]), {"FWMAP_Spamhaus_DROP": "ok"})
            self.assertEqual(FEEDS.update(fetch=fetch, now=2000.0, feeds=[feed]), {"FWMAP_Spamhaus_DROP": "recent"})
            self.assertEqual(len(calls), 1)

            def broken(url):
                raise OSError("offline")

            FEEDS.update(force=True, fetch=broken, now=3000.0, feeds=[feed])
            with open(BLOCKLISTS.feed_file("FWMAP_Spamhaus_DROP")) as handle:
                self.assertEqual(handle.read().split(), ["1.10.16.0/20", "2001:db8::/32"])

    def test_a_downloaded_feed_counts_without_its_alias(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(BLOCKLISTS, "FEED_DIR", directory):
            with open(BLOCKLISTS.feed_file("FWMAP_Feodo"), "w") as handle:
                handle.write("203.0.113.9\n")
            with mock.patch.object(BLOCKLISTS, "pf_tables", return_value=["Other"]):
                self.assertEqual(BLOCKLISTS.chosen_threat_lists("FWMAP_Feodo,Other"), {"FWMAP_Feodo", "Other"})
            index = BLOCKLISTS.BlocklistIndex()
            with mock.patch.object(BLOCKLISTS, "ABUSEIPDB_BLACKLIST", os.path.join(directory, "none")):
                index.refresh({"FWMAP_Feodo"}, background=False)
            self.assertEqual(index.lookup("203.0.113.9"), ["FWMAP_Feodo"])


if __name__ == "__main__":
    unittest.main()
