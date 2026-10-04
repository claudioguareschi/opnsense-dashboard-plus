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

"""Unit tests for investigations and the AbuseIPDB blacklist."""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import ABUSEIPDB, CACHE, COMMON, INVESTIGATE  # noqa: E402


class InvestigateTest(unittest.TestCase):
    RDAP = {
        "name": "GOGL", "handle": "NET-8-8-8-0-2", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
        "events": [{"eventAction": "registration", "eventDate": "2023-12-28T17:24:33-05:00"}],
        "entities": [{
            "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
            "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]]}],
        }],
    }

    def test_parses_rdap_owner_and_abuse_contact(self):
        parsed = INVESTIGATE.parse_rdap(self.RDAP)
        self.assertEqual(parsed["owner"], "Google LLC")
        self.assertEqual(parsed["abuse_email"], "network-abuse@google.com")
        self.assertEqual(parsed["range"], "8.8.8.0 – 8.8.8.255")
        self.assertEqual(parsed["registered"], "2023-12-28")

    def test_rejects_private_and_invalid_addresses(self):
        self.assertEqual(INVESTIGATE.investigate("192.168.1.1", store=object(), fetchers={})["status"], "failed")
        self.assertEqual(INVESTIGATE.investigate("fd12:3456::1", store=object(), fetchers={})["status"], "failed")
        self.assertEqual(INVESTIGATE.investigate("8.8.8.8; rm -rf /", store=object(), fetchers={})["status"], "failed")

    def test_ipv6_lookup_urls_are_encoded(self):
        address = "2001:4860:4860::8888"
        with mock.patch.object(INVESTIGATE, "fetch_json", return_value={}) as fetch:
            sources = INVESTIGATE.lookups(address, "key")
            sources["rdap"]()
            sources["ripestat"]()
            sources["abuseipdb"]()
        urls = [call.args[0] for call in fetch.call_args_list]
        self.assertTrue(all("2001%3A4860%3A4860%3A%3A8888" in url for url in urls))

    def test_caches_and_reports_errors_per_source(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CACHE.CacheStore(os.path.join(directory, "cache.db"))
            calls = []

            def rdap():
                calls.append("rdap")
                return {"name": "GOGL"}

            def broken():
                raise RuntimeError("boom secret-key")
            result = INVESTIGATE.investigate("8.8.8.8", store=store, key="secret-key",
                                             fetchers={"rdap": rdap, "abuseipdb": broken}, now=1000.0)
            self.assertEqual(result["rdap"], {"name": "GOGL"})
            self.assertEqual(result["abuseipdb"], {"error": "boom <key>"})
            good = INVESTIGATE.investigate("8.8.8.8", store=store, fetchers={"abuseipdb": lambda: {"score": 90}}, now=1000.5)
            self.assertEqual(good["abuseipdb"], {"score": 90})
            # the verdict outlives the 6-hour lookup cache
            self.assertEqual(store.get_all(COMMON.REPUTATION_KIND, now=1000.0 + 7 * 86400), {"8.8.8.8": {"score": 90}})
            again = INVESTIGATE.investigate("8.8.8.8", store=store, fetchers={"rdap": rdap}, now=1001.0)
            self.assertTrue(again["rdap"]["cached"])
            self.assertEqual(calls, ["rdap"])


class AbuseBlacklistTest(unittest.TestCase):
    def setUp(self):
        # update() loads the PF table after a download; keep the real config.xml and pfctl out of it
        patcher = mock.patch.object(ABUSEIPDB, "alias_settings", return_value=(False, True))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_downloads_parses_and_rate_limits(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ABUSEIPDB, "LIST_FILE", os.path.join(directory, "list.txt")), \
                mock.patch.object(ABUSEIPDB, "STATUS_FILE", os.path.join(directory, "status.json")):
            calls = []

            def fetch(key):
                calls.append(key)
                return "94.154.43.203\n10.0.0.1\nnot-an-ip\n204.76.203.231\n2001:4860:4860::8888\n"
            self.assertEqual(ABUSEIPDB.update(key="", fetch=fetch)["reason"], "no key")
            self.assertEqual(ABUSEIPDB.update(key="k", fetch=fetch, now=1000.0), {"result": "ok", "count": 3})
            with open(ABUSEIPDB.LIST_FILE) as handle:
                self.assertEqual(handle.read().split(),
                                 ["94.154.43.203", "204.76.203.231", "2001:4860:4860::8888"])
            self.assertEqual(ABUSEIPDB.update(key="k", fetch=fetch, now=2000.0)["reason"], "recent")
            self.assertEqual(ABUSEIPDB.update(force=True, key="k", fetch=fetch, now=2000.0)["result"], "ok")
            # "Download now" clicked again right after a download does not spend another one
            self.assertEqual(ABUSEIPDB.update(force=True, key="k", fetch=fetch, now=2100.0)["reason"], "recent")
            # a new key downloads at once, the same key again waits
            self.assertEqual(ABUSEIPDB.update(key="other", fetch=fetch, now=3000.0)["result"], "ok")
            self.assertEqual(ABUSEIPDB.update(key="other", fetch=fetch, now=4000.0)["reason"], "recent")
            self.assertEqual(calls, ["k", "k", "other"])

    def test_errors_never_contain_the_key(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ABUSEIPDB, "LIST_FILE", os.path.join(directory, "list.txt")), \
                mock.patch.object(ABUSEIPDB, "STATUS_FILE", os.path.join(directory, "status.json")):

            def broken(key):
                raise RuntimeError(f"failed with {key}")
            result = ABUSEIPDB.update(force=True, key="secret", fetch=broken)
            self.assertEqual(result["error"], "failed with <key>")
            with open(ABUSEIPDB.STATUS_FILE) as handle:
                self.assertNotIn("secret", handle.read())


class AbuseAliasTest(unittest.TestCase):
    def test_alias_settings(self):
        alias = {"name": "FWMAP_AbuseIPDB", "type": "external", "enabled": True, "description": ""}
        self.assertEqual(ABUSEIPDB.alias_settings({"blocklist_aliases": "1"}, [alias]), (True, True))
        self.assertEqual(ABUSEIPDB.alias_settings({"blocklist_aliases": "0"}, []), (False, False))

    def test_pf_table_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            list_file = os.path.join(directory, "list.txt")
            run = mock.Mock(return_value=mock.Mock(returncode=0, stderr=""))
            with mock.patch.object(ABUSEIPDB, "LIST_FILE", list_file):
                # on, but nothing downloaded yet: the table is left alone and no file is created
                self.assertFalse(ABUSEIPDB.sync_pf_table((True, True), run=run)["loaded"])
                self.assertFalse(os.path.exists(list_file))
                run.assert_not_called()
                with open(list_file, "w") as handle:
                    handle.write("192.0.2.1\n2001:db8::1\n")
                self.assertEqual(ABUSEIPDB.sync_pf_table((True, True), run=run), {"enabled": True, "loaded": True})
                self.assertEqual(run.call_args.args[0],
                                 [COMMON.PFCTL, "-t", "FWMAP_AbuseIPDB", "-T", "replace", "-f", list_file])
                # off with the alias still defined (in use by a rule, or the administrator's own): untouched
                run.reset_mock()
                ABUSEIPDB.sync_pf_table((False, True), run=run)
                run.assert_not_called()
                # off and the alias gone: the leftover table is dropped
                ABUSEIPDB.sync_pf_table((False, False), run=run)
                self.assertEqual(run.call_args.args[0], [COMMON.PFCTL, "-q", "-t", "FWMAP_AbuseIPDB", "-T", "kill"])
                run.return_value = mock.Mock(returncode=1, stderr="pfctl: Table does not exist.")
                self.assertEqual(ABUSEIPDB.sync_pf_table((True, True), run=run),
                                 {"enabled": True, "loaded": False, "error": "pfctl: Table does not exist."})


if __name__ == "__main__":
    unittest.main()
