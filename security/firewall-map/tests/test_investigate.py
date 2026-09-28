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
        self.assertEqual(INVESTIGATE.investigate("8.8.8.8; rm -rf /", store=object(), fetchers={})["status"], "failed")

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
    def test_downloads_parses_and_rate_limits(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(ABUSEIPDB, "LIST_FILE", os.path.join(directory, "list.txt")), \
                mock.patch.object(ABUSEIPDB, "STATUS_FILE", os.path.join(directory, "status.json")):
            calls = []

            def fetch(key):
                calls.append(key)
                return "94.154.43.203\n10.0.0.1\nnot-an-ip\n204.76.203.231\n"
            self.assertEqual(ABUSEIPDB.update(key="", fetch=fetch)["reason"], "no key")
            self.assertEqual(ABUSEIPDB.update(key="k", fetch=fetch, now=1000.0), {"result": "ok", "count": 2})
            with open(ABUSEIPDB.LIST_FILE) as handle:
                self.assertEqual(handle.read().split(), ["94.154.43.203", "204.76.203.231"])
            self.assertEqual(ABUSEIPDB.update(key="k", fetch=fetch, now=2000.0)["reason"], "recent")
            self.assertEqual(ABUSEIPDB.update(force=True, key="k", fetch=fetch, now=2000.0)["result"], "ok")
            self.assertEqual(len(calls), 2)

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


if __name__ == "__main__":
    unittest.main()
