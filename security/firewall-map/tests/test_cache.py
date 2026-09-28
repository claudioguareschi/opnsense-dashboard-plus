"""Unit tests for the SQLite cache and geolocation (fwmap_cache)."""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import CACHE, COLLECTOR, COMMON, PF  # noqa: E402


class RobustnessTest(unittest.TestCase):
    def test_parses_translation_after_both_endpoints(self):
        line = ("all tcp 192.168.1.2:443 (198.13.91.163:443) <- 45.56.79.53:35799 (10.0.0.9:35799)"
                "       ESTABLISHED:ESTABLISHED\n   age 00:00:05, expires in 23:59:37, 1:1 pkts, 1:1 bytes\n"
                "   id: 01 creatorid: 02\n")
        record = PF.parse_states(line)[0]
        self.assertEqual(record["src"]["address"], "45.56.79.53")
        self.assertEqual(record["nat"]["address"], "198.13.91.163")
        self.assertEqual(record["state"], "ESTABLISHED:ESTABLISHED")

    def test_cgnat_counts_as_inside(self):
        self.assertTrue(COMMON.private_ipv4("100.101.102.103"))
        self.assertFalse(COMMON.public_ipv4("100.101.102.103"))

    def test_transient_geo_failures_are_not_cached(self):
        calls = []

        def flaky(address):
            calls.append(address)
            if len(calls) == 1:
                raise LookupError("timeout")
            return {"lat": 1.0, "lon": 2.0}
        with tempfile.TemporaryDirectory() as directory:
            geo = CACHE.GeoCache(path=os.path.join(directory, "cache.db"), lookup=flaky)
            geo.resolve(["8.8.8.8"])
            self.assertNotIn("8.8.8.8", geo.entries)
            geo.resolve(["8.8.8.8"])
            self.assertEqual(geo.get("8.8.8.8"), {"lat": 1.0, "lon": 2.0})

    def test_single_collector_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "collector.lock")
            first = COLLECTOR.acquire_lock(path)
            self.assertIsNotNone(first)
            self.assertIsNone(COLLECTOR.acquire_lock(path))
            first.close()


class CacheStoreTest(unittest.TestCase):
    def test_persists_expires_and_prunes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            store = CACHE.CacheStore(path)
            store.put_many("hostname", [("8.8.8.8", ["dns.google", 1.0]), ("1.1.1.1", ["one.one.one.one", 1.0])], now=100.0)
            store.put_many("hostname", [("9.9.9.9", ["dns9.quad9.net", 1.0])], now=200.0)
            reopened = CACHE.CacheStore(path)
            self.assertEqual(sorted(reopened.get_all("hostname")), ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
            self.assertEqual(sorted(reopened.get_all("hostname", max_age=50, now=220.0)), ["9.9.9.9"])
            self.assertIsNone(reopened.get("hostname", "8.8.8.8", max_age=50, now=220.0))
            reopened.prune("hostname", keep=1)
            self.assertEqual(list(reopened.get_all("hostname")), ["9.9.9.9"])

    def test_geo_cache_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            store = CACHE.CacheStore(path)
            geo = CACHE.GeoCache(store=store, lookup=lambda address: {"lat": 1.0, "lon": 2.0})
            geo.resolve(["8.8.8.8"])
            geo.save(force=True)
            again = CACHE.GeoCache(store=CACHE.CacheStore(path), lookup=lambda address: None)
            self.assertEqual(again.get("8.8.8.8"), {"lat": 1.0, "lon": 2.0})


class CacheResilienceTest(unittest.TestCase):
    def test_corrupt_cache_file_is_moved_aside(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            with open(path, "wb") as handle:
                handle.write(b"this is not a database" * 100)
            store = CACHE.CacheStore(path)
            store.put_many("hostname", [("8.8.8.8", ["dns.google", 1.0])])
            self.assertEqual(list(store.get_all("hostname")), ["8.8.8.8"])
            self.assertTrue(os.path.exists(path + ".corrupt"))

    def test_skipped_state_details_do_not_leak(self):
        output = ("all tcp 198.13.91.163:1 (192.168.30.30:2) -> 34.209.15.107:8883       ESTABLISHED:ESTABLISHED\n"
                  "   age 00:00:05, expires in 23:59:37, 1:1 pkts, 1:1 bytes\n   id: 01 creatorid: 02\n"
                  "all tcp 192.168.30.30:5 -> 192.168.40.2:6       ESTABLISHED:ESTABLISHED\n"
                  "   age 00:00:05, expires in 23:59:37, 1:1 pkts, 1:1 bytes\n   id: 03 creatorid: 04\n   origif: vlan03\n")
        records = PF.parse_states(output)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0]["origif"])


if __name__ == "__main__":
    unittest.main()
