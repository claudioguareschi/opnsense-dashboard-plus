"""Unit tests for persisted threat history and disposition views."""

import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import CACHE, COLLECTOR, COMMON, PF, THREATS, NAT_OUT  # noqa: E402


class ThreatQueueTest(unittest.TestCase):
    INBOUND = ("all tcp 192.168.1.2:80 (198.13.91.163:80) <- 108.188.77.155:51234       ESTABLISHED:ESTABLISHED\n"
               "   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:9000 bytes\n   id: 0a creatorid: 01\n")
    OUTBOUND = ("all tcp 192.168.1.50:50000 (198.13.91.163:50000) -> 8.8.8.8:443       ESTABLISHED:ESTABLISHED\n"
                "   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:900 bytes\n   id: 0b creatorid: 01\n")

    def observe(self, states):
        lists = {"108.188.77.155": ["AbuseIPDB blacklist"]}
        return THREATS.observe(PF.parse_states(states), lambda address: lists.get(address, []), {"198.13.91.163"})

    def test_records_only_flagged_addresses_with_target(self):
        seen = self.observe(self.INBOUND + self.OUTBOUND)
        self.assertEqual(list(seen), ["108.188.77.155"])
        self.assertEqual(seen["108.188.77.155"]["targets"], ["tcp|192.168.1.2|80"])
        self.assertEqual(seen["108.188.77.155"]["inbound"], 1)
        self.assertEqual(seen["108.188.77.155"]["service_ports"], {"HTTP": "80/tcp"})

    def test_reply_state_from_a_server_counts_as_inbound(self):
        # the SYN passed the other CARP node; the mail server's reply created an outbound NAT state
        reply = ("all tcp 198.13.91.163:13526 (192.168.1.2:443) -> 108.188.77.155:48824       TIME_WAIT:TIME_WAIT\n"
                 "   age 00:01:01, expires in 00:00:29, 2:1 pkts, 100:40 bytes\n   id: c6 creatorid: a9\n")
        entry = self.observe(reply)["108.188.77.155"]
        self.assertEqual((entry["inbound"], entry["outbound"], entry["targets"], entry["services"]),
                         (1, 0, ["tcp|192.168.1.2|443"], ["HTTPS"]))
        self.assertEqual(PF.orientation(PF.parse_states(NAT_OUT)[0], "34.209.15.107")[0], False)

    def test_review_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            THREATS.record(db, self.observe(self.INBOUND), now=100.0)
            THREATS.record(db, self.observe(self.INBOUND), now=200.0)
            rows = THREATS.listing(db)["rows"]
            self.assertEqual((rows[0]["first_seen"], rows[0]["last_seen"], rows[0]["samples"], rows[0]["status"]),
                             (100.0, 200.0, 2, "new"))
            self.assertTrue(rows[0]["inbound"])
            self.assertEqual(rows[0]["target_services"], {"tcp|192.168.1.2|80": "HTTP"})
            note = "Port forward probe; checked logs ✓"
            encoded = __import__("base64").urlsafe_b64encode(note.encode()).decode().rstrip("=")
            self.assertEqual(THREATS.main(["set", "108.188.77.155", "blocked", encoded], path=os.path.join(directory, "cache.db")),
                             {"result": "saved"})
            self.assertEqual(THREATS.listing(db, "all")["rows"][0]["note"], note)
            # a status change alone keeps the note
            THREATS.set_status(db, "108.188.77.155", "blocked")
            self.assertEqual(THREATS.listing(db)["rows"][0]["note"], note)
            # states that already existed (or linger in TIME_WAIT) do not reopen it
            THREATS.set_status(db, "108.188.77.155", "blocked", now=300.0)
            THREATS.record(db, self.observe(self.INBOUND), now=310.0)
            self.assertEqual(THREATS.listing(db)["rows"][0]["status"], "blocked")
            # a connection opened after the block means it did not hold: back to new, flagged
            THREATS.record(db, self.observe(self.INBOUND), now=400.0)
            row = THREATS.listing(db)["rows"][0]
            self.assertEqual((row["status"], row["seen_after_block"]), ("new", True))
            self.assertEqual(THREATS.listing(db)["counts"], {"passed": 1, "firewall_blocked": 0,
                             "ips_dropped": 0, "reviewed": 0, "dismissed": 0, "all": 1})
            self.assertEqual(THREATS.listing(db, "counts")["rows"], [])
            THREATS.set_status(db, "108.188.77.155", "reviewed")
            self.assertNotIn("seen_after_block", THREATS.listing(db)["rows"][0])

    def test_multicast_is_not_a_remote_endpoint(self):
        self.assertFalse(COMMON.public_ipv4("224.0.0.18"))
        self.assertTrue(COMMON.public_ipv4("9.9.9.9"))
        self.assertTrue(COMMON.public_ip("2606:4700:4700::1111"))
        self.assertTrue(COMMON.private_ip("fd00::1"))
        self.assertFalse(COMMON.public_ip("ff02::1"))

    def test_remote_identity_is_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            seen = self.observe(self.INBOUND)
            seen["108.188.77.155"]["remote"] = {"org": "Example ISP", "country": "United States", "asn": 64500}
            THREATS.record(db, seen, now=100.0)
            THREATS.record(db, self.observe(self.INBOUND), now=200.0)  # a sample without the facts
            self.assertEqual(THREATS.listing(db)["rows"][0]["remote"],
                             {"org": "Example ISP", "country": "United States", "asn": 64500})

    def test_country_code_from_geo_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            store = CACHE.CacheStore(path)
            store.put_many("geo:2:city.mmdb:1", [("108.188.77.155", {"country": "RO", "lat": 1, "lon": 2})])
            db = THREATS.connect(path)
            THREATS.record(db, self.observe(self.INBOUND), now=100.0)
            self.assertEqual(THREATS.listing(db)["rows"][0]["remote"]["country_code"], "RO")

    def test_bulk_dismiss_and_purge(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            THREATS.record(db, self.observe(self.INBOUND + self.OUTBOUND), now=100.0)
            self.assertEqual(THREATS.bulk_status(db, "passed", "dismissed")["changed"], 1)
            self.assertEqual(THREATS.listing(db)["counts"]["dismissed"], 1)
            self.assertEqual(THREATS.purge(db, "new")["result"], "failed")
            self.assertEqual(THREATS.purge(db, "dismissed")["deleted"], 1)
            self.assertEqual(THREATS.listing(db)["rows"], [])

    def test_search_pages_and_filtered_bulk(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(THREATS, "inside_names", lambda: {"192.168.1.2": "mail"}):
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            seen = {}
            for index in range(5):
                entry = self.observe(self.INBOUND)["108.188.77.155"]
                entry["remote"] = {"country": "Russia" if index < 2 else "Brazil"}
                seen[f"108.188.77.{index}"] = entry
            THREATS.record(db, seen, now=100.0)
            # key names never match: every entry has a status, none displays the word
            self.assertEqual(THREATS.listing(db, "passed", query="status")["total"], 0)
            self.assertEqual(THREATS.listing(db, "passed", query="russia")["total"], 2)
            # inside host names count, as displayed
            self.assertEqual(THREATS.listing(db, "passed", query="mail")["total"], 5)
            page = THREATS.listing(db, "passed", offset=2, limit=2)
            self.assertEqual((page["total"], len(page["rows"]), page["offset"]), (5, 2, 2))
            # a bulk action with a search touches only what the search shows
            self.assertEqual(THREATS.bulk_status(db, "passed", "dismissed", query="russia")["changed"], 2)
            self.assertEqual(THREATS.listing(db, "counts")["counts"]["passed"], 3)
            self.assertEqual(THREATS.purge(db, "dismissed", query="brazil")["deleted"], 0)
            self.assertEqual(THREATS.purge(db, "dismissed", query="russia")["deleted"], 2)
            # the command line carries the search as base64url
            encoded = __import__("base64").urlsafe_b64encode(b"brazil").decode().rstrip("=")
            self.assertEqual(THREATS.main(["list", "passed", "0", "1", encoded], path=os.path.join(directory, "cache.db"))["total"], 3)

    def test_ipv6_persistence_key_and_status_action(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            entry = self.observe(self.INBOUND)["108.188.77.155"]
            THREATS.record(db, {"2606:4700:4700::1111": entry}, now=100.0)
            row = THREATS.listing(db, "passed")["rows"][0]
            self.assertEqual((row["address"], row["disposition"]), ("2606:4700:4700::1111", "passed"))
            self.assertEqual(THREATS.set_status(db, "2606:4700:4700::1111", "reviewed")["result"], "saved")
            self.assertEqual(THREATS.listing(db, "reviewed")["rows"][0]["address"], "2606:4700:4700::1111")

    def test_blocked_attempts_after_a_pass_stay_behind_the_passed_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            passed = self.observe(self.INBOUND)
            passed["108.188.77.155"]["connections"] = [
                {"key": "pass", "decision": "pass", "seen": 100, "inside": "192.168.1.2:80"}]
            THREATS.record(db, passed, now=100.0)
            blocked = {"108.188.77.155": {
                "lists": ["FWMAP_FireHOL_L1"], "inbound": 1, "outbound": 0, "inside": [], "bytes": 0,
                "youngest": None, "service_ports": {}, "disposition": "firewall_blocked",
                "targets": [f"tcp|198.13.91.163|{port}" for port in range(1000, 1000 + THREATS.MAX_ITEMS)],
                "services": [f"TCP/{port}" for port in range(1000, 1000 + THREATS.MAX_ITEMS)],
                "connections": [{"key": f"block{n}", "decision": "block", "seen": 200 + n}
                                for n in range(THREATS.MAX_CONNECTIONS)],
            }}
            THREATS.record(db, blocked, now=200.0)
            row = THREATS.listing(db, "passed")["rows"][0]
            self.assertEqual(row["disposition"], "passed")
            self.assertEqual((row["targets"][0], row["services"][0]), ("tcp|192.168.1.2|80", "HTTP"))
            self.assertEqual(row["connections"][0]["key"], "pass")
            self.assertEqual(row["lists"], ["FWMAP_FireHOL_L1", "AbuseIPDB blacklist"])

    def test_old_dropped_status_migrates_to_ips_disposition(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE threats (address TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, "
                       "samples INTEGER, data TEXT, status TEXT, note TEXT, status_changed REAL)")
            db.execute("INSERT INTO threats VALUES (?, 1, 2, 1, ?, 'dropped', '', NULL)",
                       ("2001:4860:4860::8888", json.dumps({})))
            db.commit()
            db.close()
            migrated = THREATS.connect(path)
            self.assertEqual(migrated.execute("SELECT status, disposition FROM threats").fetchone(),
                             ("new", "ips_dropped"))

    def test_rejects_bad_input(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            self.assertEqual(THREATS.set_status(db, "1.2.3.4; rm", "new")["result"], "failed")
            self.assertEqual(THREATS.set_status(db, "1.2.3.4", "deleted")["result"], "failed")
            self.assertEqual(THREATS.set_status(db, "1.2.3.4", "new")["result"], "failed")

    def test_prune_by_age(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            THREATS.record(db, self.observe(self.INBOUND), now=0.0)
            THREATS.prune(db, now=THREATS.KEEP_SECONDS + 1)
            self.assertEqual(THREATS.listing(db)["rows"], [])

    def test_prune_keeps_passed_entries_over_blocked_floods(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            rows = [("198.51.100.1", "passed", 1.0)] + [(f"203.0.113.{n}", "firewall_blocked", 10.0 + n) for n in range(3)]
            db.executemany("INSERT INTO threats (address, first_seen, last_seen, samples, data, disposition) "
                           "VALUES (?, ?, ?, 1, '{}', ?)", [(a, t, t, d) for a, d, t in rows])
            with mock.patch.object(THREATS, "KEEP_ROWS", 2):
                THREATS.prune(db, now=20.0)
            self.assertEqual({row[0] for row in db.execute("SELECT address FROM threats")},
                             {"198.51.100.1", "203.0.113.2"})

    def test_widget_in_use(self):
        dashboard = __import__("base64").b64encode(json.dumps({"widgets": [{"id": "firewallmap"}]}).encode()).decode()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.xml")
            with open(path, "w") as handle:
                handle.write(f"<opnsense><system><user><dashboard>{dashboard}</dashboard></user></system></opnsense>")
            self.assertTrue(COLLECTOR.widget_in_use(path))
            self.assertTrue(COLLECTOR.recording_wanted({"record_threats": "1"}, path))
            self.assertFalse(COLLECTOR.recording_wanted({"record_threats": "0"}, path))
            with open(path, "w") as handle:
                handle.write("<opnsense><system><user><dashboard>bnVsbA==</dashboard></user>"
                             "<user><dashboard>e30=</dashboard></user></system></opnsense>")
            self.assertFalse(COLLECTOR.widget_in_use(path))


if __name__ == "__main__":
    unittest.main()
