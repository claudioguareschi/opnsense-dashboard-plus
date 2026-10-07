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

"""Unit tests for persisted threat history and disposition views."""

import json
import ipaddress
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import CACHE, COMMON, PF, THREATS, NAT_OUT  # noqa: E402


class ThreatQueueTest(unittest.TestCase):
    INBOUND = ("all tcp 192.168.1.2:80 (1.2.3.163:80) <- 108.188.77.155:51234       ESTABLISHED:ESTABLISHED\n"
               "   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:9000 bytes\n   id: 0a creatorid: 01\n")
    OUTBOUND = ("all tcp 192.168.1.50:50000 (1.2.3.163:50000) -> 8.8.8.8:443       ESTABLISHED:ESTABLISHED\n"
                "   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:900 bytes\n   id: 0b creatorid: 01\n")

    def observe(self, states):
        lists = {"108.188.77.155": ["AbuseIPDB blacklist"]}
        return THREATS.observe(PF.parse_states(states), lambda address: lists.get(address, []), {"1.2.3.163"})

    def test_attribution_matches_ordered_list_accumulation(self):
        views = []
        expected = {"targets": [], "inside": [], "services": [], "service_ports": {}}
        for number in (4, 1, 4, 8, 1, 2, 9, 8, 3, 0, 7, 6, 5):
            host, service = f"192.168.1.{number}", f"TCP/{number}"
            target = f"tcp|{host}|{number}"
            facts = SimpleNamespace(pair=("1.2.3.163", "34.1.1.1"), remote_started=True,
                                    target=target, inside=SimpleNamespace(address=host),
                                    service=service, service_port=str(number))
            views.append((SimpleNamespace(age=1, protocol="tcp", bytes_in=1, bytes_out=2), facts))
            for field, value in (("targets", target), ("inside", host), ("services", service)):
                if value not in expected[field]:
                    expected[field].append(value)
            expected["service_ports"].setdefault(service, f"{number}/tcp")
        lists_for = mock.Mock(return_value=["Test list"])
        entry = THREATS.observe([], lists_for, {"1.2.3.163"}, sample=(views, {}))["34.1.1.1"]
        for field, value in expected.items():
            self.assertEqual(entry[field], value)
        self.assertEqual((entry["inbound"], entry["outbound"], entry["bytes"]), (len(views), 0, len(views) * 3))
        self.assertEqual(json.loads(json.dumps(entry))["inside"], expected["inside"])
        lists_for.assert_called_once_with("34.1.1.1")
        # Existing accumulation is not capped at MAX_ITEMS; preserve that behavior.
        self.assertGreater(len(entry["inside"]), THREATS.MAX_ITEMS)

    def test_native_remote_summary_matches_pf_attribution(self):
        records = PF.parse_states(self.INBOUND + self.OUTBOUND)
        views, _ = PF.StateFacts().view(records, {"1.2.3.163"})
        remotes, candidates, remote_ids = [], [], {}
        for sequence, (record, facts) in enumerate(views):
            if facts.pair is None:
                continue
            remote = facts.pair[1]
            if remote not in remote_ids:
                remote_ids[remote] = len(remotes)
                remotes.append({"address": remote, "inbound": 0, "outbound": 0,
                                "bytes": 0, "youngest": None})
            item = remotes[remote_ids[remote]]
            item["inbound"] += int(facts.remote_started)
            item["outbound"] += int(not facts.remote_started)
            item["bytes"] += record.bytes_in + record.bytes_out
            item["youngest"] = record.age if item["youngest"] is None else min(item["youngest"], record.age)
            if facts.inside:
                packed = ipaddress.ip_address(facts.inside.address).packed
                address = bytes([4 if len(packed) == 4 else 6]) + packed.ljust(16, b"\0")
                candidates.append((remote_ids[remote], 2, sequence, 0, address))
            port = int(facts.service_port or 0)
            number = 6 if record.protocol == "tcp" else 17
            candidates.append((remote_ids[remote], 4, sequence, (number << 16) | port, b""))
            if facts.remote_started:
                target = facts.target
                address, target_port = target.split("|")[1:]
                packed = ipaddress.ip_address(address).packed
                target_data = b"".join((
                    bytes([number, 4 if len(packed) == 4 else 6]),
                    packed.ljust(16, b"\0"),
                    int(target_port).to_bytes(2, "big")))
                candidates.append((remote_ids[remote], 5, sequence, 0, target_data))
        native = {"threat_remotes": remotes, "threat_candidates": candidates}

        def lists(_address):
            return ["AbuseIPDB blacklist"]

        expected = THREATS.observe(records, lists, {"1.2.3.163"})
        actual = THREATS.observe_aggregates(native, lists)
        self.assertEqual(actual, expected)

    def test_distinct_attributions_use_indexed_membership(self):
        class CountedText(str):
            comparisons = 0
            __hash__ = str.__hash__

            def __eq__(self, other):
                type(self).comparisons += 1
                return super().__eq__(other)

        views = []
        for number in range(500):
            facts = SimpleNamespace(pair=("1.2.3.163", "34.1.1.1"), remote_started=True,
                                    target=CountedText(f"tcp|192.168.1.2|{number}"),
                                    inside=SimpleNamespace(address=CountedText(f"10.0.{number // 256}.{number % 256}")),
                                    service=CountedText(f"TCP/{number}"), service_port=str(number))
            views.append((SimpleNamespace(age=1, protocol="tcp", bytes_in=1, bytes_out=2), facts))
        entry = THREATS.observe([], lambda address: ["Test list"], {}, sample=(views, {}))["34.1.1.1"]
        self.assertLess(CountedText.comparisons, len(views) * 10)
        self.assertEqual(len(entry["inside"]), len(views))

    def test_records_only_flagged_addresses_with_target(self):
        seen = self.observe(self.INBOUND + self.OUTBOUND)
        self.assertEqual(list(seen), ["108.188.77.155"])
        self.assertEqual(seen["108.188.77.155"]["targets"], ["tcp|192.168.1.2|80"])
        self.assertEqual(seen["108.188.77.155"]["inbound"], 1)
        self.assertEqual(seen["108.188.77.155"]["service_ports"], {"HTTP": "80/tcp"})

    def test_reply_state_from_a_server_counts_as_inbound(self):
        # the SYN passed the other CARP node; the mail server's reply created an outbound NAT state
        reply = ("all tcp 1.2.3.163:13526 (192.168.1.2:443) -> 108.188.77.155:48824       TIME_WAIT:TIME_WAIT\n"
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
        self.assertFalse(COMMON.public_ip("224.0.0.18"))
        self.assertTrue(COMMON.public_ip("9.9.9.9"))
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
                "targets": [f"tcp|1.2.3.163|{port}" for port in range(1000, 1000 + THREATS.MAX_ITEMS)],
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

    def test_prune_keeps_entries_the_operator_touched(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            insert = ("INSERT INTO threats (address, first_seen, last_seen, samples, data, disposition, status, note, "
                      "status_changed) VALUES (?, ?, ?, 1, '{}', 'firewall_blocked', ?, ?, ?)")
            # blocked with a note an hour ago, then a flood of newer blocked scanners
            db.execute(insert, ("198.51.100.77", 1.0, 1.0, "blocked", "our pentester", 1.0))
            db.executemany(insert, [(f"203.0.113.{n}", 10.0 + n, 10.0 + n, "new", "", None) for n in range(5)])
            with mock.patch.object(THREATS, "KEEP_ROWS", 2):
                THREATS.prune(db, now=20.0)
            self.assertEqual({row[0] for row in db.execute("SELECT address FROM threats")},
                             {"198.51.100.77", "203.0.113.3", "203.0.113.4"})
            # a touched entry ages from its status change, not only from its last sighting
            db.execute("UPDATE threats SET status_changed = ? WHERE address = '198.51.100.77'", (THREATS.KEEP_SECONDS,))
            THREATS.prune(db, now=THREATS.KEEP_SECONDS + 5)
            self.assertIn("198.51.100.77", {row[0] for row in db.execute("SELECT address FROM threats")})
            # touched entries have a cap of their own: the oldest decision goes first
            db.executemany(insert, [(f"192.0.2.{n}", 30.0, 30.0, "dismissed", "", THREATS.KEEP_SECONDS + n) for n in range(3)])
            with mock.patch.object(THREATS, "KEEP_TOUCHED", 2):
                THREATS.prune(db, now=THREATS.KEEP_SECONDS + 5)
            touched = {row[0] for row in db.execute(f"SELECT address FROM threats WHERE {THREATS.TOUCHED}")}
            self.assertEqual(touched, {"192.0.2.1", "192.0.2.2"})


class ThreatHistoryFileTest(unittest.TestCase):
    def test_history_moves_out_of_the_cache_once(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = os.path.join(directory, "cache.db")
            old = sqlite3.connect(cache)
            old.execute("CREATE TABLE cache (kind TEXT, key TEXT, value TEXT, stored REAL, PRIMARY KEY (kind, key))")
            old.execute("CREATE TABLE threats (address TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, samples INTEGER, "
                        "data TEXT, status TEXT DEFAULT 'new', note TEXT DEFAULT '', status_changed REAL)")
            old.execute("INSERT INTO threats VALUES ('203.0.113.9', 1, 2, 3, '{}', 'reviewed', 'seen before', 2)")
            old.commit()
            old.close()
            db = THREATS.connect(os.path.join(directory, "threats.db"))
            THREATS.move_from_cache(db, cache)
            row = db.execute("SELECT status, note, disposition FROM threats WHERE address = '203.0.113.9'").fetchone()
            self.assertEqual(row, ("reviewed", "seen before", "passed"))
            # gone from the cache, so a later cache problem cannot touch it
            check = sqlite3.connect(cache)
            self.assertIsNone(check.execute("SELECT 1 FROM sqlite_master WHERE name = 'threats'").fetchone())
            check.close()
            # a second start does not copy again (nothing is there)
            THREATS.move_from_cache(db, cache)
            self.assertEqual(db.execute("SELECT count(*) FROM threats").fetchone()[0], 1)

    def test_a_failed_move_is_tried_again(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = os.path.join(directory, "cache.db")
            database = os.path.join(directory, "threats.db")
            os.mkdir(cache)  # not a database: it cannot be attached
            with mock.patch.object(THREATS, "DATABASE", database), mock.patch.object(THREATS, "CACHE_DB", cache), \
                    mock.patch.object(THREATS, "log_error"):
                THREATS.connect(database).close()
                check = sqlite3.connect(database)
                self.assertEqual(check.execute("PRAGMA user_version").fetchone()[0], 0)
                check.close()
                # the collector records a new entry before the move is tried again
                check = sqlite3.connect(database)
                check.execute("INSERT INTO threats (address, status) VALUES ('198.51.100.1', 'new')")
                check.commit()
                check.close()
                os.rmdir(cache)
                old = sqlite3.connect(cache)
                old.execute("CREATE TABLE threats (address TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, samples INTEGER, "
                            "data TEXT, status TEXT DEFAULT 'new', note TEXT DEFAULT '', status_changed REAL)")
                old.execute("INSERT INTO threats VALUES ('203.0.113.9', 1, 2, 3, '{}', 'reviewed', 'seen before', 2)")
                old.execute("INSERT INTO threats VALUES ('198.51.100.1', 1, 2, 3, '{}', 'dismissed', 'scanner', 2)")
                old.execute("INSERT INTO threats VALUES ('198.51.100.2', 1, 2, 3, '{}', 'new', '', NULL)")
                old.commit()
                old.close()
                db = THREATS.connect(database)
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], THREATS.SCHEMA_VERSION)
                # the entry recorded since keeps the operator's earlier decision and note
                rows = {row[0]: row[1:] for row in db.execute("SELECT address, status, note FROM threats")}
                self.assertEqual(rows, {"203.0.113.9": ("reviewed", "seen before"), "198.51.100.1": ("dismissed", "scanner"),
                                        "198.51.100.2": ("new", "")})
                db.close()


if __name__ == "__main__":
    unittest.main()
