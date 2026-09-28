"""Unit tests for the threat review queue."""

import json
import os
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
            self.assertEqual(THREATS.listing(db, "blocked")["rows"][0]["note"], note)
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
            self.assertEqual(THREATS.listing(db)["counts"], {"new": 1, "reviewed": 0, "dismissed": 0, "blocked": 0, "dropped": 0})
            self.assertEqual(THREATS.listing(db, "counts")["rows"], [])
            THREATS.set_status(db, "108.188.77.155", "reviewed")
            self.assertNotIn("seen_after_block", THREATS.listing(db)["rows"][0])

    def test_multicast_is_not_a_remote_endpoint(self):
        self.assertFalse(COMMON.public_ipv4("224.0.0.18"))
        self.assertTrue(COMMON.public_ipv4("9.9.9.9"))

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
            self.assertEqual(THREATS.bulk_status(db, "new", "dismissed")["changed"], 1)
            self.assertEqual(THREATS.listing(db)["counts"]["dismissed"], 1)
            self.assertEqual(THREATS.purge(db, "new")["result"], "failed")
            self.assertEqual(THREATS.purge(db, "dismissed")["deleted"], 1)
            self.assertEqual(THREATS.listing(db)["rows"], [])

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
