"""Unit tests for Suricata alerts and connection matching (fwmap_ids)."""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import BLOCKLISTS, BLOCKS, IDS, PF, THREATS, BLOCK_LINE, Geo  # noqa: E402


class AlertTest(unittest.TestCase):
    LINE = json.dumps({
        "timestamp": "2026-09-26T20:20:01.123456-0400", "event_type": "alert", "src_ip": "94.154.43.203",
        "src_port": 51234, "dest_ip": "198.13.91.163", "dest_port": 80, "proto": "TCP",
        "alert": {"action": "allowed", "signature_id": 2001219, "signature": "ET SCAN Potential SSH Scan",
                  "category": "Attempted Information Leak", "severity": 2},
    })

    def test_parses_only_alerts(self):
        alert = IDS.parse_alert(self.LINE)
        self.assertEqual((alert["src"], alert["dst_port"], alert["severity"], alert["protocol"]),
                         ("94.154.43.203", 80, 2, "tcp"))
        self.assertIsNone(IDS.parse_alert('{"event_type":"anomaly"}'))
        self.assertIsNone(IDS.parse_alert('{"event_type":"alert", broken'))

    def test_tracks_per_remote_address_and_flags(self):
        alerts = IDS.AlertTracker()
        alerts.feed([self.LINE, self.LINE, '{"event_type":"flow"}'], {"198.13.91.163"})
        summary = alerts.summary("94.154.43.203", now=IDS.parse_alert(self.LINE)["time"] + 60)
        self.assertEqual((summary["count"], summary["severity"], summary["inbound"], summary["last_seconds"]),
                         (2, 2, True, 60))
        self.assertEqual(summary["targets"], ["198.13.91.163:80/tcp"])
        self.assertEqual(summary["signatures"][0]["count"], 2)
        self.assertEqual(BLOCKLISTS.threat_lists_for("94.154.43.203", None, None, alerts), [BLOCKLISTS.IDS_LIST])
        # low severity (3) is shown but does not flag
        low = self.LINE.replace('"severity": 2', '"severity": 3').replace("94.154.43.203", "8.8.8.8")
        alerts.feed([low], {"198.13.91.163"})
        self.assertFalse(alerts.flags("8.8.8.8"))
        self.assertIsNotNone(alerts.summary("8.8.8.8"))
        # outbound alert from an inside host: the remote side is the destination
        outbound = self.LINE.replace('"src_ip": "94.154.43.203"', '"src_ip": "192.168.1.50"').replace(
            '"dest_ip": "198.13.91.163"', '"dest_ip": "45.56.79.53"')
        alerts.feed([outbound], {"198.13.91.163"})
        self.assertTrue(alerts.summary("45.56.79.53")["outbound"])
        alerts.expire(IDS.parse_alert(self.LINE)["time"] + IDS.ALERT_WINDOW_SECONDS + 1)
        self.assertEqual(alerts.sources, {})


class CorrelationTest(unittest.TestCase):
    LOCAL = {"198.13.91.163"}
    OUTBOUND = ("all tcp 198.13.91.163:13526 (192.168.30.52:52114) -> 162.217.103.70:443       ESTABLISHED:ESTABLISHED\n"
                "   age 00:04:00, expires in 23:59:37, 5:9 pkts, 400:9000 bytes, rule 106, rlabel abc123, allow-opts\n"
                "   id: 0a creatorid: 01\n   origif: igb1\n")
    INBOUND = ("all tcp 192.168.1.2:443 (198.13.91.163:443) <- 94.154.43.203:51234       ESTABLISHED:ESTABLISHED\n"
               "   age 00:00:05, expires in 23:59:37, 5:9 pkts, 400:9000 bytes, rule 7, rlabel fwd1\n   id: 0b creatorid: 01\n")

    def alert(self, src, sport, dst, dport, flow_id=1, signature="ET MALWARE Possible C2 Activity", severity=1):
        return {"time": 1000.0, "src": src, "dst": dst, "src_port": sport, "dst_port": dport, "protocol": "tcp",
                "sid": 1, "signature": signature, "category": "Malware Command and Control",
                "severity": severity, "action": "allowed", "flow_id": flow_id}

    def test_outbound_nat_connection_is_found_by_its_outside_tuple(self):
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1000.0, {"abc123": "IoT to Internet"})
        correlator.add_alert(self.alert("198.13.91.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.add_alert(self.alert("162.217.103.70", 443, "198.13.91.163", 13526), 1000.5)
        correlator.resolve(self.LOCAL, 1001.0)
        (flow,) = correlator.flows.values()
        self.assertEqual((flow["kind"], flow["connection"]["inside"], flow["connection"]["rule_description"]),
                         ("current", "192.168.30.52:52114", "IoT to Internet"))
        # both directions of the same Suricata flow group under one flow_id and signature
        self.assertEqual(flow["alerts"]["1"][1]["count"], 2)
        self.assertEqual(correlator.diagnostics()["current"], 2)
        self.assertEqual(correlator.diagnostics()["correlated_share"], 1.0)

    def test_port_forward_recent_blocked_and_unmatched(self):
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(self.INBOUND), self.LOCAL, 1000.0)
        correlator.observe_states([], self.LOCAL, 1100.0)  # the connection closed
        correlator.add_alert(self.alert("94.154.43.203", 51234, "198.13.91.163", 443), 1100.0)
        block = BLOCKS.parse_block(BLOCK_LINE)
        correlator.observe_block(block, 1100.0)
        correlator.add_alert(self.alert(block["source"], int(block["source_port"]), block["destination"],
                                        int(block["port"]), flow_id=2), 1100.0)
        correlator.add_alert(self.alert("45.1.1.1", 4444, "198.13.91.163", 22, flow_id=3), 1100.0)
        correlator.resolve(self.LOCAL, 1101.0)
        self.assertEqual(correlator.stats["pending"], 1)  # the unknown one waits for a later sample
        correlator.resolve(self.LOCAL, 1100.0 + IDS.CORRELATION_RETRY_SECONDS + 1)
        stats = correlator.diagnostics()
        self.assertEqual((stats["recent"], stats["blocked"], stats["unmatched"], stats["pending"]), (1, 1, 1, 0))
        kinds = sorted(flow["kind"] for flow in correlator.flows.values())
        # the unmatched alert is kept as a connection of its own, from Suricata's record
        self.assertEqual(kinds, ["alert", "blocked", "recent"])
        # connections are forgotten after the correlation window
        correlator.observe_states([], self.LOCAL, 1100.0 + IDS.CORRELATION_SECONDS + 1)
        self.assertEqual((len(correlator.recent), len(correlator.blocked)), (0, 0))

    def test_alert_before_the_state_is_sampled_still_matches(self):
        correlator = IDS.Correlator()
        correlator.add_alert(self.alert("198.13.91.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1002.0)
        correlator.resolve(self.LOCAL, 1002.0)
        self.assertEqual(correlator.stats["current"], 1)

    def test_firewall_own_dns_with_port_translation(self):
        state = ("all udp 198.13.91.163:21021 (198.13.91.163:15069) -> 104.128.145.3:53       MULTIPLE:SINGLE\n"
                 "   age 00:00:02, expires in 00:00:58, 1:1 pkts, 60:120 bytes\n   id: 0c creatorid: 01\n")
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(state), self.LOCAL, 1000.0)
        alert = self.alert("198.13.91.163", 21021, "104.128.145.3", 53, signature="ET DNS Query for .cc TLD", severity=3)
        alert["protocol"] = "udp"
        correlator.add_alert(alert, 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        self.assertEqual(correlator.stats["current"], 1)

    def test_ids_flow_snapshot_and_evidence_flag(self):
        class Geo:
            def resolve(self, addresses):
                pass

            def get(self, address):
                return {"lat": 1.0, "lon": 2.0, "country": "US", "country_name": "United States"}
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1000.0, {"abc123": "IoT to Internet"})
        correlator.add_alert(self.alert("198.13.91.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        self.assertTrue(correlator.flags("162.217.103.70"))
        self.assertFalse(correlator.flags("8.8.8.8"))
        (flow,) = correlator.snapshot(Geo(), "198.13.91.163", {"192.168.30.52": "seachartly"}, [], {"igb1": "WAN"}, now=1000.0)
        self.assertEqual((flow["inside"], flow["inside_host"]["name"], flow["rule"], flow["interface"], flow["active"]),
                         ("192.168.30.52:52114", "seachartly", "IoT to Internet", "WAN", True))
        self.assertEqual((flow["severity"], flow["count"], flow["kind"]), (1, 1, "current"))
        # history on the address alone no longer turns aggregate arcs red
        self.assertEqual(BLOCKLISTS.threat_lists_for("162.217.103.70", None, None), [])

    def test_rule_comes_from_the_inside_state(self):
        lan = ("all tcp 162.217.103.70:443 <- 192.168.30.52:52114       ESTABLISHED:ESTABLISHED\n"
               "   age 00:04:00, expires in 23:59:37, 5:9 pkts, 400:9000 bytes, rule 12, rlabel iot1\n"
               "   id: 0d creatorid: 01\n   origif: vlan03\n")
        records = PF.parse_states(self.OUTBOUND + lan)
        correlator = IDS.Correlator()
        correlator.observe_states(records, self.LOCAL, 1000.0, {"iot1": "IoT to Internet", "abc123": "let out anything"})
        (connection,) = correlator.current.values()
        self.assertEqual(connection["rule_description"], "IoT to Internet")

    def test_connection_snapshot_for_the_queue(self):
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1000.0, {"abc123": "IoT to Internet"})
        correlator.add_alert(self.alert("198.13.91.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        (item,) = IDS.connection_snapshot("162.217.103.70", correlator, {"192.168.30.52": "seachartly"}, {"igb1": "WAN"},
                                                wall=1240.0)
        self.assertEqual((item["inside"], item["inside_name"], item["public"], item["remote"], item["rule"], item["started"]),
                         ("192.168.30.52:52114", "seachartly", "198.13.91.163:13526", "162.217.103.70:443", "IoT to Internet", 1000))
        self.assertEqual(item["ids"][0]["signature"], "ET MALWARE Possible C2 Activity")
        merged = THREATS.merge_connections([item], [{**item, "ids": [], "seen": 2000}])
        self.assertEqual((len(merged), merged[0]["seen"], bool(merged[0]["ids"])), (1, 2000, True))

    def test_ips_drop_to_a_port_forward_is_a_full_record(self):
        with tempfile.TemporaryDirectory() as directory:
            rules = os.path.join(directory, "rules.debug")
            with open(rules, "w") as handle:
                handle.write("rdr on igb1 inet proto tcp from {any} to {(igb1)} port {443} -> $MailServer port 443 # NAT HTTPS Forward Rule\n"
                             "rdr on vlan02 inet proto tcp from {!<zone>} to {(self)} port {443} -> 127.0.0.1 port 8000 # portal\n")
            forwards = PF.port_forwards(rules, table_lookup=lambda name: {"MailServer": "192.168.1.2"}.get(name))
            self.assertEqual(PF.forward_target(forwards, "tcp", "443"), ("192.168.1.2:443", "NAT HTTPS Forward Rule"))
            correlator = IDS.Correlator()
            correlator.forwards = forwards
            alert = self.alert("94.154.43.203", 51234, "198.13.91.163", 443, signature="ET EXPLOIT something")
            alert.update(action="blocked", flow={"bytes_toserver": 900, "bytes_toclient": 60, "start": 990.0})
            correlator.add_alert(alert, 1000.0)
            correlator.resolve(self.LOCAL, 1000.0 + IDS.CORRELATION_RETRY_SECONDS + 1)
            (flow,) = correlator.flows.values()
            connection = flow["connection"]
            self.assertEqual((flow["kind"], connection["inside"], connection["decision"], connection["bytes_in"], connection["source"]),
                             ("alert", "192.168.1.2:443", None, 900, "suricata"))
            entries = IDS.ips_drops(correlator, {}, 0.0)
            entry = entries["94.154.43.203"]
            self.assertEqual((entry["status_hint"], entry["targets"], entry["inbound"]), ("dropped", ["tcp|192.168.1.2|443"], 1))
            (snap,) = IDS.connection_snapshot("94.154.43.203", correlator, {"192.168.1.2": "mail"}, {})
            self.assertEqual((snap["inside_name"], snap["ips_dropped"], snap["decision"]), ("mail", True, None))
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            THREATS.record(db, entries, now=1000.0)
            self.assertEqual(THREATS.listing(db)["rows"][0]["status"], "dropped")
            # the same address later getting through reopens it for review
            THREATS.record(db, {"94.154.43.203": {**entry, "status_hint": None}}, now=1100.0)
            self.assertEqual(THREATS.listing(db)["rows"][0]["status"], "new")

    def test_rule_label_is_parsed_from_states(self):
        (record,) = PF.parse_states(self.OUTBOUND)
        self.assertEqual(record["rule"], "abc123")


if __name__ == "__main__":
    unittest.main()
