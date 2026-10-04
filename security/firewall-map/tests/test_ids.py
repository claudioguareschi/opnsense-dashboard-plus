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

"""Unit tests for Suricata alerts and connection matching (lib/ids.py)."""

import json
import ipaddress
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import BLOCKLISTS, BLOCKS, COMMON, IDS, PF, THREATS, BLOCK_LINE, Geo  # noqa: E402


class AlertTest(unittest.TestCase):
    LINE = json.dumps({
        "timestamp": "2026-09-26T20:20:01.123456-0400", "event_type": "alert", "src_ip": "94.154.43.203",
        "src_port": 51234, "dest_ip": "1.2.3.163", "dest_port": 80, "proto": "TCP",
        "alert": {"action": "allowed", "signature_id": 2001219, "signature": "ET SCAN Potential SSH Scan",
                  "category": "Attempted Information Leak", "severity": 2},
    })

    def test_parses_only_alerts(self):
        alert = IDS.parse_alert(self.LINE)
        self.assertEqual((alert["src"], alert["dst_port"], alert["severity"], alert["protocol"]),
                         ("94.154.43.203", 80, 2, "tcp"))
        self.assertIsNone(IDS.parse_alert('{"event_type":"anomaly"}'))
        self.assertIsNone(IDS.parse_alert('{"event_type":"alert", broken'))
        ipv6 = IDS.parse_alert(self.LINE.replace("94.154.43.203", "2001:4860:4860:0:0:0:0:8888"))
        self.assertEqual(ipv6["src"], "2001:4860:4860::8888")

    def test_tracks_per_remote_address_and_flags(self):
        alerts = IDS.AlertTracker()
        alerts.feed([self.LINE, self.LINE, '{"event_type":"flow"}'], {"1.2.3.163"})
        summary = alerts.summary("94.154.43.203", now=IDS.parse_alert(self.LINE)["time"] + 60)
        self.assertEqual((summary["count"], summary["severity"], summary["inbound"], summary["last_seconds"]),
                         (2, 2, True, 60))
        self.assertEqual(summary["targets"], ["1.2.3.163:80/tcp"])
        self.assertEqual(summary["signatures"][0]["count"], 2)
        self.assertEqual(BLOCKLISTS.threat_lists_for("94.154.43.203", None, None, alerts), [BLOCKLISTS.IDS_LIST])
        # low severity (3) is shown but does not flag
        low = self.LINE.replace('"severity": 2', '"severity": 3').replace("94.154.43.203", "8.8.8.8")
        alerts.feed([low], {"1.2.3.163"})
        self.assertFalse(alerts.flags("8.8.8.8"))
        self.assertIsNotNone(alerts.summary("8.8.8.8"))
        # outbound alert from an inside host: the remote side is the destination
        outbound = self.LINE.replace('"src_ip": "94.154.43.203"', '"src_ip": "192.168.1.50"').replace(
            '"dest_ip": "1.2.3.163"', '"dest_ip": "45.56.79.53"')
        alerts.feed([outbound], {"1.2.3.163"})
        self.assertTrue(alerts.summary("45.56.79.53")["outbound"])
        alerts.expire(IDS.parse_alert(self.LINE)["time"] + IDS.ALERT_WINDOW_SECONDS + 1)
        self.assertEqual(alerts.sources, {})


class CorrelationTest(unittest.TestCase):
    LOCAL = {"1.2.3.163"}
    OUTBOUND = ("all tcp 1.2.3.163:13526 (192.168.30.52:52114) -> 162.217.103.70:443       ESTABLISHED:ESTABLISHED\n"
                "   age 00:04:00, expires in 23:59:37, 5:9 pkts, 400:9000 bytes, rule 106, rlabel abc123, allow-opts\n"
                "   id: 0a creatorid: 01\n   origif: igb1\n")
    INBOUND = ("all tcp 192.168.1.2:443 (1.2.3.163:443) <- 94.154.43.203:51234       ESTABLISHED:ESTABLISHED\n"
               "   age 00:00:05, expires in 23:59:37, 5:9 pkts, 400:9000 bytes, rule 7, rlabel fwd1\n   id: 0b creatorid: 01\n")

    def alert(self, src, sport, dst, dport, flow_id=1, signature="ET MALWARE Possible C2 Activity", severity=1):
        return {"time": 1000.0, "src": src, "dst": dst, "src_port": sport, "dst_port": dport, "protocol": "tcp",
                "sid": 1, "signature": signature, "category": "Malware Command and Control",
                "severity": severity, "action": "allowed", "flow_id": flow_id}

    def test_outbound_nat_connection_is_found_by_its_outside_tuple(self):
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1000.0, {"abc123": "IoT to Internet"})
        correlator.add_alert(self.alert("1.2.3.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.add_alert(self.alert("162.217.103.70", 443, "1.2.3.163", 13526), 1000.5)
        correlator.resolve(self.LOCAL, 1001.0)
        (flow,) = correlator.flows.values()
        self.assertEqual((flow["kind"], flow["connection"]["inside"], flow["connection"]["rule_description"]),
                         ("current", "192.168.30.52:52114", "IoT to Internet"))
        # both directions of the same Suricata flow group under one flow_id and signature
        self.assertEqual(flow["alerts"]["1"][1]["count"], 2)
        self.assertEqual(correlator.diagnostics()["current"], 2)
        self.assertEqual(correlator.diagnostics()["correlated_share"], 1.0)

    def test_routed_ipv6_alert_matches_the_public_inside_host(self):
        state = ("all tcp 2606:4700:4701::20[52114] -> 2001:4860:4860::8888[443] ESTABLISHED:ESTABLISHED\n"
                 "   age 00:00:05, expires in 23:59:37, 2:3 pkts, 128:512 bytes, rlabel routed6\n"
                 "   id: 0e creatorid: 02\n   origif: igb1\n")
        local = {"2606:4700:4700::1111"}
        networks = [(ipaddress.ip_network("2606:4700:4701::/64"), "vlan03"),
                    (ipaddress.ip_network("2606:4700:4700::/64"), "igb1")]
        alert = self.alert("2606:4700:4701::20", 52114, "2001:4860:4860::8888", 443)
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(state), local, 1000.0, networks=networks)
        correlator.add_alert(alert, 1000.0)
        correlator.resolve(local, 1000.0, networks)
        (key,) = correlator.current
        self.assertEqual(key, ("tcp", "2606:4700:4701::20", "52114", "2001:4860:4860::8888", "443"))
        self.assertEqual(correlator.diagnostics()["current"], 1)

        alerts = IDS.AlertTracker()
        alerts.add(alert, local, networks=networks)
        summary = alerts.summary("2001:4860:4860::8888", now=1000.0)
        self.assertTrue(summary["outbound"])
        self.assertEqual(summary["targets"], ["[2606:4700:4701::20]:52114/tcp"])

    def test_port_forward_recent_blocked_and_unmatched(self):
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(self.INBOUND), self.LOCAL, 1000.0)
        correlator.observe_states([], self.LOCAL, 1100.0)  # the connection closed
        correlator.add_alert(self.alert("94.154.43.203", 51234, "1.2.3.163", 443), 1100.0)
        block = BLOCKS.parse_block(BLOCK_LINE)
        correlator.observe_block(block, 1100.0)
        correlator.add_alert(self.alert(block["source"], int(block["source_port"]), block["destination"],
                                        int(block["port"]), flow_id=2), 1100.0)
        correlator.add_alert(self.alert("45.1.1.1", 4444, "1.2.3.163", 22, flow_id=3), 1100.0)
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
        correlator.add_alert(self.alert("1.2.3.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1002.0)
        correlator.resolve(self.LOCAL, 1002.0)
        self.assertEqual(correlator.stats["current"], 1)

    def test_firewall_own_dns_with_port_translation(self):
        state = ("all udp 1.2.3.163:21021 (1.2.3.163:15069) -> 104.128.145.3:53       MULTIPLE:SINGLE\n"
                 "   age 00:00:02, expires in 00:00:58, 1:1 pkts, 60:120 bytes\n   id: 0c creatorid: 01\n")
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(state), self.LOCAL, 1000.0)
        alert = self.alert("1.2.3.163", 21021, "104.128.145.3", 53, signature="ET DNS Query for .cc TLD", severity=3)
        alert["protocol"] = "udp"
        correlator.add_alert(alert, 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        self.assertEqual(correlator.stats["current"], 1)

    def test_ids_flow_summary_and_evidence_flag(self):
        class Geo:
            def resolve(self, addresses):
                pass

            def get(self, address):
                return {"lat": 1.0, "lon": 2.0, "country": "US", "country_name": "United States"}
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1000.0, {"abc123": "IoT to Internet"})
        correlator.add_alert(self.alert("1.2.3.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        self.assertTrue(correlator.flags("162.217.103.70"))
        self.assertFalse(correlator.flags("8.8.8.8"))
        (flow,) = correlator.summary(Geo(), "1.2.3.163", {"192.168.30.52": "laptop"}, [], {"igb1": "WAN"}, now=1000.0)
        self.assertEqual((flow["inside"], flow["inside_host"]["name"], flow["rule"], flow["interface"], flow["active"]),
                         ("192.168.30.52:52114", "laptop", "IoT to Internet", "WAN", True))
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
        correlator.add_alert(self.alert("1.2.3.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        (item,) = IDS.connection_summary("162.217.103.70", correlator, {"192.168.30.52": "laptop"}, {"igb1": "WAN"},
                                                wall=1240.0)
        self.assertEqual((item["inside"], item["inside_name"], item["public"], item["remote"], item["rule"], item["started"]),
                         ("192.168.30.52:52114", "laptop", "1.2.3.163:13526", "162.217.103.70:443", "IoT to Internet", 1000))
        self.assertEqual(item["ids"][0]["signature"], "ET MALWARE Possible C2 Activity")
        merged = THREATS.merge_connections([item], [{**item, "ids": [], "seen": 2000}])
        self.assertEqual((len(merged), merged[0]["seen"], bool(merged[0]["ids"])), (1, 2000, True))

    def test_flagged_firewall_block_has_its_own_disposition(self):
        correlator = IDS.Correlator()
        correlator.observe_block(BLOCKS.parse_block(BLOCK_LINE), 1000.0)
        with mock.patch.object(IDS, "threat_lists_for", return_value=["AbuseIPDB blacklist"]):
            entries = IDS.firewall_blocks(correlator, {}, 900.0)
        entry = entries["45.56.79.53"]
        self.assertEqual(entry["disposition"], "firewall_blocked")
        self.assertEqual(entry["targets"], ["tcp|1.2.3.163|23"])
        self.assertEqual(entry["lists"], ["AbuseIPDB blacklist"])

    def test_ips_drop_to_a_port_forward_is_a_full_record(self):
        with tempfile.TemporaryDirectory() as directory:
            rules = os.path.join(directory, "rules.debug")
            with open(rules, "w") as handle:
                handle.write("rdr on igb1 inet proto tcp from {any} to {(igb1)} port {443} -> $MailServer port 443 # NAT HTTPS Forward Rule\n"
                             "rdr on igb1 inet6 proto tcp from {any} to {(igb1)} port {8443} -> 2606:4700:4701::20 port 443 # IPv6 HTTPS Forward\n"
                             "rdr on vlan02 inet proto tcp from {!<zone>} to {(self)} port {443} -> 127.0.0.1 port 8000 # portal\n")
            forwards = PF.port_forwards(rules, table_lookup=lambda name: {"MailServer": "192.168.1.2"}.get(name))
            self.assertEqual(PF.forward_target(forwards, "tcp", "443"), ("192.168.1.2:443", "NAT HTTPS Forward Rule"))
            self.assertEqual(PF.forward_target(forwards, "tcp", "8443"),
                             ("[2606:4700:4701::20]:443", "IPv6 HTTPS Forward"))
            correlator = IDS.Correlator()
            correlator.forwards = forwards
            alert = self.alert("94.154.43.203", 51234, "1.2.3.163", 443, signature="ET EXPLOIT something")
            alert.update(action="blocked", flow={"bytes_toserver": 900, "bytes_toclient": 60, "start": 990.0})
            correlator.add_alert(alert, 1000.0)
            correlator.resolve(self.LOCAL, 1000.0 + IDS.CORRELATION_RETRY_SECONDS + 1)
            (flow,) = correlator.flows.values()
            connection = flow["connection"]
            self.assertEqual((flow["kind"], connection["inside"], connection["decision"], connection["bytes_in"], connection["source"]),
                             ("alert", "192.168.1.2:443", None, 900, "suricata"))
            entries = IDS.ips_drops(correlator, {}, 0.0)
            entry = entries["94.154.43.203"]
            self.assertEqual((entry["disposition"], entry["targets"], entry["inbound"]), ("ips_dropped", ["tcp|192.168.1.2|443"], 1))
            (snap,) = IDS.connection_summary("94.154.43.203", correlator, {"192.168.1.2": "mail"}, {})
            self.assertEqual((snap["inside_name"], snap["ips_dropped"], snap["decision"]), ("mail", True, None))
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            THREATS.record(db, entries, now=1000.0)
            self.assertEqual(THREATS.listing(db)["rows"][0]["disposition"], "ips_dropped")
            # a passed state outranks containment and becomes the primary operational disposition
            THREATS.record(db, {"94.154.43.203": {**entry, "disposition": "passed"}}, now=1100.0)
            self.assertEqual(THREATS.listing(db)["rows"][0]["disposition"], "passed")

    def test_ipv6_endpoints_keep_their_ports_apart(self):
        key = PF.outside_key("tcp", "2001:db8::1", "443", "2001:db8::2", "51234")
        connection = IDS.make_connection(key)
        self.assertEqual((connection["public"], connection["remote"]), ("[2001:db8::1]:443", "[2001:db8::2]:51234"))
        self.assertEqual(COMMON.split_host_port(connection["remote"]), ("2001:db8::2", "51234"))
        self.assertEqual(COMMON.split_host_port("192.0.2.1:80"), ("192.0.2.1", "80"))
        self.assertEqual(COMMON.split_host_port("2001:db8::2"), ("2001:db8::2", ""))

    def test_rule_label_is_parsed_from_states(self):
        (record,) = PF.parse_states(self.OUTBOUND)
        self.assertEqual(record["rule"], "abc123")


class BoundsTest(unittest.TestCase):
    def test_one_connection_cannot_grow_its_alert_history_without_limit(self):
        correlator = IDS.Correlator()
        key = PF.outside_key("tcp", "1.2.3.163", "443", "94.154.43.203", "51234")
        connection = IDS.make_connection(key)
        for index in range(100):
            alert = {"time": 1000.0, "src": "94.154.43.203", "dst": "1.2.3.163", "src_port": 51234, "dst_port": 443,
                     "protocol": "tcp", "sid": index, "signature": f"s{index}", "category": "", "severity": 3,
                     "action": "allowed", "flow_id": index // 3}
            correlator._attach(key, "current", connection, alert, 1000.0 + index)
        (flow,) = correlator.flows.values()
        self.assertLessEqual(len(flow["alerts"]), IDS.MAX_GROUPS_PER_FLOW)
        self.assertTrue(all(len(group) <= IDS.MAX_SIGNATURES_PER_GROUP for group in flow["alerts"].values()))
        # the latest Suricata flow is the one kept
        self.assertIn(str(99 // 3), flow["alerts"])


if __name__ == "__main__":
    unittest.main()
