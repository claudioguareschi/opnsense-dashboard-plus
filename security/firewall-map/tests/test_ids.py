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
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import BLOCKLISTS, BLOCKS, COMMON, IDS as PRODUCTION_IDS, PF, THREATS, BLOCK_LINE  # noqa: E402

from reference import ids as IDS  # noqa: E402


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
        # malformed alert lines are reported, so the feed can count and skip them
        for line in ('{"event_type":"alert", broken', '[{"event_type":"alert"}]',
                     '{"event_type":"alert","src_ip":["a"],"dest_ip":"1.2.3.4"}',
                     '{"event_type":"alert","alert":"x","src_ip":"1.1.1.1","dest_ip":"1.2.3.4"}',
                     '{"event_type":"alert","src_ip":"1.1.1.1","dest_ip":"1.2.3.4","src_port":70000}'):
            with self.subTest(line=line), self.assertRaises(IDS.MalformedAlert):
                IDS.parse_alert(line)
        odd = IDS.parse_alert('{"event_type":"alert","src_ip":"1.1.1.1","dest_ip":"1.2.3.4",'
                              '"dns":{"queries":"abc"},"alert":{"severity":"high","signature":5}}')
        self.assertEqual((odd["severity"], odd["signature"], odd["query"]), (3, "", None))
        ipv6 = IDS.parse_alert(self.LINE.replace("94.154.43.203", "2001:4860:4860:0:0:0:0:8888"))
        self.assertEqual(ipv6["src"], "2001:4860:4860::8888")

    def test_feed_contains_bad_lines_one_by_one(self):
        alerts = IDS.AlertTracker()
        rejected = alerts.feed(['{"event_type":"alert", broken', self.LINE, '[{"event_type":"alert"}]'],
                               {"1.2.3.163"})
        self.assertEqual(rejected, 2)
        self.assertIn("MalformedAlert", alerts.last_rejection)
        self.assertEqual(alerts.summary("94.154.43.203")["count"], 1)

    def test_caps_are_counted(self):
        alerts = IDS.AlertTracker(max_sources=2)
        lines = [self.LINE.replace("94.154.43.203", f"94.154.43.{n}") for n in range(5)]
        alerts.feed(lines, {"1.2.3.163"})
        self.assertEqual((len(alerts.sources), alerts.evicted_sources), (2, 3))
        signatures = [self.LINE.replace("2001219", str(2001219 + n)) for n in range(IDS.MAX_SIGNATURES_PER_SOURCE + 4)]
        alerts.feed(signatures, {"1.2.3.163"})
        self.assertEqual(alerts.dropped_signatures, 4)

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

    def test_compact_state_connection_preserves_all_fields(self):
        correlator = IDS.Correlator()
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1000.0, {"abc123": "IoT to Internet"})
        key, connection = next(iter(correlator.current.items()))
        self.assertNotIsInstance(connection, dict)
        self.assertFalse(hasattr(connection, "__dict__"))
        self.assertEqual(dict(connection), {
            "key": key, "protocol": "tcp", "public": "1.2.3.163:13526", "remote": "162.217.103.70:443",
            "inside": "192.168.30.52:52114", "remote_started": False, "bytes_in": 400, "bytes_out": 9000,
            "age": 240, "rule": "abc123", "rule_description": "IoT to Internet", "interface": "igb1",
            "state": "ESTABLISHED:ESTABLISHED", "decision": "pass", "source": "state", "seen": 1000.0,
        })
        self.assertIs(correlator.recent[key], connection)

    def test_duplicate_tuple_last_winner_ambiguity_and_recent_order(self):
        correlator = IDS.Correlator()
        other = self.OUTBOUND.replace("162.217.103.70", "162.217.103.71").replace("id: 0a", "id: 0b")
        duplicate = self.OUTBOUND.replace("192.168.30.52", "192.168.30.53").replace("id: 0a", "id: 0c")
        correlator.observe_states(PF.parse_states(self.OUTBOUND + other + duplicate), self.LOCAL, 1000.0)
        first, second = correlator.current
        self.assertEqual(correlator.current[first]["inside"], "192.168.30.53:52114")
        self.assertEqual(correlator.ambiguous_keys, {first})
        self.assertEqual(list(correlator.recent), [first, second])
        old = correlator.current[first]
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1002.0)
        self.assertEqual(list(correlator.recent), [second, first])
        self.assertIsNot(correlator.current[first], old)
        self.assertEqual(correlator.ambiguous_keys, set())

    def test_pending_nat_evidence_retains_its_original_sample_record(self):
        correlator = IDS.Correlator()
        correlator.add_alert(self.alert("1.2.3.163", 13526, "162.217.103.70", 443), 1000.0)
        correlator.resolve(self.LOCAL, 1000.0)
        self.assertEqual(len(correlator.pending), 1)
        correlator.observe_states(PF.parse_states(self.OUTBOUND), self.LOCAL, 1002.0)
        correlator.resolve(self.LOCAL, 1002.0)
        key, old = next(iter(correlator.current.items()))
        evidence = correlator.flows[key]["connection"]
        self.assertIs(evidence, old)
        correlator.observe_states(PF.parse_states(self.OUTBOUND.replace("400:9000 bytes", "800:18000 bytes")),
                                  self.LOCAL, 1004.0)
        self.assertIsNot(correlator.current[key], old)
        self.assertIs(correlator.flows[key]["connection"], old)
        self.assertEqual((old["bytes_in"], old["bytes_out"], old["seen"]), (400, 9000, 1002.0))
        correlator.observe_states([], self.LOCAL, 1006.0)
        self.assertEqual(correlator.current, {})
        self.assertEqual(correlator.recent[key]["seen"], 1004.0)

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

    def test_collector_tuple_exchange_is_limited_to_incident_queries(self):
        correlator = IDS.Correlator()
        alert = self.alert("1.2.3.163", 13526, "162.217.103.70", 443)
        correlator.add_alert(alert, 1000.0)
        key = IDS.outside_key("tcp", "1.2.3.163", 13526, "162.217.103.70", 443)
        self.assertEqual(correlator.collector_queries(self.LOCAL), [key])
        match = {key: {"kind": 1, "inside": "192.168.30.52", "inside_port": 52114,
                       "id": 10, "creator": 1, "ambiguous": False, "age": 240,
                       "bytes_in": 400, "bytes_out": 9000, "remote_started": False,
                       "interface": "igb1", "rule": "abc123"}}
        correlator.observe_collector_matches(match, 1002.0, {"abc123": "IoT to Internet"})
        correlator.resolve_collector_matches(match, self.LOCAL, 1002.0)
        flow = correlator.flows[key]
        self.assertEqual((flow["kind"], flow["connection"]["inside"],
                          flow["connection"]["rule_description"]),
                         ("current", "192.168.30.52:52114", "IoT to Internet"))
        self.assertEqual(flow["connection"]["state"], "10/1")

    def test_collector_recent_match_resolves_pending_alert_without_exporting_index(self):
        correlator = IDS.Correlator()
        alert = self.alert("1.2.3.163", 13526, "162.217.103.70", 443)
        correlator.add_alert(alert, 1000.0)
        key = IDS.outside_key("tcp", "1.2.3.163", 13526, "162.217.103.70", 443)
        match = {key: {"kind": 2, "inside": "192.168.30.52", "inside_port": 52114,
                       "id": 10, "creator": 1, "ambiguous": False, "age": 240,
                       "bytes_in": 400, "bytes_out": 9000, "remote_started": False,
                       "interface": "igb1", "rule": "abc123"}}
        correlator.resolve_collector_matches(match, self.LOCAL, 1002.0)
        self.assertEqual(correlator.flows[key]["kind"], "recent")
        self.assertEqual(len(correlator.pending), 0)

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
        (item,) = IDS.connection_summary(
            "162.217.103.70", correlator, {"192.168.30.52": "laptop"}, {"igb1": "WAN"}, wall=1240.0)
        self.assertEqual((item["inside"], item["inside_name"], item["public"], item["remote"], item["rule"], item["started"]),
                         ("192.168.30.52:52114", "laptop", "1.2.3.163:13526", "162.217.103.70:443", "IoT to Internet", 1000))
        self.assertEqual(item["ids"][0]["signature"], "ET MALWARE Possible C2 Activity")
        merged = THREATS.merge_connections([item], [{**item, "ids": [], "seen": 2000}])
        self.assertEqual((len(merged), merged[0]["seen"], bool(merged[0]["ids"])), (1, 2000, True))

    def test_flagged_firewall_block_has_its_own_disposition(self):
        correlator = IDS.Correlator()
        correlator.observe_block(BLOCKS.parse_block(BLOCK_LINE), 1000.0)
        with mock.patch.object(PRODUCTION_IDS, "threat_lists_for", return_value=["AbuseIPDB blacklist"]):
            entries = PRODUCTION_IDS.firewall_blocks(correlator, {}, 900.0)
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


class CorrelationExpiryTest(unittest.TestCase):
    LOCAL = {"1.2.3.163"}

    @staticmethod
    def states(*remotes):
        return PF.parse_states("".join(
            f"all tcp 192.168.1.2:443 (1.2.3.163:443) <- {remote}:51234       ESTABLISHED:ESTABLISHED\n"
            f"   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:9000 bytes\n   id: {index:02x} creatorid: 01\n"
            for index, remote in enumerate(remotes, 1)))

    def remotes(self, correlator):
        return [key[3] for key in correlator.recent]

    def test_closed_connections_expire_in_the_order_they_were_seen(self):
        correlator = IDS.Correlator()
        correlator.observe_states(self.states("94.154.43.1", "94.154.43.2"), self.LOCAL, 1000.0)
        correlator.observe_states(self.states("94.154.43.2"), self.LOCAL, 1300.0)
        correlator.observe_states(self.states("94.154.43.3"), self.LOCAL, 1000.0 + IDS.CORRELATION_SECONDS + 1)
        self.assertEqual(self.remotes(correlator), ["94.154.43.2", "94.154.43.3"])

    def test_a_clock_set_back_still_expires_every_old_connection(self):
        correlator = IDS.Correlator()
        correlator.observe_states(self.states("94.154.43.1"), self.LOCAL, 5000.0)
        # the clock goes back: the entry seen "later" now sits in front of older ones
        correlator.observe_states(self.states("94.154.43.2"), self.LOCAL, 1000.0)
        correlator.observe_states(self.states("94.154.43.3"), self.LOCAL, 1000.0 + IDS.CORRELATION_SECONDS + 1)
        self.assertEqual(self.remotes(correlator), ["94.154.43.1", "94.154.43.3"])

    def test_eviction_preserves_oldest_first_order_and_values(self):
        for size in (0, 2, 5, 20):
            with self.subTest(size=size), mock.patch.object(IDS, "MAX_CORRELATION_KEYS", 5):
                correlator = IDS.Correlator()
                for store in (correlator.recent, correlator.blocked):
                    store.update((key, {"seen": 1000.0}) for key in range(size))
                    if size:
                        store[0] = store.pop(0)  # a refreshed entry moves to the end
                expected = list(correlator.recent.items())[-5:]
                correlator._expire(1000.0)
                self.assertEqual(list(correlator.recent.items()), expected)
                self.assertEqual(list(correlator.blocked.items()), expected)
                self.assertLessEqual(len(correlator.recent), 5)

    def test_large_eviction_traverses_each_store_only_once(self):
        class CountedDict(dict):
            iterations = 0

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        correlator = IDS.Correlator()
        size = IDS.MAX_CORRELATION_KEYS + 50000
        correlator.recent = CountedDict((key, {"seen": 1000.0}) for key in range(size))
        correlator._expire(1000.0)
        self.assertLessEqual(correlator.recent.iterations, 1)
        self.assertEqual(list(correlator.recent), list(range(50000, size)))

    def test_production_correlator_expires_blocked_attempts_and_evidence(self):
        correlator = PRODUCTION_IDS.Correlator()
        key = ("tcp", "1.2.3.163", "443", "94.154.43.203", "51234")
        connection = PRODUCTION_IDS.make_connection(key, seen=1000.0)
        correlator.blocked[key] = connection
        correlator._seen(1000.0)
        alert = {"time": 1000.0, "sid": 1, "signature": "test", "category": "",
                 "severity": 2, "action": "allowed", "flow_id": 1}
        correlator._attach(key, "blocked", connection, alert, 1000.0)

        correlator._expire(1000.0 + PRODUCTION_IDS.ALERT_WINDOW_SECONDS + 1)

        self.assertEqual(correlator.blocked, {})
        self.assertEqual(correlator.flows, {})


class ConnectionSelectionTest(unittest.TestCase):
    def test_bounded_selection_matches_stable_full_ranking(self):
        for size in (0, 3, 6, 100):
            with self.subTest(size=size):
                correlator = PRODUCTION_IDS.Correlator()
                for number in range(size):
                    key = ("tcp", "1.2.3.163", str(number), "34.1.1.1", "443")
                    connection = PRODUCTION_IDS.make_connection(key, bytes_in=(number % 4) * 100,
                                                                bytes_out=None, age=10)
                    # Include current, historical IDS, and blocked connections, and tied rates.
                    if number % 3 == 0:
                        correlator.current[key] = connection
                    elif number % 3 == 1:
                        correlator.flows[key] = {"kind": "recent", "connection": connection, "alerts": {}}
                    else:
                        correlator.blocked[key] = connection
                    if number % 5 == 0:
                        correlator.flows[key] = {"kind": "current", "connection": connection, "alerts": {
                            "1": {"1": {"sid": 1, "signature": "test", "severity": 2, "count": 1,
                                        "action": "allowed", "query": None}}}}
                # Asking for every row gives the stable sorted reference, including all fields.
                with mock.patch.object(PRODUCTION_IDS, "MAX_SNAPSHOT_CONNECTIONS", max(1, size)):
                    complete = PRODUCTION_IDS.connection_summary("34.1.1.1", correlator, {}, {}, wall=1000.0)
                order = PRODUCTION_IDS.connection_keys(correlator).get("34.1.1.1", [])
                ranked = sorted(order, key=lambda key: (int(key[2]) % 5 != 0, -(int(key[2]) % 4) * 100))
                self.assertEqual([item["key"] for item in complete], ["|".join(key) for key in ranked])
                actual = PRODUCTION_IDS.connection_summary("34.1.1.1", correlator, {}, {}, wall=1000.0)
                self.assertEqual(actual, complete[:6])


if __name__ == "__main__":
    unittest.main()
