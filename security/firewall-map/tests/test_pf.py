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

"""Unit tests for PF state parsing and flow endpoints (lib/pf.py)."""

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
from support import BLOCKLISTS, CACHE, COLLECTOR, COMMON, LEASES, PF, THREATS, NAT_OUT, nat_state  # noqa: E402


class ParseTest(unittest.TestCase):
    def test_parses_verbose_state_record(self):
        records = PF.parse_states(nat_state(368, 5072))
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["protocol"], "tcp")
        self.assertEqual(record["bytes_out"], 5072)
        self.assertEqual(record["packets_in"], 8)
        self.assertEqual(record["src"]["address"], "45.56.79.53")
        self.assertEqual(record["dst"]["address"], "1.2.3.163")
        self.assertEqual(record["nat"]["address"], "192.168.1.2")
        self.assertEqual(record["id"], "f501b86a00000000/2ec5c347")
        self.assertEqual(record["age"], 605)

    def test_uses_nat_public_address_as_map_origin(self):
        output = """all tcp 192.168.1.2:443 (1.2.3.163:443) <- 45.56.79.53:35799 ESTABLISHED:ESTABLISHED
   age 00:10:05, expires in 23:59:48, 8:12 pkts, 368:5072 bytes
   id: 01 creatorid: 02
"""
        record = PF.parse_states(output)[0]
        self.assertEqual(PF.flow_endpoints(record, {"1.2.3.163"}), ("1.2.3.163", "45.56.79.53"))

    def test_parses_and_maps_ipv6_state(self):
        output = """all tcp 2606:4700:4700:0:0:0:0:1111[443] <- 2001:4860:4860:0:0:0:0:8888[51234] ESTABLISHED:ESTABLISHED
   age 00:00:05, expires in 23:59:48, 2:3 pkts, 128:512 bytes
   id: 0abc creatorid: 0123
   origif: wg0
"""
        record = PF.parse_states(output)[0]
        self.assertEqual(record["src"], {"address": "2001:4860:4860::8888", "port": "51234"})
        self.assertEqual(record["dst"], {"address": "2606:4700:4700::1111", "port": "443"})
        self.assertEqual(record["origif"], "wg0")
        self.assertEqual(PF.flow_endpoints(record, {"2606:4700:4700::1111"}),
                         ("2606:4700:4700::1111", "2001:4860:4860::8888"))

    def test_excludes_firewall_to_firewall_state(self):
        record = {
            "src": {"address": "1.2.2.230", "port": "443"},
            "dst": {"address": "1.2.3.163", "port": "443"},
            "nat": None,
        }
        self.assertIsNone(PF.flow_endpoints(record, {"1.2.2.230", "1.2.3.163"}))


class InsideTest(unittest.TestCase):
    NAT_OUT = NAT_OUT
    IFCONFIG = """igb1: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500
\tinet 1.2.2.230 netmask 0xffffff00 broadcast 1.2.2.255
\tinet6 2606:4700:4700::1111 prefixlen 64
vlan03: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500
\tinet 192.168.30.248 netmask 0xffffff00 broadcast 192.168.30.255
\tinet 192.168.30.250 netmask 0xffffffff vhid 30
\tinet6 fd12:3456:789a:30::1 prefixlen 64
"""

    def test_parses_origif_and_inside_host(self):
        record = PF.parse_states(self.NAT_OUT)[0]
        self.assertEqual(record["origif"], "igb1")
        self.assertEqual(PF.inside_endpoint(record)["address"], "192.168.30.30")

    def test_vpn_egress_is_drawn_from_the_firewall(self):
        tunnel = self.NAT_OUT.replace("1.2.3.163:19421", "10.74.109.115:19421").replace("origif: igb1", "origif: wg0")
        record = PF.parse_states(tunnel)[0]
        self.assertEqual(PF.flow_endpoints(record, {"1.2.3.163", "1.2.2.230"}),
                         ("1.2.2.230", "34.209.15.107"))
        self.assertEqual(record["origif"], "wg0")
        lan_side = "all tcp 192.168.30.30:51858 -> 34.209.15.107:8883       ESTABLISHED:ESTABLISHED\n" \
                   "   age 00:00:05, expires in 23:59:37, 1:1 pkts, 1:1 bytes\n   id: 01 creatorid: 02\n"
        self.assertIsNone(PF.flow_endpoints(PF.parse_states(lan_side)[0], {"1.2.3.163"}))

    def test_maps_inside_host_to_interface_and_name(self):
        networks = PF.interface_networks(self.IFCONFIG)
        self.assertIn(("192.168.30.250/32", "vlan03"), [(str(network), device) for network, device in networks])
        described = LEASES.describe_inside("192.168.30.30", {"192.168.30.30": "nas"}, networks, {"vlan03": "VLAN30_IOT"})
        self.assertEqual(described, {"ip": "192.168.30.30", "name": "nas", "interface": "VLAN30_IOT"})
        self.assertEqual(LEASES.describe_inside("fd12:3456:789a:30::20", {}, networks,
                                                {"vlan03": "VLAN30_IOT"})["interface"], "VLAN30_IOT")

    def test_tracker_reports_inside_hosts_and_egress(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        records = PF.parse_states(self.NAT_OUT)
        tracker.update(records, {"1.2.3.163"}, now=0.0)
        flow = tracker.flows[("1.2.3.163", "34.209.15.107")]
        self.assertEqual(flow["inside"], ["192.168.30.30"])
        self.assertEqual(flow["egress"], "igb1")

    def test_routed_ipv6_host_is_mapped_recorded_and_kept_as_inside(self):
        state = ("all tcp 2606:4700:4701::20[52114] -> 2001:4860:4860::8888[443] ESTABLISHED:ESTABLISHED\n"
                 "   age 00:00:05, expires in 23:59:37, 2:3 pkts, 128:512 bytes, rlabel routed6\n"
                 "   id: 0e creatorid: 02\n   origif: igb1\n")
        local = {"2606:4700:4700::1111"}
        networks = [(ipaddress.ip_network("2606:4700:4701::/64"), "vlan03"),
                    (ipaddress.ip_network("2606:4700:4700::/64"), "igb1")]
        record = PF.parse_states(state)[0]
        pair = PF.flow_endpoints(record, local, networks)
        self.assertEqual(pair, ("2606:4700:4700::1111", "2001:4860:4860::8888"))
        self.assertEqual(PF.inside_endpoint(record, networks, local)["address"], "2606:4700:4701::20")
        self.assertEqual(PF.state_outside(record, pair),
                         ("tcp", "2606:4700:4701::20", "52114", "2001:4860:4860::8888", "443"))

        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update([record], local, now=0.0, networks=networks)
        flow = tracker.flows[pair]
        self.assertEqual((flow["inside"], flow["initiated"]), (["2606:4700:4701::20"], "local"))

        seen = THREATS.observe([record], lambda address: ["IPv6 test"] if address == pair[1] else [],
                               local, networks)
        self.assertEqual(seen[pair[1]]["inside"], ["2606:4700:4701::20"])

    def test_reads_kea_and_dnsmasq_leases(self):
        with tempfile.TemporaryDirectory() as directory:
            kea = os.path.join(directory, "kea.csv")
            with open(kea, "w") as handle:
                handle.write("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n"
                             "192.168.30.80,aa,01,3600,100,30,0,0,old-name,0\n"
                             "192.168.30.80,aa,01,3600,9999999999,30,0,0,homeassistant,0\n"
                             "192.168.30.81,bb,02,3600,1,30,0,0,expired,0\n"
                             "192.168.30.82,cc,03,3600,9999999999,30,0,0,reused,0\n"
                             "192.168.30.82,cc,03,3600,9999999999,30,0,0,,0\n")
            dnsmasq = os.path.join(directory, "dnsmasq.leases")
            with open(dnsmasq, "w") as handle:
                handle.write("9999999999 cc:cc 192.168.40.5 tv *\n9999999999 dd:dd 192.168.40.6 printer *\n"
                             "9999999999 ee:ee 2606:4700:4700::99 workstation6 *\n")
            kea6 = os.path.join(directory, "kea6.csv")
            with open(kea6, "w") as handle:
                handle.write("address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,state\n"
                             "fd12:3456:789a:30:0:0:0:80,aa,3600,9999999999,30,3600,0,1,128,0,0,sensor6,0\n")
            # Kea's configuration as OPNsense renders it; an unconfigured family is an empty file
            kea4_conf, kea6_conf = os.path.join(directory, "kea-dhcp4.conf"), os.path.join(directory, "kea-dhcp6.conf")
            with open(kea4_conf, "w") as handle:
                json.dump({"Dhcp4": {"subnet4": [{"reservations": [
                    {"hw-address": "aa", "ip-address": "192.168.30.80", "hostname": "ha-reserved"}]}]}}, handle)
            with open(kea6_conf, "w") as handle:
                json.dump({"Dhcp6": {"subnet6": [{"reservations": [
                    {"duid": "01", "ip-addresses": ["fd12:3456:789a:30::81"], "hostname": "reserved6"}]}]}}, handle)
            empty = os.path.join(directory, "empty.conf")
            open(empty, "w").close()
            names = LEASES.lease_names(kea, dnsmasq, (kea4_conf, kea6_conf, empty), now=1000, kea6=kea6)
            # a reservation's name wins over the lease's
            self.assertEqual(names, {"192.168.30.80": "ha-reserved", "192.168.40.5": "tv",
                                     "192.168.40.6": "printer", "2606:4700:4700::99": "workstation6",
                                     "fd12:3456:789a:30::80": "sensor6",
                                     "fd12:3456:789a:30::81": "reserved6"})


class InitiatorTest(unittest.TestCase):
    INBOUND = ("all tcp 192.168.1.2:443 (1.2.3.163:443) <- 94.154.43.203:51234       ESTABLISHED:ESTABLISHED\n"
               "   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:9000 bytes\n   id: 0a creatorid: 01\n   origif: ix0\n")

    def test_inbound_port_forward_reports_initiator_and_target(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update([], {"1.2.3.163"}, now=0.0)
        tracker.update(PF.parse_states(self.INBOUND), {"1.2.3.163"}, now=2.0)
        flow = tracker.flows[("1.2.3.163", "94.154.43.203")]
        self.assertEqual(flow["initiated"], "remote")
        self.assertEqual(flow["targets"], ["tcp|192.168.1.2|443"])
        self.assertEqual((flow["service_ports"], flow["age"]), ({"HTTPS": "443/tcp"}, 1))
        # the server's replies dominate: the bytes go away from the firewall although the remote started it
        self.assertGreater(flow["rate_out"], flow["rate_in"])
        target = LEASES.describe_target("tcp|192.168.1.2|443", {"192.168.1.2": "mail"}, [], {}, {"1.2.3.163"})
        self.assertEqual((target["name"], target["service"]), ("mail", "HTTPS"))

    def test_inbound_udp_to_the_firewall_keeps_its_protocol(self):
        states = ("all udp 1.2.3.163:51820 <- 94.154.43.203:51234       MULTIPLE:MULTIPLE\n"
                  "   age 00:00:01, expires in 00:00:59, 5:9 pkts, 400:900 bytes\n   id: 0b creatorid: 01\n")
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update([], {"1.2.3.163"}, now=0.0)
        tracker.update(PF.parse_states(states), {"1.2.3.163"}, now=2.0)
        flow = tracker.flows[("1.2.3.163", "94.154.43.203")]
        self.assertEqual(flow["targets"], ["udp|1.2.3.163|51820"])
        target = LEASES.describe_target(flow["targets"][0], {}, [], {}, {"1.2.3.163"})
        self.assertEqual((target["name"], target["service"]), ("firewall", "WireGuard"))

    def test_outbound_flows_are_local(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update(PF.parse_states(NAT_OUT), {"1.2.3.163"}, now=0.0)
        self.assertEqual(tracker.flows[("1.2.3.163", "34.209.15.107")]["initiated"], "local")

    def test_reputation_from_cached_lookups(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CACHE.CacheStore(os.path.join(directory, "cache.db"))
            store.put_many(COMMON.REPUTATION_KIND, [("94.154.43.203", {"score": 100}), ("8.8.8.8", {"score": 0})])
            reputation = BLOCKLISTS.Reputation(store)
            reputation.refresh(now=0.0)
            index = BLOCKLISTS.BlocklistIndex()
            self.assertEqual(BLOCKLISTS.threat_lists_for("94.154.43.203", index, reputation), [BLOCKLISTS.REPUTATION_LIST])
            self.assertEqual(BLOCKLISTS.threat_lists_for("8.8.8.8", index, reputation), [])


class StateRecordTest(unittest.TestCase):
    OUTPUT = ("all tcp 198.51.100.7:40000 (10.0.0.5:51000) -> 203.0.113.9:443       ESTABLISHED:ESTABLISHED\n"
              "   age 01:02:03, expires in 23:59:59, 10:20 pkts, 1000:2000 bytes, rule 7, rlabel abc\n"
              "   id: 0000000000000001 creatorid: 12345678\n"
              "   origif: igb0\n")

    def test_records_read_like_dicts(self):
        (record,) = PF.parse_states(self.OUTPUT)
        self.assertEqual(record["src"], {"address": "198.51.100.7", "port": "40000"})
        self.assertEqual(record["nat"]["address"], "10.0.0.5")
        self.assertEqual((record["age"], record["bytes_out"], record.get("origif"), record["rule"]), (3723, 2000, "igb0", "abc"))
        self.assertIsNone(record.get("missing"))
        with self.assertRaises(KeyError):
            record["missing"]

    def test_lines_can_be_parsed_as_they_arrive(self):
        self.assertEqual(PF.parse_states(iter(self.OUTPUT.splitlines(keepends=True))), PF.parse_states(self.OUTPUT))


class StateGuardTest(unittest.TestCase):
    def test_a_huge_state_table_is_not_walked(self):
        walked = []
        with mock.patch.object(PF, "physical_memory", lambda: 4 * 1024 ** 3), \
                mock.patch.object(PF, "state_count", lambda: 100001), \
                mock.patch.object(PF.subprocess, "run", lambda *a, **k: walked.append(a)):
            with self.assertRaises(PF.TooManyStates):
                PF.sample_states()
        self.assertEqual(walked, [])

    def test_the_walk_stops_past_the_limit(self):
        three = NAT_OUT * 3
        self.assertEqual(len(PF.parse_states(three, limit=3)), 3)
        with self.assertRaises(PF.TooManyStates) as raised:
            PF.parse_states(three, limit=2)
        self.assertEqual(raised.exception.limit, 2)

    def test_a_slow_walk_is_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            pfctl = os.path.join(directory, "pfctl")
            with open(pfctl, "w") as handle:
                handle.write("#!/bin/sh\nexec sleep 5\n")
            os.chmod(pfctl, 0o755)
            with mock.patch.object(PF, "PFCTL", pfctl), mock.patch.object(PF, "SAMPLE_TIMEOUT", 0.2), \
                    mock.patch.object(PF, "state_count", lambda: 30000):
                started = time.monotonic()
                with self.assertRaises(PF.TooManyStates) as raised:
                    PF.sample_states(limit=35000)
        self.assertTrue(raised.exception.slow)
        self.assertEqual(raised.exception.count, 30000)
        self.assertLess(time.monotonic() - started, 3)

    def test_the_limit_follows_the_firewalls_memory(self):
        gigabyte = 1024 ** 3
        self.assertEqual(PF.state_limit(4 * gigabyte), 35000)
        self.assertEqual(PF.state_limit(8 * gigabyte), 70000)
        # a small box keeps a floor, a big one a ceiling (a sample must stay quick)
        self.assertEqual(PF.state_limit(gigabyte // 2), PF.MIN_SAMPLED_STATES)
        self.assertEqual(PF.state_limit(64 * gigabyte), PF.MAX_SAMPLED_STATES)

    def test_reads_the_state_count(self):
        output = "State Table                          Total             Rate\n  current entries                     1246               \n"
        with mock.patch.object(PF.subprocess, "run", lambda *a, **k: mock.Mock(stdout=output)):
            self.assertEqual(PF.state_count(), 1246)


class SampleCacheTest(unittest.TestCase):
    """What a state's header and endpoints parse to is kept between samples; nothing else changes."""

    ROUTED = ("all tcp 2a01:4f8:1:3::20[51234] -> 2606:4700::1111[443]       ESTABLISHED:ESTABLISHED\n"
              "   age 1d02:03:04, expires in 23:59:58, 10:20 pkts, 1000:2000 bytes, rule 7, rlabel lan\n"
              "   id: 00000000000000a1 creatorid: 12345678\n"
              "   origif: igb1\n")
    LAN = ("all tcp 192.168.30.30:51858 -> 34.209.15.107:8883       ESTABLISHED:ESTABLISHED\n"
           "   age 00:00:05, expires in 23:59:37, 4:2 pkts, 400:200 bytes, rule 3, rlabel iot\n"
           "   id: 00000000000000a2 creatorid: 12345678\n"
           "   origif: vlan03\n")
    NETWORKS = [(ipaddress.ip_network("2a01:4f8:1:3::/64"), "igb0"), (ipaddress.ip_network("2a01:4f8:1:2::/64"), "igb1")]
    LOCAL = {"1.2.3.163", "2a01:4f8:1:2::1"}

    def setUp(self):
        patcher = mock.patch.object(PF, "_known_headers", {})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_repeated_walk_parses_the_same_and_shares_endpoints(self):
        text = NAT_OUT + self.ROUTED + self.LAN
        first = PF.parse_states(text)
        self.assertIs(first[0].nat, PF.parse_states(text)[0].nat)
        second = PF.parse_states(iter(text.splitlines(keepends=True)))
        self.assertEqual(first, second)
        self.assertEqual(second[1]["age"], 93784)
        # a changed TCP state is a new header line
        closing = PF.parse_states(text.replace("ESTABLISHED:ESTABLISHED", "FIN_WAIT_2:FIN_WAIT_2", 1))
        self.assertEqual(closing[0]["state"], "FIN_WAIT_2:FIN_WAIT_2")
        self.assertEqual(closing[0]["src"], first[0]["src"])

    def test_an_unusual_detail_line_is_still_read(self):
        record, = PF.parse_states(self.LAN.replace("4:2 pkts, 400:200 bytes", "4:2 pkts,  400:200 bytes")
                                  .replace("expires in 23:59:37", "expires in 1d23:59:37"))
        self.assertEqual((record.age, record.bytes_in, record.bytes_out, record.rule), (5, 400, 200, "iot"))

    def facts_match_the_functions(self, records, local, networks):
        views, lan_rules = PF.StateFacts().view(records, local, networks)
        self.assertEqual(lan_rules, PF.lan_rule_index(records))
        for record, facts in views:
            pair = PF.flow_endpoints(record, local, networks)
            self.assertEqual(facts.pair, pair)
            if pair is None:
                continue
            self.assertIs(facts.inside, PF.inside_endpoint(record, networks, local))
            self.assertEqual((facts.remote_started, facts.service_port), PF.orientation(record, pair[1], networks, local))
            self.assertEqual(facts.outside, PF.state_outside(record, pair))
            self.assertEqual(facts.rule_of(record, lan_rules), PF.rule_for(record, pair, lan_rules, networks, local))

    def test_facts_are_what_the_functions_say(self):
        # the inside-facing state of NAT_OUT, created by the operator's rule
        nat_pair = NAT_OUT.replace("1.2.3.163:19421 (192.168.30.30:51858)", "192.168.30.30:51858") \
            .replace("allow-opts", "rule 3, rlabel iot")
        records = PF.parse_states(NAT_OUT + self.ROUTED + self.LAN + nat_pair + nat_state(10, 20))
        self.facts_match_the_functions(records, self.LOCAL, self.NETWORKS)
        self.facts_match_the_functions(records, {"1.2.3.163"}, [])

    def test_facts_are_kept_while_the_state_lasts(self):
        facts = PF.StateFacts()
        text = NAT_OUT + self.ROUTED
        (_, first), _ = facts.view(PF.parse_states(text), self.LOCAL, self.NETWORKS)[0]
        (_, again), _ = facts.view(PF.parse_states(text.replace("429:258", "500:300")), self.LOCAL, self.NETWORKS)[0]
        self.assertIs(again, first)
        # other firewall addresses, or the same id on other endpoints: worked out again
        (_, other), _ = facts.view(PF.parse_states(text), {"1.2.3.163"}, self.NETWORKS)[0]
        self.assertIsNot(other, first)
        moved = PF.parse_states(text.replace("34.209.15.107", "34.209.15.108"))
        (_, moved_facts), _ = facts.view(moved, {"1.2.3.163"}, self.NETWORKS)[0]
        self.assertEqual(moved_facts.pair, ("1.2.3.163", "34.209.15.108"))


if __name__ == "__main__":
    unittest.main()
