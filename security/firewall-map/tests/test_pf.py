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

"""Unit tests for PF state parsing and flow endpoints (fwmap_pf)."""

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

    def test_parses_mmdblookup_dump(self):
        output = """
  {
    "city":
      {
        "names":
          {
            "en":
              "Mountain View" <utf8_string>
          }
      }
    "country":
      {
        "iso_code":
          "US" <utf8_string>
      }
    "location":
      {
        "latitude":
          37.751000 <double>
        "longitude":
          -97.822000 <double>
      }
    "subdivisions":
      [
        {
          "iso_code":
            "CA" <utf8_string>
        }
      ]
  }
"""
        values = CACHE.parse_mmdb(output)
        self.assertEqual(values[("city", "names", "en")], "Mountain View")
        self.assertEqual(values[("country", "iso_code")], "US")
        self.assertEqual(float(values[("location", "longitude")]), -97.822)
        self.assertEqual(values[("subdivisions", "iso_code")], "CA")


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
        described = LEASES.describe_inside("192.168.30.30", {"192.168.30.30": "nas"}, networks,
                                              {"vlan03": "VLAN30_IOT"})
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
            config = os.path.join(directory, "config.xml")
            with open(config, "w") as handle:
                handle.write("<opnsense><OPNsense><Kea><dhcp6><reservations><reservation>"
                             "<ip_address>fd12:3456:789a:30::81</ip_address><hostname>reserved6</hostname>"
                             "</reservation></reservations></dhcp6></Kea></OPNsense></opnsense>")
            names = LEASES.lease_names(kea, dnsmasq, config, now=1000, kea6=kea6)
            self.assertEqual(names, {"192.168.30.80": "homeassistant", "192.168.40.5": "tv",
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


class StateGuardTest(unittest.TestCase):
    def test_a_huge_state_table_is_not_walked(self):
        walked = []
        with mock.patch.object(PF, "state_count", lambda: PF.MAX_SAMPLED_STATES + 1), \
                mock.patch.object(PF.subprocess, "run", lambda *a, **k: walked.append(a)):
            with self.assertRaises(PF.TooManyStates):
                PF.sample_states()
        self.assertEqual(walked, [])

    def test_reads_the_state_count(self):
        output = "State Table                          Total             Rate\n  current entries                     1246               \n"
        with mock.patch.object(PF.subprocess, "run", lambda *a, **k: mock.Mock(stdout=output)):
            self.assertEqual(PF.state_count(), 1246)


if __name__ == "__main__":
    unittest.main()
