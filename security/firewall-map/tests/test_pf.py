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
import unittest
import weakref
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import REFERENCE, REFERENCE_THREATS, BLOCKLISTS, CACHE, COMMON, LEASES, PF, NAT_OUT, nat_state  # noqa: E402


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


class SampleStringSharingTest(unittest.TestCase):
    @staticmethod
    def copy(value):
        return value.encode().decode()

    @staticmethod
    def table(count=48):
        rows = []
        for number in range(count):
            remote = f"34.77.0.{number + 1}" if number % 2 == 0 else f"2606:4700:4701::{number + 1:x}"
            far = f"{remote}:443" if number % 2 == 0 else f"{remote}[443]"
            rows.append(f"all tcp 1.2.3.163:{30000 + number} (192.168.1.2:41000) -> {far} ESTABLISHED:ESTABLISHED\n"
                        f"   age 00:10:00, expires in 00:00:30, 2:3 pkts, 100:200 bytes\n"
                        f"   id: {number:016x} creatorid: 01\n   origif: igb1\n")
        return "".join(rows)

    def tracked_pools(self, limit):
        references, sizes = [], []
        original = PF._StringPool

        class Values(dict):
            __slots__ = ("__weakref__",)

        class Pool(original):
            __slots__ = ("__weakref__", "index")

            def __init__(self):
                super().__init__(limit)
                self.values = Values()
                self.index = len(sizes)
                sizes.append(0)
                references.append((weakref.ref(self), weakref.ref(self.values)))

            def share(self, value):
                result = super().share(value)
                sizes[self.index] = max(sizes[self.index], len(self.values))
                return result

        return Pool, references, sizes

    def test_bound_reuses_admitted_values_but_never_admits_overflow(self):
        with PF._StringPool(limit=2) as pool:
            first = self.copy("34.77.0.1")
            duplicate = self.copy(first)
            self.assertIsNot(first, duplicate)
            self.assertIs(pool.share(first), first)
            self.assertIs(pool.share(duplicate), first)
            pool.share("2606:4700:4701::1")
            for number in range(32):
                value = f"34.78.0.{number + 1}"
                self.assertIs(pool.share(value), value)
            self.assertIs(pool.share(self.copy(first)), first)
            self.assertEqual(len(pool.values), 2)
            self.assertIsNone(pool.share(None))
        self.assertEqual(pool.values, {})

    def test_zero_bound_and_new_sample_have_correct_value_semantics(self):
        first = self.copy("30000")
        with PF._StringPool(limit=0) as empty:
            self.assertIs(empty.share(first), first)
            self.assertEqual(empty.values, {})
        with PF._StringPool(limit=2) as old:
            self.assertIs(old.share(first), first)
        second = self.copy(first)
        with PF._StringPool(limit=2) as fresh:
            self.assertIs(fresh.share(second), second)
            self.assertIsNot(fresh.share(second), first)
        self.assertEqual(old.values, {})

    def test_endpoint_sharing_preserves_all_existing_formats_and_invalid_values(self):
        values = ("34.77.0.1:443", "34.77.0.1", "(192.168.1.2:41000)",
                  "2606:4700:4701:0:0:0:0:1[443]", "[2606:4700:4701::1]:443",
                  "2606:4700:4701::1", "", "34.77.0.1:unusual")
        with PF._StringPool(limit=2) as addresses, PF._StringPool(limit=2) as ports:
            for value in values:
                self.assertEqual(PF.endpoint(value, addresses, ports), PF.endpoint(value))
            self.assertLessEqual(len(addresses.values), 2)
            self.assertLessEqual(len(ports.values), 2)

    def test_parser_and_facts_share_only_values_without_retaining_lookup_tables(self):
        first = self.table(1)
        second = first.replace("1.2.3.163:30000", "1.2.3.163:30001").replace("id: 0000000000000000", "id: 01")
        third = first.replace("34.77.0.1:443", "34.77.0.2:443").replace("id: 0000000000000000", "id: 02")
        inbound = nat_state(100, 200)
        inbound2 = inbound.replace("45.56.79.53:35799", "45.56.79.53:35800").replace("f501b86a", "f501b86b")
        Pool, references, sizes = self.tracked_pools(64)
        with mock.patch.object(PF, "_known_headers", {}), mock.patch.object(PF, "_StringPool", Pool):
            records = PF.parse_states(first + second + third + inbound + inbound2)
            headers = PF._known_headers
            cache = PF.StateFacts()
            views, _ = cache.view(records, {"1.2.3.163"})
        self.assertIs(records[0].dst.address, records[1].dst.address)
        self.assertIs(records[0].dst.port, records[1].dst.port)
        a, b, c, incoming, incoming2 = [facts for record, facts in views]
        self.assertIs(a.port_label, b.port_label)
        self.assertIs(a.inside_text, b.inside_text)
        self.assertIs(a.remote, b.remote)
        self.assertIs(a.public, c.public)
        self.assertIs(incoming.target, incoming2.target)
        self.assertEqual(incoming.target, "tcp|192.168.1.2|443")
        self.assertTrue(headers and cache.known and records and views)
        self.assertEqual(len(references), 3)
        self.assertTrue(all(owner() is None and values() is None for owner, values in references))
        self.assertTrue(all(size <= 64 for size in sizes))

    def test_adversarial_addresses_and_ports_are_bounded_and_not_retained(self):
        Pool, references, sizes = self.tracked_pools(4)
        with mock.patch.object(PF, "_known_headers", {}), mock.patch.object(PF, "_StringPool", Pool):
            text = self.table()
            records = PF.parse_states(text)
            views, _ = PF.StateFacts().view(records, {"1.2.3.163"})
        self.assertEqual(len(records), 48)
        self.assertEqual(records[-1].dst.address, "2606:4700:4701::30")
        self.assertEqual(records[-1].src.port, "30047")
        self.assertIs(records[-1].src.address, records[0].src.address)
        self.assertIs(records[-1].dst.port, records[0].dst.port)
        self.assertEqual(views[-1][1].port_label, "443/tcp")
        self.assertEqual(sizes, [4, 4, 4])
        self.assertTrue(all(owner() is None and values() is None for owner, values in references))

    def test_new_parse_uses_fresh_pools_without_changing_header_or_facts_cache_hits(self):
        with mock.patch.object(PF, "_known_headers", {}):
            text = self.table(1)
            first = PF.parse_states(text)
            cache = PF.StateFacts()
            sample, _ = cache.view(first, {"1.2.3.163"})
            second = PF.parse_states(text)
            repeated, _ = cache.view(second, {"1.2.3.163"})
            self.assertIs(first[0].src, second[0].src)
            self.assertIs(sample[0][1], repeated[0][1])
            third = PF.parse_states(text.replace("1.2.3.163:30000", "1.2.3.163:30001"))
            self.assertEqual(first[0].dst.address, third[0].dst.address)
            self.assertIsNot(first[0].dst.address, third[0].dst.address)

    def test_failed_parse_clears_pools_even_when_its_traceback_survives(self):
        Pool, references, sizes = self.tracked_pools(4)
        retained = None
        with mock.patch.object(PF, "_known_headers", {}), mock.patch.object(PF, "_StringPool", Pool):
            try:
                PF.parse_states(self.table(), limit=0)
            except PF.TooManyStates as error:
                retained = error
        self.assertIsNotNone(retained)
        self.assertTrue(any(size for size in sizes))
        self.assertTrue(all(values() is None or not values() for owner, values in references))

    def test_failed_fact_view_clears_pool_even_when_its_traceback_survives(self):
        records = PF.parse_states(self.table(1))

        def failing_records():
            yield records[0]
            raise ValueError("failed sample")

        Pool, references, sizes = self.tracked_pools(4)
        retained = None
        with mock.patch.object(PF, "_StringPool", Pool):
            try:
                PF.StateFacts().view(failing_records(), {"1.2.3.163"})
            except ValueError as error:
                retained = error
        self.assertIsNotNone(retained)
        self.assertEqual(sizes, [4])
        self.assertTrue(all(values() is None or not values() for owner, values in references))


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

    def test_private_primary_wan_nat_keeps_its_real_wire_address(self):
        state = self.NAT_OUT.replace("1.2.3.163:19421", "192.168.0.2:19421")
        record = PF.parse_states(state)[0]
        topology = {"igb1": {"192.168.0.2"}}
        self.assertEqual(PF.flow_endpoints(record, set(), interface_addresses=topology,
                                           primary_wan_device="igb1"),
                         ("192.168.0.2", "34.209.15.107"))
        # A public address elsewhere on the firewall is not this state\'s origin.
        self.assertEqual(PF.flow_endpoints(record, {"152.44.11.230"}, interface_addresses=topology,
                                           primary_wan_device="igb1"),
                         ("192.168.0.2", "34.209.15.107"))

    def test_private_wan_requires_the_exact_local_address_and_origif(self):
        state = self.NAT_OUT.replace("1.2.3.163:19421", "192.168.0.3:19421")
        record = PF.parse_states(state)[0]
        topology = {"igb1": {"192.168.0.2"}}
        self.assertIsNone(PF.flow_endpoints(record, set(), interface_addresses=topology,
                                            primary_wan_device="igb1"))
        record.origif = "vlan03"
        self.assertIsNone(PF.flow_endpoints(record, set(), interface_addresses=topology,
                                            primary_wan_device="igb1"))

    def test_maps_inside_host_to_interface_and_name(self):
        networks = PF.interface_networks(self.IFCONFIG)
        self.assertIn(("192.168.30.250/32", "vlan03"), [(str(network), device) for network, device in networks])
        self.assertEqual(PF.interface_addresses(self.IFCONFIG)["igb1"], {"1.2.2.230", "2606:4700:4700::1111"})
        described = LEASES.describe_inside("192.168.30.30", {"192.168.30.30": "nas"}, networks, {"vlan03": "VLAN30_IOT"})
        self.assertEqual(described, {"ip": "192.168.30.30", "name": "nas", "interface": "VLAN30_IOT"})
        self.assertEqual(LEASES.describe_inside("fd12:3456:789a:30::20", {}, networks,
                                                {"vlan03": "VLAN30_IOT"})["interface"], "VLAN30_IOT")

    def test_tracker_reports_inside_hosts_and_egress(self):
        tracker = REFERENCE.FlowTracker(smoothing=1.0)
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

        tracker = REFERENCE.FlowTracker(smoothing=1.0)
        tracker.update([record], local, now=0.0, networks=networks)
        flow = tracker.flows[pair]
        self.assertEqual((flow["inside"], flow["initiated"]), (["2606:4700:4701::20"], "local"))

        seen = REFERENCE_THREATS.observe([record], lambda address: ["IPv6 test"] if address == pair[1] else [],
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
        tracker = REFERENCE.FlowTracker(smoothing=1.0)
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

    def test_inbound_private_primary_wan_port_forward_reports_real_wire_address(self):
        state = self.INBOUND.replace("1.2.3.163", "192.168.0.2").replace("origif: ix0", "origif: igb1")
        record = PF.parse_states(state)[0]
        topology = {"igb1": {"192.168.0.2"}}
        pair = PF.flow_endpoints(record, set(), interface_addresses=topology, primary_wan_device="igb1")
        self.assertEqual(pair, ("192.168.0.2", "94.154.43.203"))
        self.assertEqual(PF.state_outside(record, pair),
                         ("tcp", "192.168.0.2", "443", "94.154.43.203", "51234"))
        tracker = REFERENCE.FlowTracker(smoothing=1.0)
        tracker.update([], set(), now=0.0, interface_addresses=topology, primary_wan_device="igb1")
        tracker.update([record], set(), now=2.0, interface_addresses=topology, primary_wan_device="igb1")
        flow = tracker.flows[pair]
        self.assertEqual((flow["initiated"], flow["targets"]), ("remote", ["tcp|192.168.1.2|443"]))

    def test_inbound_udp_to_the_firewall_keeps_its_protocol(self):
        states = ("all udp 1.2.3.163:51820 <- 94.154.43.203:51234       MULTIPLE:MULTIPLE\n"
                  "   age 00:00:01, expires in 00:00:59, 5:9 pkts, 400:900 bytes\n   id: 0b creatorid: 01\n")
        tracker = REFERENCE.FlowTracker(smoothing=1.0)
        tracker.update([], {"1.2.3.163"}, now=0.0)
        tracker.update(PF.parse_states(states), {"1.2.3.163"}, now=2.0)
        flow = tracker.flows[("1.2.3.163", "94.154.43.203")]
        self.assertEqual(flow["targets"], ["udp|1.2.3.163|51820"])
        target = LEASES.describe_target(flow["targets"][0], {}, [], {}, {"1.2.3.163"})
        self.assertEqual((target["name"], target["service"]), ("firewall", "WireGuard"))

    def test_outbound_flows_are_local(self):
        tracker = REFERENCE.FlowTracker(smoothing=1.0)
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

    def test_facts_are_reworked_when_primary_wan_topology_changes(self):
        record = PF.parse_states(NAT_OUT.replace("1.2.3.163:19421", "192.168.0.2:19421"))[0]
        facts = PF.StateFacts()
        (_, first), = facts.view([record], set(), interface_addresses={"igb1": {"192.168.0.2"}},
                                 primary_wan_device="igb1")[0]
        (_, changed), = facts.view([record], set(), interface_addresses={"igb1": {"192.168.0.3"}},
                                   primary_wan_device="igb1")[0]
        self.assertEqual(first.pair, ("192.168.0.2", "34.209.15.107"))
        self.assertIsNone(changed.pair)
        self.assertIsNot(first, changed)


if __name__ == "__main__":
    unittest.main()
