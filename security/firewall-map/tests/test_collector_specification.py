# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
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

"""Specification tests: hand-built PF states with expected results derived from PF semantics.

Independent of the retired Python engine (the oracle). Each scenario states the PF keys as the
kernel holds them: for a state created by an outbound packet the wire key is (destination,
translated source) and the stack key (destination, original source); for an inbound packet the
wire key is (source, original destination) and the stack key (source, redirected destination).
Counters are [forward, reverse]: forward is the creating packet's direction. Samples are 2 s apart
and rates are smoothed with weight 0.5, so a first rated sample shows half the raw rate.
"""

import ipaddress
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/opnsense/scripts/OPNsense/FirewallMap"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import collector  # noqa: E402
from collector_build import compile_worker  # noqa: E402

WAN = "45.33.32.10"
LAN_NET = (ipaddress.ip_network("10.0.0.0/24"), "lan0")
WAN_NET = (ipaddress.ip_network("45.33.32.0/24"), "wan0")
CONTEXT = {"local": {WAN}, "networks": [LAN_NET, WAN_NET], "assigned": {"wan0": {WAN}}, "wan": "wan0"}


def state(id, direction, keys, counters, age=10, interface="wan0", original="wan0", protocols=(6, 6), label=""):
    wire0, wire1, stack0, stack1 = keys
    forward, reverse, forward_packets, reverse_packets = counters
    return (f"state {id} 7 {direction} {protocols[0]} {protocols[1]} {wire0} {wire1} {stack0} {stack1} "
            f"{forward} {reverse} {forward_packets} {reverse_packets} {age} {interface} {original} {label}").rstrip()


OUTBOUND_NAT = ("1.1.1.1:443", f"{WAN}:50000", "1.1.1.1:443", "10.0.0.2:40000")
PORT_FORWARD = ("8.8.4.4:55000", f"{WAN}:443", "8.8.4.4:55000", "10.0.0.5:8443")


class SpecificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_scenario(self, samples, context=CONTEXT, count=None, **options):
        path = Path(self.directory.name) / f"{self._testMethodName}.txt"
        path.write_text("".join(f"sample {number}\n" + "".join(line + "\n" for line in lines)
                                for number, lines in samples.items()))
        engine = collector.CollectorEngine(self.worker)
        self.addCleanup(engine.close)
        with patch.dict(os.environ, FM_TEST_STATES=str(path), FM_TEST_INTERVAL="2"):
            return [engine.sample(context["local"], context["networks"], context["assigned"], context["wan"],
                                  **options) for _ in range(count or len(samples))]

    @staticmethod
    def candidates(sample, kind):
        return [value for _, candidate_kind, _, _, _, value in sample["candidates"] if candidate_kind == kind]

    def test_outbound_nat_is_local_initiated_and_oriented(self):
        query = ("tcp", WAN, "50000", "1.1.1.1", "443")
        _, second = self.run_scenario({1: [state(1, "out", OUTBOUND_NAT, (1000, 5000, 10, 50))],
                                       2: [state(1, "out", OUTBOUND_NAT, (1400, 9000, 14, 90))]},
                                      event_queries=[query])
        (flow,) = second["flows"]
        self.assertEqual(flow["key"], (WAN, "1.1.1.1"))
        # the remote's traffic is PF's reverse counter: (9000 - 5000) / 2 s, smoothed by half
        self.assertEqual((flow["rate_from_remote"], flow["rate_to_remote"]), (1000.0, 100.0))
        self.assertEqual((flow["bytes_from_remote"], flow["bytes_to_remote"]), (9000, 1400))
        self.assertEqual(self.candidates(second, collector.INSIDE_HOST),
                         [bytes([4]) + bytes([10, 0, 0, 2]) + bytes(12)])
        match = second["matches"][query]
        self.assertEqual((match["inside"], match["inside_port"], match["remote_initiated"]), ("10.0.0.2", 40000, False))
        self.assertEqual((match["bytes_in"], match["bytes_out"]), (9000, 1400))
        self.assertEqual((match["packets_from_remote"], match["packets_to_remote"]), (90, 14))

    def test_inbound_port_forward_is_remote_initiated_and_oriented(self):
        query = ("tcp", WAN, "443", "8.8.4.4", "55000")
        _, second = self.run_scenario({1: [state(1, "in", PORT_FORWARD, (2000, 100, 20, 1))],
                                       2: [state(1, "in", PORT_FORWARD, (6000, 300, 60, 3))]},
                                      event_queries=[query])
        (flow,) = second["flows"]
        self.assertEqual(flow["key"], (WAN, "8.8.4.4"))
        # the remote initiated: its traffic is PF's forward counter
        self.assertEqual((flow["rate_from_remote"], flow["rate_to_remote"]), (1000.0, 50.0))
        self.assertGreater(flow["remote_initiated_weight"], 0)
        match = second["matches"][query]
        self.assertEqual((match["inside"], match["inside_port"], match["remote_initiated"]), ("10.0.0.5", 8443, True))
        self.assertEqual((match["bytes_in"], match["bytes_out"]), (6000, 300))

    def test_double_nat_behind_a_private_primary_wan(self):
        context = {"local": set(), "networks": [LAN_NET, (ipaddress.ip_network("192.168.1.0/24"), "wan0")],
                   "assigned": {"wan0": {"192.168.1.2"}}, "wan": "wan0"}
        keys = ("1.1.1.1:443", "192.168.1.2:50000", "1.1.1.1:443", "10.0.0.2:40000")
        _, second = self.run_scenario({1: [state(1, "out", keys, (100, 100, 1, 1))],
                                       2: [state(1, "out", keys, (300, 500, 3, 5))]}, context)
        (flow,) = second["flows"]
        self.assertEqual(flow["key"], ("192.168.1.2", "1.1.1.1"))

    def test_routed_public_ipv6_inside_host(self):
        context = {"local": {"2001:470:0:1::2"},
                   "networks": [(ipaddress.ip_network("2001:470:1:2::/64"), "lan0"),
                                (ipaddress.ip_network("2001:470:0:1::/64"), "wan0")],
                   "assigned": {"wan0": {"2001:470:0:1::2"}}, "wan": "wan0"}
        keys = ("[2606:4700::1111]:443", "[2001:470:1:2::10]:40000", "[2606:4700::1111]:443",
                "[2001:470:1:2::10]:40000")
        _, second = self.run_scenario({1: [state(1, "out", keys, (100, 100, 1, 1))],
                                       2: [state(1, "out", keys, (300, 900, 3, 9))]}, context)
        (flow,) = second["flows"]
        # no translation: the map anchors the flow at the firewall's own address on the egress
        # interface, and the routed host is its inside endpoint
        self.assertEqual(flow["key"], ("2001:470:0:1::2", "2606:4700::1111"))
        inside = ipaddress.ip_address("2001:470:1:2::10").packed
        self.assertEqual(self.candidates(second, collector.INSIDE_HOST), [bytes([6]) + inside])
        self.assertEqual((flow["rate_from_remote"], flow["rate_to_remote"]), (200.0, 50.0))

    def test_icmp_echo_keeps_the_inside_identifier(self):
        keys = ("1.0.0.1:61000", f"{WAN}:61000", "1.0.0.1:4321", "10.0.0.2:4321")
        query = ("icmp", WAN, "61000", "1.0.0.1", "61000")
        _, second = self.run_scenario({1: [state(1, "out", keys, (84, 84, 1, 1), protocols=(1, 1))],
                                       2: [state(1, "out", keys, (168, 168, 2, 2), protocols=(1, 1))]},
                                      event_queries=[query])
        self.assertEqual(second["flows"][0]["key"], (WAN, "1.0.0.1"))
        self.assertEqual(self.candidates(second, collector.PROTOCOL), [b"\x01"])
        match = second["matches"][query]
        self.assertEqual((match["inside"], match["inside_port"]), ("10.0.0.2", 4321))

    def test_counter_reset_and_reappearance_never_spike(self):
        keys = OUTBOUND_NAT
        samples = {1: [state(1, "out", keys, (1000, 5000, 1, 1), age=10)],
                   2: [state(1, "out", keys, (1400, 9000, 1, 1), age=12)],
                   3: [state(1, "out", keys, (100, 200, 1, 1), age=14)],     # counters reset
                   4: [],                                                      # the state is gone
                   5: [state(1, "out", keys, (100000, 900000, 1, 1), age=20)],  # back, not new
                   6: [state(1, "out", keys, (100400, 904000, 1, 1), age=22)]}
        results = self.run_scenario(samples)
        self.assertEqual(results[1]["flows"][0]["rate_from_remote"], 1000.0)
        # a reset contributes nothing: the smoothed rate only decays
        self.assertEqual(results[2]["flows"][0]["rate_from_remote"], 500.0)
        self.assertEqual(results[3]["flows"], [])
        # a reappearing old state is a new baseline for its counters, not a burst
        self.assertEqual(results[4]["flows"], [])
        self.assertEqual(results[5]["flows"][0]["rate_from_remote"], 1000.0)

    def test_two_inside_hosts_behind_one_outside_tuple_are_ambiguous(self):
        other = PORT_FORWARD[:3] + ("10.0.0.6:8443",)
        query = ("tcp", WAN, "443", "8.8.4.4", "55000")
        (sample,) = self.run_scenario({1: [state(1, "in", PORT_FORWARD, (10, 10, 1, 1)),
                                           state(2, "in", other, (10, 10, 1, 1))]}, event_queries=[query])
        match = sample["matches"][query]
        self.assertTrue(match["ambiguous"])
        self.assertEqual(match["inside"], "10.0.0.6")  # the last state supplies the value

    def test_address_family_translation_is_skipped_and_counted(self):
        af_to = ("1.1.1.1:443", f"{WAN}:50001", "[64:ff9b::101:101]:443", "[2001:470:1:2::10]:40000")
        icmp_af_to = ("1.1.1.1:7", f"{WAN}:7", "[64:ff9b::101:101]:7", "[2001:470:1:2::10]:7")
        sample = {1: [state(1, "out", OUTBOUND_NAT, (1000, 5000, 1, 1)), state(2, "out", af_to, (5, 5, 1, 1)),
                      state(3, "out", icmp_af_to, (5, 5, 1, 1), protocols=(1, 58))]}
        (result,) = self.run_scenario(sample)
        self.assertEqual(result["telemetry"]["skipped_af_translation"], 2)
        self.assertEqual(result["skipped"], {"af_translation": 2})
        self.assertEqual((result["counts"]["states"], result["counts"]["retained"]), (3, 1))
        self.assertIsNone(result["refused"])
        query = ("tcp", WAN, "50000", "1.1.1.1", "443")
        (degraded,) = self.run_scenario(sample, event_queries=[query])
        self.assertTrue(degraded["matches"][query]["sample_degraded"])

    def test_unrecognised_protocol_mismatch_is_structural(self):
        keys = OUTBOUND_NAT
        with self.assertRaises(collector.CollectorError) as raised:
            self.run_scenario({1: [state(1, "out", keys, (1, 1, 1, 1), protocols=(6, 17))]})
        self.assertEqual(raised.exception.failure_class, "structural")

    def test_carp_vip_is_the_local_anchor(self):
        context = dict(CONTEXT, local={WAN, "45.33.32.100"})
        keys = ("8.8.4.4:55000", "45.33.32.100:443", "8.8.4.4:55000", "10.0.0.5:8443")
        _, second = self.run_scenario({1: [state(1, "in", keys, (10, 10, 1, 1))],
                                       2: [state(1, "in", keys, (50, 10, 1, 1))]}, context)
        self.assertEqual(second["flows"][0]["key"], ("45.33.32.100", "8.8.4.4"))

    def test_firewall_local_traffic_is_mapped_and_lan_internal_is_not(self):
        local = ("9.9.9.9:53", f"{WAN}:12345", "9.9.9.9:53", f"{WAN}:12345")
        internal = ("10.0.0.3:22", "10.0.0.2:5000", "10.0.0.3:22", "10.0.0.2:5000")
        _, second = self.run_scenario({1: [state(1, "out", local, (10, 10, 1, 1), protocols=(17, 17)),
                                           state(2, "in", internal, (10, 10, 1, 1), interface="lan0",
                                                 original="lan0")],
                                       2: [state(1, "out", local, (50, 90, 1, 1), protocols=(17, 17)),
                                           state(2, "in", internal, (90, 90, 1, 1), interface="lan0",
                                                 original="lan0")]})
        self.assertEqual([flow["key"] for flow in second["flows"]], [(WAN, "9.9.9.9")])
        self.assertEqual(self.candidates(second, collector.INSIDE_HOST), [])
        self.assertEqual((second["counts"]["states"], second["counts"]["retained"]), (2, 1))


if __name__ == "__main__":
    unittest.main()
