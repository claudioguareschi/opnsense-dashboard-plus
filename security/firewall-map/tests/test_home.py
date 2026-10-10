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

"""Where the firewall stands on the map (lib/home.py): IPv4 is the baseline, IPv6 joins it when a
precise IPv6 location agrees and gets its own house only when it is precisely somewhere else."""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import COLLECTOR, HOME, REFERENCE  # noqa: E402

CHARLESTON = {"lat": 32.9379, "lon": -80.0283, "city": "Charleston", "region": "South Carolina",
              "accuracy_km": 20, "country": "US", "country_name": "United States"}
NORTH_CHARLESTON = {"lat": 32.853, "lon": -79.9876, "city": "North Charleston", "accuracy_km": 10,
                    "country": "US", "country_name": "United States"}
# a database's "somewhere in the United States"
COUNTRY = {"lat": 37.751, "lon": -97.822, "city": None, "accuracy_km": 1000, "country": "US",
           "country_name": "United States"}
CHICAGO = {"lat": 41.9703, "lon": -87.664, "city": "Chicago", "accuracy_km": 50, "country": "US",
           "country_name": "United States"}
FREMONT = {"lat": 37.5483, "lon": -121.9886, "city": "Fremont", "accuracy_km": 20, "country": "US",
           "country_name": "United States"}

WAN4, WAN6, LAN6, TUNNEL6 = "73.180.73.118", "2601:740:1::2", "2601:740:8500:5e78::1", "2001:470:1f06::2"


def beach(**overrides):
    """A dual-stack firewall: IPv4 WAN and the inside prefix in Charleston, the WAN's own IPv6
    address known only by country."""
    locations = {WAN4: CHARLESTON, WAN6: COUNTRY, LAN6: NORTH_CHARLESTON, TUNNEL6: FREMONT}
    locations.update(overrides)
    return locations


def plan(locations, addresses=None, **options):
    addresses = addresses or {"igb0": {WAN4, WAN6, "fe80::1"}, "igb1": {"192.168.90.1", LAN6}}
    return HOME.plan(addresses, locations.get, "igb0", **options)


class HomePlanTest(unittest.TestCase):
    def test_ipv6_joins_the_ipv4_home_when_the_inside_prefix_agrees(self):
        homes = plan(beach())
        self.assertEqual(len(homes.homes), 1)
        home = homes.homes[0]
        self.assertEqual((home["source"], home["evidence"], home["name"]),
                         ("ipv4_wan", WAN4, "Charleston, United States"))
        # the WAN's IPv6 address, known only by country, starts from the same house
        for address in (WAN4, WAN6, LAN6):
            location = homes.location(address)
            self.assertEqual((location["id"], location["lat"], location["lon"], location["local"]),
                             (address, CHARLESTON["lat"], CHARLESTON["lon"], True))
        self.assertEqual(homes.describe()[0]["families"], ["IPv4", "IPv6"])

    def test_country_only_ipv6_is_no_evidence(self):
        homes = plan(beach(**{LAN6: COUNTRY}))
        self.assertEqual(len(homes.homes), 1)
        self.assertIs(homes.home(WAN6), homes.home(WAN4))

    def test_precise_ipv6_elsewhere_gets_its_own_house_unless_set_to_follow_ipv4(self):
        homes = plan(beach(**{LAN6: CHICAGO}))
        self.assertEqual([home["source"] for home in homes.homes], ["ipv4_wan", "ipv6_inside"])
        self.assertEqual(homes.location(WAN6)["name"], "Chicago, United States")
        self.assertEqual(homes.location(WAN4)["name"], "Charleston, United States")
        self.assertEqual([row["families"] for row in homes.describe()], [["IPv4"], ["IPv6"]])
        followed = plan(beach(**{LAN6: CHICAGO}), ipv6_home="ipv4")
        self.assertEqual(len(followed.homes), 1)
        self.assertIs(followed.home(LAN6), followed.home(WAN4))

    def test_the_inside_prefix_is_tried_before_the_wan_address(self):
        # the WAN address agrees with IPv4, the inside prefix does not: any agreement joins
        homes = plan(beach(**{WAN6: CHARLESTON, LAN6: CHICAGO}))
        self.assertEqual(len(homes.homes), 1)
        # neither agrees: the second house is the inside prefix's, not the WAN address's
        homes = plan(beach(**{WAN6: FREMONT, LAN6: CHICAGO}))
        self.assertEqual((homes.homes[1]["source"], homes.homes[1]["evidence"]), ("ipv6_inside", LAN6))

    def test_tunnel_and_vpn_interfaces_are_never_evidence(self):
        addresses = {"igb0": {WAN4, WAN6}, "igb1": {LAN6}, "gif0": {TUNNEL6}, "wg0": {"2a01:4f8:1::1"}}
        homes = plan(beach(**{LAN6: COUNTRY, "2a01:4f8:1::1": FREMONT}), addresses)
        self.assertEqual(len(homes.homes), 1)
        # their addresses still start from the house of their family
        self.assertIs(homes.home(TUNNEL6), homes.home(WAN4))
        self.assertTrue(HOME.tunnel("ovpns1") and HOME.tunnel("ipsec2") and HOME.tunnel("wg0"))
        self.assertFalse(HOME.tunnel("pppoe0") or HOME.tunnel("igb0") or HOME.tunnel("vlan01"))

    def test_agreement_allows_for_the_two_radii(self):
        near = dict(CHARLESTON, lat=CHARLESTON["lat"] + 0.4)          # about 44 km north
        far = dict(CHARLESTON, lat=CHARLESTON["lat"] + 1.1)           # about 122 km north
        self.assertTrue(HOME.agree(CHARLESTON, near))
        self.assertFalse(HOME.agree(CHARLESTON, far))
        self.assertTrue(HOME.agree(dict(CHARLESTON, accuracy_km=100), dict(far, accuracy_km=50)))
        self.assertAlmostEqual(HOME.distance_km(CHARLESTON, NORTH_CHARLESTON), 10.1, delta=0.5)
        self.assertFalse(HOME.precise(COUNTRY) or HOME.precise(None) or HOME.precise(dict(CHICAGO, accuracy_km=500)))
        self.assertTrue(HOME.precise(dict(CHICAGO, accuracy_km=None)))

    def test_coordinates_place_every_address(self):
        homes = plan(beach(**{LAN6: CHICAGO}), coordinates=(40.7128, -74.006))
        self.assertEqual(len(homes.homes), 1)
        self.assertEqual(homes.homes[0]["source"], "coordinates")
        self.assertEqual((homes.location(LAN6)["lat"], homes.location(WAN4)["lon"]), (40.7128, -74.006))
        self.assertEqual(homes.location("192.168.90.1")["name"], "Firewall")

    def test_behind_an_upstream_nat_the_discovered_address_is_the_baseline(self):
        addresses = {"igb0": {"192.168.0.2", WAN6}, "igb1": {LAN6}}
        homes = plan(beach(), addresses, external=("73.1.2.3", CHARLESTON))
        self.assertEqual((homes.homes[0]["source"], homes.homes[0]["evidence"]), ("external_ip", "73.1.2.3"))
        self.assertEqual(len(homes.homes), 1)
        # the private WAN address flows start from is drawn at the home
        self.assertEqual(homes.location("192.168.0.2")["lat"], CHARLESTON["lat"])
        # a carrier-grade NAT gateway known only by country gives way to the inside prefix
        homes = plan(beach(), addresses, external=("100.64.1.1", COUNTRY))
        self.assertEqual([home["source"] for home in homes.homes], ["ipv6_inside"])
        self.assertIs(homes.home("192.168.0.2"), homes.home(LAN6))

    def test_ipv6_only(self):
        homes = plan(beach(), {"igb0": {WAN6}, "igb1": {LAN6}})
        self.assertEqual([(home["source"], home["evidence"]) for home in homes.homes], [("ipv6_inside", LAN6)])
        self.assertIs(homes.home(WAN6), homes.homes[0])

    def test_with_nothing_precise_one_approximate_home(self):
        homes = plan(beach(**{WAN4: COUNTRY, LAN6: None}))
        self.assertEqual([(home["source"], home["evidence"]) for home in homes.homes], [("approximate", WAN4)])
        self.assertIs(homes.home(WAN6), homes.home(WAN4))
        self.assertIsNone(plan({}).location(WAN4))

    def test_a_second_wan_precisely_elsewhere_keeps_its_house(self):
        addresses = {"igb0": {WAN4}, "igb2": {"1.2.3.163"}, "igb1": {LAN6}}
        homes = plan(beach(**{"1.2.3.163": CHICAGO}), addresses)
        self.assertEqual([home["name"] for home in homes.homes],
                         ["Charleston, United States", "Chicago, United States"])
        self.assertEqual(homes.location("1.2.3.163")["name"], "Chicago, United States")
        # IPv6 compares with the primary WAN's house
        self.assertIs(homes.home(LAN6), homes.home(WAN4))


class CollectorHomeTest(unittest.TestCase):
    def collector(self, locations):
        collector = object.__new__(COLLECTOR.Collector)
        collector.location_settings = {"latitude": None, "longitude": None, "discover_external_ip": False,
                                       "ipv6_home": "auto"}
        collector.primary_wan_device = "igb0"
        collector.interface_addresses = {"igb0": {WAN4, WAN6}, "igb1": {"192.168.90.1", LAN6}}
        collector.local_addresses = {WAN4, WAN6, LAN6}
        collector.external_ip = collector.external_ip_key = collector.external_ip_checked = None
        collector.homes = collector.homes_key = None
        collector.store = mock.Mock()

        class Geo:
            def resolve(self, addresses):
                pass

            def get(self, address):
                return locations.get(address)
        collector.geo = Geo()
        return collector

    def test_ipv6_flows_start_from_the_ipv4_house(self):
        locations = dict(beach(), **{"2606:4700::1111": FREMONT})
        collector = self.collector(locations)
        homes = collector.home_plan(0.0)
        self.assertIs(collector.home_plan(1.0), homes, "kept while nothing changes")
        # an inside host's IPv6 flow: the collector reports the firewall's WAN IPv6 address as its origin
        flow = {
            "rate": 1.0, "rate_in": 0.0, "rate_out": 1.0, "packet_rate": 1.0, "last_active": 0.0,
            "first_seen": 0.0, "states": 1, "protocols": ["tcp"], "services": ["HTTPS"],
            "service_ports": {"HTTPS": "443/tcp"}, "inside": ["2601:740:8500:5e78::20"], "egress": "igb0",
            "initiated": "local", "targets": [], "age": 1, "transferred": (1, 1), "rule": None,
        }
        tracker = REFERENCE.FlowTracker(smoothing=1.0)
        payload = COLLECTOR.summarize_flows(tracker, collector.geo, collector.local_addresses, None, 0.0, 0.0,
                                            context={}, anchor=homes.location,
                                            visible=[(None, WAN6, "2606:4700::1111", flow, 1.0)])
        origin = next(location for location in payload["locations"] if location["id"] == WAN6)
        self.assertEqual((origin["lat"], origin["lon"], origin["local"], origin["home"]),
                         (CHARLESTON["lat"], CHARLESTON["lon"], True, "ipv4_wan"))
        remote = next(location for location in payload["locations"] if location["id"] == "2606:4700::1111")
        self.assertFalse(remote["local"])
        json.dumps(homes.describe())

    def test_a_changed_setting_replans(self):
        collector = self.collector(beach(**{LAN6: CHICAGO}))
        self.assertEqual(len(collector.home_plan(0.0).homes), 2)
        collector.location_settings["ipv6_home"] = "ipv4"
        self.assertEqual(len(collector.home_plan(1.0).homes), 1)
        collector.location_settings.update(latitude=40.0, longitude=-74.0)
        self.assertEqual(collector.home_plan(2.0).homes[0]["source"], "coordinates")


if __name__ == "__main__":
    unittest.main()
