"""Unit tests for the Firewall Map collector and snapshot reader."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest


SCRIPTS = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/FirewallMap"


def load(name):
    spec = importlib.util.spec_from_file_location(f"firewall_map_{name}", SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEODB = load("firewallmap_geodb")
COLLECTOR = load("firewallmap_collector")
INVESTIGATE = load("firewallmap_investigate")
ABUSEIPDB = load("firewallmap_abuseipdb")
SNAPSHOT = load("flow_snapshot")
THREATS = load("firewallmap_threats")

NAT_STATE = """all tcp 198.13.91.163:443 (192.168.1.2:443) <- 45.56.79.53:35799       ESTABLISHED:ESTABLISHED
   [123 + 456] wscale 9  [789 + 101112] wscale 6
   age 00:10:05, expires in 23:59:48, {pkts_in}:{pkts_out} pkts, {bytes_in}:{bytes_out} bytes
   id: f501b86a00000000 creatorid: 2ec5c347
   origif: vlan01
"""


def nat_state(bytes_in, bytes_out, pkts_in=8, pkts_out=12):
    return NAT_STATE.format(bytes_in=bytes_in, bytes_out=bytes_out, pkts_in=pkts_in, pkts_out=pkts_out)


class ParseTest(unittest.TestCase):
    def test_parses_verbose_state_record(self):
        records = COLLECTOR.parse_states(nat_state(368, 5072))
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["protocol"], "tcp")
        self.assertEqual(record["bytes_out"], 5072)
        self.assertEqual(record["packets_in"], 8)
        self.assertEqual(record["src"]["address"], "45.56.79.53")
        self.assertEqual(record["dst"]["address"], "198.13.91.163")
        self.assertEqual(record["nat"]["address"], "192.168.1.2")
        self.assertEqual(record["id"], "f501b86a00000000/2ec5c347")
        self.assertEqual(record["age"], 605)

    def test_uses_nat_public_address_as_map_origin(self):
        output = """all tcp 192.168.1.2:443 (198.13.91.163:443) <- 45.56.79.53:35799 ESTABLISHED:ESTABLISHED
   age 00:10:05, expires in 23:59:48, 8:12 pkts, 368:5072 bytes
   id: 01 creatorid: 02
"""
        record = COLLECTOR.parse_states(output)[0]
        self.assertEqual(COLLECTOR.flow_endpoints(record, {"198.13.91.163"}), ("198.13.91.163", "45.56.79.53"))

    def test_excludes_firewall_to_firewall_state(self):
        record = {
            "src": {"address": "152.44.11.230", "port": "443"},
            "dst": {"address": "198.13.91.163", "port": "443"},
            "nat": None,
        }
        self.assertIsNone(COLLECTOR.flow_endpoints(record, {"152.44.11.230", "198.13.91.163"}))

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
        values = COLLECTOR.parse_mmdb(output)
        self.assertEqual(values[("city", "names", "en")], "Mountain View")
        self.assertEqual(values[("country", "iso_code")], "US")
        self.assertEqual(float(values[("location", "longitude")]), -97.822)
        self.assertEqual(values[("subdivisions", "iso_code")], "CA")


class TrackerTest(unittest.TestCase):
    LOCAL = {"198.13.91.163"}
    PAIR = ("198.13.91.163", "45.56.79.53")

    def test_rate_comes_from_counter_deltas_not_totals(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update(COLLECTOR.parse_states(nat_state(1000, 1000)), self.LOCAL, now=100.0)
        self.assertIsNone(tracker.flows[self.PAIR]["last_active"])
        self.assertEqual(tracker.visible(100.0), [])
        tracker.update(COLLECTOR.parse_states(nat_state(1500, 2500)), self.LOCAL, now=102.0)
        self.assertEqual(tracker.flows[self.PAIR]["rate"], 1000.0)
        self.assertEqual(len(tracker.visible(102.0)), 1)

    def test_splits_rate_toward_and_away_from_firewall(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        # remote 45.56.79.53 initiated this state: first counter is remote -> firewall
        tracker.update(COLLECTOR.parse_states(nat_state(1000, 1000)), self.LOCAL, now=0.0)
        tracker.update(COLLECTOR.parse_states(nat_state(1600, 1100)), self.LOCAL, now=1.0)
        flow = tracker.flows[self.PAIR]
        self.assertEqual((flow["rate_in"], flow["rate_out"]), (600.0, 100.0))

    def test_names_the_responder_service(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update(COLLECTOR.parse_states(nat_state(1000, 1000)), self.LOCAL, now=0.0)
        self.assertEqual(tracker.flows[self.PAIR]["services"], ["HTTPS"])
        self.assertEqual(COLLECTOR.service_name("udp", "51820"), "WireGuard")
        self.assertEqual(COLLECTOR.service_name("tcp", "9999"), "TCP/9999")

    def test_idle_flow_fades_then_state_removal_drops_it(self):
        tracker = COLLECTOR.FlowTracker(fade_seconds=10, smoothing=1.0)
        tracker.update(COLLECTOR.parse_states(nat_state(1000, 1000)), self.LOCAL, now=0.0)
        tracker.update(COLLECTOR.parse_states(nat_state(2000, 1000)), self.LOCAL, now=1.0)
        tracker.update(COLLECTOR.parse_states(nat_state(2000, 1000)), self.LOCAL, now=6.0)
        flow = tracker.flows[self.PAIR]
        self.assertEqual(flow["rate"], 0.0)
        self.assertAlmostEqual(tracker.activity(flow, 6.0), 0.5)
        self.assertEqual(tracker.visible(12.0), [])
        tracker.update([], self.LOCAL, now=13.0)
        self.assertNotIn(self.PAIR, tracker.flows)

    def test_new_state_counts_its_bytes(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update([], self.LOCAL, now=0.0)
        fresh = nat_state(300, 700).replace("age 00:10:05", "age 00:00:01")
        tracker.update(COLLECTOR.parse_states(fresh), self.LOCAL, now=1.0)
        self.assertEqual(tracker.flows[self.PAIR]["rate"], 1000.0)

    def test_visible_flows_are_capped(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        for index in range(5):
            tracker.flows[("198.13.91.163", f"8.8.8.{index}")] = {
                "rate": float(index), "rate_in": 0.0, "rate_out": 0.0, "packet_rate": 0.0,
                "last_active": 0.0, "first_seen": 0.0,
            }
        visible = tracker.visible(0.0, limit=2)
        self.assertEqual([item[2] for item in visible], ["8.8.8.4", "8.8.8.3"])


class IdleTest(unittest.TestCase):
    def test_stops_only_after_grace_period_without_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = os.path.join(directory, "last_request")
            self.assertFalse(COLLECTOR.idle(started=1000, now=1100, marker=marker, idle_seconds=300))
            self.assertTrue(COLLECTOR.idle(started=1000, now=1400, marker=marker, idle_seconds=300))
            SNAPSHOT.mark_request(marker)
            now = os.stat(marker).st_mtime
            self.assertFalse(COLLECTOR.idle(started=now - 1000, now=now + 10, marker=marker, idle_seconds=300))
            self.assertTrue(COLLECTOR.idle(started=now - 1000, now=now + 301, marker=marker, idle_seconds=300))


class InsideTest(unittest.TestCase):
    NAT_OUT = """all tcp 198.13.91.163:19421 (192.168.30.30:51858) -> 34.209.15.107:8883       ESTABLISHED:ESTABLISHED
   [499210651 + 65535]  [1522661447 + 31469]
   age 21:44:28, expires in 23:59:37, 429:258 pkts, 27391:18836 bytes, allow-opts
   id: 5415dc6a00000000 creatorid: fc08c4c0
   origif: igb1
"""
    IFCONFIG = """igb1: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500
\tinet 152.44.11.230 netmask 0xffffff00 broadcast 152.44.11.255
vlan03: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500
\tinet 192.168.30.248 netmask 0xffffff00 broadcast 192.168.30.255
\tinet 192.168.30.250 netmask 0xffffffff vhid 30
"""

    def test_parses_origif_and_inside_host(self):
        record = COLLECTOR.parse_states(self.NAT_OUT)[0]
        self.assertEqual(record["origif"], "igb1")
        self.assertEqual(COLLECTOR.inside_address(record), "192.168.30.30")

    def test_vpn_egress_is_drawn_from_the_firewall(self):
        tunnel = self.NAT_OUT.replace("198.13.91.163:19421", "10.74.109.115:19421").replace("origif: igb1", "origif: wg0")
        record = COLLECTOR.parse_states(tunnel)[0]
        self.assertEqual(COLLECTOR.flow_endpoints(record, {"198.13.91.163", "152.44.11.230"}),
                         ("152.44.11.230", "34.209.15.107"))
        self.assertEqual(record["origif"], "wg0")
        lan_side = "all tcp 192.168.30.30:51858 -> 34.209.15.107:8883       ESTABLISHED:ESTABLISHED\n" \
                   "   age 00:00:05, expires in 23:59:37, 1:1 pkts, 1:1 bytes\n   id: 01 creatorid: 02\n"
        self.assertIsNone(COLLECTOR.flow_endpoints(COLLECTOR.parse_states(lan_side)[0], {"198.13.91.163"}))

    def test_maps_inside_host_to_interface_and_name(self):
        networks = COLLECTOR.interface_networks(self.IFCONFIG)
        self.assertEqual(networks[0][0].prefixlen, 32)
        described = COLLECTOR.describe_inside("192.168.30.30", {"192.168.30.30": "nas"}, networks,
                                              {"vlan03": "VLAN30_IOT"})
        self.assertEqual(described, {"ip": "192.168.30.30", "name": "nas", "interface": "VLAN30_IOT"})

    def test_tracker_reports_inside_hosts_and_egress(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        records = COLLECTOR.parse_states(self.NAT_OUT)
        tracker.update(records, {"198.13.91.163"}, now=0.0)
        flow = tracker.flows[("198.13.91.163", "34.209.15.107")]
        self.assertEqual(flow["inside"], ["192.168.30.30"])
        self.assertEqual(flow["egress"], "igb1")

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
                handle.write("9999999999 cc:cc 192.168.40.5 tv *\n9999999999 dd:dd 192.168.40.6 printer *\n")
            names = COLLECTOR.lease_names(kea, dnsmasq, os.path.join(directory, "none.xml"), now=1000)
            self.assertEqual(names, {"192.168.30.80": "homeassistant", "192.168.40.5": "tv", "192.168.40.6": "printer"})


class InitiatorTest(unittest.TestCase):
    INBOUND = ("all tcp 192.168.1.2:443 (198.13.91.163:443) <- 94.154.43.203:51234       ESTABLISHED:ESTABLISHED\n"
               "   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:9000 bytes\n   id: 0a creatorid: 01\n   origif: ix0\n")

    def test_inbound_port_forward_reports_initiator_and_target(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update([], {"198.13.91.163"}, now=0.0)
        tracker.update(COLLECTOR.parse_states(self.INBOUND), {"198.13.91.163"}, now=2.0)
        flow = tracker.flows[("198.13.91.163", "94.154.43.203")]
        self.assertEqual(flow["initiated"], "remote")
        self.assertEqual(flow["targets"], ["tcp|192.168.1.2|443"])
        # the server's replies dominate: the bytes go away from the firewall although the remote started it
        self.assertGreater(flow["rate_out"], flow["rate_in"])
        target = COLLECTOR.describe_target("tcp|192.168.1.2|443", {"192.168.1.2": "mail"}, [], {}, {"198.13.91.163"})
        self.assertEqual((target["name"], target["service"]), ("mail", "HTTPS"))

    def test_inbound_udp_to_the_firewall_keeps_its_protocol(self):
        states = ("all udp 198.13.91.163:51820 <- 94.154.43.203:51234       MULTIPLE:MULTIPLE\n"
                  "   age 00:00:01, expires in 00:00:59, 5:9 pkts, 400:900 bytes\n   id: 0b creatorid: 01\n")
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update([], {"198.13.91.163"}, now=0.0)
        tracker.update(COLLECTOR.parse_states(states), {"198.13.91.163"}, now=2.0)
        flow = tracker.flows[("198.13.91.163", "94.154.43.203")]
        self.assertEqual(flow["targets"], ["udp|198.13.91.163|51820"])
        target = COLLECTOR.describe_target(flow["targets"][0], {}, [], {}, {"198.13.91.163"})
        self.assertEqual((target["name"], target["service"]), ("firewall", "WireGuard"))

    def test_outbound_flows_are_local(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update(COLLECTOR.parse_states(InsideTest.NAT_OUT), {"198.13.91.163"}, now=0.0)
        self.assertEqual(tracker.flows[("198.13.91.163", "34.209.15.107")]["initiated"], "local")

    def test_reputation_from_cached_lookups(self):
        with tempfile.TemporaryDirectory() as directory:
            store = COLLECTOR.CacheStore(os.path.join(directory, "cache.db"))
            store.put_many(COLLECTOR.REPUTATION_KIND, [("94.154.43.203", {"score": 100}), ("8.8.8.8", {"score": 0})])
            reputation = COLLECTOR.Reputation(store)
            reputation.refresh(now=0.0)
            index = COLLECTOR.BlocklistIndex()
            self.assertEqual(COLLECTOR.threat_lists_for("94.154.43.203", index, reputation), [COLLECTOR.REPUTATION_LIST])
            self.assertEqual(COLLECTOR.threat_lists_for("8.8.8.8", index, reputation), [])


class BlocklistTest(unittest.TestCase):
    def test_longest_prefix_lookup_across_tables(self):
        index = COLLECTOR.BlocklistIndex()
        index.load({
            "spamhaus_drop": ["45.56.0.0/16", "   203.0.113.7", "!10.0.0.0/8", "2001:db8::/32"],
            "crowdsec_blacklists": ["45.56.79.53"],
        })
        self.assertEqual(index.lookup("45.56.79.53"), ["crowdsec_blacklists", "spamhaus_drop"])
        self.assertEqual(index.lookup("203.0.113.7"), ["spamhaus_drop"])
        self.assertEqual(index.lookup("10.1.2.3"), [])
        self.assertEqual(index.lookup("not-an-ip"), [])

    def test_selects_feed_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            config = os.path.join(directory, "config.xml")
            with open(config, "w") as handle:
                handle.write("<opnsense><OPNsense><Firewall><Alias><aliases>"
                             "<alias><name>Drop</name><type>urltable</type><enabled>1</enabled></alias>"
                             "<alias><name>Office</name><type>host</type><enabled>1</enabled></alias>"
                             "<alias><name>Off</name><type>url</type><enabled>0</enabled></alias>"
                             "</aliases></Alias></Firewall></OPNsense></opnsense>")
            tables = ["Drop", "Office", "Off", "crowdsec_blacklists", "bogons"]
            self.assertEqual(COLLECTOR.blocklist_tables(config, tables, blocked={"Drop", "Off"}),
                             {"Drop", "crowdsec_blacklists"})
            # a leftover FWMAP_ table whose alias was deleted is ignored
            self.assertEqual(COLLECTOR.blocklist_tables(config, tables + ["FWMAP_Old"], blocked=set()),
                             {"crowdsec_blacklists"})
            # a URL alias used only by pass rules (an allowlist) is not a threat list
            self.assertEqual(COLLECTOR.blocklist_tables(config, tables, blocked=set()), {"crowdsec_blacklists"})

    def test_threat_list_candidates_offer_feeds_not_lan_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            config = os.path.join(directory, "config.xml")
            with open(config, "w") as handle:
                handle.write("<opnsense><OPNsense><Firewall><Alias><aliases>"
                             "<alias><name>Drop</name><type>urltable</type><enabled>1</enabled></alias>"
                             "<alias><name>RFC1918</name><type>network</type><enabled>1</enabled></alias>"
                             "<alias><name>FWMAP_Feodo</name><type>urltable</type><enabled>1</enabled></alias>"
                             "</aliases></Alias></Firewall></OPNsense></opnsense>")
            candidates = COLLECTOR.threat_list_candidates(config, ["Drop", "RFC1918", "FWMAP_Feodo", "crowdsec_blacklists"])
            names = [item["name"] for item in candidates]
            self.assertNotIn("RFC1918", names)
            self.assertIn("Drop", names)
            self.assertIn("crowdsec_blacklists", names)
            feeds = {item["name"]: item for item in candidates if item.get("curated")}
            self.assertEqual(len(feeds), len(COLLECTOR.FEEDS))
            self.assertTrue(feeds["FWMAP_Feodo"]["installed"])
            self.assertFalse(feeds["FWMAP_Spamhaus_DROP"]["installed"])

    def test_reads_block_rule_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            rules = os.path.join(directory, "rules.debug")
            with open(rules, "w") as handle:
                handle.write('block in log quick from {<Drop>} to {any} label "abc" # <NotThis>\n'
                             'pass in quick from {<Allow>} to {any} label "def"\n')
            self.assertEqual(COLLECTOR.blocked_rule_tables(rules), {"Drop"})


class BlockTest(unittest.TestCase):
    LINE = ('<134>1 2026-09-25T21:27:07-04:00 fw filterlog 31386 - [meta sequenceId="1"] '
            '15,,,ecd3a310894625657c6591b80daa956a,igb1,match,block,in,4,0x0,,244,54321,0,none,6,tcp,40,'
            '45.56.79.53,198.13.91.163,51234,23,0,S,1,,1024,,')

    def test_parses_inbound_block(self):
        event = COLLECTOR.parse_block(self.LINE)
        self.assertEqual(event["source"], "45.56.79.53")
        self.assertEqual(event["destination"], "198.13.91.163")
        self.assertEqual((event["protocol"], event["port"], event["interface"]), ("tcp", "23", "igb1"))
        self.assertIsNone(COLLECTOR.parse_block(self.LINE.replace(",block,in,", ",pass,in,")))
        self.assertIsNone(COLLECTOR.parse_block(self.LINE.replace(",block,in,", ",block,out,")))

    def test_tracks_hits_fades_and_flags_threats(self):
        blocks = COLLECTOR.BlockTracker(fade=6, show=60, window=600)
        event = COLLECTOR.parse_block(self.LINE)
        for second in range(COLLECTOR.THREAT_HITS_PER_MINUTE):
            blocks.add(event, now=float(second))
        now = float(COLLECTOR.THREAT_HITS_PER_MINUTE - 1)
        (address, entry), = blocks.visible(now)
        self.assertEqual(blocks.per_minute(entry, now), COLLECTOR.THREAT_HITS_PER_MINUTE)
        self.assertEqual(blocks.activity(entry, now), 1.0)
        self.assertAlmostEqual(blocks.activity(entry, now + 3), 0.5)
        # quiet for over a minute: no longer drawn, but its hits still count toward the window
        self.assertEqual(blocks.visible(now + 61), [])
        blocks.add(event, now=now + 300)
        (address, entry), = blocks.visible(now + 300)
        self.assertEqual(blocks.hits(entry), COLLECTOR.THREAT_HITS_PER_MINUTE + 1)
        self.assertEqual(blocks.per_minute(entry, now + 300), 1)
        # and they age out of the 10-minute window
        self.assertEqual(blocks.visible(now + 1000), [])
        self.assertEqual(blocks.sources, {})

    def test_eviction_keeps_recently_hit_sources(self):
        blocks = COLLECTOR.BlockTracker(max_sources=2)
        event = COLLECTOR.parse_block(self.LINE)
        blocks.add({**event, "source": "45.56.79.1"}, now=1.0)
        blocks.add({**event, "source": "45.56.79.2"}, now=2.0)
        blocks.add({**event, "source": "45.56.79.1"}, now=3.0)
        blocks.add({**event, "source": "45.56.79.3"}, now=4.0)
        self.assertEqual(sorted(blocks.sources), ["45.56.79.1", "45.56.79.3"])

    def test_bounded_under_a_flood(self):
        blocks = COLLECTOR.BlockTracker(max_sources=3)
        event = COLLECTOR.parse_block(self.LINE)
        for index in range(10):
            blocks.add({**event, "source": f"45.56.79.{index}", "port": str(index)}, now=float(index))
        self.assertEqual(sorted(blocks.sources), ["45.56.79.7", "45.56.79.8", "45.56.79.9"])
        for port in range(100):
            blocks.add({**event, "port": str(port)}, now=20.0)
        self.assertEqual(len(blocks.sources["45.56.79.53"]["ports"]), COLLECTOR.MAX_PORTS_PER_SOURCE)

    def test_log_tail_returns_complete_lines_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "latest.log")
            with open(path, "w") as handle:
                handle.write("old line\n")
            tail = COLLECTOR.FilterLogTail(path)
            self.assertEqual(tail.lines(), [])
            with open(path, "a") as handle:
                handle.write("first\nsec")
            self.assertEqual(tail.lines(), ["first"])
            with open(path, "a") as handle:
                handle.write("ond\n")
            self.assertEqual(tail.lines(), ["second"])

    def test_old_log_lines_do_not_count_as_current(self):
        wall = COLLECTOR.log_time(self.LINE)
        self.assertEqual(COLLECTOR.block_event_time(self.LINE, 100.0, wall + 30), 70.0)
        self.assertIsNone(COLLECTOR.block_event_time(self.LINE, 100.0, wall + 3600))

    def test_reads_log_timestamps(self):
        self.assertEqual(COLLECTOR.log_time(self.LINE),
                         COLLECTOR.datetime.fromisoformat("2026-09-25T21:27:07-04:00").timestamp())
        self.assertIsNone(COLLECTOR.log_time("garbage"))

    def test_reader_applies_viewer_threshold(self):
        payload = {"blocks": [{"hits": 1}, {"hits": 3}, {"hits": 7}]}
        result = SNAPSHOT.apply_block_threshold(payload, 3)
        self.assertEqual([block["hits"] for block in result["blocks"]], [3, 7])
        self.assertEqual(result["blocks_below"], 1)


class RobustnessTest(unittest.TestCase):
    def test_parses_translation_after_both_endpoints(self):
        line = ("all tcp 192.168.1.2:443 (198.13.91.163:443) <- 45.56.79.53:35799 (10.0.0.9:35799)"
                "       ESTABLISHED:ESTABLISHED\n   age 00:00:05, expires in 23:59:37, 1:1 pkts, 1:1 bytes\n"
                "   id: 01 creatorid: 02\n")
        record = COLLECTOR.parse_states(line)[0]
        self.assertEqual(record["src"]["address"], "45.56.79.53")
        self.assertEqual(record["nat"]["address"], "198.13.91.163")
        self.assertEqual(record["state"], "ESTABLISHED:ESTABLISHED")

    def test_cgnat_counts_as_inside(self):
        self.assertTrue(COLLECTOR.private_ipv4("100.101.102.103"))
        self.assertFalse(COLLECTOR.public_ipv4("100.101.102.103"))

    def test_transient_geo_failures_are_not_cached(self):
        calls = []

        def flaky(address):
            calls.append(address)
            if len(calls) == 1:
                raise LookupError("timeout")
            return {"lat": 1.0, "lon": 2.0}
        with tempfile.TemporaryDirectory() as directory:
            geo = COLLECTOR.GeoCache(path=os.path.join(directory, "cache.db"), lookup=flaky)
            geo.resolve(["8.8.8.8"])
            self.assertNotIn("8.8.8.8", geo.entries)
            geo.resolve(["8.8.8.8"])
            self.assertEqual(geo.get("8.8.8.8"), {"lat": 1.0, "lon": 2.0})

    def test_single_collector_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "collector.lock")
            first = COLLECTOR.acquire_lock(path)
            self.assertIsNotNone(first)
            self.assertIsNone(COLLECTOR.acquire_lock(path))
            first.close()


class CacheStoreTest(unittest.TestCase):
    def test_persists_expires_and_prunes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            store = COLLECTOR.CacheStore(path)
            store.put_many("hostname", [("8.8.8.8", ["dns.google", 1.0]), ("1.1.1.1", ["one.one.one.one", 1.0])], now=100.0)
            store.put_many("hostname", [("9.9.9.9", ["dns9.quad9.net", 1.0])], now=200.0)
            reopened = COLLECTOR.CacheStore(path)
            self.assertEqual(sorted(reopened.get_all("hostname")), ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
            self.assertEqual(sorted(reopened.get_all("hostname", max_age=50, now=220.0)), ["9.9.9.9"])
            self.assertIsNone(reopened.get("hostname", "8.8.8.8", max_age=50, now=220.0))
            reopened.prune("hostname", keep=1)
            self.assertEqual(list(reopened.get_all("hostname")), ["9.9.9.9"])

    def test_geo_cache_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            store = COLLECTOR.CacheStore(path)
            geo = COLLECTOR.GeoCache(store=store, lookup=lambda address: {"lat": 1.0, "lon": 2.0})
            geo.resolve(["8.8.8.8"])
            geo.save(force=True)
            again = COLLECTOR.GeoCache(store=COLLECTOR.CacheStore(path), lookup=lambda address: None)
            self.assertEqual(again.get("8.8.8.8"), {"lat": 1.0, "lon": 2.0})


class CacheResilienceTest(unittest.TestCase):
    def test_corrupt_cache_file_is_moved_aside(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            with open(path, "wb") as handle:
                handle.write(b"this is not a database" * 100)
            store = COLLECTOR.CacheStore(path)
            store.put_many("hostname", [("8.8.8.8", ["dns.google", 1.0])])
            self.assertEqual(list(store.get_all("hostname")), ["8.8.8.8"])
            self.assertTrue(os.path.exists(path + ".corrupt"))

    def test_skipped_state_details_do_not_leak(self):
        output = ("all tcp 198.13.91.163:1 (192.168.30.30:2) -> 34.209.15.107:8883       ESTABLISHED:ESTABLISHED\n"
                  "   age 00:00:05, expires in 23:59:37, 1:1 pkts, 1:1 bytes\n   id: 01 creatorid: 02\n"
                  "all tcp 192.168.30.30:5 -> 192.168.40.2:6       ESTABLISHED:ESTABLISHED\n"
                  "   age 00:00:05, expires in 23:59:37, 1:1 pkts, 1:1 bytes\n   id: 03 creatorid: 04\n   origif: vlan03\n")
        records = COLLECTOR.parse_states(output)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0]["origif"])


class InvestigateTest(unittest.TestCase):
    RDAP = {
        "name": "GOGL", "handle": "NET-8-8-8-0-2", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
        "events": [{"eventAction": "registration", "eventDate": "2023-12-28T17:24:33-05:00"}],
        "entities": [{
            "roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
            "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]]}],
        }],
    }

    def test_parses_rdap_owner_and_abuse_contact(self):
        parsed = INVESTIGATE.parse_rdap(self.RDAP)
        self.assertEqual(parsed["owner"], "Google LLC")
        self.assertEqual(parsed["abuse_email"], "network-abuse@google.com")
        self.assertEqual(parsed["range"], "8.8.8.0 – 8.8.8.255")
        self.assertEqual(parsed["registered"], "2023-12-28")

    def test_rejects_private_and_invalid_addresses(self):
        self.assertEqual(INVESTIGATE.investigate("192.168.1.1", store=object(), fetchers={})["status"], "failed")
        self.assertEqual(INVESTIGATE.investigate("8.8.8.8; rm -rf /", store=object(), fetchers={})["status"], "failed")

    def test_caches_and_reports_errors_per_source(self):
        with tempfile.TemporaryDirectory() as directory:
            store = COLLECTOR.CacheStore(os.path.join(directory, "cache.db"))
            calls = []

            def rdap():
                calls.append("rdap")
                return {"name": "GOGL"}

            def broken():
                raise RuntimeError("boom secret-key")
            result = INVESTIGATE.investigate("8.8.8.8", store=store, key="secret-key",
                                             fetchers={"rdap": rdap, "abuseipdb": broken}, now=1000.0)
            self.assertEqual(result["rdap"], {"name": "GOGL"})
            self.assertEqual(result["abuseipdb"], {"error": "boom <key>"})
            good = INVESTIGATE.investigate("8.8.8.8", store=store, fetchers={"abuseipdb": lambda: {"score": 90}}, now=1000.5)
            self.assertEqual(good["abuseipdb"], {"score": 90})
            # the verdict outlives the 6-hour lookup cache
            self.assertEqual(store.get_all(COLLECTOR.REPUTATION_KIND, now=1000.0 + 7 * 86400), {"8.8.8.8": {"score": 90}})
            again = INVESTIGATE.investigate("8.8.8.8", store=store, fetchers={"rdap": rdap}, now=1001.0)
            self.assertTrue(again["rdap"]["cached"])
            self.assertEqual(calls, ["rdap"])


class AbuseBlacklistTest(unittest.TestCase):
    def test_downloads_parses_and_rate_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            ABUSEIPDB.LIST_FILE = os.path.join(directory, "list.txt")
            ABUSEIPDB.STATUS_FILE = os.path.join(directory, "status.json")
            calls = []

            def fetch(key):
                calls.append(key)
                return "94.154.43.203\n10.0.0.1\nnot-an-ip\n204.76.203.231\n"
            self.assertEqual(ABUSEIPDB.update(key="", fetch=fetch)["reason"], "no key")
            self.assertEqual(ABUSEIPDB.update(key="k", fetch=fetch, now=1000.0), {"result": "ok", "count": 2})
            with open(ABUSEIPDB.LIST_FILE) as handle:
                self.assertEqual(handle.read().split(), ["94.154.43.203", "204.76.203.231"])
            self.assertEqual(ABUSEIPDB.update(key="k", fetch=fetch, now=2000.0)["reason"], "recent")
            self.assertEqual(ABUSEIPDB.update(force=True, key="k", fetch=fetch, now=2000.0)["result"], "ok")
            self.assertEqual(len(calls), 2)

    def test_errors_never_contain_the_key(self):
        with tempfile.TemporaryDirectory() as directory:
            ABUSEIPDB.LIST_FILE = os.path.join(directory, "list.txt")
            ABUSEIPDB.STATUS_FILE = os.path.join(directory, "status.json")

            def broken(key):
                raise RuntimeError(f"failed with {key}")
            result = ABUSEIPDB.update(force=True, key="secret", fetch=broken)
            self.assertEqual(result["error"], "failed with <key>")
            with open(ABUSEIPDB.STATUS_FILE) as handle:
                self.assertNotIn("secret", handle.read())


class GeoDatabaseTest(unittest.TestCase):
    def test_reads_key_from_maxmind_alias_url_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "filter_geoip.conf")
            with open(path, "w") as handle:
                handle.write("[settings]\nurl=https://download.maxmind.com/app/geoip_download"
                             "?edition_id=GeoLite2-Country-CSV&license_key=abc_123&suffix=zip\n")
            self.assertEqual(GEODB.alias_license_key(path), "abc_123")
            with open(path, "w") as handle:
                handle.write("[settings]\nurl=https://ipinfo.io/data/free/country.csv.gz?token=xyz\n")
            self.assertIsNone(GEODB.alias_license_key(path))
            self.assertIsNone(GEODB.alias_license_key(os.path.join(directory, "missing.conf")))

    def test_reads_plugin_settings_from_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.xml")
            with open(path, "w") as handle:
                handle.write("<opnsense><OPNsense><FirewallMap><general><provider>dbip</provider>"
                             "<license_key/><update_days>7</update_days></general></FirewallMap></OPNsense></opnsense>")
            self.assertEqual(GEODB.settings(path), {"provider": "dbip", "license_key": "", "update_days": 7, "threat_lists": "", "record_threats": "1"})
            self.assertEqual(GEODB.settings(os.path.join(directory, "none.xml"))["provider"], "auto")

    def test_automatic_provider_prefers_maxmind_with_a_key(self):
        original = GEODB.alias_license_key
        try:
            GEODB.alias_license_key = lambda path=None: None
            self.assertEqual(GEODB.effective_provider({"provider": "auto", "license_key": ""}), "dbip")
            self.assertEqual(GEODB.effective_provider({"provider": "auto", "license_key": "k"}), "maxmind")
            GEODB.alias_license_key = lambda path=None: "alias"
            self.assertEqual(GEODB.effective_provider({"provider": "auto", "license_key": ""}), "maxmind")
            self.assertEqual(GEODB.effective_provider({"provider": "dbip", "license_key": "k"}), "dbip")
        finally:
            GEODB.alias_license_key = original


class SnapshotReaderTest(unittest.TestCase):
    def test_reads_fresh_and_rejects_stale_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "flows.json")
            with open(path, "w") as handle:
                json.dump({"status": "ok", "flows": []}, handle)
            self.assertEqual(SNAPSHOT.read_snapshot(path)["status"], "ok")
            self.assertIsNone(SNAPSHOT.read_snapshot(path, now=time.time() + 60))


class ThreatQueueTest(unittest.TestCase):
    INBOUND = ("all tcp 192.168.1.2:80 (198.13.91.163:80) <- 108.188.77.155:51234       ESTABLISHED:ESTABLISHED\n"
               "   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:9000 bytes\n   id: 0a creatorid: 01\n")
    OUTBOUND = ("all tcp 192.168.1.50:50000 (198.13.91.163:50000) -> 8.8.8.8:443       ESTABLISHED:ESTABLISHED\n"
                "   age 00:00:01, expires in 23:59:37, 5:9 pkts, 400:900 bytes\n   id: 0b creatorid: 01\n")

    def observe(self, states):
        lists = {"108.188.77.155": ["AbuseIPDB blacklist"]}
        return THREATS.observe(COLLECTOR.parse_states(states), COLLECTOR.flow_endpoints, lambda address: lists.get(address, []),
                               {"198.13.91.163"}, COLLECTOR.inside_endpoint, COLLECTOR.service_name,
                               COLLECTOR.orientation)

    def test_records_only_flagged_addresses_with_target(self):
        seen = self.observe(self.INBOUND + self.OUTBOUND)
        self.assertEqual(list(seen), ["108.188.77.155"])
        self.assertEqual(seen["108.188.77.155"]["targets"], ["tcp|192.168.1.2|80"])
        self.assertEqual(seen["108.188.77.155"]["inbound"], 1)

    def test_reply_state_from_a_server_counts_as_inbound(self):
        # the SYN passed the other CARP node; the mail server's reply created an outbound NAT state
        reply = ("all tcp 198.13.91.163:13526 (192.168.1.2:443) -> 108.188.77.155:48824       TIME_WAIT:TIME_WAIT\n"
                 "   age 00:01:01, expires in 00:00:29, 2:1 pkts, 100:40 bytes\n   id: c6 creatorid: a9\n")
        entry = self.observe(reply)["108.188.77.155"]
        self.assertEqual((entry["inbound"], entry["outbound"], entry["targets"], entry["services"]),
                         (1, 0, ["tcp|192.168.1.2|443"], ["HTTPS"]))
        self.assertEqual(COLLECTOR.orientation(COLLECTOR.parse_states(InsideTest.NAT_OUT)[0], "34.209.15.107")[0], False)

    def test_review_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            db = THREATS.connect(os.path.join(directory, "cache.db"))
            THREATS.record(db, self.observe(self.INBOUND), now=100.0)
            THREATS.record(db, self.observe(self.INBOUND), now=200.0)
            rows = THREATS.listing(db)["rows"]
            self.assertEqual((rows[0]["first_seen"], rows[0]["last_seen"], rows[0]["samples"], rows[0]["status"]),
                             (100.0, 200.0, 2, "new"))
            self.assertTrue(rows[0]["inbound"])
            note = "Port forward probe; checked logs ✓"
            encoded = __import__("base64").urlsafe_b64encode(note.encode()).decode().rstrip("=")
            self.assertEqual(THREATS.main(["set", "108.188.77.155", "blocked", encoded], path=os.path.join(directory, "cache.db")),
                             {"result": "saved"})
            self.assertEqual(THREATS.listing(db, "blocked")["rows"][0]["note"], note)
            # a status change alone keeps the note
            THREATS.set_status(db, "108.188.77.155", "blocked")
            self.assertEqual(THREATS.listing(db)["rows"][0]["note"], note)
            # traffic after "blocked" means the block did not hold: back to new, flagged
            THREATS.record(db, self.observe(self.INBOUND), now=300.0)
            row = THREATS.listing(db)["rows"][0]
            self.assertEqual((row["status"], row["seen_after_block"]), ("new", True))
            self.assertEqual(THREATS.listing(db)["counts"], {"new": 1, "reviewed": 0, "dismissed": 0, "blocked": 0})

    def test_multicast_is_not_a_remote_endpoint(self):
        self.assertFalse(COLLECTOR.public_ipv4("224.0.0.18"))
        self.assertTrue(COLLECTOR.public_ipv4("9.9.9.9"))

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
                handle.write("<opnsense><system><user><dashboard>e30=</dashboard></user></system></opnsense>")
            self.assertFalse(COLLECTOR.widget_in_use(path))


if __name__ == "__main__":
    unittest.main()
