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
SNAPSHOT = load("flow_snapshot")

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
            # a URL alias used only by pass rules (an allowlist) is not a threat list
            self.assertEqual(COLLECTOR.blocklist_tables(config, tables, blocked=set()), {"crowdsec_blacklists"})

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
            geo = COLLECTOR.GeoCache(path=os.path.join(directory, "geo.json"), lookup=flaky)
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
            self.assertEqual(GEODB.settings(path), {"provider": "dbip", "license_key": "", "update_days": 7})
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


if __name__ == "__main__":
    unittest.main()
