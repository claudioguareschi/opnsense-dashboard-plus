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
        blocks = COLLECTOR.BlockTracker(fade=6, keep=60, window=60)
        event = COLLECTOR.parse_block(self.LINE)
        for second in range(COLLECTOR.THREAT_HITS_PER_MINUTE):
            blocks.add(event, now=float(second))
        now = float(COLLECTOR.THREAT_HITS_PER_MINUTE - 1)
        (address, entry), = blocks.visible(now)
        self.assertEqual(len(entry["hits"]), COLLECTOR.THREAT_HITS_PER_MINUTE)
        self.assertEqual(blocks.activity(entry, now), 1.0)
        self.assertAlmostEqual(blocks.activity(entry, now + 3), 0.5)
        self.assertEqual(blocks.visible(now + 61), [])


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
            self.assertEqual(GEODB.settings(os.path.join(directory, "none.xml"))["provider"], "maxmind")


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
