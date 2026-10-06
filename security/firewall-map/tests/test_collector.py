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

"""Unit tests for the collector loop and flow tracker."""

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import COLLECTOR, COMMON, PF, SUMMARY, THREATS, Geo, nat_state  # noqa: E402


class TrackerTest(unittest.TestCase):
    LOCAL = {"1.2.3.163"}
    PAIR = ("1.2.3.163", "45.56.79.53")

    def test_rate_comes_from_counter_deltas_not_totals(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update(PF.parse_states(nat_state(1000, 1000)), self.LOCAL, now=100.0)
        self.assertIsNone(tracker.flows[self.PAIR]["last_active"])
        self.assertEqual(tracker.visible(100.0), [])
        tracker.update(PF.parse_states(nat_state(1500, 2500)), self.LOCAL, now=102.0)
        self.assertEqual(tracker.flows[self.PAIR]["rate"], 1000.0)
        self.assertEqual(len(tracker.visible(102.0)), 1)

    def test_splits_rate_toward_and_away_from_firewall(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        # remote 45.56.79.53 initiated this state: first counter is remote -> firewall
        tracker.update(PF.parse_states(nat_state(1000, 1000)), self.LOCAL, now=0.0)
        tracker.update(PF.parse_states(nat_state(1600, 1100)), self.LOCAL, now=1.0)
        flow = tracker.flows[self.PAIR]
        self.assertEqual((flow["rate_in"], flow["rate_out"]), (600.0, 100.0))

    def test_names_the_responder_service(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        tracker.update(PF.parse_states(nat_state(1000, 1000)), self.LOCAL, now=0.0)
        self.assertEqual(tracker.flows[self.PAIR]["services"], ["HTTPS"])
        self.assertEqual(COMMON.service_name("udp", "51820"), "WireGuard")
        self.assertEqual(COMMON.service_name("tcp", "9999"), "TCP/9999")

    def test_idle_flow_fades_then_state_removal_drops_it(self):
        tracker = COLLECTOR.FlowTracker(fade_seconds=10, smoothing=1.0)
        tracker.update(PF.parse_states(nat_state(1000, 1000)), self.LOCAL, now=0.0)
        tracker.update(PF.parse_states(nat_state(2000, 1000)), self.LOCAL, now=1.0)
        tracker.update(PF.parse_states(nat_state(2000, 1000)), self.LOCAL, now=6.0)
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
        tracker.update(PF.parse_states(fresh), self.LOCAL, now=1.0)
        self.assertEqual(tracker.flows[self.PAIR]["rate"], 1000.0)

    def test_visible_flows_are_capped(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        for index in range(5):
            tracker.flows[("1.2.3.163", f"8.8.8.{index}")] = {
                "rate": float(index), "rate_in": 0.0, "rate_out": 0.0, "packet_rate": 0.0,
                "last_active": 0.0, "first_seen": 0.0,
            }
        visible = tracker.visible(0.0, limit=2)
        self.assertEqual([item[2] for item in visible], ["8.8.8.4", "8.8.8.3"])

    def test_private_origin_is_kept_without_a_map_anchor(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        pair = ("192.168.0.2", "45.56.79.53")
        tracker.flows[pair] = {
            "rate": 1.0, "rate_in": 0.0, "rate_out": 1.0, "packet_rate": 1.0, "last_active": 0.0,
            "first_seen": 0.0, "states": 1, "protocols": ["tcp"], "services": ["HTTPS"],
            "service_ports": {"HTTPS": "443/tcp"}, "inside": ["192.168.30.60"], "egress": "igb1",
            "initiated": "local", "targets": [], "age": 1, "transferred": (1, 1), "rule": None,
        }

        class RemoteOnlyGeo(Geo):
            def get(self, address):
                return None if address == pair[0] else super().get(address)

        payload = COLLECTOR.summarize_flows(tracker, RemoteOnlyGeo(), set(), None, 0.0, 0.0, context={})
        self.assertEqual([flow["origin"] for flow in payload["flows"]], [pair[0]])
        self.assertEqual([location["id"] for location in payload["locations"]], [pair[1]])
        anchored = COLLECTOR.summarize_flows(tracker, RemoteOnlyGeo(), set(), None, 0.0, 0.0, context={},
                                             anchor={"lat": 40.7, "lon": -74.0, "name": "Firewall"})
        origin = next(location for location in anchored["locations"] if location["id"] == pair[0])
        self.assertEqual((origin["lat"], origin["lon"], origin["local"]), (40.7, -74.0, True))

    def test_hostname_lookup_includes_unnamed_inside_hosts_under_the_existing_opt_in(self):
        tracker = COLLECTOR.FlowTracker(smoothing=1.0)
        pair = ("1.2.3.163", "45.56.79.53")
        tracker.flows[pair] = {
            "rate": 1.0, "rate_in": 0.0, "rate_out": 1.0, "packet_rate": 1.0, "last_active": 0.0,
            "first_seen": 0.0, "states": 1, "protocols": ["tcp"], "services": ["HTTPS"],
            "service_ports": {"HTTPS": "443/tcp"}, "inside": ["192.168.1.2"], "egress": "igb1",
            "initiated": "local", "targets": ["tcp|192.168.1.3|443"], "age": 1,
            "transferred": (1, 1), "rule": None,
        }

        class Resolver:
            def __init__(self):
                self.calls = []
                self.names = {}

            def update(self, addresses, now):
                self.calls.append(list(addresses))

            def get(self, address):
                return self.names.get(address)

        resolver = Resolver()
        COLLECTOR.summarize_flows(tracker, Geo(), set(), None, 0.0, 0.0, resolver, {"names": {}})
        self.assertEqual(resolver.calls[0][:2], [
            ("192.168.1.2", 600, 120), ("192.168.1.3", 600, 120),
        ])
        self.assertEqual(resolver.calls[0][2:], [pair[1]])
        resolver.names = {"192.168.1.2": "pi-hole", "192.168.1.3": "server"}
        payload = COLLECTOR.summarize_flows(
            tracker, Geo(), set(), None, 1.0, 1.0, resolver, {"names": dict(resolver.names)}
        )
        self.assertEqual(payload["flows"][0]["inside"][0]["name"], "pi-hole")
        self.assertEqual(payload["flows"][0]["targets"][0]["name"], "server")

    def test_external_ip_discovery_validates_a_public_ipv4(self):
        self.assertEqual(COLLECTOR.discover_external_ipv4(lambda: b"73.1.2.3\n"), "73.1.2.3")
        self.assertIsNone(COLLECTOR.discover_external_ipv4(lambda: b"192.168.0.2"))
        self.assertIsNone(COLLECTOR.discover_external_ipv4(lambda: b"not an address"))

    def test_anchor_ignores_private_aliases_on_a_public_primary_wan(self):
        collector = object.__new__(COLLECTOR.Collector)
        collector.location_settings = {"latitude": None, "longitude": None, "discover_external_ip": True}
        collector.primary_wan_device = "igb1"
        collector.interface_addresses = {"igb1": {"1.2.3.163", "192.168.0.2"}}
        collector.external_ip = collector.external_ip_key = collector.external_ip_checked = None
        collector.store, collector.geo = mock.Mock(), Geo()
        with mock.patch.object(COLLECTOR, "discover_external_ipv4") as discover:
            self.assertIsNone(collector.map_anchor(0.0))
        discover.assert_not_called()

    def test_anchor_uses_the_primary_wan_device_not_one_of_its_carp_addresses(self):
        collector = object.__new__(COLLECTOR.Collector)
        collector.location_settings = {"latitude": None, "longitude": None, "discover_external_ip": True}
        collector.primary_wan_device = "igb1"
        collector.interface_addresses = {"igb1": {"192.168.0.2", "192.168.0.254"}}
        collector.external_ip = collector.external_ip_key = collector.external_ip_checked = None
        collector.store, collector.geo = mock.Mock(), Geo()
        collector.store.get.return_value = None
        with mock.patch.object(COLLECTOR, "discover_external_ipv4", return_value="73.1.2.3") as discover:
            self.assertEqual(collector.map_anchor(0.0), {"lat": 1.0, "lon": 2.0, "name": "Firewall"})
            self.assertEqual(collector.external_ip_key, "igb1")
            collector.interface_addresses["igb1"] = {"192.168.0.254", "192.168.0.2"}
            collector.map_anchor(1.0)
        discover.assert_called_once_with()


class IdleTest(unittest.TestCase):
    def test_stops_only_after_grace_period_without_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = os.path.join(directory, "last_request")
            self.assertFalse(COLLECTOR.idle(started=1000, now=1100, marker=marker, idle_seconds=300))
            self.assertTrue(COLLECTOR.idle(started=1000, now=1400, marker=marker, idle_seconds=300))
            SUMMARY.mark_request(marker)
            now = os.stat(marker).st_mtime
            self.assertFalse(COLLECTOR.idle(started=now - 1000, now=now + 10, marker=marker, idle_seconds=300))
            self.assertTrue(COLLECTOR.idle(started=now - 1000, now=now + 301, marker=marker, idle_seconds=300))


class StubGeo(Geo):
    """What the collector needs from a GeoCache, without geolocation databases."""

    def __init__(self, store=None, database=None, asn_database=None):
        super().__init__()
        self.database = database
        self.database_mtime = None
        self.saved = 0

    def _database_mtime(self):
        return None

    def forget_old_databases(self):
        pass

    def save(self, force=False):
        self.saved += 1


class CollectorLoopTest(unittest.TestCase):
    """One iteration of the collector at a time, with the firewall replaced by stand-ins."""

    REMOTE = "45.56.79.53"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = directory.name
        self.output = os.path.join(self.directory, "flows.json")
        self.idle = False
        self.bytes = 1000
        self.metadata_reads = 0

        def lease_names():
            self.metadata_reads += 1
            return {"192.168.1.2": "mail"}
        patches = {
            "OUTPUT_FILE": self.output,
            "COLLECTOR_TIMINGS": os.path.join(self.directory, "collector_timings.json"),
            "sample_states": lambda: PF.parse_states(nat_state(self.bytes, self.bytes)),
            "host_info": lambda: ({"1.2.3.163"}, None, [], {"igb1": {"1.2.3.163"}}),
            "recording_wanted": lambda values=None: True,
            "database_state": lambda values: ("city.mmdb", "asn.mmdb", None),
            "rule_descriptions": dict, "interface_names": dict, "lease_names": lease_names, "port_forwards": list,
            "chosen_threat_lists": lambda setting: set(),
            "idle": lambda started: self.idle,
            "requested": lambda marker, seconds: False,
            "reload_token": lambda: None,
            "GeoCache": StubGeo,
        }
        for name, value in patches.items():
            patcher = mock.patch.object(COLLECTOR, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        settings = mock.patch.object(COLLECTOR.geodb, "settings", lambda: {"provider": "dbip", "threat_lists": ""})
        settings.start()
        self.addCleanup(settings.stop)
        self.collector = COLLECTOR.Collector(store=COLLECTOR.CacheStore(os.path.join(self.directory, "cache.db")))
        self.collector.log = COLLECTOR.FilterLogTail(os.path.join(self.directory, "filter.log"))
        self.collector.eve = COLLECTOR.FilterLogTail(os.path.join(self.directory, "eve.json"))
        self.addCleanup(self.collector.log.close)
        self.addCleanup(self.collector.eve.close)
        self.queue = os.path.join(self.directory, "queue.db")
        self.collector.recorder = COLLECTOR.ThreatRecorder(self.queue)
        self.collector.blocklists.index = COLLECTOR.BlocklistIndex.build({"Test list": [self.REMOTE]})
        # the list above stands in for pf tables: no refresh from pf during the test
        self.collector.checked["blocklists"] = time.monotonic()

    def queued(self):
        return [row["address"] for row in THREATS.listing(THREATS.connect(self.queue))["rows"]]

    def test_foreground_writes_the_map_and_feeds_the_queue(self):
        self.assertIsNotNone(self.collector.step())
        self.bytes = 5000
        self.collector.recorder.recorded = None  # record again without waiting
        self.assertIsNotNone(self.collector.step())
        with open(self.output) as handle:
            payload = json.load(handle)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual([flow["dest"] for flow in payload["flows"]], [self.REMOTE])
        self.assertEqual(payload["flows"][0]["lists"], ["Test list"])
        self.assertEqual(self.queued(), [self.REMOTE])

    def test_camera_request_saves_every_flow_and_its_states(self):
        snapshots = os.path.join(self.directory, "snapshots")
        requests = os.path.join(self.directory, "requests")
        os.makedirs(requests)
        for name, value in (("SNAPSHOT_DIR", snapshots), ("SNAPSHOT_REQUEST_DIR", requests)):
            patcher = mock.patch.object(COLLECTOR, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.collector.step()
        self.bytes = 5000
        snapshot_id = "20261003T164210Z-1a2b"
        with open(os.path.join(requests, f"{snapshot_id}.request"), "w") as handle:
            handle.write("{}")
        self.collector.step()
        with open(os.path.join(snapshots, f"{snapshot_id}.json")) as handle:
            saved = json.load(handle)
        self.assertEqual([flow["dest"] for flow in saved["flows"]], [self.REMOTE])
        self.assertTrue(saved["full"])
        state = saved["states"][self.REMOTE][0]
        self.assertEqual((state["proto"], state["src_addr"], state["state"]), ("tcp", self.REMOTE, "ESTABLISHED:ESTABLISHED"))
        self.assertEqual(state["nat"], "192.168.1.2:443")
        self.assertFalse(os.listdir(requests))

    def test_background_feeds_the_queue_without_a_map(self):
        self.idle = True
        rest = self.collector.step()
        self.assertEqual(self.queued(), [self.REMOTE])
        self.assertFalse(os.path.exists(self.output))
        self.assertGreater(rest, 1.0)
        # names are read in the background too, so queue entries never carry stale ones
        self.assertEqual(self.metadata_reads, 1)
        # locations resolved for the queue are saved in the background as well
        self.assertGreater(self.collector.geo.saved, 0)

    def test_background_stops_when_recording_is_off(self):
        self.idle = True
        with mock.patch.object(COLLECTOR, "recording_wanted", lambda values=None: False):
            self.collector = COLLECTOR.Collector(store=self.collector.store)
            self.assertIsNone(self.collector.step())

    def test_a_failing_iteration_is_logged_and_retried(self):
        steps = iter([RuntimeError("boom"), 0.01, None])

        def step(collector):
            result = next(steps)
            if isinstance(result, Exception):
                raise result
            return result
        store = COLLECTOR.CacheStore(os.path.join(self.directory, "run.db"))
        with mock.patch.object(COLLECTOR, "acquire_lock", lambda: object()), \
                mock.patch.object(COLLECTOR, "CacheStore", lambda: store), \
                mock.patch.object(COLLECTOR.Collector, "step", step), \
                mock.patch.object(COLLECTOR.time, "sleep") as sleep, \
                mock.patch.object(COLLECTOR.signal, "signal"), \
                mock.patch.object(COLLECTOR, "log_error") as log_error, \
                mock.patch.object(COLLECTOR, "log_notice") as log_notice:
            COLLECTOR.run()
        # the failure once, with its traceback on one line, then the recovery
        self.assertEqual(log_error.call_count, 1)
        self.assertIn("boom", log_error.call_args.args[0])
        self.assertNotIn("\n", log_error.call_args.args[0])
        self.assertIn("works again", " ".join(call.args[0] for call in log_notice.call_args_list))
        # backed off after the failure, then kept going until the collector chose to stop
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2.0, 0.01])


class CollectorStateGuardTest(CollectorLoopTest):
    def test_too_many_states_pauses_and_says_so(self):
        def huge():
            raise COLLECTOR.TooManyStates(500000, 100000)
        with mock.patch.object(COLLECTOR, "sample_states", huge):
            rest = self.collector.step()
        with open(self.output) as handle:
            payload = json.load(handle)
        self.assertEqual((payload["status"], payload["count"], rest), ("too_many_states", 500000, COLLECTOR.TOO_MANY_STATES_INTERVAL))
        # sampling resumes as soon as the table is small again
        self.assertIsNotNone(self.collector.step())
        with open(self.output) as handle:
            self.assertEqual(json.load(handle)["status"], "ok")

    def test_a_slow_walk_says_so(self):
        def slow():
            raise COLLECTOR.TooManyStates(30000, 35000, slow=True)
        with mock.patch.object(COLLECTOR, "sample_states", slow):
            self.collector.step()
        with open(self.output) as handle:
            payload = json.load(handle)
        self.assertEqual((payload["status"], payload["slow"]), ("too_many_states", True))


class ThreatRecorderTest(unittest.TestCase):
    def test_hostnames_are_loaded_once_per_recording(self):
        recorder = COLLECTOR.ThreatRecorder(":memory:")
        collector = mock.Mock()
        collector.local_addresses, collector.networks, collector.interfaces = {"1.2.3.163"}, [], {}
        collector.geo, collector.hostnames = None, None
        collector.alerts.summary.return_value = None
        collector.correlator = COLLECTOR.Correlator()
        names = {"192.168.1.2": "mail"}
        collector.host_names.return_value = names
        records = PF.parse_states(nat_state(100, 100) + nat_state(100, 100).replace("45.56.79.53", "34.1.1.1"))
        with mock.patch.object(COLLECTOR, "threat_lists_for", return_value=["Test list"]), \
                mock.patch.object(COLLECTOR, "connection_summary", return_value=[]) as connections:
            recorder.update(records, collector, now=0.0)
            collector.host_names.assert_called_once_with()
            self.assertEqual(connections.call_count, 2)
            self.assertTrue(all(call.args[2] is names for call in connections.call_args_list))
            recorder.update(records, collector, now=1.0)
            collector.host_names.assert_called_once_with()
            recorder.update(records, collector, now=COLLECTOR.THREAT_RECORD_SECONDS)
            self.assertEqual(collector.host_names.call_count, 2)
        recorder.db.close()

    def test_no_flagged_addresses_do_not_load_hostnames(self):
        recorder = COLLECTOR.ThreatRecorder(":memory:")
        collector = mock.Mock()
        collector.local_addresses, collector.networks = {"1.2.3.163"}, []
        collector.correlator = COLLECTOR.Correlator()
        with mock.patch.object(COLLECTOR, "threat_lists_for", return_value=[]):
            recorder.update(PF.parse_states(nat_state(100, 100)), collector, now=0.0)
        collector.host_names.assert_not_called()
        recorder.db.close()

    def test_records_flagged_addresses_with_identity_and_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = COLLECTOR.ThreatRecorder(os.path.join(directory, "queue.db"))
            collector = mock.Mock()
            collector.local_addresses = {"1.2.3.163"}
            collector.geo = Geo({"lat": 1.0, "lon": 2.0, "country": "NL", "country_name": "The Netherlands",
                                 "asn": 64500, "as_org": "Example"})
            collector.hostnames.names = {"45.56.79.53": ("scanner.example", 0.0)}
            collector.alerts.summary.return_value = None
            collector.correlator = COLLECTOR.Correlator()
            collector.leases, collector.interfaces = {}, {}
            records = PF.parse_states(nat_state(100, 100))
            with mock.patch.object(COLLECTOR, "threat_lists_for", lambda address, *args: ["Test list"]):
                recorder.update(records, collector, now=0.0)
                recorder.update(records, collector, now=1.0)  # within the recording interval: skipped
            (row,) = THREATS.listing(THREATS.connect(os.path.join(directory, "queue.db")))["rows"]
            self.assertEqual((row["address"], row["samples"], row["lists"]), ("45.56.79.53", 1, ["Test list"]))
            self.assertEqual(row["remote"]["hostname"], "scanner.example")
            self.assertEqual(row["remote"]["org"], "Example")


class BenchmarkHarnessTest(unittest.TestCase):
    def test_table_construction_does_not_recount_all_connections(self):
        path = os.path.join(os.path.dirname(__file__), "..", "devel", "collector_benchmark.py")
        spec = importlib.util.spec_from_file_location("collector_benchmark", path)
        benchmark = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(benchmark)
        with mock.patch.object(benchmark.StateTable, "_states", side_effect=AssertionError("full recount")):
            table = benchmark.StateTable(1000, seed=7)
        self.assertGreaterEqual(table._states(), 1000)
        self.assertLess(table._states(), 1002)


class SampleTimingTest(CollectorLoopTest):
    def test_each_sample_records_where_its_time_went(self):
        self.collector.step()
        with open(os.path.join(self.directory, "collector_timings.json")) as handle:
            written = json.load(handle)
        self.assertEqual(written, self.collector.timings)
        self.assertEqual((written["states"], written["background"]), (1, False))
        for phase in ("walk", "parse", "facts", "tracker", "ingest", "threats", "payload", "write"):
            self.assertGreaterEqual(written["phases"][phase], 0.0)
        self.assertGreaterEqual(written["wall"], written["phases"]["payload"])
        # kept in memory every sample, written to the file every few seconds
        self.collector.step()
        self.assertNotEqual(self.collector.timings, written)
        with open(os.path.join(self.directory, "collector_timings.json")) as handle:
            self.assertEqual(json.load(handle), written)


if __name__ == "__main__":
    unittest.main()
