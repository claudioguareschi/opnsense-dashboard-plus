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

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import COLLECTOR, COMMON, PF, SNAPSHOT, THREATS, Geo, nat_state  # noqa: E402


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
            "sample_states": lambda: PF.parse_states(nat_state(self.bytes, self.bytes)),
            "host_info": lambda: ({"1.2.3.163"}, None, []),
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
                mock.patch("sys.stderr") as stderr:
            COLLECTOR.run()
        self.assertIn("boom", "".join(str(call) for call in stderr.write.call_args_list))
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


class ThreatRecorderTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
