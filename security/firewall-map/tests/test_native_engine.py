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

"""Specification tests of the native engine (compiled with the synthetic PF reader).

Expected values are derived by hand from the fixture's counters and from PF semantics, not
from the retired Python engine:

* PF counts ``bytes[0]``/``packets[0]`` in the direction of the packet that created the state
  (initiator to responder) and ``[1]`` for the replies.
* The fixture's state n in sample k has forward bytes 1000 + 100k + n % 50, reverse bytes
  2000 + 200k, forward packets 10 + k and reverse packets 20 + k.
* With FM_TEST_INTERVAL=2 sample k is anchored at 2k seconds; rates use a 0.5 smoothing weight.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/opnsense/scripts/OPNsense/FirewallMap"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import native  # noqa: E402
from native_build import compile_worker  # noqa: E402

LOCAL = {"8.8.8.1", "2001:4860::1"}
CONTEXT = (LOCAL, [], {}, None)
OUTBOUND_QUERY = ("tcp", "8.8.8.1", "30000", "9.9.9.9", "443")
INBOUND_QUERY = ("tcp", "8.8.8.1", "443", "9.9.9.9", "55000")


class NativeEngineSpecificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.engine = native.NativeEngine(self.worker)
        self.addCleanup(self.engine.close)

    def samples(self, count, mode="one", states=12, **options):
        with patch.dict(os.environ, FM_TEST_MODE=mode, FM_TEST_COUNT=str(states), FM_TEST_INTERVAL="2"):
            return [self.engine.sample(*CONTEXT, **options) for _ in range(count)]

    def test_first_sample_of_a_helper_is_a_baseline_then_intervals_are_measured_in_c(self):
        first, second, third = self.samples(3)
        self.assertTrue(first["baseline"])
        self.assertEqual(first["telemetry"]["interval"], -1)
        self.assertEqual(first["flows"], [])  # no rates without a committed predecessor
        self.assertEqual(first["counts"]["flows"], 1)
        self.assertFalse(second["baseline"])
        self.assertEqual((second["telemetry"]["interval"], third["telemetry"]["interval"]), (2.0, 2.0))
        self.assertEqual([sample["telemetry"]["sequence"] for sample in (first, second, third)], [1, 2, 3])
        self.engine.close()
        self.assertTrue(self.samples(1)[0]["baseline"])  # a new helper never inherits a baseline

    def test_rates_of_a_locally_initiated_flow_are_oriented_by_the_pf_initiator(self):
        _, second, third = self.samples(3)
        flow = second["flows"][0]
        self.assertEqual(flow["key"], ("8.8.8.1", "9.9.9.9"))
        # local initiator: the remote's traffic is PF's reverse counter (12 states x 200 bytes / 2 s)
        self.assertEqual((flow["rate_from_remote"], flow["rate_to_remote"]), (600.0, 300.0))
        self.assertEqual(flow["packet_rate"], 6.0)  # 12 states x 2 packets / 2 s, smoothed by half
        self.assertEqual((flow["bytes_from_remote"], flow["bytes_to_remote"]),
                         (12 * (2000 + 400), sum(1000 + 200 + n for n in range(12))))
        self.assertEqual((third["flows"][0]["rate_from_remote"], third["flows"][0]["rate_to_remote"]),
                         (900.0, 450.0))

    def test_rates_of_a_remotely_initiated_flow_are_oriented_by_the_pf_initiator(self):
        _, second = self.samples(2, "inbound")
        flow = second["flows"][0]
        # remote initiator: the remote's traffic is PF's forward counter
        self.assertEqual((flow["rate_from_remote"], flow["rate_to_remote"]), (300.0, 600.0))
        self.assertEqual(flow["remote_initiated_weight"] > 0, True)

    def test_event_matches_are_oriented_by_the_pf_initiator_not_raw_counter_order(self):
        # Declared divergence from the retired engine, which reported raw [forward, reverse]
        # as (bytes_in, bytes_out): bytes_in means from the remote in both cases.
        _, outbound = self.samples(2, event_queries=[OUTBOUND_QUERY])
        match = outbound["matches"][OUTBOUND_QUERY]
        self.assertEqual((match["bytes_in"], match["bytes_out"]), (2000 + 400, 1000 + 200))
        self.assertEqual((match["packets_from_remote"], match["packets_to_remote"]), (22, 12))
        self.assertFalse(match["remote_initiated"])
        self.assertEqual((match["inside"], match["inside_port"]), ("10.0.0.2", 30000))
        self.engine.close()
        _, inbound = self.samples(2, "inbound", event_queries=[INBOUND_QUERY])
        match = inbound["matches"][INBOUND_QUERY]
        # every inbound state shares the outside tuple; the last one (n = 11) supplies the value
        self.assertEqual((match["bytes_in"], match["bytes_out"]), (1000 + 200 + 11, 2000 + 400))
        self.assertTrue(match["remote_initiated"])
        self.assertFalse(match["ambiguous"])
        self.assertEqual((match["inside"], match["inside_port"]), ("10.0.0.2", 8443))

    def test_truncated_utf8_rule_labels_never_break_samples_or_snapshots(self):
        with patch.dict(os.environ, FM_TEST_MODE="badlabel", FM_TEST_COUNT="3", FM_TEST_INTERVAL="2"):
            self.engine.sample(*CONTEXT)
            sample = self.engine.sample(*CONTEXT, snapshot=True)
            labels = [value for _, kind, _, _, _, value in sample["candidates"] if kind == native.RULE_LABEL]
            self.assertEqual(labels, [b"caf\xc3"])
            pages = [row for page in self.engine.snapshot_pages() for row in page]
            identities = [(local, remote, False) for local, remote, _, _ in pages]
            self.engine.snapshot_selection(identities)
            rows, _ = self.engine.snapshot_detail(identities, native.SNAPSHOT_BYTES)
        self.assertEqual(rows["9.9.9.9"][0]["rule_label"], "caf\ufffd")
        self.assertEqual(rows["9.9.9.9"][0]["bytes_from_remote"], 2000 + 600)

    def test_operator_context_over_its_maximum_refuses_the_sample_explicitly(self):
        self.samples(2)
        too_many = {f"8.8.{n // 256}.{n % 256}" for n in range(300)}
        with patch.dict(os.environ, FM_TEST_MODE="one", FM_TEST_COUNT="12", FM_TEST_INTERVAL="2"):
            refused = self.engine.sample(too_many, [], {}, None, snapshot=True)
            self.assertEqual(refused["refused"], {"reason": "refused_context", "kind": "L",
                                                  "actual": 300, "limit": 256})
            self.assertEqual(refused["flows"], [])
            self.assertFalse(self.engine.snapshot_open)
            # a refusal is not a helper failure, and the next accepted sample is a baseline
            self.assertIsNotNone(self.engine.process)
            recovered = self.engine.sample(*CONTEXT)
        self.assertTrue(recovered["baseline"])
        self.assertEqual(self.engine.starts, 1)

    def test_helper_failures_are_classified_and_close_the_helper(self):
        with patch.dict(os.environ, FM_TEST_MODE="incomplete", FM_TEST_COUNT="4"):
            self.engine.sample(*CONTEXT)
            self.engine.sample(*CONTEXT)
            with self.assertRaises(native.NativeError) as raised:
                self.engine.sample(*CONTEXT)
        self.assertEqual(raised.exception.failure_class, "structural")
        self.assertIn("synthetic incomplete multipart dump", str(raised.exception))
        self.assertIsNone(self.engine.process)
        self.engine._start()
        with self.assertRaises(native.NativeError) as raised:
            self.engine._request("FMCONF2\nBOGUS\nRUN\n",
                                 lambda stream, process: native._decode(stream, process, (), False))
        self.assertEqual(raised.exception.failure_class, "request")
        self.assertIsNone(self.engine.process)

    def test_an_exception_while_a_request_is_in_flight_closes_the_helper(self):
        self.samples(1)

        def interrupted(stream, process):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.engine._request("FMCONF2\nRUN\n", interrupted)
        self.assertIsNone(self.engine.process)

    def test_banner_metadata(self):
        self.samples(1)
        self.assertEqual(self.engine.metadata["pf_state_version"], 0)  # test build: no PF headers
        self.assertEqual(self.engine.starts, 1)


class NativeMemoryTest(unittest.TestCase):
    """Steady-state memory: what C1 (the ranking leak) would have failed."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker", ("-g",))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_samples(self, count, states=2000, mode="many"):
        engine = native.NativeEngine(self.worker)
        self.addCleanup(engine.close)
        with patch.dict(os.environ, FM_TEST_MODE=mode, FM_TEST_COUNT=str(states), FM_TEST_INTERVAL="2"):
            telemetry = [engine.sample(*CONTEXT, threat_summary=True,
                                       event_queries=[OUTBOUND_QUERY])["telemetry"] for _ in range(count)]
        return engine, telemetry

    def test_heap_plateaus_across_samples(self):
        _, telemetry = self.run_samples(150)
        steady = telemetry[4]
        for later in telemetry[5:]:
            self.assertEqual((later["heap_bytes"], later["heap_blocks"]),
                             (steady["heap_bytes"], steady["heap_blocks"]))
        # RSS is a high-water mark that also moves with allocator fragmentation, so it is only
        # checked for gross growth; the exact accounted-heap equality above is the leak check
        self.assertLessEqual(telemetry[-1]["max_rss"], telemetry[len(telemetry) // 2]["max_rss"] * 1.25)
        self.assertGreater(steady["heap_peak"], steady["heap_bytes"])  # per-sample peak window

    def test_no_unreachable_heap_after_many_samples(self):
        """LeakSanitizer stand-in: macOS leaks(1) inspects the live helper for unreachable blocks."""
        tool = shutil.which("leaks")
        if not tool:
            raise unittest.SkipTest("leaks(1) unavailable; run the sanitizer build instead")
        engine, _ = self.run_samples(40, states=500)
        result = subprocess.run([tool, str(engine.process.pid)], capture_output=True, text=True, timeout=120)
        if result.returncode not in (0, 1):
            raise unittest.SkipTest(f"leaks(1) could not inspect the helper: {result.stderr.strip()[:200]}")
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])


if __name__ == "__main__":
    unittest.main()
