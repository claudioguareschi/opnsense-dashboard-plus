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
# POSSIBILITY OF SUCH DAMAGE.


"""Maximum flows on the map: the collector's --flows, how many flows it ranks and sends per sample.

The collector validates the option itself; the engine passes it, restarts the collector when it
changes and holds the response to it. The tracked set stays the memory budget's.
"""

import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/opnsense/scripts/OPNsense/FirewallMap"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import collector, evidence, profiles  # noqa: E402
from collector_build import budget_limits, compile_worker  # noqa: E402

CONTEXT = ({"8.8.8.1"}, [], {}, None)
BALANCED = profiles.validate(profiles.BY_UUID[profiles.BALANCED])
USAGE_ERROR = "--flows must be a whole number from 25 to 1000"


def custom(floors=(0, 0, 0), **weights):
    return profiles.validate({
        "uuid": "6f36c7b2-70ad-4c41-a32d-4cb1e3fb1a01", "name": "Test",
        "weights": {feature: weights.get(feature, 0) for feature in profiles.FEATURES},
        "floors": dict(zip(profiles.FLOORS, floors)), "default_multiplier": 1, "assets": [], "direction": "equal"})


class FlowsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker")
        cls.profile = Path(cls.directory.name) / "profile.json"
        cls.profile.write_text(profiles.startup_text(BALANCED))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_collector(self, *arguments):
        """The collector with `arguments` and nothing to read: (exit status, stdout, stderr)."""
        result = subprocess.run([self.worker, *arguments], input=b"", capture_output=True, timeout=60)
        return result.returncode, result.stdout.decode(), result.stderr.decode()

    def test_help_documents_the_option(self):
        status, out, _ = self.run_collector("--help")
        self.assertEqual(status, 0)
        self.assertIn("[--flows <N>]", out)
        self.assertIn("--flows <N>       ranked flows sent per sample, 25 to 1000 (default 150)", out)

    def test_accepted_values_start_the_collector(self):
        for flows in ("25", "50", "150", "500", "1000"):
            with self.subTest(flows=flows):
                status, out, err = self.run_collector("--profile", str(self.profile), "--flows", flows)
                # it starts (banner), then sees the closed input as the end of its requests
                self.assertTrue(out.startswith("FMCOLLECTOR protocol=1 "), (out, err))
                self.assertEqual(status, 0, err)
        # either order
        status, out, _ = self.run_collector("--flows", "500", "--profile", str(self.profile))
        self.assertTrue(out.startswith("FMCOLLECTOR"))

    def test_invalid_values_are_refused_clearly(self):
        for flows in ("0", "24", "1001", "-5", "+150", " 150", "150 ", "150x", "abc", "", "1e3", "0x96",
                      "99999999999999999999999"):
            with self.subTest(flows=flows):
                status, out, err = self.run_collector("--profile", str(self.profile), "--flows", flows)
                self.assertEqual((status, out), (2, ""))
                self.assertIn(USAGE_ERROR, err)
                self.assertIn("usage: firewallmap-collector --profile <file> [--flows <N>]", err)

    def test_malformed_command_lines_are_usage_errors(self):
        for arguments in (("--profile", str(self.profile), "--flows", "150", "--flows", "150"),
                          ("--profile", str(self.profile), "--profile", str(self.profile)),
                          ("--profile", str(self.profile), "--flows"),
                          ("--flows", "150"),
                          ("--profile", str(self.profile), "--other", "1"), ()):
            with self.subTest(arguments=arguments):
                status, out, err = self.run_collector(*arguments)
                self.assertEqual((status, out), (2, ""))
                self.assertIn("usage:", err)

    def engine(self, flows=None, profile=None):
        options = {} if flows is None else {"flows": flows}
        engine = collector.CollectorEngine(self.worker, profile=profile or BALANCED, **options)
        self.addCleanup(engine.close)
        return engine

    def run_mode(self, engine, mode, count, samples=2, **options):
        environment = {"FM_TEST_MODE": mode, "FM_TEST_COUNT": str(count), "FM_TEST_INTERVAL": "2"}
        with patch.dict(os.environ, environment):
            return [engine.sample(*CONTEXT, **options) for _ in range(samples)]

    def test_the_option_bounds_the_ranked_flows(self):
        """3,000 flows: each limit is filled exactly, in rank order; the tracked set is the budget's."""
        for flows in (25, 50, 150, 500, 1000, None):
            with self.subTest(flows=flows):
                engine = self.engine(flows)
                first, last = self.run_mode(engine, "unique", 3000)
                self.assertIn(f"--flows {flows or 150}", " ".join(engine.process.args))
                self.assertEqual(len(last["flows"]), flows or 150)
                scores = [flow["score"] for flow in last["flows"]]
                self.assertEqual(scores, sorted(scores, reverse=True))
                self.assertEqual(len({tuple(flow["key"]) for flow in last["flows"]}), len(last["flows"]))
                telemetry = last["telemetry"]
                self.assertEqual(telemetry["tracked_limit"],
                                 budget_limits(collector.memory_budget(), telemetry["classifier_bytes"])[1])
                self.assertGreaterEqual(telemetry["tracked_flows"], len(last["flows"]))
        # fewer flows than the limit: what there is, never padded
        _, last = self.run_mode(self.engine(500), "unique", 37)
        self.assertEqual(len(last["flows"]), 37)

    def argv(self, engine):
        engine._start()
        return engine.process.args

    def test_security_floors_scale_with_the_limit(self):
        """A 1% S3 floor is ceil(1% of N) reserved places: 20 S3 flows that rank last on their score
        take exactly that many places at every limit."""
        s3 = {f"9.0.11.{n}": evidence.facts(ids_alerts=1, ids_severity=1) for n in range(20)}
        profile = custom((1, 0, 0), active_states=100)
        for flows in (25, 50, 150, 500, 1000):
            with self.subTest(flows=flows):
                _, last = self.run_mode(self.engine(flows, profile), "unique", 3000, evidence=s3)
                chosen = [flow["key"][1] for flow in last["flows"]]
                self.assertEqual(len(chosen), flows)
                self.assertEqual(len(set(chosen) & set(s3)), min(len(s3), math.ceil(flows / 100)))

    def test_bounded_tracking_keeps_its_limits_at_the_largest_setting(self):
        """64 MiB: about 2,450 flows fit the tracked set; 5,000 flows with 1,000 on the map. The
        selected flows are pinned within the tracked limit (the C2 rule); forced evidence may add
        its own places; the map gets exactly 1,000."""
        facts = {f"9.0.{16 + n // 256}.{n % 256}": evidence.facts(ids_alerts=1, ids_severity=1) for n in range(50)}
        first, last = self.run_mode(self.engine(1000), "unique", 5000, memory=64 << 20, evidence=facts)
        telemetry = last["telemetry"]
        self.assertEqual(last["quality"]["ranking"], "bounded")
        self.assertGreaterEqual(telemetry["tracked_limit"], 1000)
        self.assertLessEqual(telemetry["tracked_flows"], telemetry["tracked_limit"] + telemetry["forced_limit"])
        self.assertEqual(len(last["flows"]), 1000)
        self.assertLess(telemetry["heap_peak"], 64 << 20)

    def test_the_engine_validates_and_restarts_on_change(self):
        for flows in (0, 24, 1001, -5, "500", 1.5, True, None):
            with self.subTest(flows=flows), self.assertRaises(ValueError):
                collector.CollectorEngine(self.worker, profile=BALANCED, flows=flows)
        engine = self.engine(150)
        self.argv(engine)
        process = engine.process
        self.assertFalse(engine.set_flows(150))
        self.assertIs(engine.process, process)
        self.assertTrue(engine.set_flows(500))
        self.assertIsNone(engine.process)
        self.assertIn("500", self.argv(engine))
        with self.assertRaises(ValueError):
            engine.set_flows(5000)
        self.assertEqual(engine.flows, 500)


if __name__ == "__main__":
    unittest.main()
