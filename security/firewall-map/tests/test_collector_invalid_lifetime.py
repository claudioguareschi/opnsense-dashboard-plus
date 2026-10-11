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

"""PF states with an impossible lifetime never become Firewall Map states (collector/lifetime.h).

Through the real engine (the test worker's fixture reader): the reported EXPIRE of the
observed pfsync-import wrap is rejected at the normalization boundary, before counting,
baseline, flows, discovery, the tracked set, ranking, mirroring and snapshots; a state whose
age PF cannot have measured is kept with an unknown age; without a timeout bound nothing is
rejected."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/opnsense/scripts/OPNsense/FirewallMap"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import collector, profiles  # noqa: E402
from collector_build import compile_worker  # noqa: E402
from test_collector_specification import CONTEXT, WAN, state  # noqa: E402

BALANCED = profiles.validate(profiles.BY_UUID[profiles.BALANCED])
WRAPPED = 1270699076  # EXPIRE of the states observed on fw2 (2026-10-08)
UPTIME = "385008"
BOUND = {"FM_TEST_UPTIME": UPTIME, "FM_TEST_TIMEOUT_MAX": "86400"}


def keys(remote, port):
    return (f"{remote}:443", f"{WAN}:{port}", f"{remote}:443", f"10.0.0.2:{port}")


def scenario(sample):
    """1.1.1.1 valid; 2.2.2.2 only invalid states; 3.3.3.3 one valid and one invalid state;
    4.4.4.4 valid lifetime, wrapped age. Every state carries traffic, so nothing else hides it."""
    traffic = (1000 * sample, 5000 * sample, 10 * sample, 50 * sample)
    bad = f"@expire={WRAPPED}"
    return [state(1, "out", keys("1.1.1.1", 50000), traffic),
            state(2, "out", keys("2.2.2.2", 50001), traffic, label=bad),
            state(3, "out", keys("2.2.2.2", 50002), traffic, label=bad),
            state(4, "out", keys("3.3.3.3", 50003), traffic),
            state(5, "out", keys("3.3.3.3", 50004), traffic, label=bad),
            state(6, "out", keys("4.4.4.4", 50005), traffic, age=1444590337)]


class InvalidLifetimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def engine(self):
        engine = collector.CollectorEngine(self.worker, profile=BALANCED)
        self.addCleanup(engine.close)
        return engine

    def run_scenario(self, environment, samples=2, **options):
        path = Path(self.directory.name) / f"{self._testMethodName}.txt"
        path.write_text("".join(f"sample {n}\n" + "".join(line + "\n" for line in scenario(n))
                                for n in range(1, samples + 1)))
        engine = self.engine()
        with patch.dict(os.environ, {"FM_TEST_STATES": str(path), "FM_TEST_INTERVAL": "2", **environment}):
            results = [engine.sample(CONTEXT["local"], CONTEXT["networks"], CONTEXT["assigned"], CONTEXT["wan"],
                                     **options) for _ in range(samples)]
        return engine, results, path

    @staticmethod
    def flows(result):
        return {flow["key"][1]: flow for flow in result["flows"]}

    def test_invalid_lifetimes_never_become_map_states(self):
        _, results, _ = self.run_scenario(BOUND)
        for result in results:
            telemetry = result["telemetry"]
            # every PF record observed, each invalid one counted exactly once per sample
            self.assertEqual((telemetry["pf_records_observed"], telemetry["invalid_pf_states_skipped"],
                              telemetry["age_unknown_states"]), (6, 3, 1))
            self.assertEqual((telemetry["lifetime_validation"], telemetry["lifetime_limit"],
                              telemetry["lifetime_error"]), (1, 86400, 0))
            # Firewall Map's state count, flow count and tracked set never include them
            self.assertEqual(result["counts"]["states"], 3)
            self.assertEqual(result["counts"]["flows"], 3)
            self.assertEqual(telemetry["flows_total"], 3)
        flows = self.flows(results[-1])
        self.assertEqual(set(flows), {"1.1.1.1", "3.3.3.3", "4.4.4.4"})
        # the mixed flow keeps its valid state only (its traffic too)
        self.assertEqual(flows["3.3.3.3"]["states"], 1)
        self.assertEqual(flows["3.3.3.3"]["bytes_from_remote"], flows["1.1.1.1"]["bytes_from_remote"])
        # a wrapped age is unknown, never 0 and never the absurd value
        self.assertEqual((flows["4.4.4.4"]["oldest"], flows["4.4.4.4"]["youngest"]), (None, None))
        self.assertEqual(flows["1.1.1.1"]["oldest"], 10)

    def test_without_a_timeout_bound_nothing_is_rejected(self):
        for environment, error in (({"FM_TEST_UPTIME": UPTIME}, None),
                                   ({"FM_TEST_UPTIME": UPTIME, "FM_TEST_TIMEOUT_ERROR": "5"}, 5)):
            with self.subTest(environment=environment):
                _, results, _ = self.run_scenario(environment)
                telemetry = results[-1]["telemetry"]
                self.assertEqual((telemetry["lifetime_validation"], telemetry["invalid_pf_states_skipped"]), (0, 0))
                self.assertNotEqual(telemetry["lifetime_error"], 0)
                if error:
                    self.assertEqual(telemetry["lifetime_error"], error)
                self.assertEqual(telemetry["age_unknown_states"], 1)  # ages are screened regardless
                self.assertEqual(results[-1]["counts"]["states"], 6)
                self.assertIn("2.2.2.2", self.flows(results[-1]))

    def test_a_carp_backup_never_mirrors_an_invalid_state(self):
        _, results, _ = self.run_scenario(BOUND, carp_backup={WAN}, mirror=True)
        flows = self.flows(results[-1])
        self.assertEqual(set(flows), {"1.1.1.1", "3.3.3.3", "4.4.4.4"})
        self.assertEqual({flow["presence"] for flow in flows.values()}, {"mirror"})
        # the same states mirror when no bound is known (fail open)
        _, results, _ = self.run_scenario({"FM_TEST_UPTIME": UPTIME}, carp_backup={WAN}, mirror=True)
        self.assertIn("2.2.2.2", self.flows(results[-1]))

    def test_snapshots_never_capture_an_invalid_state(self):
        path = Path(self.directory.name) / "snapshot.txt"
        path.write_text("".join(f"sample {n}\n" + "".join(line + "\n" for line in scenario(n)) for n in (1, 2)))
        engine = self.engine()
        with patch.dict(os.environ, {"FM_TEST_STATES": str(path), "FM_TEST_INTERVAL": "2", **BOUND}):
            args = (CONTEXT["local"], CONTEXT["networks"], CONTEXT["assigned"], CONTEXT["wan"])
            engine.sample(*args)
            warm = engine.sample(*args, snapshot=True)
            remotes = {item["remote"] for item in warm["snapshot_candidates"]}
            self.assertNotIn("2.2.2.2", remotes)
            identities = [(item["local"], item["remote"], item["owner"], False) for item in warm["snapshot_candidates"]]
            engine.snapshot_selection(identities)
            rows, coverage = engine.snapshot_detail(identities, collector.SNAPSHOT_BYTES, 5000)
        self.assertEqual(len(rows["3.3.3.3"]), 1)  # the mixed flow's valid state only
        self.assertNotIn("2.2.2.2", rows)
        self.assertEqual(rows["4.4.4.4"][0]["age"], None)
        self.assertEqual(coverage["skipped_states"], 3)  # the invalid states are skipped, not hidden

    def test_bounded_discovery_and_tracking_never_see_an_invalid_state(self):
        """Every state its own flow, every odd one invalid, past the tracked-set limit."""
        count = 10000
        engine = self.engine()
        with patch.dict(os.environ, {"FM_TEST_MODE": "invalid", "FM_TEST_COUNT": str(count),
                                     "FM_TEST_INTERVAL": "2", **BOUND}):
            results = [engine.sample({"8.8.8.1"}, [], {}, None, memory=64 << 20) for _ in range(3)]
        for result in results:
            telemetry = result["telemetry"]
            self.assertEqual(result["regime"], "bounded")
            self.assertEqual((telemetry["pf_records_observed"], telemetry["invalid_pf_states_skipped"]),
                             (count, count // 2))
            self.assertEqual(result["counts"]["states"], count // 2)
            self.assertLessEqual(telemetry["flows_total"], count // 2)
            self.assertLessEqual(telemetry["tracked_flows"] + telemetry["untracked_states"], count // 2)
            # every flow on the map is an even (valid) state's: 9.x.y.z with z = n & 255
            self.assertTrue(all(int(flow["key"][1].split(".")[3]) % 2 == 0 for flow in result["flows"]))


if __name__ == "__main__":
    unittest.main()
