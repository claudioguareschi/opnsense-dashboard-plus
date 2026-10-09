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

"""The classification snapshot's refresh: an explicit memory bound, and a failed refresh never
destroys the snapshot in use (collector main.c refresh_classifier, classify.c).

Through the real engine with test tables (FM_TEST_CLASS_DIR); FM_TEST_CLASSIFIER_BUDGET fixes a
build's bound above what is allocated, for the whole collector process, so a scenario changes
the table's contents between requests: small tables fit, a 300,000-entry one does not."""

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

BALANCED = profiles.validate(profiles.BY_UUID[profiles.BALANCED])
CONTEXT = ({"8.8.8.1"}, [], {}, None)
ENOMEM = 12


def hosts(count, first=10):
    """count /32s two apart, from 10.<first>.0.0 up: none adjacent, so every one is its own span."""
    return "".join(f"10.{first + (n >> 15)}.{(n >> 7) & 255}.{(n & 127) * 2}\n" for n in range(count))


class ClassifierRefreshTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.tables = Path(tempfile.mkdtemp(dir=self.directory.name))

    def engine(self, budget=None):
        environment = {"FM_TEST_MODE": "one", "FM_TEST_CLASS_DIR": str(self.tables)}
        if budget is not None:
            environment["FM_TEST_CLASSIFIER_BUDGET"] = str(budget)
        patcher = patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)
        engine = collector.CollectorEngine(self.worker, profile=BALANCED)
        self.addCleanup(engine.close)
        return engine

    def table(self, name, text):
        (self.tables / f"{name}.txt").write_text(text)

    @staticmethod
    def sample(engine, generation, sets=(("T", "threats"),), classify=("9.0.0.5", "9.0.1.5")):
        return engine.sample(*CONTEXT, classification=(generation, list(sets)), classify=list(classify))

    def test_a_failed_refresh_keeps_the_snapshot_in_use_until_one_succeeds(self):
        engine = self.engine(budget=2 << 20)
        self.table("threats", "9.0.0.0/24\n")
        first = self.sample(engine, "g1")
        self.assertEqual((first["telemetry"]["classifier_stale"], first["classified"]), (0, {"9.0.0.5": 1}))
        self.assertGreater(first["telemetry"]["classifier_build_peak"], 0)
        # a new generation of the same table that does not fit: the sample goes on with the
        # previous snapshot (9.0.0.0/24, one entry), reported stale
        self.table("threats", hosts(300000) + "9.0.1.0/24\n")
        stale = self.sample(engine, "g2")
        telemetry = stale["telemetry"]
        self.assertEqual((telemetry["classifier_stale"], telemetry["classifier_error"]), (1, ENOMEM))
        self.assertIsNone(stale["refused"])
        self.assertEqual(stale["classified"], {"9.0.0.5": 1})
        self.assertEqual([(row["status"], row["entries"]) for row in stale["class_sets"]], [("ok", 1)])
        # not tried again for the same configuration: still stale, still answering
        again = self.sample(engine, "g2")
        self.assertEqual((again["telemetry"]["classifier_stale"], again["classified"]), (1, {"9.0.0.5": 1}))
        # a later generation that fits replaces it
        self.table("threats", "9.0.1.0/24\n")
        fresh = self.sample(engine, "g3")
        self.assertEqual((fresh["telemetry"]["classifier_stale"], fresh["telemetry"]["classifier_error"]), (0, 0))
        self.assertEqual(fresh["classified"], {"9.0.1.5": 1})

    def test_failed_and_successful_refreshes_leak_nothing(self):
        engine = self.engine(budget=2 << 20)
        heaps = []
        for cycle in range(5):
            self.table("threats", "9.0.0.0/24\n")
            self.sample(engine, f"ok{cycle}")
            self.table("threats", hosts(300000))
            failed = self.sample(engine, f"big{cycle}")
            self.assertEqual(failed["telemetry"]["classifier_stale"], 1)
            heaps.append((failed["telemetry"]["heap_bytes"], failed["telemetry"]["heap_blocks"]))
        # after the first cycle (structures sized once), every cycle ends where the last did
        self.assertEqual(len(set(heaps[1:])), 1, heaps)

    def test_other_sets_or_no_snapshot_fail_the_request_as_before(self):
        engine = self.engine(budget=2 << 20)
        self.table("threats", hosts(300000))
        # no snapshot yet: the request fails (and is retried by the next one)
        with self.assertRaises(collector.CollectorError):
            self.sample(engine, "g1")
        self.table("threats", "9.0.0.0/24\n")
        self.assertEqual(self.sample(engine, "g2")["telemetry"]["classifier_stale"], 0)
        # another set list cannot keep the old snapshot's set ids: the request fails
        self.table("country", hosts(300000, first=20))
        with self.assertRaises(collector.CollectorError):
            self.sample(engine, "g3", sets=(("T", "threats"), ("C", "country")))
        self.table("country", "9.0.1.0/24\n")
        recovered = self.sample(engine, "g4", sets=(("T", "threats"), ("C", "country")))
        self.assertEqual(recovered["classified"], {"9.0.0.5": 1, "9.0.1.5": 2})

    def test_the_largest_supported_configuration_builds_within_its_bound(self):
        """Two tables of 500,000 entries (the per-table and total caps), every entry its own span."""
        engine = self.engine()
        self.table("threats", hosts(500000))
        self.table("country", hosts(500000, first=40))
        result = self.sample(engine, "max", sets=(("T", "threats"), ("C", "country")), classify=("10.10.0.6", "10.40.1.2"))
        telemetry = result["telemetry"]
        self.assertEqual(telemetry["classifier_stale"], 0)
        self.assertEqual([(row["status"], row["entries"]) for row in result["class_sets"]], [("ok", 500000)] * 2)
        self.assertEqual(result["classified"], {"10.10.0.6": 1, "10.40.1.2": 2})
        self.assertGreater(telemetry["classifier_build_peak"], 0)
        self.assertLess(telemetry["classifier_build_peak"], telemetry["classifier_build_bound"])
        print(f"\n  classifier at the caps: build peak {telemetry['classifier_build_peak'] >> 20} MiB, "
              f"snapshot {telemetry['classifier_bytes'] >> 20} MiB, bound {telemetry['classifier_build_bound'] >> 20} MiB")


if __name__ == "__main__":
    unittest.main()
