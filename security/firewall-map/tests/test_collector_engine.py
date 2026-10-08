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

"""Specification tests of the state collector (compiled with the synthetic PF reader).

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
from lib import collector  # noqa: E402
from collector_build import compile_worker, state_limit  # noqa: E402

LOCAL = {"8.8.8.1", "2001:4860::1"}
CONTEXT = (LOCAL, [], {}, None)
OUTBOUND_QUERY = ("tcp", "8.8.8.1", "30000", "9.9.9.9", "443")
INBOUND_QUERY = ("tcp", "8.8.8.1", "443", "9.9.9.9", "55000")
KERNEL_IDENTITY = collector.kernel_identity  # the real one; the identity tests patch it


class CollectorEngineSpecificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.engine = collector.CollectorEngine(self.worker)
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
            labels = [value for _, kind, _, _, _, value in sample["candidates"] if kind == collector.RULE_LABEL]
            self.assertEqual(labels, [b"caf\xc3"])
            identities = [(item["local"], item["remote"], False) for item in sample["snapshot_candidates"]]
            self.engine.snapshot_selection(identities)
            rows, _ = self.engine.snapshot_detail(identities, collector.SNAPSHOT_BYTES)
        self.assertEqual(rows["9.9.9.9"][0]["rule_label"], "caf\ufffd")
        self.assertEqual(rows["9.9.9.9"][0]["bytes_from_remote"], 2000 + 600)

    def test_operator_context_over_its_maximum_refuses_the_sample_explicitly(self):
        self.samples(2)
        too_many = {f"8.{n // 65536}.{n // 256 % 256}.{n % 256}" for n in range(4100)}
        with patch.dict(os.environ, FM_TEST_MODE="one", FM_TEST_COUNT="12", FM_TEST_INTERVAL="2"):
            # Python refuses before sending: the helper never sees the request
            refused = self.engine.sample(too_many, [], {}, None, snapshot=True)
            self.assertEqual(refused["refused"], {"reason": "refused_context", "kind": "L",
                                                  "actual": 4100, "limit": 4096})
            self.assertFalse(self.engine.snapshot_open)
            # the helper enforces the same maximum on its own
            rows = "".join(f"L {address}\n" for address in sorted(too_many))
            text = f"FMCONF2\nBUDGET {collector.memory_budget()} 16 20000\n{rows}RUN\n"
            direct = self.engine._request(text, lambda stream, process: collector._decode(stream, process, (), False))
            self.assertEqual(direct["refused"], {"reason": "refused_context", "kind": "L",
                                                 "actual": 4100, "limit": 4096})
            # a refusal is not a helper failure, and the next accepted sample is a baseline
            self.assertIsNotNone(self.engine.process)
            recovered = self.engine.sample(*CONTEXT)
        self.assertTrue(recovered["baseline"])
        self.assertEqual(self.engine.starts, 1)

    def test_state_admission_preflight_and_backstop(self):
        memory = 64 << 20
        limit = state_limit(memory)
        # preflight: refused before any traversal
        with patch.dict(os.environ, FM_TEST_MODE="unique", FM_TEST_COUNT=str(limit + 5), FM_TEST_INTERVAL="2",
                        FM_TEST_PREFLIGHT=str(limit + 5)):
            refused = self.engine.sample(*CONTEXT, memory=memory)
        self.assertEqual(refused["refused"], {"reason": "refused_states", "kind": None,
                                              "actual": limit + 5, "limit": limit})
        self.assertEqual(refused["telemetry"]["state_limit"], limit)
        self.assertEqual(refused["telemetry"]["preflight_states"], limit + 5)
        self.engine.close()
        # backstop: no preflight; the traversal stops as soon as the count passes the limit
        with patch.dict(os.environ, FM_TEST_MODE="unique", FM_TEST_COUNT=str(limit + 5), FM_TEST_INTERVAL="2"):
            refused = self.engine.sample(*CONTEXT, memory=memory)
            self.assertEqual(refused["refused"]["reason"], "refused_states")
            self.assertEqual((refused["refused"]["actual"], refused["counts"]["states"]), (limit + 1, limit + 1))
            # within the limit the same helper accepts, starting with a baseline
            accepted = self.engine.sample(*CONTEXT, memory=memory + (8 << 20))
        self.assertIsNone(accepted["refused"])
        self.assertTrue(accepted["baseline"])
        self.assertEqual(accepted["counts"]["states"], limit + 5)
        self.assertLessEqual(accepted["telemetry"]["heap_peak"], memory + (8 << 20))
        self.assertEqual(self.engine.starts, 2)

    def test_memory_budget_exhaustion_is_a_refusal_not_a_failure(self):
        with patch.dict(os.environ, FM_TEST_MODE="unique", FM_TEST_COUNT="20000", FM_TEST_INTERVAL="2",
                        FM_TEST_HEAP_BUDGET=f"{2 << 20}:2"):
            first = self.engine.sample(*CONTEXT)
            refused = self.engine.sample(*CONTEXT)
            recovered = self.engine.sample(*CONTEXT)
        self.assertIsNone(first["refused"])
        self.assertEqual(refused["refused"]["reason"], "refused_memory")
        self.assertEqual(refused["refused"]["limit"], collector.memory_budget())
        self.assertTrue(recovered["baseline"])
        self.assertEqual(self.engine.starts, 1)

    def test_helper_failures_are_classified_and_close_the_helper(self):
        with patch.dict(os.environ, FM_TEST_MODE="incomplete", FM_TEST_COUNT="4"):
            self.engine.sample(*CONTEXT)
            self.engine.sample(*CONTEXT)
            with self.assertRaises(collector.CollectorError) as raised:
                self.engine.sample(*CONTEXT)
        self.assertEqual(raised.exception.failure_class, "structural")
        self.assertIn("synthetic incomplete multipart dump", str(raised.exception))
        self.assertIsNone(self.engine.process)
        self.engine._start()
        with self.assertRaises(collector.CollectorError) as raised:
            self.engine._request("FMCONF2\nBOGUS\nRUN\n",
                                 lambda stream, process: collector._decode(stream, process, (), False))
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
        self.assertEqual(self.engine.metadata["protocol"], collector.PROTOCOL_VERSION)
        self.assertEqual(self.engine.metadata["pf_state_version"], 0)  # test build: no PF headers
        self.assertEqual(self.engine.starts, 1)

    def test_version_reports_the_collector_protocol(self):
        report = subprocess.run([str(self.worker), "--version"], capture_output=True, text=True, check=True)
        self.assertEqual(__import__("json").loads(report.stdout)["protocol"], 1)


class CollectorProtocolIdentityTest(unittest.TestCase):
    """Persistent incompatibilities: a collector of another protocol is never run again until
    its binary changes; one built for another PF state ABI is never run again until its binary
    or the running kernel changes. Ordinary failures keep restarting the collector."""

    PF_ABI = b"PF state ABI version 7, collector built for 5"

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "firewallmap-collector"
        self.runs = Path(directory.name) / "runs"
        kernel = patch.object(collector, "kernel_identity", return_value=("14.3-RELEASE-p2", "build A"))
        self.kernel = kernel.start()
        self.addCleanup(kernel.stop)

    def install(self, banner, failure=None):
        """A stand-in collector that counts its executions, announces banner and, given a
        (class, message) failure, answers the first request with that FMFAIL1 report."""
        if self.path.exists():
            self.path.unlink()  # a new binary, as a reinstall makes it
        announced = banner.encode() + b"\n"
        self.path.write_text(f"""#!{sys.executable}
import struct, sys
with open({str(self.runs)!r}, "a") as runs:
    runs.write("x")
sys.stdout.buffer.write({announced!r})
sys.stdout.flush()
failure = {failure!r}
for line in sys.stdin.buffer:
    if failure and line == b"RUN\\n":
        record = b"\\xfe" + struct.pack("!Ii", failure[0], 71) + failure[1]
        sys.stdout.buffer.write(b"FMFAIL1\\0" + struct.pack("!I", len(record)) + record)
        sys.stdout.flush()
        sys.exit(1)
""")
        self.path.chmod(0o755)

    def executions(self):
        return len(self.runs.read_text()) if self.runs.exists() else 0

    def engine(self):
        engine = collector.CollectorEngine(str(self.path))
        self.addCleanup(engine.close)
        return engine

    def start(self, engine):
        with self.assertRaises(collector.CollectorError) as raised:
            engine.sample(*CONTEXT)
        return raised.exception

    def test_expected_protocol_is_1(self):
        self.assertEqual(collector.PROTOCOL_VERSION, 1)

    def test_kernel_identity_is_uname_release_and_build(self):
        self.assertEqual(KERNEL_IDENTITY(), (os.uname().release, os.uname().version))

    def test_other_protocol_is_not_run_again_until_the_binary_changes(self):
        self.install("FMCOLLECTOR protocol=2 pf_state_version=5 freebsd_version=1500000 extra=1")
        engine = self.engine()
        for _ in range(3):
            error = self.start(engine)
            self.assertIsInstance(error, collector.CollectorIncompatible)
            self.assertEqual((error.failure_class, error.reason, error.protocol), ("incompatible", "protocol", 2))
            self.assertIn("protocol 2", str(error))
        self.assertEqual((self.executions(), engine.starts), (1, 1))
        self.assertIsNone(engine.process)
        self.kernel.return_value = ("15.0-RELEASE", "build B")  # the kernel does not matter here
        self.start(engine)
        self.assertEqual(self.executions(), 1)
        self.install("FMCOLLECTOR protocol=3 pf_state_version=0 freebsd_version=0")
        self.assertEqual(self.start(engine).protocol, 3)
        self.assertEqual(self.executions(), 2)

    def test_unannounced_protocol_is_unknown(self):
        for banner in ("FMOTHER pf_state_version=0 freebsd_version=0", "garbage", "FMCOLLECTOR protocol=x"):
            with self.subTest(banner=banner):
                self.install(banner)
                error = self.start(self.engine())
                self.assertIsInstance(error, collector.CollectorIncompatible)
                self.assertIsNone(error.protocol)
                self.assertIn("unknown protocol", str(error))

    def test_pf_abi_mismatch_is_not_run_again_on_the_same_binary_and_kernel(self):
        self.install("FMCOLLECTOR protocol=1 pf_state_version=5 freebsd_version=1403000", (3, self.PF_ABI))
        engine = self.engine()
        for _ in range(3):
            error = self.start(engine)
            self.assertIsInstance(error, collector.CollectorIncompatible)
            self.assertEqual((error.failure_class, error.reason, error.protocol), ("incompatible", "pf_abi", 1))
            self.assertEqual((error.collector_pf_state_version, error.running_pf_state_version), (5, 7))
            self.assertIn("PF state version 5, the running kernel uses 7", str(error))
        self.assertEqual((self.executions(), engine.starts), (1, 1))
        # another running kernel: evaluated again (here still incompatible), then latched again
        self.kernel.return_value = ("15.0-RELEASE", "build B")
        self.assertEqual(self.start(engine).reason, "pf_abi")
        self.start(engine)
        self.assertEqual(self.executions(), 2)
        # another binary on the same kernel: evaluated again
        self.install("FMCOLLECTOR protocol=1 pf_state_version=5 freebsd_version=1403000", (3, self.PF_ABI))
        self.start(engine)
        self.start(engine)
        self.assertEqual(self.executions(), 3)

    def test_pf_abi_versions_are_not_invented(self):
        self.install("FMCOLLECTOR protocol=1 pf_state_version=5 freebsd_version=0", (3, b"something else"))
        error = self.start(self.engine())
        self.assertEqual((error.reason, error.collector_pf_state_version, error.running_pf_state_version),
                         ("pf_abi", 5, None))
        self.assertIn("the running kernel uses unknown", str(error))

    def test_ordinary_failures_restart_the_collector(self):
        self.install("FMCOLLECTOR protocol=1 pf_state_version=5 freebsd_version=0", (1, b"truncated dump"))
        engine = self.engine()
        for _ in range(3):
            error = self.start(engine)
            self.assertNotIsInstance(error, collector.CollectorIncompatible)
            self.assertEqual(error.failure_class, "structural")
        self.assertEqual((self.executions(), engine.starts), (3, 3))

    def test_malformed_protocol_1_banner_is_an_ordinary_failure(self):
        self.install("FMCOLLECTOR protocol=1 pf_state_version=x")
        engine = self.engine()
        error = self.start(engine)
        self.assertNotIsInstance(error, collector.CollectorIncompatible)
        self.assertIsNone(error.failure_class)
        self.start(engine)
        self.assertEqual((self.executions(), engine.starts), (2, 2))


class CollectorMemoryTest(unittest.TestCase):
    """Steady-state memory: what C1 (the ranking leak) would have failed."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker", ("-g",))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_samples(self, count, states=2000, mode="many"):
        engine = collector.CollectorEngine(self.worker)
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
