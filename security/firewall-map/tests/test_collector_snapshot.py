# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Collector snapshot protocol, association, and bounded-resource regression tests."""
import ipaddress
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/opnsense/scripts/OPNsense/FirewallMap"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import collector  # noqa: E402
from collector_build import compile_worker  # noqa: E402


class CollectorSnapshotTest(unittest.TestCase):
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

    def capture(self, mode="one", count=12, byte_limit=collector.SNAPSHOT_BYTES, state_limit=5000,
                select=None, incident=False):
        with patch.dict(os.environ, FM_TEST_MODE=mode, FM_TEST_COUNT=str(count)):
            args = ({"8.8.8.1", "2001:4860::1"}, [], {}, None)
            cold = self.engine.sample(*args)
            warm = self.engine.sample(*args, snapshot=True)
            pages = [row for page in self.engine.snapshot_pages() for row in page]
            identities = [(local, remote, incident) for local, remote, _rank, _order in pages
                          if select is None or select(remote)]
            summary = self.engine.snapshot_selection(identities)
            rows, coverage = self.engine.snapshot_detail(identities, byte_limit, state_limit)
        return cold, warm, summary, rows, coverage

    def test_same_flow_all_states_and_forensic_fields(self):
        cold, warm, summary, rows, meta = self.capture(count=60)
        self.assertEqual(len(rows["9.9.9.9"]), 60)  # no old 50/remote cap
        self.assertEqual(meta["available"], 60)
        self.assertTrue(meta["complete"])
        self.assertFalse(meta["atomic"])
        self.assertEqual(meta["population"], "detail_traversal")
        self.assertEqual(len(summary["flows"]), 1)
        # exemplars are ordered most bytes first: state 50 (forward bytes ... + 49) leads
        self.assertEqual(rows["9.9.9.9"][0]["id"], "0000000000000032")
        row = next(row for row in rows["9.9.9.9"] if row["id"] == "0000000000000001")
        self.assertEqual(row["flow"], {"origin": "8.8.8.1", "dest": "9.9.9.9"})
        self.assertEqual(row["id"], "0000000000000001")
        self.assertEqual(row["creatorid"], "00000007")
        self.assertEqual(row["rule_number"], 19)
        self.assertEqual(row["rule_label"], 'snapshot "rule"')
        self.assertEqual(row["inside"]["address"], "10.0.0.2")
        self.assertEqual(row["interface"], "igb0")
        self.assertEqual(row["original_interface"], "igb1")
        self.assertEqual(row["byte_counters"], [1300, 2600])
        self.assertEqual(row["expire"], 120)
        self.assertNotIn("states", cold)
        self.assertNotIn("states", warm)
        self.assertTrue(cold["baseline"])
        self.assertFalse(warm["baseline"])
        (totals,) = meta["flows"]
        self.assertEqual((totals["matching"], totals["captured"], totals["omitted"]), (60, 60, 0))
        self.assertTrue(meta["required_evidence_complete"])

    def test_multiple_flows_nat_ipv6_icmp_association(self):
        _, _, summary, rows, meta = self.capture("mixed", 18)
        self.assertEqual(meta["captured"], 18)
        self.assertEqual(len(summary["flows"]), 2)
        for remote, records in rows.items():
            for row in records:
                self.assertEqual(row["flow"]["dest"], remote)
                self.assertEqual(ipaddress.ip_address(remote).version, 6 if ":" in remote else 4)
                if row["direction"] == 1 and row["protocol"] == 6:
                    self.assertEqual(row["inside"]["port"], 8443)
                    self.assertEqual(row["wire"][1]["port"], 443)
                    self.assertEqual(row["stack"][1]["port"], 8443)
        self.assertEqual({row["protocol"] for records in rows.values() for row in records}, {1, 6, 58})

    def test_unrelated_excluded_and_selection_beyond_live_150(self):
        _, warm, selected, rows, meta = self.capture("many", 700, select=lambda remote: remote == "9.1.2.187")
        self.assertEqual(len(warm["flows"]), 150)
        self.assertEqual(selected["flows"][0]["key"], ("8.8.8.1", "9.1.2.187"))
        self.assertEqual(meta["captured"], 1)
        self.assertEqual(meta["traversed"], 700)
        self.assertEqual(list(rows), ["9.1.2.187"])

    def test_shuffle_and_churn(self):
        first = self.capture("one", 12)[3]
        self.engine.close()
        shuffled = self.capture("shuffle", 12)[3]
        self.assertEqual({r["id"]: r for r in first["9.9.9.9"]},
                         {r["id"]: r for r in shuffled["9.9.9.9"]})
        self.engine.close()
        rows, meta = self.capture("churn", 12)[3:]
        ids = {row["id"] for row in rows["9.9.9.9"]}
        self.assertNotIn("0000000000000001", ids)
        self.assertIn("000000000000000d", ids)
        self.assertTrue(meta["complete"])  # complete for pass 2, not an atomic pass-1 freeze

    def test_byte_and_count_backstops_and_incident_truncation(self):
        for limit in ({"byte_limit": 1200}, {"state_limit": 2}):
            with self.subTest(limit=limit):
                self.engine.close()
                rows, meta = self.capture(count=12, **limit)[3:]
                self.assertTrue(meta["truncated"])
                self.assertEqual(meta["captured"] + meta["omitted"], 12)
                self.assertLess(meta["captured"], 12)
                self.assertTrue(meta["omission_reasons"])
                self.assertLessEqual(meta["encoded_bytes"], meta["encoded_limit"])
                (totals,) = meta["flows"]
                self.assertEqual((totals["matching"], totals["captured"]), (12, meta["captured"]))
                # exact totals over every matching state, whatever was captured
                self.assertEqual(totals["bytes_from_remote"], 12 * (2000 + 3 * 200))  # the third traversal
                if "state_limit" in limit:
                    self.assertEqual((meta["available"], meta["captured"], meta["omitted"]), (12, 2, 10))
                    self.assertFalse(meta["complete"])
                    self.assertEqual(meta["omission_reasons"], ["per_flow_evidence_limit"])
                    self.assertEqual((totals["omission_reasons"], totals["quota"]), (["per_flow_evidence_limit"], 2))
                    # the two kept are the two with the most bytes
                    self.assertEqual([row["id"] for row in rows["9.9.9.9"]], ["000000000000000c", "000000000000000b"])
                else:
                    self.assertEqual(totals["omission_reasons"], ["encoded_bytes"])
                self.engine.close()
                # incident evidence over the ceiling is truncated and says so; it never fails
                rows, meta = self.capture(count=12, incident=True, **limit)[3:]
                (totals,) = meta["flows"]
                self.assertTrue(totals["required"])
                self.assertFalse(meta["required_evidence_complete"])
                self.assertEqual(totals["matching"], 12)
                self.assertLess(totals["captured"], 12)

    def test_incomplete_reader_and_cross_family_fail_atomically(self):
        for mode in ("incomplete", "cross"):
            self.engine.close()
            with self.subTest(mode=mode), self.assertRaises(collector.CollectorError):
                self.capture(mode)
            self.assertIsNone(self.engine.process)

    def test_session_finishes_and_normal_sample_remains_bounded(self):
        self.capture(count=20)
        self.assertFalse(self.engine.snapshot_open)
        self.engine.snapshot_cancel()  # must not send CANCEL into the next sample parser
        with patch.dict(os.environ, FM_TEST_MODE="one", FM_TEST_COUNT="20"):
            sample = self.engine.sample({"8.8.8.1"}, [], {}, None)
        self.assertEqual(sample["counts"]["states"], 20)
        self.assertNotIn("states", sample)

    def test_protocol_truncated_version_checksum_and_wrong_flow(self):
        row = {"id": "0000000000000001", "creatorid": "00000007",
               "flow": {"origin": "8.8.8.1", "dest": "9.9.9.9"}}
        encoded = json.dumps(row, separators=(",", ":")).encode()

        def response(version=collector.PROTOCOL_VERSION):
            records = [b"\0" + struct.pack("!IQ", version, 2), b"\1" + struct.pack("!I", 0) + encoded,
                       b"\2" + struct.pack("!IQQQQQQQQB", 0, 1, 1, 5, 6, 1, 1, 1, 20, 0)]
            body, checksum = b"", 0
            for record in records:
                framed = struct.pack("!I", len(record)) + record
                body += framed
                checksum = zlib.crc32(framed, checksum)
            cost = len(encoded) + len("9.9.9.9") + 8
            footer = b"\xff" + struct.pack("!QQQQIIQIddd", 1, 1, 1, cost, 0, 2, 0, checksum, 3, 2, 1)
            return b"FMSTATE2" + body + struct.pack("!I", len(footer)) + footer

        valid = response()

        def decode(data, identities=(("8.8.8.1", "9.9.9.9", False),)):
            with tempfile.TemporaryFile() as stream:
                stream.write(data)
                stream.seek(0)
                return collector._decode_detail(stream, Mock(poll=lambda: 0), identities, 2, 4096, 5000)

        # wall-clock times are reported, not required to be ordered
        rows, meta = decode(valid)
        self.assertTrue(meta["complete"])
        self.assertEqual(meta["flows"][0]["bytes_from_remote"], 5)
        self.assertEqual(meta["selection_policy"], "bytes_desc_newest_identity_v1")
        for invalid in (valid[:-1], b"FMAGG4\0\0" + valid[8:], valid[:-26] + b"x" + valid[-25:],
                        response(version=0), response(version=2)):
            with self.subTest(length=len(invalid)), self.assertRaises(collector.CollectorError):
                decode(invalid)
        with self.assertRaises(collector.CollectorError):
            decode(valid, (("8.8.8.2", "9.9.9.9", False),))
        # a flow without its totals record is incomplete evidence accounting
        with self.assertRaises(collector.CollectorError):
            decode(valid, (("8.8.8.1", "9.9.9.9", False), ("8.8.8.1", "9.9.9.8", False)))

    def test_page_header_version(self):
        def decode(version):
            record = b"\0" + struct.pack("!IQQQI", version, 7, 0, 0, 0)
            framed = struct.pack("!I", len(record)) + record
            footer = b"\xff" + struct.pack("!I", zlib.crc32(framed))
            with tempfile.TemporaryFile() as stream:
                stream.write(b"FMPAGE1\0" + framed + struct.pack("!I", len(footer)) + footer)
                stream.seek(0)
                return collector._decode_page(stream, Mock(poll=lambda: 0))

        self.assertEqual(decode(collector.PROTOCOL_VERSION)["generation"], 7)
        for version in (0, 2):
            with self.subTest(version=version), self.assertRaises(collector.CollectorError):
                decode(version)

    def test_exact_encoded_budget(self):
        _, _, _, rows, meta = self.capture(count=1)
        cost = meta["encoded_bytes"]
        self.engine.close()
        self.assertTrue(self.capture(count=1, byte_limit=cost)[4]["complete"])
        self.engine.close()
        self.assertEqual(self.capture(count=1, byte_limit=cost - 1)[4]["captured"], 0)


if __name__ == "__main__":
    unittest.main()
