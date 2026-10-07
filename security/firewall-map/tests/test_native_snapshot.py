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

"""Native snapshot protocol, association, and bounded-resource regression tests."""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/opnsense/scripts/OPNsense/FirewallMap"))
from lib import native  # noqa: E402


class NativeSnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable")
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = str(Path(cls.directory.name) / "worker")
        sources = [str(path) for path in sorted((ROOT / "native").glob("*.c")) if path.name != "pf_reader.c"]
        subprocess.run([compiler, "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "native"),
                        *sources, str(ROOT / "devel/native_snapshot_fixture.c"), "-lm", "-o", cls.worker], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.engine = native.NativeEngine(self.worker)
        self.addCleanup(self.engine.close)

    def capture(self, mode="one", count=12, byte_limit=native.SNAPSHOT_BYTES, state_limit=5000,
                select=None, incident=False):
        with patch.dict(os.environ, FM_TEST_MODE=mode, FM_TEST_COUNT=str(count)):
            args = ({"8.8.8.1", "2001:4860::1"}, [], {}, None)
            cold = self.engine.sample(*args, -1)
            warm = self.engine.sample(*args, 2, snapshot=True)
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
        row = rows["9.9.9.9"][0]
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

    def test_byte_and_count_backstops_and_incident_failure(self):
        for limit in ({"byte_limit": 1200}, {"state_limit": 2}):
            with self.subTest(limit=limit):
                self.engine.close()
                rows, meta = self.capture(count=12, **limit)[3:]
                self.assertTrue(meta["truncated"])
                self.assertEqual(meta["captured"] + meta["omitted"], 12)
                self.assertLess(meta["captured"], 12)
                self.assertTrue(meta["omission_reasons"])
                self.assertLessEqual(meta["encoded_bytes"], meta["encoded_limit"])
                if "state_limit" in limit:
                    self.assertEqual((meta["available"], meta["captured"], meta["omitted"]), (12, 2, 10))
                    self.assertFalse(meta["complete"])
                    self.assertEqual(meta["omission_reasons"], ["state_count"])
                self.engine.close()
                with self.assertRaises(native.NativeError):
                    self.capture(count=12, incident=True, **limit)

    def test_incomplete_reader_and_cross_family_fail_atomically(self):
        for mode in ("incomplete", "cross"):
            self.engine.close()
            with self.subTest(mode=mode), self.assertRaises(native.NativeError):
                self.capture(mode)
            self.assertIsNone(self.engine.process)

    def test_session_finishes_and_normal_sample_remains_bounded(self):
        self.capture(count=20)
        self.assertFalse(self.engine.snapshot_open)
        self.engine.snapshot_cancel()  # must not send CANCEL into the next sample parser
        with patch.dict(os.environ, FM_TEST_MODE="one", FM_TEST_COUNT="20"):
            sample = self.engine.sample({"8.8.8.1"}, [], {}, None, 2)
        self.assertEqual(sample["counts"]["states"], 20)
        self.assertNotIn("states", sample)

    def test_protocol_truncated_version_checksum_and_wrong_flow(self):
        row = {"id": "0000000000000001", "creatorid": "00000007",
               "flow": {"origin": "8.8.8.1", "dest": "9.9.9.9"}}
        encoded = json.dumps(row, separators=(",", ":")).encode()
        records = [b"\0" + struct.pack("!IQ", 1, 2), b"\1" + struct.pack("!I", 0) + encoded]
        body, checksum = b"", 0
        for record in records:
            framed = struct.pack("!I", len(record)) + record
            body += framed
            checksum = zlib.crc32(framed, checksum)
        cost = len(encoded) + len("9.9.9.9") + 8
        footer = b"\xff" + struct.pack("!QQQQIIddd", 1, 1, 1, cost, 0, checksum, 1, 2, 3)
        valid = b"FMSTATE1" + body + struct.pack("!I", len(footer)) + footer

        def decode(data, identities=(("8.8.8.1", "9.9.9.9", False),)):
            with tempfile.TemporaryFile() as stream:
                stream.write(data)
                stream.seek(0)
                return native._decode_detail(stream, Mock(poll=lambda: 0), identities, 2, 4096, 5000)

        self.assertTrue(decode(valid)[1]["complete"])
        for invalid in (valid[:-1], b"FMSTATE2" + valid[8:], valid[:-32] + b"x" + valid[-31:]):
            with self.subTest(length=len(invalid)), self.assertRaises(native.NativeError):
                decode(invalid)
        with self.assertRaises(native.NativeError):
            decode(valid, (("8.8.8.2", "9.9.9.9", False),))

    def test_exact_encoded_budget(self):
        _, _, _, rows, meta = self.capture(count=1)
        cost = meta["encoded_bytes"]
        self.engine.close()
        self.assertTrue(self.capture(count=1, byte_limit=cost)[4]["complete"])
        self.engine.close()
        self.assertEqual(self.capture(count=1, byte_limit=cost - 1)[4]["captured"], 0)


if __name__ == "__main__":
    unittest.main()
