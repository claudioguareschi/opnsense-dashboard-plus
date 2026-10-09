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

"""Request rows the collector refuses (collector main.c read_request, read_line).

A row is at most 512 bytes, newline included; a longer one, a NUL byte, a last row without its
newline or a second W row is a request error. The collector answers FMFAIL1 and exits, so a row
after a refused one is never parsed: nothing can desynchronize. Through the real worker."""

import os
import struct
import subprocess
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
LINE_MAX = 512


class RequestRowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        patcher = patch.dict(os.environ, FM_TEST_MODE="one", FM_TEST_INTERVAL="2")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.engine = collector.CollectorEngine(self.worker, profile=BALANCED)
        self.addCleanup(self.engine.close)

    def send(self, rows):
        self.engine._start()
        text = f"FMCONF2\nBUDGET {collector.memory_budget()} 16 20000\n{rows}"
        return self.engine._request(text, lambda stream, process: collector._decode(stream, process, (), False))

    def refused(self, rows, message):
        with self.assertRaises(collector.CollectorError) as raised:
            self.send(rows)
        self.assertEqual(raised.exception.failure_class, "request")
        self.assertIn(message, str(raised.exception))
        self.assertIsNone(self.engine.process, "the collector exits after a refused request")
        # the next request starts a fresh collector and is answered
        self.assertIsNone(self.engine.sample(*CONTEXT)["refused"])

    def test_a_row_at_the_maximum_is_accepted(self):
        row = "W wan0".ljust(LINE_MAX - 1) + "\n"
        self.assertEqual(len(row), LINE_MAX)
        self.assertIsNone(self.send(row + "RUN\n")["refused"])

    def test_a_row_one_byte_over_is_refused(self):
        row = "W wan0".ljust(LINE_MAX) + "\n"
        self.refused(row + "RUN\n", "request row too long")

    def direct(self, data):
        """The collector given `data` on a closed input (it may exit before reading it all):
        its FMFAIL1 message."""
        profile = Path(self.directory.name) / "profile.json"
        profile.write_text(profiles.startup_text(BALANCED))
        result = subprocess.run([self.worker, "--profile", str(profile)], input=data, capture_output=True,
                                timeout=60)
        out = result.stdout
        start = out.find(b"FMFAIL1\0")
        self.assertGreaterEqual(start, 0, out[:200])
        length, = struct.unpack_from("!I", out, start + 8)
        record = out[start + 12:start + 12 + length]
        return record[9:].decode()

    def test_a_very_large_row_is_refused_and_what_follows_is_never_read(self):
        # 2 MB: never buffered (the collector stops after 512 bytes and exits, while the rest is
        # still being written); the malformed row after it never reaches the parser
        rows = b"FMCONF2\nK " + b"1" * (2 << 20) + b"\nBOGUS ROW\nRUN\n"
        self.assertEqual(self.direct(rows), "request row too long")

    def test_a_nul_byte_is_refused_not_truncated(self):
        # parsed as a C string, "W wan0" would pass and the rest would vanish
        self.refused("W wan0\x00 ignored\nRUN\n", "NUL byte")

    def test_a_second_w_row_is_refused(self):
        self.refused("W wan0\nW wan1\nRUN\n", "duplicate request keyword")

    def test_a_last_row_without_a_newline_is_refused(self):
        # on an open pipe the collector waits for the rest of the row; at the end of its input
        # the incomplete row is refused, never taken for RUN
        self.assertEqual(self.direct(b"FMCONF2\nRUN"), "request row without a newline")

    def test_every_single_keyword_row_is_single(self):
        for row in ("THREATS\n", "SNAPSHOT\n", "CORRELATION 1\n", "MIRROR 0\n", "CLASSGEN g1\n", "W wan0\n"):
            with self.subTest(row=row.strip()):
                self.refused(row + row + "RUN\n", "duplicate request keyword")
        self.refused(f"BUDGET {collector.memory_budget()} 16 20000\nRUN\n", "duplicate request keyword")

    def test_the_service_request_is_answered(self):
        result = self.engine.sample(*CONTEXT, threat_summary=True, carp_backup={"8.8.8.9"}, mirror=True)
        self.assertIsNone(result["refused"])


if __name__ == "__main__":
    unittest.main()
