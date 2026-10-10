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

"""Free text from the browser to the scripts: ConfigdArgument::text cuts and encodes it in PHP,
decode_text/decode_note read it back in Python; and each note's limits agree from the page to the
database (the textarea's maxlength, the controller's byte cut, the script's character limit)."""

import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import SNAPSHOTS, THREATS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MVC = ROOT / "src/opnsense/mvc/app"
ARGUMENT = MVC / "models/OPNsense/FirewallMap/ConfigdArgument.php"
API = MVC / "controllers/OPNsense/FirewallMap/Api"
# configd reads one message of 4 kB: an encoded argument must leave room for the rest of the command
CONFIGD_ARGUMENT = 3500

TEXTS = ["", "   ", "plain note", "  padded  ", "Zürich – São Paulo", "東京の攻撃元", "🔥🛡️ blocked",
         "e\u0301 combining", "x" * 5000, "語" * 2000, "🔥" * 1000, "a" + "語" * 1000]


def encode(texts, limit):
    """ConfigdArgument::text in the PHP command line, for each text."""
    code = ("namespace { require getenv('ARGUMENT'); foreach (json_decode(file_get_contents('php://stdin')) as $t) "
            "{ echo OPNsense\\FirewallMap\\ConfigdArgument::text($t, (int)getenv('LIMIT')), \"\\n\"; } }")
    result = subprocess.run(["php", "-r", code], input=json.dumps(texts), capture_output=True, text=True, check=True,
                            env=dict(os.environ, ARGUMENT=str(ARGUMENT), LIMIT=str(limit)))
    return result.stdout.split("\n")[:len(texts)]


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class RoundTripTest(unittest.TestCase):
    def test_text_survives_the_trip_cut_on_a_character(self):
        for limit in (256, 1500, 2400):
            for text, encoded in zip(TEXTS, encode(TEXTS, limit), strict=True):
                with self.subTest(limit=limit, text=text[:20]):
                    self.assertRegex(encoded, r"^(-|[A-Za-z0-9_-]+)$", "base64url, no padding")
                    self.assertLessEqual(len(encoded), CONFIGD_ARGUMENT)
                    decoded = SNAPSHOTS.decode_text(encoded, 10**6)
                    # the trimmed text, cut to the byte limit on a character boundary: a prefix
                    stripped = text.strip()
                    self.assertTrue(stripped.startswith(decoded))
                    self.assertLessEqual(len(decoded.encode()), limit)
                    self.assertGreater(len(decoded.encode()) + 4, min(limit, len(stripped.encode())))
                    if encoded != "-":
                        self.assertEqual(THREATS.decode_note(encoded), decoded)


class LimitsTest(unittest.TestCase):
    """One note, one limit: what the page lets one type is what the script keeps, and the controller
    carries it at three bytes a character (any script; four-byte emoji count double)."""

    def page_limit(self, module, marker):
        source = (ROOT / "renderer/page" / module).read_text()
        line = next(line for line in source.splitlines() if marker in line and "maxlength" in line)
        return int(re.search(r'maxlength="(\d+)"', line).group(1))

    def test_snapshot_note(self):
        self.assertEqual(self.page_limit("snapshots.js", "<textarea"), SNAPSHOTS.MAX_NOTE)
        source = (API / "SnapshotsController.php").read_text()
        self.assertIn(f"ConfigdArgument::text($this->request->getPost('note') ?? '', {3 * SNAPSHOTS.MAX_NOTE})", source)
        self.assertIn("ConfigdArgument::text($user, 256)", source)
        self.assertGreaterEqual(256, 3 * SNAPSHOTS.MAX_USER)

    def test_threat_note(self):
        self.assertEqual(self.page_limit("queue.js", "<textarea"), THREATS.MAX_NOTE)
        self.assertIn(f"NOTE_BYTES = {3 * THREATS.MAX_NOTE};", (API / "ThreatsController.php").read_text())


if __name__ == "__main__":
    unittest.main()
