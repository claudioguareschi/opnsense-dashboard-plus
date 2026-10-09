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

"""The inputs kept under devel/fuzz/regressions/ replayed through their fuzz targets.

Each target is linked exactly as devel/fuzz/run.sh links it (every collector source but
main.c), with the replay driver (devel/fuzz/replay.c) in place of libFuzzer, under
UndefinedBehaviorSanitizer and, where it works, AddressSanitizer: any sanitizer report
aborts the replay. The netlink target needs FreeBSD's pf headers (the build host)."""

import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUZZ = ROOT / "devel/fuzz"


def build(target, output):
    compiler = shutil.which("cc")
    if not compiler:
        raise unittest.SkipTest("C compiler unavailable")
    # AddressSanitizer hangs at startup on macOS (Apple clang); FreeBSD runs both
    sanitizers = "address,undefined" if platform.system() == "FreeBSD" else "undefined"
    sources = [str(path) for path in sorted((ROOT / "collector").glob("*.c")) if path.name != "main.c"]
    subprocess.run([compiler, "-std=c11", "-g", "-O1", f"-fsanitize={sanitizers}", "-fno-sanitize-recover=all",
                    "-DFM_DEVEL_TOOLS", "-I", str(ROOT / "collector"), *sources, str(FUZZ / f"fuzz_{target}.c"),
                    str(FUZZ / "replay.c"), "-lm", "-o", str(output)], check=True)
    return output


class FuzzRegressionTest(unittest.TestCase):
    def replay(self, target):
        inputs = FUZZ / "regressions" / target
        kept = sorted(path for path in inputs.iterdir() if path.is_file())
        self.assertTrue(kept)
        with tempfile.TemporaryDirectory() as directory:
            program = build(target, Path(directory) / f"replay_{target}")
            result = subprocess.run([str(program), str(inputs)], capture_output=True, text=True, timeout=300)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, f"replayed {len(kept)}"), result.stderr)

    def test_state_engine_regressions(self):
        """Portable: the state target links from the current collector sources and replays clean."""
        self.replay("state")

    def test_netlink_decoder_regressions(self):
        if platform.system() != "FreeBSD":
            raise unittest.SkipTest("the netlink decoder needs FreeBSD's pf headers")
        self.replay("netlink")


if __name__ == "__main__":
    unittest.main()
