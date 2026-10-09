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

"""The collector's PF state lifetime screen (collector_lifetime_check.c)."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CollectorLifetimeTest(unittest.TestCase):
    def test_lifetime_screen(self):
        compiler = shutil.which("cc")
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable")
        with tempfile.TemporaryDirectory() as directory:
            program = Path(directory) / "lifetime_check"
            subprocess.run([compiler, "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-DFM_TEST_HOOKS",
                            "-I", str(ROOT / "collector"), str(Path(__file__).with_name("collector_lifetime_check.c")),
                            str(ROOT / "collector" / "lifetime.c"), "-o", str(program)], check=True)
            result = subprocess.run([str(program)], capture_output=True, text=True, timeout=60)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "ok"), result.stdout)


if __name__ == "__main__":
    unittest.main()
