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


"""The development tools (devel/*.c, devel/fuzz/*.c) keep compiling against the collector's
current interfaces; they are not part of the package, so nothing else would notice."""

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# needs FreeBSD's pf headers
FREEBSD_ONLY = {"getstates_probe.c", "fuzz_netlink.c", "collector_cost.c"}


class DevelToolsTest(unittest.TestCase):
    def test_every_tool_compiles(self):
        compiler = shutil.which("cc")
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable")
        sources = sorted((ROOT / "devel").glob("*.c")) + sorted((ROOT / "devel/fuzz").glob("*.c"))
        self.assertTrue(sources)
        for source in sources:
            if source.name in FREEBSD_ONLY:
                continue
            with self.subTest(tool=source.name):
                result = subprocess.run([compiler, "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-DFM_TEST_HOOKS",
                                         "-DFM_DEVEL_TOOLS", "-I", str(ROOT / "collector"), str(source)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
