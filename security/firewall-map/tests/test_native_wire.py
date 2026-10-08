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

"""Raw netlink decoder tests: saved PF captures and their mutations through the real decoder.

The decoder (native/pf_reader.c) compiles only against FreeBSD's pf/netlink headers, which the
repository deliberately does not vendor. On the FreeBSD build host:

    python3 devel/native_equivalence.py live --src src/opnsense/scripts/OPNsense/FirewallMap \
        --helper <native_sample built with -DFM_DEVEL_TOOLS> --dir <directory>    # needs PF access
    FM_WIRE_CAPTURE_DIR=<directory> python3 -m unittest tests.test_native_wire

The check decodes the capture, compares it field by field with pfctl's own export of the same
states, and replays the mutation table (missing NLMSG_DONE, kernel error, wrong sequence,
NLM_F_DUMP_INTR, duplicate and missing attributes, wrong PF state ABI version, truncations),
each of which must fail the whole dump. Elsewhere the test is skipped.
"""

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeWireTest(unittest.TestCase):
    def test_saved_captures_and_mutations(self):
        directory = os.environ.get("FM_WIRE_CAPTURE_DIR")
        if platform.system() != "FreeBSD" or not directory:
            raise unittest.SkipTest("needs FreeBSD and FM_WIRE_CAPTURE_DIR (see the module docstring)")
        with tempfile.TemporaryDirectory() as build:
            helper = Path(build) / "native_sample"
            sources = [str(path) for path in sorted((ROOT / "native").glob("*.c"))
                       if path.name != "firewallmap_native.c"]
            subprocess.run([shutil.which("cc") or "cc", "-O2", "-Wall", "-Wextra", "-Werror", "-DFM_DEVEL_TOOLS",
                            "-I", str(ROOT / "native"), *sources, str(ROOT / "devel/native_fmagg2.c"),
                            str(ROOT / "devel/native_sample.c"), "-lm", "-o", str(helper)], check=True)
            result = subprocess.run([sys.executable, str(ROOT / "devel/native_equivalence.py"), "readercheck",
                                     "--src", str(ROOT / "src/opnsense/scripts/OPNsense/FirewallMap"),
                                     "--helper", str(helper), "--dir", directory],
                                    capture_output=True, text=True, timeout=600)
        self.assertEqual(result.returncode, 0, result.stdout[-4000:] + result.stderr[-4000:])


if __name__ == "__main__":
    unittest.main()
