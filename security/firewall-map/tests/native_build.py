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

"""Builds the production helper with the synthetic PF reader for tests (no PF access).

The fixture (devel/native_snapshot_fixture.c) replaces only pf_reader.c; every other native
source is the shipped code. FM_TEST_MODE, FM_TEST_COUNT and FM_TEST_INTERVAL select the
synthetic state table and make sample anchors deterministic.
"""

import os
import shlex
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ("-O2", "-Wall", "-Wextra", "-Werror")


def compile_worker(output, extra_flags=()):
    """FM_NATIVE_TEST_CC and FM_NATIVE_TEST_FLAGS select a sanitizer build, e.g.
    FM_NATIVE_TEST_CC=clang FM_NATIVE_TEST_FLAGS="-g -fsanitize=undefined -fno-sanitize-recover=all"."""
    compiler = shutil.which(os.environ.get("FM_NATIVE_TEST_CC", "cc"))
    if not compiler:
        raise unittest.SkipTest("C compiler unavailable")
    extra_flags = (*extra_flags, *shlex.split(os.environ.get("FM_NATIVE_TEST_FLAGS", "")))
    sources = [str(path) for path in sorted((ROOT / "native").glob("*.c")) if path.name != "pf_reader.c"]
    subprocess.run([compiler, *FLAGS, *extra_flags, "-I", str(ROOT / "native"), *sources,
                    str(ROOT / "devel/native_snapshot_fixture.c"), "-lm", "-o", str(output)], check=True)
    return str(output)
