#!/bin/sh

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

# Bounded, reproducible fuzzing of the state collector (not part of the normal test run).
#
#   devel/fuzz/run.sh state [seconds]      portable: PF states through the whole engine
#   devel/fuzz/run.sh netlink [seconds]    FreeBSD build host only: the raw netlink decoder
#
# Needs a clang with libFuzzer (FUZZ_CC, default clang). FUZZ_SANITIZERS defaults to
# fuzzer,address,undefined; use fuzzer,undefined where AddressSanitizer is unavailable.
# Corpora and artifacts go to a temporary directory, never into the repository.

set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${HERE}/../../collector"
TARGET="${1:-state}"
SECONDS_BUDGET="${2:-300}"
CC="${FUZZ_CC:-clang}"
SANITIZERS="${FUZZ_SANITIZERS:-fuzzer,address,undefined}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/firewallmap-fuzz.XXXXXX")"
case "${TARGET}" in
state)
    SOURCES="$(ls "${COLLECTOR}"/*.c | grep -v "/main\.c$")"
    ;;
netlink)
    [ "$(uname -s)" = "FreeBSD" ] || { echo "the netlink target needs FreeBSD's pf headers" >&2; exit 1; }
    SOURCES="${COLLECTOR}/pf_reader.c ${COLLECTOR}/error.c ${COLLECTOR}/protocol.c ${COLLECTOR}/alloc.c"
    ;;
*)
    echo "usage: $0 state|netlink [seconds]" >&2
    exit 2
    ;;
esac
# shellcheck disable=SC2086
"${CC}" -g -O1 -fsanitize="${SANITIZERS}" -fno-sanitize-recover=undefined \
    -fno-sanitize=unsigned-integer-overflow -DFM_DEVEL_TOOLS -I"${COLLECTOR}" ${SOURCES} \
    "${HERE}/fuzz_${TARGET}.c" -lm -o "${WORK}/fuzz_${TARGET}"
mkdir -p "${WORK}/corpus" "${WORK}/artifacts"
if [ -n "${FUZZ_SEEDS:-}" ]; then
    cp "${FUZZ_SEEDS}"/* "${WORK}/corpus/"
fi
echo "fuzzing ${TARGET} for ${SECONDS_BUDGET} s in ${WORK}"
"${WORK}/fuzz_${TARGET}" -max_total_time="${SECONDS_BUDGET}" -seed="${FUZZ_SEED:-1}" \
    -artifact_prefix="${WORK}/artifacts/" "${WORK}/corpus"
