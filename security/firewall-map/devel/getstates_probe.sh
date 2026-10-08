#!/bin/sh
# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
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

# Runs devel/getstates_probe with kernel memory snapshots taken before the
# request, while the reply sits unread (halfway through the delay) and after
# the drain, then prints the malloc(9) types and UMA zones that changed.
# Read-only for PF: one GETSTATES dump. Not part of any package.
#
#   getstates_probe.sh PROBE [delay_seconds] [per_datagram_ms]

set -eu
PROBE="$1"
DELAY="${2:-5}"
PER="${3:-0}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/getstates-probe.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

snapshot() {
    vmstat -m > "${WORK}/m.$1"
    vmstat -z > "${WORK}/z.$1"
    netstat -m > "${WORK}/n.$1"
}

# lines that changed between two snapshots (raw, so multi-word type names survive)
changed() {
    diff "${WORK}/$1.$2" "${WORK}/$1.$3" | grep '^[<>]' | sed 's/^/  /' || true
}

snapshot before
"${PROBE}" "${DELAY}" "${PER}" > "${WORK}/result" 2> "${WORK}/stderr" &
PID=$!
sleep "$(echo "${DELAY} / 2" | bc -l)"
snapshot during
wait "${PID}" || true
snapshot after

echo "result: $(cat "${WORK}/result")"
grep -v '^sent$' "${WORK}/stderr" || true
echo "kernel malloc, before -> during (reply unread):"
changed m before during
echo "UMA zones, before -> during:"
changed z before during
echo "kernel malloc, before -> after:"
changed m before after
echo "mbufs during:"
grep -E 'mbufs in use|mbuf clusters in use|bytes allocated to network' "${WORK}/n.during" | sed 's/^/  /'
