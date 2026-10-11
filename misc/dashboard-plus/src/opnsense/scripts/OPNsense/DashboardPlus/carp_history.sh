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


# CARP+: the last CARP state changes the kernel logged ("carp: 1@igb1: INIT -> BACKUP (...)"), from
# today's and the previous system log (configd action dashboardplus system carp.history, cached).

LOGS=${DASHBOARDPLUS_SYSTEM_LOGS:-/var/log/system}
COUNT=${DASHBOARDPLUS_CARP_HISTORY:-20}

# the dated logs, newest last (latest.log is a link to today's)
files=$(ls "${LOGS}"/system_*.log 2> /dev/null | sort | tail -n 2)
[ -n "${files}" ] || exit 0
# shellcheck disable=SC2086
grep -h -E 'carp: [0-9]+@[^:]+: [A-Z]+ -> [A-Z]+' ${files} 2> /dev/null | tail -n "${COUNT}"
exit 0
