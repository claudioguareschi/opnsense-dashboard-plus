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

# The map's poll (configd "firewallmap flow summary", every 2 seconds per open map), without
# starting Python: mark the collector as in use, as flow_summary.py does, and print the summary the
# collector wrote, as {"modified": <its mtime>, "summary": <flows.json>}. The API adds the age and
# applies the viewer's block threshold and host name setting.
#
# flow_summary.py answers instead, as {"summary": <its document>}, whenever it has more to do: the
# summary is old or missing (the collector must be started), there is no geolocation database, or
# the geolocation download reports errors (the map shows them, and a retry may be due).
#
#     flow_summary.sh [hostnames]

RUN_DIR=/var/run/firewallmap
STATE_DIR=/var/db/firewallmap
PYTHON=/usr/local/bin/python3
FLOW_SUMMARY=/usr/local/opnsense/scripts/OPNsense/FirewallMap/flow_summary.py

SUMMARY=${RUN_DIR}/flows.json
GEODB_STATUS=${STATE_DIR}/geodb.json
# whole seconds on both clocks: an age of 9 here is under flow_summary.py's 10 s, however the
# fractions fall
FRESH_SECONDS=9

# owner and group only, like everything else in RUN_DIR (secure_umask() in the Python scripts)
umask 027

# a dashboard is watching: the collector keeps running (and reverse DNS, for viewers who use it)
mkdir -p "${RUN_DIR}" 2>/dev/null
touch "${RUN_DIR}/last_request" 2>/dev/null
for argument in "$@"; do
	if [ "${argument}" = "hostnames" ]; then
		touch "${RUN_DIR}/hostnames_request" 2>/dev/null
	fi
done

python_answers()
{
	printf '{"summary":'
	"${PYTHON}" "${FLOW_SUMMARY}" "$@"
	printf '}\n'
	exit 0
}

modified=$(date -r "${SUMMARY}" +%s 2>/dev/null) || python_answers "$@"
now=$(date +%s)
[ $((now - modified)) -le ${FRESH_SECONDS} ] || python_answers "$@"

# the map waits for a database (and may have to start its download): flow_summary.py says so
case "$(head -c 24 "${SUMMARY}" 2>/dev/null)" in
'{"status":"no_database"'*)
	python_answers "$@"
	;;
'{"status":"'*)
	;;
*)
	python_answers "$@"
	;;
esac

# Any error recorded by the geolocation download: a non-empty "errors" (also the DB-IP stand-in's),
# or an older version's "last_error" other than the missing MaxMind key. When in doubt, Python.
if [ -f "${GEODB_STATUS}" ]; then
	if grep -Eq '"errors":[[:space:]]*(\[[[:space:]]*[^][:space:]]|[^[:space:]n[])' "${GEODB_STATUS}"; then
		python_answers "$@"
	fi
	if grep -Eo '"last_error":[[:space:]]*"[^"]*' "${GEODB_STATUS}" | grep -Evq '^"last_error":[[:space:]]*"maxmind_key_missing$'; then
		python_answers "$@"
	fi
fi

summary=$(cat "${SUMMARY}" 2>/dev/null)
[ -n "${summary}" ] || python_answers "$@"
printf '{"modified":%s,"summary":%s}\n' "${modified}" "${summary}"
