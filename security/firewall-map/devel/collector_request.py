#!/usr/local/bin/python3
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
"""Usage: collector_request.py [count] [scripts_dir] | FM_PROBE_BACKLOG=1 ./firewallmap-collector

Writes N identical FMCONF2 sample requests built like the collector service builds them
(this host's interfaces, the current classification table, automatic memory budget,
correlation and threat summary on), 2 s apart. Devel measurement only."""
import sys
import time

sys.path.insert(0, sys.argv[2] if len(sys.argv) > 2 else "/usr/local/opnsense/scripts/OPNsense/FirewallMap")
from lib import collector, config, pf  # noqa: E402

local, _role, networks, interfaces = pf.host_info()
wan = config.topology().get("primary_wan_device")
rows, refused = collector._context_rows(local, networks, interfaces, wan)
if refused:
    sys.exit(f"context refused: {refused}")
text = "FMCONF2\n%sBUDGET %d %d %d\nCORRELATION 1\nTHREATS\nRUN\n" % (
    "".join(row + "\n" for row in rows), collector.memory_budget(), collector.CANDIDATES_PER_KIND,
    collector.THREAT_REMOTES)
sys.stderr.write("context: %d rows, %d local, %d networks, wan %s\n" % (len(rows), len(local), len(networks), wan))
for _ in range(int(sys.argv[1]) if len(sys.argv) > 1 else 4):
    sys.stdout.write(text)
    sys.stdout.flush()
    time.sleep(2)
