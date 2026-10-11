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


# CARP+: the readings of this firewall's CARP and pfsync state, in sections, for
# models/OPNsense/DashboardPlus/Carp.php to parse (configd action dashboardplus system carp).
# The system's own tools only; read fresh on every refresh, as the widget turns the counters into
# rates between two reads.

IFCONFIG=${DASHBOARDPLUS_IFCONFIG:-/sbin/ifconfig}
SYSCTL=${DASHBOARDPLUS_SYSCTL:-/sbin/sysctl}
NETSTAT=${DASHBOARDPLUS_NETSTAT:-/usr/bin/netstat}

echo "@@ifconfig"; "${IFCONFIG}" -L 2> /dev/null
echo "@@sysctl"; "${SYSCTL}" net.inet.carp 2> /dev/null
echo "@@pfsync"; "${IFCONFIG}" pfsync0 2> /dev/null
echo "@@carpstats"; "${NETSTAT}" -s -p carp --libxo json 2> /dev/null; echo
echo "@@pfsyncstats"; "${NETSTAT}" -s -p pfsync --libxo json 2> /dev/null; echo
exit 0
