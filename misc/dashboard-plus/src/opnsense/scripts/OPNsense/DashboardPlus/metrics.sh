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

# System Metrics+, Thermal Sensors+ and System Information+: the raw readings, in sections,
# for models/OPNsense/DashboardPlus/Metrics.php to parse (configd action dashboardplus system
# metrics). A shell and the system's own tools, no interpreter: one sysctl call and pfctl twice
# per refresh; the temperature sensors are found once per boot by walking every sysctl, and
# mbufs, swap and filesystems (netstat -m alone costs 0.1 s of CPU) are read at most once a minute.

SYSCTL=${DASHBOARDPLUS_SYSCTL:-/sbin/sysctl}
PFCTL=${DASHBOARDPLUS_PFCTL:-/sbin/pfctl}
NETSTAT=${DASHBOARDPLUS_NETSTAT:-/usr/bin/netstat}
SWAPINFO=${DASHBOARDPLUS_SWAPINFO:-/usr/sbin/swapinfo}
DF=${DASHBOARDPLUS_DF:-/bin/df}
CACHE=${DASHBOARDPLUS_CACHE:-/var/run/dashboardplus}
NOW=${DASHBOARDPLUS_NOW:-$(date +%s)}
SLOW_SECONDS=60
VALUES="kern.boottime hw.physmem vm.stats.vm.v_page_count vm.stats.vm.v_inactive_count vm.stats.vm.v_cache_count
vm.stats.vm.v_free_count kstat.zfs.misc.arcstats.size vm.loadavg dev.cpu.0.freq dev.cpu.0.freq_levels hw.clockrate"
SENSORS="${CACHE}/sensors.list"
SLOW="${CACHE}/slow.txt"

mkdir -p "${CACHE}" 2> /dev/null

# a temporary file beside the cache, renamed over it: a reader never sees half a file
replace() {
    tmp="$1.$$"
    cat > "${tmp}" 2> /dev/null && mv -f "${tmp}" "$1" 2> /dev/null || rm -f "${tmp}"
}

boot_seconds() {
    # the seconds before "usec": { sec = 1727000000, usec = 123456 } ...
    sed -n 's/^kern\.boottime=[^0-9]*sec = \([0-9][0-9]*\).*/\1/p' | head -n 1
}

# sensors: OIDs in deciKelvin (format IK, printed in Celsius) named as a temperature, or amdtemp
# sensors; settings in the same format (ACPI trip points, coretemp's tjmax) are left out
discover() {
    "${SYSCTL}" -aF 2> /dev/null | awk '
    {
        separator = index($0, ":")
        if (separator == 0) separator = index($0, "=")
        if (separator == 0) next
        name = substr($0, 1, separator - 1)
        gsub(/^[ \t]+|[ \t]+$/, "", name)
        if (name == "" || name ~ / / || (name in seen)) next
        count = split(substr($0, separator + 1), tokens, /[ \t]+/)
        formatted = 0
        for (i = 1; i <= count; i++) if (tokens[i] ~ /^IK[0-9]*$/) formatted = 1
        if (!formatted) next
        parts = split(name, components, ".")
        if (components[parts] == "temperature" || name ~ /^dev\.amdtemp\.[0-9]+\.[A-Za-z0-9_]+\.sensor[0-9]+$/) {
            seen[name] = 1
            print name
        }
    }'
}

known_boot=$(head -n 1 "${SENSORS}" 2> /dev/null)
known=$(tail -n +2 "${SENSORS}" 2> /dev/null)
# shellcheck disable=SC2086
values=$("${SYSCTL}" -i -e ${VALUES} ${known} 2> /dev/null)
boot=$(printf '%s\n' "${values}" | boot_seconds)
if [ -z "${boot}" ] || [ "${boot}" != "${known_boot}" ] || [ ! -f "${SENSORS}" ]; then
    known=$(discover)
    if [ -n "${boot}" ]; then
        printf '%s\n%s\n' "${boot}" "${known}" | replace "${SENSORS}"
    fi
    # shellcheck disable=SC2086
    [ -n "${known}" ] && values=$(printf '%s\n%s' "${values}" "$("${SYSCTL}" -i -e ${known} 2> /dev/null)")
fi

echo "@@values"; printf '%s\n' "${values}"
echo "@@sensors"; [ -n "${known}" ] && printf '%s\n' "${known}"
echo "@@pfinfo"; "${PFCTL}" -si 2> /dev/null
echo "@@pfmemory"; "${PFCTL}" -sm 2> /dev/null

# mbufs, swap and filesystems: from the cache while it is younger than a minute (and not from the
# future, after the clock was set back), otherwise read now and kept when the cache is writable
slow_time=$(sed -n '1s/^@@time \([0-9][0-9]*\)$/\1/p' "${SLOW}" 2> /dev/null)
if [ -n "${slow_time}" ] && [ "${NOW}" -ge "${slow_time}" ] && [ $((NOW - slow_time)) -lt ${SLOW_SECONDS} ]; then
    sed 1d "${SLOW}" 2> /dev/null
else
    slow=$(
        echo "@@time ${NOW}"
        echo "@@mbufs"; "${NETSTAT}" -m --libxo json 2> /dev/null; echo
        echo "@@swap"; "${SWAPINFO}" -k 2> /dev/null
        echo "@@filesystems"; "${DF}" -hT --libxo json / /tmp /var/log 2> /dev/null; echo
    )
    printf '%s\n' "${slow}" | replace "${SLOW}"
    printf '%s\n' "${slow}" | sed 1d
fi
exit 0
