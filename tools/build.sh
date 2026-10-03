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

# Build the plugin packages on an OPNsense machine.
#
#   tools/build.sh                          both plugins, release package names
#   tools/build.sh security/firewall-map    one plugin
#   DEVEL=1 tools/build.sh                  development packages (os-<name>-devel)
#
# OPNsense plugins build with the framework of the opnsense/plugins repository (Mk/,
# Scripts/, Templates/). It is fetched into $WORK at the branch matching this firewall's
# release series, and each plugin is built there unchanged; packages land in ./dist.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERIES="${SERIES:-$(opnsense-version -a 2>/dev/null || echo master)}"
WORK="${WORK:-/tmp/opnsense-plugins-framework}"
UPSTREAM="${UPSTREAM:-https://github.com/opnsense/plugins.git}"
PLUGINS="${*:-misc/dashboard-plus security/firewall-map}"

if [ ! -d "${WORK}/.git" ]; then
    BRANCH="stable/${SERIES}"
    git ls-remote --exit-code --heads "${UPSTREAM}" "${BRANCH}" > /dev/null 2>&1 || BRANCH=master
    echo "Fetching the plugin framework (${BRANCH})"
    git clone -q --depth 1 --branch "${BRANCH}" "${UPSTREAM}" "${WORK}"
else
    git -C "${WORK}" pull -q --ff-only || echo "Warning: could not update ${WORK}, using it as is" >&2
fi

mkdir -p "${ROOT}/dist"
for PLUGIN in ${PLUGINS}; do
    if [ ! -f "${ROOT}/${PLUGIN}/Makefile" ]; then
        echo "No plugin at ${PLUGIN}" >&2
        exit 1
    fi
    echo "Building ${PLUGIN}"
    rm -rf "${WORK:?}/${PLUGIN}"
    mkdir -p "$(dirname "${WORK}/${PLUGIN}")"
    cp -R "${ROOT}/${PLUGIN}" "${WORK}/${PLUGIN}"
    # Bytecode from running the tests locally must not ship in the package.
    find "${WORK}/${PLUGIN}" -name __pycache__ -type d -prune -exec rm -rf {} +
    if [ -n "${DEVEL:-}" ]; then
        (cd "${WORK}/${PLUGIN}" && make PLUGIN_DEVEL=yes package > /dev/null)
    else
        (cd "${WORK}/${PLUGIN}" && make PLUGIN_DEVEL= package > /dev/null)
    fi
    cp "${WORK}/${PLUGIN}"/work/pkg/*.pkg "${ROOT}/dist/"
done
ls -1 "${ROOT}/dist"
