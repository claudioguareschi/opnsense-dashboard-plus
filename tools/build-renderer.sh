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

# Build Firewall Map+'s browser scripts from security/firewall-map/renderer: the map renderer
# (with deck.gl and luma.gl) and its third-party license file, the map page, and the
# development-only diagnostics panel. Versions are pinned in package-lock.json.
#
#   tools/build-renderer.sh           install, build, test and copy into src/opnsense/www/js
#   tools/build-renderer.sh --check   build and compare with the committed files instead
#
# Needs Node.js 20 or newer and npm (any machine; the output does not depend on it).

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RENDERER="${ROOT}/security/firewall-map/renderer"
TARGET="${ROOT}/security/firewall-map/src/opnsense/www/js"
FILES="dist-firewall-map/firewall-map-renderer.js dist-firewall-map/firewall-map-renderer.LICENSE
dist-firewall-map-page/firewall-map-page.js dist-firewall-map-diagnostics/firewall-map-diagnostics.js"

cd "${RENDERER}"
npm ci --ignore-scripts --no-audit --no-fund
npm run build
npm test

if [ "${1:-}" = "--check" ]; then
    STATUS=0
    # the build regenerates src/text.js from the widget's translations: it must match the commit
    if git -C "${ROOT}" diff --quiet -- security/firewall-map/renderer/src/text.js; then
        echo "same      text.js"
    else
        echo "DIFFERENT text.js (edit the strings in Metadata/FirewallMap.xml)"
        STATUS=1
    fi
    for FILE in ${FILES}; do
        if cmp -s "${FILE}" "${TARGET}/$(basename "${FILE}")"; then
            echo "same      $(basename "${FILE}")"
        else
            echo "DIFFERENT $(basename "${FILE}")"
            STATUS=1
        fi
    done
    exit ${STATUS}
fi

for FILE in ${FILES}; do
    cp "${FILE}" "${TARGET}/"
done
cd "${TARGET}" && shasum -a 256 firewall-map-renderer.js firewall-map-renderer.LICENSE firewall-map-page.js firewall-map-diagnostics.js
