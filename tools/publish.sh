#!/bin/sh

# Copyright (C) 2026 Claudio Guareschi <cguareschi@gmail.com>
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

# Sign the package feed (run on the machine that holds the repository signing key).
#
#   tools/publish.sh <feed checkout> [package ...]
#
# <feed checkout> is a checkout of this repository's `packages` branch. The given release
# packages (default: everything in ./dist) replace older versions of the same package in
# repo/<series>, and the whole catalogue is signed again: pkg lists only what is in the folder
# at signing time, so every package of the feed must be present. Commit and push the feed
# checkout afterwards.

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FEED="${1:?usage: $0 <feed checkout> [package ...]}"
shift
SERIES="${SERIES:-$(opnsense-version -a)}"
KEY="${KEY:-/root/dashboard-plus-repository.key}"
DIR="${FEED}/repo/${SERIES}"

if [ "$#" -eq 0 ]; then
    set -- "${ROOT}"/dist/*.pkg
fi
mkdir -p "${DIR}"
for PACKAGE in "$@"; do
    NAME="$(pkg query -F "${PACKAGE}" %n)"
    case "${NAME}" in
        *-devel) echo "Refusing development package ${PACKAGE}" >&2; exit 1 ;;
    esac
    for OLD in "${DIR}/${NAME}"-[0-9]*.pkg; do
        [ -e "${OLD}" ] && [ "$(pkg query -F "${OLD}" %n)" = "${NAME}" ] && rm -f "${OLD}"
    done
    cp "${PACKAGE}" "${DIR}/"
done
pkg repo "${DIR}" "rsa:${KEY}"
# pkg 2.x writes the catalogue as *.pkg, older pkg as *.tzst; a client may ask for either name,
# so a leftover *.tzst must never keep serving an old catalogue
for ARCHIVE in packagesite data; do
    cp "${DIR}/${ARCHIVE}.pkg" "${DIR}/${ARCHIVE}.tzst"
done
ls -1 "${DIR}"
