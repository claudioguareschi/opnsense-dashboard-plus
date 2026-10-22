#!/bin/sh
# Install the signed Dashboard Plus package feed for OPNsense 26.7 amd64.

set -eu

BASE_URL='https://raw.githubusercontent.com/claudioguareschi/opnsense-dashboard-plus/packages'
KEY_DIR='/usr/local/etc/pkg/keys'
KEY_PATH="${KEY_DIR}/dashboard-plus-repository.pub"
REPO_PATH='/usr/local/etc/pkg/repos/dashboard-plus.conf'

if [ "$(id -u)" -ne 0 ]; then
    echo 'Run this installer as root.' >&2
    exit 1
fi

TEMP_DIR="$(mktemp -d /tmp/dashboard-plus-repository.XXXXXX)"
trap 'rm -rf "${TEMP_DIR}"' EXIT HUP INT TERM

fetch -qo "${TEMP_DIR}/dashboard-plus-repository.pub" \
    "${BASE_URL}/dashboard-plus-repository.pub"
fetch -qo "${TEMP_DIR}/dashboard-plus.conf" \
    "${BASE_URL}/dashboard-plus.conf"

install -d -m 0755 "${KEY_DIR}" /usr/local/etc/pkg/repos
install -m 0644 "${TEMP_DIR}/dashboard-plus-repository.pub" "${KEY_PATH}"
install -m 0644 "${TEMP_DIR}/dashboard-plus.conf" "${REPO_PATH}"

pkg update -f

echo 'Dashboard Plus repository added. Open System -> Firmware -> Plugins to install os-dashboard-plus or os-firewall-map.'
