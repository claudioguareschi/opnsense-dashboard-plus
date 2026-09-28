#!/bin/sh
# Build the plugin packages on an OPNsense machine.
#
#   ./build.sh                          both plugins, release package names
#   ./build.sh security/firewall-map    one plugin
#   DEVEL=1 ./build.sh                  development packages (os-<name>-devel)
#
# OPNsense plugins build with the framework of the opnsense/plugins repository (Mk/,
# Scripts/, Templates/). It is fetched into $WORK at the branch matching this firewall's
# release series, and each plugin is built there unchanged; packages land in ./dist.

set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
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
