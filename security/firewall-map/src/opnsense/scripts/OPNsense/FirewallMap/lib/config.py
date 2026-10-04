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

"""The plugin's firewall-wide settings (OPNsense/FirewallMap/general in config.xml), read by the
collector, the updaters and the API helpers."""

from xml.etree import ElementTree

from .common import CONFIG_XML, config_root

# every provider the GeoIP updater knows; anything else in config.xml reads as "auto"
PROVIDERS = ("auto", "maxmind", "maxmind_paid", "dbip")


def settings(path=CONFIG_XML):
    """Read the plugin's firewall-wide settings straight from config.xml."""
    values = {"provider": "auto", "license_key": "", "update_days": 3, "threat_lists": "",
              "record_threats": "1", "blocklist_aliases": "0"}
    try:
        general = config_root(path).find("./OPNsense/FirewallMap/general")
    except (OSError, ElementTree.ParseError):
        general = None
    if general is not None:
        for field in values:
            node = general.find(field)
            if node is not None and node.text:
                values[field] = node.text.strip()
    try:
        values["update_days"] = max(1, int(values["update_days"]))
    except ValueError:
        values["update_days"] = 3
    if values["provider"] not in PROVIDERS:
        values["provider"] = "auto"
    return values
