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

"""What the Firewall Map+ scripts read from the configuration: the plugin's settings, the firewall
aliases and the interface names. OPNsense renders them into SETTINGS_FILE from the configuration
(the OPNsense/FirewallMap template) on Apply, on install and after every configuration save; the
scripts never parse config.xml.
"""

import json
import os

from .common import STATE_DIR

SETTINGS_FILE = "/usr/local/etc/firewallmap/firewallmap.json"
# whether any user's dashboard holds the Firewall Map widget (written by dashboards.php)
DASHBOARDS_FILE = f"{STATE_DIR}/dashboards.json"
# every provider the GeoIP updater knows; anything else reads as "auto"
PROVIDERS = ("auto", "maxmind", "maxmind_paid", "dbip")

_cache = {}


def _read(path):
    """The rendered file as a dict, read again only when it changes; {} while it is missing."""
    try:
        stat = os.stat(path)
    except OSError:
        return {}
    key = (stat.st_mtime_ns, stat.st_size)
    cached = _cache.get(path)
    if cached is None or cached[0] != key:
        try:
            with open(path) as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            document = {}
        cached = _cache[path] = (key, document if isinstance(document, dict) else {})
    return cached[1]


def settings(path=SETTINGS_FILE):
    """The plugin's settings, with their defaults."""
    values = {"provider": "auto", "license_key": "", "update_days": 3, "threat_lists": "",
              "record_threats": "1", "blocklist_aliases": "0"}
    general = _read(path).get("general") or {}
    for field in values:
        if str(general.get(field) or "").strip():
            values[field] = str(general[field]).strip()
    try:
        values["update_days"] = max(1, int(values["update_days"]))
    except ValueError:
        values["update_days"] = 3
    if values["provider"] not in PROVIDERS:
        values["provider"] = "auto"
    return values


def abuseipdb_key(path=SETTINGS_FILE):
    return str((_read(path).get("general") or {}).get("abuseipdb_key") or "").strip() or None


def aliases(path=SETTINGS_FILE):
    """Firewall aliases: [{"name", "type", "enabled", "description"}]."""
    return [alias for alias in _read(path).get("aliases") or [] if isinstance(alias, dict) and alias.get("name")]


def interface_names(path=SETTINGS_FILE):
    """Map devices (igb1, vlan01, ...) to their configured names (WAN, LAN, ...)."""
    names = _read(path).get("interfaces")
    return {str(device): str(name) for device, name in names.items()} if isinstance(names, dict) else {}


def widget_in_use(path=DASHBOARDS_FILE):
    """True when any user's dashboard holds the Firewall Map widget."""
    return _read(path).get("widget_in_use") is True
