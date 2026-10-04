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

"""Unit tests for the plugin's settings file reader (the OPNsense/FirewallMap template's output)."""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import COLLECTOR, CONFIG  # noqa: E402


class SettingsFileTest(unittest.TestCase):
    def write(self, path, document):
        with open(path, "w") as handle:
            json.dump(document, handle)

    def test_reads_the_rendered_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "firewallmap.json")
            self.write(path, {
                "general": {"provider": "dbip", "license_key": "", "abuseipdb_key": " key ", "update_days": "7",
                            "threat_lists": "", "record_threats": "1", "blocklist_aliases": "0"},
                "aliases": [{"name": "Drop", "type": "urltable", "enabled": True, "description": ""}, {"name": ""}],
                "interfaces": {"igb1": "WAN", "vlan01": "LAN"},
            })
            self.assertEqual(CONFIG.settings(path), {"provider": "dbip", "license_key": "", "update_days": 7,
                             "threat_lists": "", "record_threats": "1", "blocklist_aliases": "0"})
            self.assertEqual(CONFIG.abuseipdb_key(path), "key")
            self.assertEqual([alias["name"] for alias in CONFIG.aliases(path)], ["Drop"])
            self.assertEqual(CONFIG.interface_names(path), {"igb1": "WAN", "vlan01": "LAN"})
            # read again when the file changes
            self.write(path, {"general": {"provider": "nonsense", "update_days": "x"}})
            os.utime(path, ns=(1, 2))
            self.assertEqual((CONFIG.settings(path)["provider"], CONFIG.settings(path)["update_days"]), ("auto", 3))

    def test_a_file_being_written_keeps_the_last_good_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "firewallmap.json")
            self.write(path, {"general": {"provider": "dbip", "blocklist_aliases": "1"}})
            self.assertEqual(CONFIG.settings(path)["provider"], "dbip")
            with open(path, "w") as handle:
                handle.write('{"general": {"prov')  # configd caught in the middle of a write
            os.utime(path, ns=(3, 4))
            with mock.patch.object(CONFIG.time, "sleep"):
                self.assertEqual(CONFIG.settings(path)["blocklist_aliases"], "1")
                self.assertTrue(CONFIG.readable(path))
            # a process that never read it: defaults, and not readable (nothing destructive runs)
            CONFIG._cache.pop(path)
            with mock.patch.object(CONFIG.time, "sleep"):
                self.assertFalse(CONFIG.readable(path))

    def test_the_abuseipdb_table_is_not_emptied_without_settings(self):
        from support import ABUSEIPDB
        calls = []
        with mock.patch.object(ABUSEIPDB, "readable", return_value=False):
            result = ABUSEIPDB.sync_pf_table(run=lambda *a, **k: calls.append(a))
        self.assertEqual((result["loaded"], calls), (False, []))

    def test_defaults_without_the_file(self):
        missing = "/nonexistent/firewallmap.json"
        self.assertEqual(CONFIG.settings(missing)["provider"], "auto")
        self.assertIsNone(CONFIG.abuseipdb_key(missing))
        self.assertEqual((CONFIG.aliases(missing), CONFIG.interface_names(missing)), ([], {}))
        self.assertFalse(CONFIG.widget_in_use(missing))

    def test_widget_in_use_and_recording(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "dashboards.json")
            self.write(path, {"widget_in_use": True})
            self.assertTrue(CONFIG.widget_in_use(path))
            with mock.patch.object(COLLECTOR, "widget_in_use", return_value=True):
                self.assertTrue(COLLECTOR.recording_wanted({"record_threats": "1"}))
                self.assertFalse(COLLECTOR.recording_wanted({"record_threats": "0"}))
            with mock.patch.object(COLLECTOR, "widget_in_use", return_value=False):
                self.assertFalse(COLLECTOR.recording_wanted({"record_threats": "1"}))


if __name__ == "__main__":
    unittest.main()
