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

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
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
                            "threat_lists": "", "record_threats": "1", "blocklist_aliases": "0",
                            "ranking_profile": "6c02d03d-4087-46a9-b5bc-6378fb5eeada", "country_sets": "Country_CN",
                            "operational_sets": " "},
                "aliases": [{"name": "Drop", "type": "urltable", "enabled": True, "description": ""}, {"name": ""}],
                "interfaces": {"igb1": "WAN", "vlan01": "LAN"},
                "topology": {"primary_wan_device": "igb1"},
            })
            expected = {"provider": "dbip", "license_key": "", "update_days": 7, "threat_lists": "",
                        "record_threats": "1", "blocklist_aliases": "0", "helper_memory": None,
                        "ranking_profile": "6c02d03d-4087-46a9-b5bc-6378fb5eeada", "country_sets": "Country_CN",
                        "operational_sets": "", "carp_backup_view": "mirror", "interval_min": 2, "interval_max": 60}
            self.assertEqual(CONFIG.settings(path), expected)
            self.assertEqual(CONFIG.abuseipdb_key(path), "key")
            self.assertEqual([alias["name"] for alias in CONFIG.aliases(path)], ["Drop"])
            self.assertEqual(CONFIG.interface_names(path), {"igb1": "WAN", "vlan01": "LAN"})
            self.assertEqual(CONFIG.topology(path), {"primary_wan_device": "igb1", "discover_external_ip": False,
                                                      "latitude": None, "longitude": None})
            # sampling interval bounds: valid ones kept, inverted or out of range ones back to the defaults
            for low, high, expected in (("5", "30", (5, 30)), ("30", "5", (2, 60)), ("1", "30", (2, 60)),
                                        ("2", "301", (2, 60)), ("x", "30", (2, 60))):
                self.write(path, {"general": {"interval_min": low, "interval_max": high}})
                os.utime(path, ns=(len(low) + len(high), int(low) if low.isdigit() else 7))
                values = CONFIG.settings(path)
                self.assertEqual((values["interval_min"], values["interval_max"]), expected, (low, high))
            # read again when the file changes
            self.write(path, {"general": {"provider": "nonsense", "update_days": "x"}})
            os.utime(path, ns=(1, 2))
            self.assertEqual((CONFIG.settings(path)["provider"], CONFIG.settings(path)["update_days"]), ("auto", 3))
            for stamp, (memory, expected) in enumerate((("512", 512), ("63", None), ("16385", None),
                                                        ("lots", None), ("", None)), start=10):
                self.write(path, {"general": {"helper_memory": memory}})
                os.utime(path, ns=(stamp, stamp))  # a distinct mtime: the reader caches by it
                self.assertEqual(CONFIG.settings(path)["helper_memory"], expected)

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



class RankingProfileSettingTest(unittest.TestCase):
    def test_the_setting_names_a_builtin_by_uuid_and_classic_is_not_offered(self):
        model = (Path(__file__).resolve().parents[1]
                 / "src/opnsense/mvc/app/models/OPNsense/FirewallMap/FirewallMap.xml").read_text()
        default = re.search(r"<ranking_profile[^>]*>.*?<Default>([^<]+)</Default>", model, re.S).group(1)
        profiles = COLLECTOR.ranking_profiles
        self.assertEqual(default, profiles.DEFAULT)
        self.assertEqual(profiles.BY_UUID[default]["name"], "Balanced")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            COLLECTOR.main(["profiles"])
        catalog = json.loads(output.getvalue())
        self.assertEqual([item["name"] for item in catalog["profiles"]],
                         ["Balanced", "Bandwidth", "Connections", "Security"])
        self.assertEqual(catalog["default"], profiles.DEFAULT)
        self.assertNotIn("classic", output.getvalue().lower())
        # an unknown or empty setting is the default, never another ranking
        self.assertEqual(profiles.resolve({"ranking_profile": ""}), (profiles.validate(profiles.BY_UUID[profiles.DEFAULT]), None))
        resolved, problem = profiles.resolve({"ranking_profile": "not-a-profile"})
        self.assertEqual((resolved["uuid"], bool(problem)), (profiles.DEFAULT, True))

    def test_the_service_never_starts_the_collector_without_a_profile(self):
        """Classic is a test oracle only: the engine has no default profile, so production code cannot
        reach the base ranking by omission, and resolution always yields a validated profile (the
        configured one, or Balanced with the reason) for the service to pass."""
        with self.assertRaises(TypeError):
            COLLECTOR.state_collector.CollectorEngine("/nonexistent/firewallmap-collector")
        profiles = COLLECTOR.ranking_profiles
        for values, rows in (({}, []), ({"ranking_profile": profiles.SECURITY}, []),
                             ({"ranking_profile": "missing"}, []), ({"ranking_profile": "x"}, [{"uuid": "x"}])):
            profile, _problem = profiles.resolve(values, rows)
            self.assertEqual(profiles.validate(profile), profile)

if __name__ == "__main__":
    unittest.main()
