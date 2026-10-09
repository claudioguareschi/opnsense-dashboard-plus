# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
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

"""The settings page's forms: the tabs it is organized in and the profile grid's columns."""

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

MVC = Path(__file__).resolve().parents[1] / "src/opnsense/mvc/app"
FORMS = MVC / "controllers/OPNsense/FirewallMap/forms"
MODEL = MVC / "models/OPNsense/FirewallMap/FirewallMap.xml"


class SettingsFormTest(unittest.TestCase):
    def setUp(self):
        self.form = ET.parse(FORMS / "settings.xml").getroot()

    def test_four_tabs_in_order(self):
        """General, Geolocation and Security hold the settings; Profiles is the page's grid tab."""
        self.assertEqual([(tab.get("id"), tab.get("description")) for tab in self.form],
                         [("general", "General"), ("geolocation", "Geolocation"), ("security", "Security")])
        settings = (MVC / "views/OPNsense/FirewallMap/settings.volt").read_text()
        self.assertIn('href="#tab_profiles"', settings)

    def test_every_setting_is_on_exactly_one_tab(self):
        """One model behind every tab: each general field is shown once (the active profile is
        chosen in the Profiles grid)."""
        model = [field.tag for field in ET.parse(MODEL).getroot().find("./items/general")]
        shown = [field.findtext("id").removeprefix("firewallmap.general.")
                 for field in self.form.iter("field") if (field.findtext("id") or "").startswith("firewallmap.")]
        self.assertEqual(sorted(shown), sorted(set(shown)), "a field is shown twice")
        self.assertEqual(sorted(shown), sorted(set(model) - {"ranking_profile"}))

    def test_fields_are_on_their_tabs(self):
        tabs = {tab.get("id"): [field.findtext("id") for field in tab.iter("field") if field.findtext("id")]
                for tab in self.form}
        self.assertIn("firewallmap.general.latitude", tabs["general"])
        self.assertIn("firewallmap.general.provider", tabs["geolocation"])
        self.assertIn("firewallmap.general.threat_lists", tabs["security"])
        self.assertIn("firewallmap.general.record_threats", tabs["security"])

    def test_profile_grid_columns(self):
        """Active (the native row toggle) and Type are grid-only columns, never dialog fields."""
        dialog = ET.parse(FORMS / "dialogProfile.xml").getroot()
        columns = {field.findtext("id"): field for field in dialog.iter("field") if field.findtext("id")}
        active, builtin = columns["profile.active"], columns["profile.builtin"]
        self.assertEqual((active.findtext("type"), active.findtext("grid_view/formatter")), ("ignore", "rowtoggle"))
        self.assertEqual((builtin.findtext("type"), builtin.findtext("grid_view/formatter")),
                         ("ignore", "profile_type"))


if __name__ == "__main__":
    unittest.main()
