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

import json
import os
import shutil
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

MVC = Path(__file__).resolve().parents[1] / "src/opnsense/mvc/app"
FORMS = MVC / "controllers/OPNsense/FirewallMap/forms"
MODEL = MVC / "models/OPNsense/FirewallMap/FirewallMap.xml"
SET_FIELD = MVC / "models/OPNsense/FirewallMap/FieldTypes/ClassificationSetField.php"


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
        self.assertIn("firewallmap.general.record_threats", tabs["general"])
        # settings only: what the evidence sources are doing is the Status page's
        self.assertFalse([field for field in self.form.iter("field") if field.findtext("type") == "info"])


    def test_operational_sections_are_advanced(self):
        """OPNsense's own advanced mode (a header and every field in its section marked advanced)
        hides the map location, high availability and collector resources; classification and
        logging stay visible."""
        general = self.form.find("tab[@id='general']")
        section, sections = None, {None: []}
        for field in general.iter("field"):
            if field.findtext("type") == "header":
                section = field.findtext("label")
                sections[section] = [field.findtext("advanced") == "true"]
            else:
                sections[section].append(field.findtext("advanced") == "true")
        for label in ("Firewall map location", "High availability"):
            self.assertTrue(all(sections[label]), label)
        for label in (None, "Classification sets", "Logging"):
            self.assertFalse(any(sections[label]), label)
        # Collector: its header and the flows on the map stay visible, the tuning is advanced
        self.assertEqual(sections["Collector"], [False, False, True, True, True])
        # first, before any section: recording threats with the map closed
        self.assertEqual(general.find("field").findtext("id"), "firewallmap.general.record_threats")
        for tab in ("geolocation", "security"):
            self.assertFalse(any(field.findtext("advanced") for field in self.form.find(f"tab[@id='{tab}']").iter("field")))

    def field(self, key):
        return next(field for field in self.form.iter("field")
                    if field.findtext("id") == f"firewallmap.general.{key}")

    def test_public_ip_discovery_is_not_geolocation(self):
        """The external service finds the public address; the configured geolocation service places
        it (map_anchor in firewallmap_collector.py)."""
        discovery = self.field("discover_external_ip")
        self.assertEqual(discovery.findtext("label"), "Use external public IP discovery")
        self.assertIn("api.ipify.org", discovery.findtext("help"))
        self.assertIn("geolocated with the configured geolocation service", discovery.findtext("help"))
        for key in ("latitude", "longitude"):
            self.assertIn("leave both empty to locate the firewall from its public IP", self.field(key).findtext("help"))

    def test_maximum_flows_on_the_map(self):
        """The collector's --flows: 25 to 1000 ranked flows, 150 when the setting is absent."""
        flows = self.field("max_flows")
        self.assertEqual(flows.findtext("label"), "Maximum flows on the map")
        self.assertIsNone(flows.findtext("advanced"))
        self.assertIn("does not limit firewall states", flows.findtext("help"))
        self.assertNotIn("tracked", flows.findtext("help").lower())
        model = ET.parse(MODEL).getroot().find("./items/general/max_flows")
        self.assertEqual((model.get("type"), model.findtext("Required"), model.findtext("Default"),
                          model.findtext("MinimumValue"), model.findtext("MaximumValue")),
                         ("IntegerField", "Y", "150", "25", "1000"))
        budget = (MVC.parents[3] / "collector/budget.h").read_text()
        for name, value in (("DEFAULT", "150"), ("MIN", "25"), ("MAX", "1000")):
            self.assertIn(f"#define BUDGET_RANKED_FLOWS_{name} {value}\n", budget)

    def test_country_blocklists_keep_their_key(self):
        """Renamed in the form only: the configuration keys stay country_sets and operational_sets."""
        self.assertEqual(self.field("country_sets").findtext("label"), "Country blocklists")
        self.assertIn("blocks nothing", self.field("country_sets").findtext("help"))
        self.assertEqual(self.field("operational_sets").findtext("label"), "Operational sets")
        general = ET.parse(MODEL).getroot().find("./items/general")
        self.assertEqual(general.find("country_sets").findtext("AliasType"), "geoip")
        self.assertIsNone(general.find("operational_sets").find("AliasType"))

    def test_a_new_profile_starts_as_balanced(self):
        """The grid's + adds a profile from the model's defaults: Balanced's weights and shares, a
        valid policy to edit (the weights total 100), never eleven zeros."""
        sys.path.insert(0, str(MVC.parents[1] / "scripts/OPNsense/FirewallMap"))
        from lib import profiles
        balanced = profiles.BY_UUID[profiles.BALANCED]
        row = ET.parse(MODEL).getroot().find("./items/profiles/profile")
        weights = {key: int(row.find(key).findtext("Default")) for key in profiles.FEATURES}
        floors = {key: int(row.find(key).findtext("Default")) for key in profiles.FLOORS}
        self.assertEqual(weights, {key: int(value) for key, value in balanced["weights"].items()})
        self.assertEqual(floors, {key: int(value) for key, value in balanced["floors"].items()})
        self.assertEqual(sum(weights.values()), 100)
        page = (MVC / "views/OPNsense/FirewallMap/settings.volt").read_text()
        self.assertNotIn("add: {filter", page, "the grid's + is OPNsense's own add command")

    def test_profile_grid_columns(self):
        """Active (the native row toggle) and Type are grid-only columns, never dialog fields."""
        dialog = ET.parse(FORMS / "dialogProfile.xml").getroot()
        columns = {field.findtext("id"): field for field in dialog.iter("field") if field.findtext("id")}
        active, builtin = columns["profile.active"], columns["profile.builtin"]
        self.assertEqual((active.findtext("type"), active.findtext("grid_view/formatter")), ("ignore", "rowtoggle"))
        self.assertEqual((builtin.findtext("type"), builtin.findtext("grid_view/formatter")),
                         ("ignore", "profile_type"))


# the classification set field with stand-ins for its two OPNsense base classes: the static option
# cache is BaseListField's own (per class, optionally per hash)
FIELD_HARNESS = r"""
namespace OPNsense\Base\FieldTypes {
    class BaseListField {
        protected $internalOptionList = [];
        private static $internalStaticOptList = [];
        public function __construct(private string $value) {}
        protected function getInitialValue() { return $this->value; }
        protected function hasStaticOptions(?string $hash = null): bool {
            return is_null($hash) ? !empty(self::$internalStaticOptList[static::class])
                : !empty(self::$internalStaticOptList[static::class][$hash]);
        }
        protected function getStaticOptions(?string $hash = null): array {
            return is_null($hash) ? (self::$internalStaticOptList[static::class] ?? [])
                : (self::$internalStaticOptList[static::class][$hash] ?? []);
        }
        protected function setStaticOptions(array $data, ?string $hash = null) {
            if (is_null($hash)) { self::$internalStaticOptList[static::class] = $data; }
            else { self::$internalStaticOptList[static::class][$hash] = $data; }
        }
        public function getNodeData() { return $this->internalOptionList; }
        public function getValidators() { return []; }
    }
}
namespace OPNsense\Core {
    class Backend { public function configdRun($action) { return getenv('REPORT'); } }
}
namespace {
    if (!function_exists('gettext')) { function gettext($text) { return $text; } }
    require getenv('FIELD');
    $result = [];
    foreach (json_decode(file_get_contents('php://stdin'), true) as [$type, $value]) {
        $field = new OPNsense\FirewallMap\FieldTypes\ClassificationSetField($value);
        if ($type !== '') { $field->setAliasType($type); }
        $result[] = $field->getNodeData();
    }
    echo json_encode($result);
}
"""

REPORT = {"sets": [
    {"name": "BeachLanSubnet", "type": "network", "description": "Beach LAN"},
    {"name": "Country_NL", "type": "geoip", "description": "Netherlands"},
    {"name": "FWMAP_Feodo", "type": "urltable", "description": ""},
    {"name": "Partners", "type": "urltable", "description": ""},
]}


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class ClassificationSetOptionsTest(unittest.TestCase):
    def options(self, *fields):
        """Option lists of fields built in one request (one configd report), in order."""
        result = subprocess.run(["php", "-r", FIELD_HARNESS], input=json.dumps(fields), capture_output=True,
                                text=True, check=True,
                                env=dict(os.environ, FIELD=str(SET_FIELD), REPORT=json.dumps(REPORT)))
        return json.loads(result.stdout)

    def test_country_blocklists_offer_geoip_aliases_only(self):
        """Country blocklists offer GeoIP aliases, Operational sets every table, whichever field
        the request builds first."""
        country, operational = self.options(["geoip", ""], ["", ""])
        self.assertEqual(country, {"Country_NL": "Country_NL (Netherlands)"})
        self.assertEqual(set(operational), {"BeachLanSubnet", "Country_NL", "FWMAP_Feodo", "Partners"})
        operational, country = self.options(["", ""], ["geoip", ""])
        self.assertEqual(list(country), ["Country_NL"])
        self.assertEqual(len(operational), 4)

    def test_no_geoip_alias_offers_nothing(self):
        report = {"sets": [table for table in REPORT["sets"] if table["type"] != "geoip"]}
        result = subprocess.run(["php", "-r", FIELD_HARNESS], input=json.dumps([["geoip", ""]]), capture_output=True,
                                text=True, check=True,
                                env=dict(os.environ, FIELD=str(SET_FIELD), REPORT=json.dumps(report)))
        self.assertEqual(json.loads(result.stdout), [[]])

    def test_stored_choices_stay_representable(self):
        """A table chosen before the filter keeps its label (it still classifies); a deleted one is
        marked: nothing is dropped from the configuration."""
        (country,) = self.options(["geoip", "BeachLanSubnet,Gone"])
        self.assertEqual(country, {"Country_NL": "Country_NL (Netherlands)",
                                   "BeachLanSubnet": "BeachLanSubnet (Beach LAN)", "Gone": "Gone (not found)"})


if __name__ == "__main__":
    unittest.main()
