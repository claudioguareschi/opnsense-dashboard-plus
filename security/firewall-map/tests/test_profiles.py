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

"""lib/profiles.py: the schema-v1 startup document, validation, fingerprints and resolution."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from support import COLLECTOR, CONFIG

PROFILES = COLLECTOR.ranking_profiles
FIXTURES = Path(__file__).with_name("fixtures") / "profiles"


def example():
    """The contract's example (tests/fixtures/profiles/schema_v1_example.json) as a profile."""
    document = json.loads((FIXTURES / "schema_v1_example.json").read_text())["profile"]
    return {"uuid": document["uuid"], "name": document["name"], "weights": document["weights"],
            "floors": document["security_visibility"],
            "default_multiplier": document["asset_importance"]["default_multiplier"],
            "assets": document["asset_importance"]["rules"], "direction": document["direction"]}


class StartupDocumentTest(unittest.TestCase):
    def test_builtins_match_their_fixtures(self):
        """The fixtures the C contract test loads are exactly what Python writes."""
        for profile in PROFILES.BUILTINS:
            with self.subTest(profile=profile["name"]):
                path = FIXTURES / f"{profile['name'].lower()}.json"
                self.assertEqual(PROFILES.startup_text(PROFILES.validate(profile)), path.read_text())

    def test_the_example_round_trips(self):
        self.assertEqual(PROFILES.document(PROFILES.validate(example())),
                         json.loads((FIXTURES / "schema_v1_example.json").read_text()))

    def test_builtins_are_complete_policies(self):
        self.assertEqual([profile["name"] for profile in PROFILES.BUILTINS],
                         ["Balanced", "Bandwidth", "Connections", "Security"])
        for profile in PROFILES.BUILTINS:
            valid = PROFILES.validate(profile)
            self.assertEqual(sum(valid["weights"].values()), 100)
            self.assertEqual(set(valid["weights"]), set(PROFILES.FEATURES))
        self.assertEqual(PROFILES.DEFAULT, PROFILES.BALANCED)
        self.assertEqual(len({PROFILES.fingerprint(PROFILES.validate(p)) for p in PROFILES.BUILTINS}), 4)

    def test_the_document_name_is_printable_ascii(self):
        text = PROFILES.startup_text(PROFILES.validate(dict(example(), name="Sécurité\nmail")))
        self.assertEqual(json.loads(text)["profile"]["name"], "S?curit??mail")
        self.assertTrue(text.isascii())


class ValidationTest(unittest.TestCase):
    def rejects(self, **change):
        with self.assertRaises(PROFILES.ProfileError):
            PROFILES.validate(dict(example(), **change))

    def test_rejections(self):
        weights = example()["weights"]
        self.rejects(weights=dict(weights, byte_rate=29))
        self.rejects(weights=dict(weights, reputation=0))
        self.rejects(weights={k: v for k, v in weights.items() if k != "ids_evidence"})
        self.rejects(weights=dict(weights, byte_rate=-1, packet_rate=41))
        self.rejects(weights=dict(weights, byte_rate="x"))
        self.rejects(weights=dict(weights, byte_rate=True))
        self.rejects(floors={"s3_min_percent": 60, "s2_min_percent": 30, "s1_min_percent": 20})
        self.rejects(floors={"s3_min_percent": 101, "s2_min_percent": 0, "s1_min_percent": 0})
        self.rejects(assets=[{"cidr": "192.168.70.5/24", "multiplier": 2}])
        self.rejects(assets=[{"cidr": "10.0.0.0/8", "multiplier": 2}, {"cidr": "10.0.0.0/8", "multiplier": 3}])
        self.rejects(assets=[{"cidr": "10.0.0.0/8", "multiplier": 0}])
        self.rejects(assets=[{"cidr": "10.0.0.0/8", "multiplier": 2e6}])
        # asset multipliers boost only: 1 to 100 inclusive (the collector's range)
        for value in (0.999, 0.9999999999, 0, -1, -0.0, 100.000001, 101, float("nan"), float("inf"),
                      float("-inf"), "0.5", "NaN", "Infinity", "x", True, None):
            with self.subTest(multiplier=value):
                self.rejects(assets=[{"cidr": "10.0.0.0/8", "multiplier": value}])
                self.rejects(default_multiplier=value)
        for value in (1, 1.0, 2, 5, 10, 100, "100", "1e2"):
            with self.subTest(multiplier=value):
                accepted = PROFILES.validate(dict(example(), default_multiplier=value,
                                                  assets=[{"cidr": "10.0.0.0/8", "multiplier": value}]))
                self.assertEqual(accepted["default_multiplier"], float(value))
        self.rejects(assets=[{"cidr": "mail.example", "multiplier": 2}])
        self.rejects(default_multiplier=0)
        self.rejects(direction="inbound")
        self.rejects(assets=[{"cidr": f"10.{n >> 8}.{n & 255}.0/24", "multiplier": 2}
                             for n in range(PROFILES.ASSET_RULES_MAX + 1)])

    def test_canonical_forms(self):
        valid = PROFILES.validate(dict(example(), assets=[
            {"cidr": "192.168.1.25", "multiplier": "10"}, {"cidr": "2001:db8:0::/48", "multiplier": 3},
            {"cidr": "192.168.1.25/32", "multiplier": 10}]))
        self.assertEqual(valid["assets"], [{"cidr": "192.168.1.25/32", "multiplier": 10.0},
                                           {"cidr": "2001:db8::/48", "multiplier": 3.0}])

    def test_asset_text(self):
        self.assertEqual(PROFILES.parse_assets("192.168.1.25 10\n\n  10.0.0.0/8   2.5 \n"),
                         [{"cidr": "192.168.1.25", "multiplier": "10"}, {"cidr": "10.0.0.0/8", "multiplier": "2.5"}])
        with self.assertRaises(PROFILES.ProfileError):
            PROFILES.parse_assets("192.168.1.25")


class FingerprintTest(unittest.TestCase):
    def test_what_changes_the_fingerprint(self):
        base = PROFILES.validate(example())
        same = [dict(base, name="Renamed"), dict(base, uuid="0d1e4f0e-2b0c-4f39-9df1-6d1a7c1f2e10"),
                dict(base, assets=list(reversed(base["assets"])))]
        for profile in same:
            self.assertEqual(PROFILES.fingerprint(profile), PROFILES.fingerprint(base))
        weights = dict(base["weights"], byte_rate=29, packet_rate=11)
        different = [dict(base, weights=weights), dict(base, default_multiplier=2.0),
                     dict(base, assets=base["assets"][:2]),
                     dict(base, assets=[dict(base["assets"][0], multiplier=3.0)] + base["assets"][1:]),
                     dict(base, floors=dict(base["floors"], s1_min_percent=3))]
        for profile in different:
            self.assertNotEqual(PROFILES.fingerprint(PROFILES.validate(profile)), PROFILES.fingerprint(base))


class ResolutionTest(unittest.TestCase):
    ROW = {"uuid": "0d1e4f0e-2b0c-4f39-9df1-6d1a7c1f2e10", "name": "Mail Security", "description": "",
           **dict(zip(PROFILES.FEATURES, ("5", "5", "10", "15", "0", "25", "10", "30"))),
           "s3_min_percent": "20", "s2_min_percent": "10", "s1_min_percent": "0", "default_multiplier": "1",
           "direction": "equal", "assets": "192.168.1.25 10"}

    def test_uuid_resolution(self):
        for uuid in (PROFILES.BALANCED, PROFILES.SECURITY):
            self.assertEqual(PROFILES.resolve({"ranking_profile": uuid}, [self.ROW])[0]["uuid"], uuid)
        profile, problem = PROFILES.resolve({"ranking_profile": self.ROW["uuid"]}, [self.ROW])
        self.assertEqual((profile["name"], problem), ("Mail Security", None))
        # the name never resolves a profile
        profile, problem = PROFILES.resolve({"ranking_profile": "Mail Security"}, [self.ROW])
        self.assertEqual(profile["uuid"], PROFILES.DEFAULT)
        self.assertIn("does not exist", problem)
        broken = dict(self.ROW, assets="192.168.1.25/24 10")
        profile, problem = PROFILES.resolve({"ranking_profile": self.ROW["uuid"]}, [broken])
        self.assertEqual(profile["uuid"], PROFILES.DEFAULT)
        self.assertIn("invalid", problem)

    def test_catalog(self):
        catalog = PROFILES.catalog([self.ROW, dict(self.ROW, uuid="b6a0d0c8-6f4b-4f0e-8a51-2c3e0f5a9d11",
                                                   name="Broken", byte_rate="90")])
        self.assertEqual([(item["name"], item["builtin"]) for item in catalog],
                         [("Balanced", True), ("Bandwidth", True), ("Connections", True), ("Security", True),
                          ("Mail Security", False), ("Broken", False)])
        self.assertNotIn("problem", catalog[4])
        self.assertEqual(catalog[4]["assets"], "192.168.1.25/32 10")
        self.assertEqual(catalog[0]["fingerprint"], PROFILES.fingerprint(PROFILES.validate(PROFILES.BUILTINS[0])))
        self.assertIn("weights total", catalog[5]["problem"])


MODEL_PHP = Path(__file__).resolve().parents[1] / "src/opnsense/mvc/app/models/OPNsense/FirewallMap/FirewallMap.php"


class ModelParityTest(unittest.TestCase):
    """The settings model refuses exactly the asset rules the scripts (and the collector) refuse."""

    CASES = ["192.168.1.25 10", "192.168.1.0/24 2\n192.168.1.25 10", "2001:db8::/32 3", "10.0.0.0/8 0.5",
             "10.0.0.0/8 1", "10.0.0.0/8 100", "10.0.0.0/8 5", "10.0.0.0/8 0.999999", "10.0.0.0/8 100.000001",
             "10.0.0.0/8 101", "10.0.0.0/8 -1", "10.0.0.0/8 NaN", "10.0.0.0/8 INF", "10.0.0.0/8 1e2",
             "192.168.1.5/24 2", "192.168.1.0/33 2", "192.168.1.0/024 2", "mail.example 2", "10.0.0.0/8",
             "10.0.0.0/8 0", "10.0.0.0/8 2000000", "10.0.0.0/8 x", "10.0.0.0/8 2\n10.0.0.0/8 3",
             "10.0.0.0/8 2\n10.0.0.0/8 2", "2001:db8::1/64 2", "0.0.0.0/0 2", "\n\n",
             # separators and characters the two languages read differently: refused alike
             "10.0.0.0/8\f5", "10.0.0.0/8\x0b5", "10.0.0.0/8 5\x85192.168.0.0/16 2", "10.0.0.0/8 5\u2028",
             "10.0.0.0/8\xa05", "10.0.0.0/8 5\r192.168.0.0/16 2", "10.0.0.0/8 5\x00", "10.0.0.0/8 5\x1c",
             "10.0.0.0/8 \u0665", "10.0.0.0/8 1_0", "10.0.0.0/8 +5", "10.0.0.0/8 5.", "10.0.0.0/8 .5",
             # and the ones both accept
             "10.0.0.0/8\t5", "  10.0.0.0/8   5  ", "10.0.0.0/8 5\r\n192.168.0.0/16 2\r\n", "10.0.0.0/8 05"]

    def test_asset_rules_match(self):
        php = shutil.which("php")
        if not php:
            raise unittest.SkipTest("PHP unavailable")
        stub = ("namespace OPNsense\\Base { class BaseModel {} } namespace OPNsense\\Base\\Messages { class Message {} } "
                "namespace { require getenv('MODEL'); foreach (json_decode(file_get_contents('php://stdin')) as $text) "
                "{ echo json_encode(is_array(OPNsense\\FirewallMap\\FirewallMap::parseAssets($text))), \"\\n\"; } }")
        result = subprocess.run([php, "-r", stub], input=json.dumps(self.CASES), capture_output=True, text=True,
                                env=dict(os.environ, MODEL=str(MODEL_PHP)), check=True)
        accepted = [json.loads(line) for line in result.stdout.split()]
        for text, model in zip(self.CASES, accepted, strict=True):
            with self.subTest(rules=text):
                try:
                    PROFILES.validate(dict(example(), assets=PROFILES.parse_assets(text)))
                    scripts = True
                except PROFILES.ProfileError:
                    scripts = False
                self.assertEqual(model, scripts)


    # whole profiles: the model's own validateProfile (weights total, security shares, asset rules),
    # its field validators' bounds (checked against the model XML below), and the scripts' validate
    PROFILES_CASES = [
        ({"byte_rate": 100}, (0, 0, 0)), ({"byte_rate": 99}, (0, 0, 0)), ({"byte_rate": 101}, (0, 0, 0)),
        ({}, (0, 0, 0)), ({"byte_rate": 50, "ids_evidence": 50}, (50, 30, 20)),
        ({"byte_rate": 50, "ids_evidence": 50}, (50, 30, 21)), ({"byte_rate": 100}, (100, 0, 0)),
        ({feature: 12 for feature in PROFILES.FEATURES[:8]} | {"byte_rate": 16}, (4, 2, 1)),
    ]

    def test_profiles_match(self):
        php = shutil.which("php")
        if not php:
            raise unittest.SkipTest("PHP unavailable")
        cases = [{**{feature: str(weights.get(feature, 0)) for feature in PROFILES.FEATURES},
                  **dict(zip(PROFILES.FLOORS, map(str, floors))), "assets": "10.0.0.0/8 2"}
                 for weights, floors in self.PROFILES_CASES]
        # validateProfile reads a profile row's fields and uuid and appends messages: stand-ins for both
        stub = (
            "namespace OPNsense\\Base { class BaseModel {} } "
            "namespace OPNsense\\Base\\Messages { class Message { function __construct($m, $f) {} } } "
            "namespace { require getenv('MODEL'); "
            "class Row { function __construct(public array $v) {} function __get($k) { return $this->v[$k] ?? ''; } "
            "function getAttributes() { return ['uuid' => 'u']; } } "
            "class Messages { public $n = 0; function appendMessage($m) { $this->n++; } } "
            "$check = (new ReflectionClass('OPNsense\\FirewallMap\\FirewallMap'))->getMethod('validateProfile'); "
            "$model = (new ReflectionClass('OPNsense\\FirewallMap\\FirewallMap'))->newInstanceWithoutConstructor(); "
            "foreach (json_decode(file_get_contents('php://stdin'), true) as $row) "
            "{ $m = new Messages(); $check->invoke($model, new Row($row), $m); echo json_encode($m->n === 0), \"\\n\"; } }")
        result = subprocess.run([php, "-r", stub], input=json.dumps(cases), capture_output=True, text=True,
                                env=dict(os.environ, MODEL=str(MODEL_PHP)), check=True)
        accepted = [json.loads(line) for line in result.stdout.split()]
        for (weights, floors), model in zip(self.PROFILES_CASES, accepted, strict=True):
            with self.subTest(weights=weights, floors=floors):
                profile = dict(example(), weights={feature: weights.get(feature, 0) for feature in PROFILES.FEATURES},
                               floors=dict(zip(PROFILES.FLOORS, floors)), assets=PROFILES.parse_assets("10.0.0.0/8 2"))
                try:
                    PROFILES.validate(profile)
                    scripts = True
                except PROFILES.ProfileError:
                    scripts = False
                self.assertEqual(model, scripts)

    def test_bounds_match_the_model(self):
        """The limits the scripts enforce are the model's: the field bounds in FirewallMap.xml and the
        constants in FirewallMap.php."""
        import xml.etree.ElementTree as ET
        row = ET.parse(MODEL_PHP.with_suffix(".xml")).getroot().find("./items/profiles/profile")
        for key in (*PROFILES.FEATURES, *PROFILES.FLOORS):
            field = row.find(key)
            self.assertEqual((field.get("type"), field.findtext("MinimumValue"), field.findtext("MaximumValue")),
                             ("IntegerField", "0", "100"), key)
        multiplier = row.find("default_multiplier")
        self.assertEqual((float(multiplier.findtext("MinimumValue")), float(multiplier.findtext("MaximumValue"))),
                         (PROFILES.MULTIPLIER_MIN, PROFILES.MULTIPLIER_MAX))
        php = MODEL_PHP.read_text()
        for name, value in (("ASSET_RULES_MAX", PROFILES.ASSET_RULES_MAX), ("MULTIPLIER_MIN", int(PROFILES.MULTIPLIER_MIN)),
                            ("MULTIPLIER_MAX", int(PROFILES.MULTIPLIER_MAX))):
            self.assertIn(f"const {name} = {value};", php, name)


class SettingsFileTest(unittest.TestCase):
    def test_custom_rows_are_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "firewallmap.json")
            with open(path, "w") as handle:
                json.dump({"general": {}, "ranking_profiles": [ResolutionTest.ROW, {"name": "no uuid"}, "x"]}, handle)
            self.assertEqual(CONFIG.ranking_profiles(path), [ResolutionTest.ROW])
            self.assertEqual(CONFIG.ranking_profiles("/nonexistent/firewallmap.json"), [])


if __name__ == "__main__":
    unittest.main()
