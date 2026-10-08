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

"""Adversarial and scale tests of the state collector's resource model (synthetic PF reader).

These run the shipped engine code at high cardinality and check the bounds of PROTOCOL.md:
response size, candidate and threat caps, hash-key independence, correlation skipping. Timings
are printed for the record; the assertions use only generous bounds, since they run on any
development machine. Target (FreeBSD/netlink) costs are measured separately on the firewall.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/opnsense/scripts/OPNsense/FirewallMap"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import collector, evidence, profiles  # noqa: E402
from collector_build import budget_limits, compile_worker, state_limit  # noqa: E402

CONTEXT = ({"8.8.8.1"}, [], {}, None)
QUERY = ("tcp", "8.8.8.1", "30000", "9.9.9.9", "443")
# a threat list naming every synthetic remote (9.0.0.0/8): the worst case for the threat summary
THREATS_ALL = ("all", [("T", "threats_all")])


class CollectorScaleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.worker = compile_worker(Path(cls.directory.name) / "worker")
        tables = Path(cls.directory.name) / "tables"
        tables.mkdir()
        (tables / "threats_all.txt").write_text("9.0.0.0/8\n")
        (tables / "threats_some.txt").write_text("9.0.0.0/24\n!9.0.0.128/25\n")
        (tables / "country.txt").write_text("9.0.0.0/16\n")
        # flows 4096-4351 of the unique mode: past a 64 MiB budget's tracked-set limit
        (tables / "threats_late.txt").write_text("9.0.16.0/24\n")
        cls.tables = str(tables)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def engine(self, profile=None):
        """A helper started with `profile` (a validated profile), or with the base ranking (the oracle)."""
        engine = collector.CollectorEngine(self.worker, profile=profile)
        self.addCleanup(engine.close)
        return engine

    def run_mode(self, mode, count, samples=2, key=None, profile=None, **options):
        environment = {"FM_TEST_MODE": mode, "FM_TEST_COUNT": str(count), "FM_TEST_INTERVAL": "2",
                       "FM_TEST_CLASS_DIR": self.tables}
        if key:
            environment["FM_TEST_HASH_KEY"] = key
        engine = self.engine(profile)
        with patch.dict(os.environ, environment):
            results, started = [], time.perf_counter()
            for _ in range(samples):
                results.append(engine.sample(*CONTEXT, **options))
        return results, (time.perf_counter() - started) / samples

    def test_high_cardinality_sample_stays_within_budget_and_response_bounds(self):
        """Every state its own flow, all threat-listed: past the tracked-set limit the sample is
        bounded, flagged flows beyond the forced cap are refused (counted), and memory stays within
        the budget's shares."""
        count = 200000
        memory = 1024 << 20
        (first, last), seconds = self.run_mode("unique", count, threat_summary=True, event_queries=[QUERY],
                                               memory=memory, classification=THREATS_ALL)
        telemetry = last["telemetry"]
        print(f"\n  unique x{count}: {seconds:.2f} s/sample, heap peak {telemetry['heap_peak'] >> 20} MiB, "
              f"limit {telemetry['state_limit']} states, tracked {telemetry['tracked_flows']} of "
              f"{telemetry['tracked_limit']}, max RSS {telemetry['max_rss'] >> 20} MiB")
        states, tracked, candidates, joins = budget_limits(memory, telemetry["classifier_bytes"])
        self.assertIsNone(last["refused"])
        self.assertEqual((telemetry["state_limit"], telemetry["tracked_limit"], telemetry["candidate_limit"],
                          telemetry["join_limit"]), (states, tracked, candidates, joins))
        self.assertLess(telemetry["heap_peak"], memory)
        # the first sample ran out of exact admission: bounded, and so is the next
        self.assertEqual((first["regime"], first["telemetry"]["next_regime"]), ("bounded", 1))
        self.assertEqual(last["quality"]["ranking"], "bounded")
        self.assertLessEqual(telemetry["tracked_flows"], tracked + telemetry["forced_limit"])
        self.assertGreater(telemetry["forced_refused"], 0)
        self.assertEqual(last["quality"]["attribution"], "partial")
        # the untracked flows were counted, approximately (HyperLogLog, 1.6% standard error)
        self.assertTrue(last["counts"]["flows_estimated"])
        self.assertLess(abs(last["counts"]["flows"] - count), count * 0.05)
        self.assertEqual(last["quality"]["discovery"], "bounded")
        self.assertEqual(len(last["flows"]), collector.RANKED_FLOWS)
        self.assertEqual(len(last["threat_remotes"]), collector.THREAT_REMOTES)
        self.assertEqual(telemetry["threat_remotes_omitted"], telemetry["tracked_flows"] - collector.THREAT_REMOTES)

    def test_candidates_per_flow_and_kind_are_capped(self):
        (_, last), _ = self.run_mode("ports", 5000)
        services = [row for row in last["candidates"] if row[1] == collector.SERVICE]
        self.assertEqual(len(last["flows"]), 1)
        self.assertEqual(len(services), collector.CANDIDATES_PER_KIND)
        # a (flow, kind) keeps a bounded summary of its values: the rest were evicted, and the
        # sample's attribution says it is partial
        # (services and remote targets: 32 kept, 16 sent, each)
        self.assertEqual(last["telemetry"]["candidates_omitted"], 2 * (32 - collector.CANDIDATES_PER_KIND))
        self.assertGreater(last["telemetry"]["candidate_evictions"], 4000)
        self.assertEqual(last["quality"]["attribution"], "partial")
        # the heaviest were kept: their weights are not below any omitted one's (all equal here)
        self.assertEqual(len({row[0] for row in services}), 1)

    def test_small_population_is_exact(self):
        (*_, last), _ = self.run_mode("mixed", 3000, samples=3)
        self.assertEqual(last["regime"], "exact")
        self.assertEqual(last["quality"], {"discovery": "exact", "ranking": "exact", "attribution": "exact"})
        self.assertFalse(last["counts"]["flows_estimated"])
        self.assertEqual(last["counts"]["flows"], last["counts"]["tracked_flows"])
        self.assertEqual(last["telemetry"]["untracked_states"], 0)

    def test_regime_enters_bounded_and_returns_through_warming(self):
        """64 MiB budget: about 2,450 tracked flows. 5,000 flows exhaust exact admission; the
        bounded samples know the rest exactly (they fit the summaries); 1,000 flows fall below the
        exit threshold and the next samples are exact again, with history warming for one fade
        window."""
        engine = self.engine()
        memory = 64 << 20
        tracked = budget_limits(memory)[1]
        environment = {"FM_TEST_MODE": "unique", "FM_TEST_INTERVAL": "2", "FM_TEST_CLASS_DIR": self.tables,
                       "FM_TEST_COUNTS": "5000,5000,5000,1000,1000"}
        with patch.dict(os.environ, environment):
            results = [engine.sample(*CONTEXT, memory=memory) for _ in range(5)]
        exhausted, bounded, _, leaving, back = results
        self.assertEqual((exhausted["regime"], exhausted["quality"]["ranking"]), ("bounded", "bounded"))
        self.assertEqual(exhausted["telemetry"]["tracked_flows"], tracked)
        self.assertEqual(bounded["regime"], "bounded")
        self.assertLessEqual(bounded["telemetry"]["tracked_flows"], tracked)
        # the untracked flows fit the summaries: discovery and the flow count stay exact
        self.assertEqual((bounded["quality"]["discovery"], bounded["counts"]["flows"],
                          bounded["counts"]["flows_estimated"]), ("exact", 5000, False))
        # a flat population: no promotion beats an incumbent by the margin, the map does not reshuffle
        self.assertEqual(bounded["telemetry"]["promoted"], 0)
        self.assertEqual([row["key"] for row in bounded["flows"]], [row["key"] for row in results[2]["flows"]])
        self.assertEqual((leaving["regime"], leaving["telemetry"]["next_regime"]), ("bounded", 0))
        self.assertEqual((back["regime"], back["quality"]["ranking"]), ("exact", "warming"))

    def test_threat_history_keeps_detail_for_flagged_flows_past_the_limit(self):
        """Flagged flows that exact admission never reached are force-tracked during the pass and
        pinned afterwards: their threat records keep inside host and service detail."""
        engine = self.engine()
        environment = {"FM_TEST_MODE": "unique", "FM_TEST_COUNT": "5000", "FM_TEST_INTERVAL": "2",
                       "FM_TEST_CLASS_DIR": self.tables}
        with patch.dict(os.environ, environment):
            results = [engine.sample(*CONTEXT, memory=64 << 20, threat_summary=True,
                                     classification=("late", [("T", "threats_late")])) for _ in range(3)]
        for result in results:
            self.assertEqual(result["regime"], "bounded")
            remotes = [remote["address"] for remote in result["threat_remotes"]]
            self.assertEqual(sorted(remotes), sorted(f"9.0.16.{n}" for n in range(256)))
            self.assertEqual(result["telemetry"]["forced_refused"], 0)
            for kind in (collector.INSIDE_HOST, collector.SERVICE):
                owners = {row[0] for row in result["threat_candidates"] if row[1] == kind}
                self.assertEqual(owners, set(range(256)), kind)

    def profile(self, uuid):
        return profiles.validate(profiles.BY_UUID[uuid])

    @staticmethod
    def custom(floors=(0, 0, 0), assets=(), default=1, **weights):
        """A test profile: the given weights (the rest 0; totalling 100), floor percentages and
        asset rules."""
        return profiles.validate({
            "uuid": "6f36c7b2-70ad-4c41-a32d-4cb1e3fb1a01", "name": "Test",
            "weights": {feature: weights.get(feature, 0) for feature in profiles.FEATURES},
            "floors": dict(zip(profiles.FLOORS, floors)), "default_multiplier": default,
            "assets": [{"cidr": cidr, "multiplier": multiplier} for cidr, multiplier in assets],
            "direction": "equal"})

    def remotes(self, result):
        return [flow["key"][1] for flow in result["flows"]]

    def test_the_active_profile_ranks_the_flows(self):
        """One profile, given at startup: the response is its selection in rank order."""
        for uuid in profiles.BY_UUID:
            with self.subTest(profile=profiles.BY_UUID[uuid]["name"]):
                (_, last), _ = self.run_mode("mixed", 5000, profile=self.profile(uuid))
                scores = [flow["score"] for flow in last["flows"]]
                self.assertLessEqual(len(scores), collector.RANKED_FLOWS)
                self.assertEqual(scores, sorted(scores, reverse=True))
                self.assertNotIn("selections", last)

    def test_connections_ranks_by_states_and_security_reserves_flagged_places(self):
        # sparse: 9.1.0.1 holds 99% of the states
        (_, sparse), _ = self.run_mode("sparse", 5000, profile=self.profile(profiles.CONNECTIONS))
        self.assertEqual(self.remotes(sparse)[0], "9.1.0.1")
        # unique flows, 9.0.0.0-127 threat-listed: Security keeps all 128 of them (S1 floor 20, the
        # rest on their threat-list weight) although every flow carries the same traffic
        security = self.profile(profiles.SECURITY)
        (_, unique), _ = self.run_mode("unique", 1000, profile=security, threat_summary=True,
                                       classification=("some", [("T", "threats_some")]))
        self.assertEqual(set(self.remotes(unique)[:128]), {f"9.0.0.{n}" for n in range(128)})
        # light flagged flows against 1,000 heavy ones (late: index 3000 on carries 100x): the base
        # ranking shows none of them, Security reserves its places for them
        flagged = {f"9.0.0.{n}" for n in range(128)}
        lists = ("some", [("T", "threats_some")])
        (*_, base), _ = self.run_mode("late", 4000, samples=3, classification=lists)
        (*_, late), _ = self.run_mode("late", 4000, samples=3, profile=security, classification=lists)
        self.assertFalse(set(self.remotes(base)) & flagged)
        self.assertTrue(flagged <= set(self.remotes(late)))

    def test_profile_selections_do_not_depend_on_the_hash_key(self):
        outputs = []
        facts = {f"9.1.{n >> 8}.{n & 255}": evidence.facts(n % 50, n % 3, 1 + n % 3, n % 2 == 0)
                 for n in range(0, 3000, 11)}
        for key in ("00" * 16, "0123456789abcdeffedcba9876543210"):
            results, _ = self.run_mode("mixed", 3000, samples=3, key=key, profile=self.profile(profiles.BALANCED),
                                       evidence=facts)
            outputs.append([result["flows"] for result in results])
        self.assertEqual(outputs[0], outputs[1])

    def test_every_evidence_source_keeps_its_fact(self):
        facts = {"9.0.0.5": evidence.facts(40, 7, 1, True), "9.0.3.10": evidence.facts(40),
                 "9.0.3.11": evidence.facts(3), "9.0.3.12": evidence.facts(ids_alerts=2, ids_severity=3),
                 "9.0.3.13": evidence.facts(reputation=True)}
        (_, last), _ = self.run_mode("unique", 1000, profile=self.custom((0.5, 1, 97.5), active_states=100), evidence=facts,
                                     classification=("some", [("T", "threats_some")]))
        flows = {flow["key"][1]: flow for flow in last["flows"]}
        every = evidence.THREAT_LIST | evidence.PF_BLOCKED | evidence.IDS | evidence.IDS_HIGH | evidence.REPUTATION
        expected = {
            # threat-listed, blocked, high-severity IDS and reputation at once: S3, no fact lost
            "9.0.0.5": ({"mask": every, "blocked_hits": 40, "ids_alerts": 7, "ids_severity": 1}, "S3"),
            "9.0.0.6": ({"mask": evidence.THREAT_LIST, "blocked_hits": 0, "ids_alerts": 0, "ids_severity": 0}, "S1"),
            "9.0.3.10": ({"mask": evidence.PF_BLOCKED, "blocked_hits": 40, "ids_alerts": 0, "ids_severity": 0}, "S2"),
            "9.0.3.11": ({"mask": evidence.PF_BLOCKED, "blocked_hits": 3, "ids_alerts": 0, "ids_severity": 0}, "S1"),
            "9.0.3.12": ({"mask": evidence.IDS, "blocked_hits": 0, "ids_alerts": 2, "ids_severity": 3}, "S2"),
            "9.0.3.13": ({"mask": evidence.REPUTATION, "blocked_hits": 0, "ids_alerts": 0, "ids_severity": 0}, "S1"),
            "9.0.0.130": ({"mask": 0, "blocked_hits": 0, "ids_alerts": 0, "ids_severity": 0}, "S0"),
        }
        for remote, (facts_seen, security) in expected.items():
            with self.subTest(remote=remote):
                self.assertIn(remote, flows)
                self.assertEqual((flows[remote]["evidence"], flows[remote]["security_class"]), (facts_seen, security))

    def test_the_collector_answers_for_flowless_evidence_remotes(self):
        """A remote with evidence and no PF state, and one with both: the collector derives the
        class and counts the permitted states, so Python never re-implements the policy."""
        facts = {"45.56.79.53": evidence.facts(4200, 2, 3), "9.0.0.5": evidence.facts(40)}
        (_, last), _ = self.run_mode("unique", 1000, evidence=facts, classify=list(facts),
                                     classification=("some", [("T", "threats_some")]))
        self.assertEqual(last["remotes"]["45.56.79.53"],
                         {"classes": 0, "evidence": evidence.PF_BLOCKED | evidence.IDS, "security_class": "S2",
                          "states": 0})
        self.assertEqual(last["remotes"]["9.0.0.5"],
                         {"classes": 1, "evidence": evidence.PF_BLOCKED | evidence.THREAT_LIST,
                          "security_class": "S2", "states": 1})

    def test_security_floors_are_minimums_per_class(self):
        def run(profile, facts):
            (_, last), _ = self.run_mode("unique", 1000, profile=profile, evidence=facts)
            return self.remotes(last)
        ordinary = [f"9.0.{n >> 8}.{n & 255}" for n in range(150)]
        # one flow qualifying for S3, S2 and S1 takes only the S3 place: the S2 and S1 places go
        # to the flows of those classes, and the rest to the general pool
        multiple, strong, listed = "9.0.3.200", "9.0.3.201", "9.0.3.202"
        chosen = run(self.custom((0.5, 0.5, 0.5), active_states=100),
                     {multiple: evidence.facts(40, 1, 1, True), strong: evidence.facts(40),
                      listed: evidence.facts(reputation=True)})
        self.assertEqual(len(chosen), 150)
        self.assertTrue({multiple, strong, listed} <= set(chosen))
        self.assertEqual(set(chosen) - {multiple, strong, listed}, set(ordinary[:147]))
        # a reserved class also wins ordinary places on its score: five S3 flows, one reserved place
        high = {f"9.0.3.{n}": evidence.facts(ids_alerts=1, ids_severity=1) for n in range(100, 105)}
        chosen = run(self.custom((0.5, 0, 0), active_states=1, ids_evidence=99), high)
        self.assertEqual(set(chosen[:5]), set(high))
        # unused floors return to the general pool
        chosen = run(self.custom((50, 30, 20), active_states=100), {})
        self.assertEqual(chosen, ordinary)

    def test_evidence_alone_forces_tracking_past_the_limit(self):
        """As in Phase E, any evidence (here an EVIDENCE row, no threat list) is force-tracked
        during the pass, pinned afterwards and summarized with its detail."""
        engine = self.engine()
        facts = {f"9.0.16.{n}": evidence.facts(reputation=True) for n in range(256)}
        environment = {"FM_TEST_MODE": "unique", "FM_TEST_COUNT": "5000", "FM_TEST_INTERVAL": "2",
                       "FM_TEST_CLASS_DIR": self.tables}
        with patch.dict(os.environ, environment):
            results = [engine.sample(*CONTEXT, memory=64 << 20, threat_summary=True, evidence=facts)
                       for _ in range(3)]
        for result in results:
            self.assertEqual(result["regime"], "bounded")
            self.assertEqual(sorted(remote["address"] for remote in result["threat_remotes"]), sorted(facts))
            self.assertEqual(result["telemetry"]["forced_refused"], 0)
            owners = {row[0] for row in result["threat_candidates"] if row[1] == collector.INSIDE_HOST}
            self.assertEqual(owners, set(range(256)))

    def test_the_base_ranking_oracle_ignores_evidence(self):
        """The base ranking (Classic, the regression oracle) is the same with or without evidence and
        threat lists: the security machinery never leaks into it."""
        facts = {f"9.1.{n >> 8}.{n & 255}": evidence.facts(40, 3, 1, True) for n in range(0, 3000, 7)}
        (_, alone), _ = self.run_mode("mixed", 3000)
        (_, with_evidence), _ = self.run_mode("mixed", 3000, evidence=facts, classification=THREATS_ALL)
        self.assertEqual([(row["key"], row["score"]) for row in with_evidence["flows"]],
                         [(row["key"], row["score"]) for row in alone["flows"]])

    def test_malformed_evidence_is_refused_and_no_request_names_a_profile(self):
        """Ranking policy is startup configuration: a request carrying a PROFILE row (or any profile
        at all) is a malformed request, whatever it says."""
        rows, _ = collector._context_rows(*CONTEXT)
        for bad in ("EVIDENCE 9.0.0.1 8 0 1 3", "EVIDENCE 9.0.0.1 2 0 0 0", "EVIDENCE 9.0.0.1 1 0 0 0",
                    "EVIDENCE 9.0.0.1 2 2000000 0 0", "PROFILE activity=1 states=1/10",
                    "PROFILE 0 classic", "PROFILE 1 scored activity=0 states=1/10"):
            with self.subTest(row=bad):
                engine = self.engine(self.profile(profiles.BALANCED))
                engine._start()
                text = "FMCONF2\n{rows}{bad}\nRUN\n".format(rows="".join(row + "\n" for row in rows), bad=bad)
                with self.assertRaises(collector.CollectorError) as raised:
                    engine._request(text, lambda stream, process: collector._decode(stream, process, (), False))
                self.assertEqual(raised.exception.failure_class, "request")

    def test_a_malformed_profile_stops_the_helper_at_startup(self):
        valid = profiles.document(self.profile(profiles.BALANCED))
        def variant(change):
            document = json.loads(json.dumps(valid))
            change(document["profile"])
            return json.dumps(document)
        bad = {
            "schema": json.dumps(dict(valid, schema_version=2)),
            "weights": variant(lambda p: p["weights"].update(byte_rate=24)),
            "feature": variant(lambda p: p["weights"].update(reputation=0)),
            "cidr": variant(lambda p: p["asset_importance"].update(rules=[{"cidr": "10.0.0.1/8", "multiplier": 2}])),
            "direction": variant(lambda p: p.update(direction="inbound")),
            "keyword definition": "activity=1 states=1/10",
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, text in bad.items():
                with self.subTest(profile=name):
                    path = Path(directory) / "profile.json"
                    path.write_text(text)
                    result = subprocess.run([self.worker, "--profile", str(path)], capture_output=True, text=True,
                                            timeout=10, input="")
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("usage", result.stderr)
        # one profile only, and a file that does not exist
        result = subprocess.run([self.worker, "--profile", "/nonexistent.json"], capture_output=True, text=True,
                                timeout=10, input="")
        self.assertEqual(result.returncode, 2)
        result = subprocess.run([self.worker, "--profile", "a", "--profile", "b"], capture_output=True, text=True,
                                timeout=10, input="")
        self.assertEqual(result.returncode, 2)

    def test_a_new_profile_restarts_the_helper(self):
        engine = self.engine(self.profile(profiles.BALANCED))
        with patch.dict(os.environ, FM_TEST_MODE="mixed", FM_TEST_COUNT="300", FM_TEST_INTERVAL="2"):
            engine.sample(*CONTEXT)
            started = engine.metadata["pid"]
            self.assertFalse(engine.set_profile(self.profile(profiles.BALANCED)))
            # a rename is not a new definition
            self.assertFalse(engine.set_profile(dict(self.profile(profiles.BALANCED), name="Renamed")))
            self.assertEqual(engine.metadata["pid"], started)
            self.assertTrue(engine.set_profile(self.profile(profiles.SECURITY)))
            after = engine.sample(*CONTEXT)
        self.assertNotEqual(engine.metadata["pid"], started)
        self.assertTrue(after["baseline"])

    def test_any_change_to_the_active_definition_restarts_the_helper(self):
        base = self.custom(active_states=100)
        changes = [self.custom(active_states=99, byte_rate=1), self.custom((1, 0, 0), active_states=100),
                   self.custom(assets=[("192.168.1.0/24", 2)], active_states=100),
                   self.custom(default=2, active_states=100), dict(base, uuid="0d1e4f0e-2b0c-4f39-9df1-6d1a7c1f2e10")]
        for changed in changes:
            engine = self.engine(base)
            self.assertTrue(engine.set_profile(changed))
            self.assertFalse(engine.set_profile(changed))

    def test_asset_importance_multiplies_quality(self):
        """assets: one state per flow, flow n from inside host 10.0.<n / 256>.<n % 256>. The /32
        inside the 2x /24 is 10x (the longest prefix, never 20x); others keep the default."""
        plain = self.custom(active_states=100)
        weighted = self.custom(assets=[("10.0.1.0/24", 2), ("10.0.1.7/32", 10)], active_states=100)
        (_, before), _ = self.run_mode("assets", 1000, profile=plain)
        (_, after), _ = self.run_mode("assets", 1000, profile=weighted)
        base = before["flows"][0]["score"]
        self.assertTrue(all(abs(flow["score"] - base) < 1e-9 for flow in before["flows"]))
        ratios = [round(flow["score"] / base, 6) for flow in after["flows"]]
        self.assertEqual(after["flows"][0]["key"][1], "9.0.1.7")
        self.assertEqual(ratios, [10.0] + [2.0] * (collector.RANKED_FLOWS - 1))
        # the class of a flow never depends on its asset
        self.assertTrue(all(flow["security_class"] == "S0" for flow in after["flows"]))

    def test_asset_importance_reaches_bounded_discovery(self):
        """assets_late at 64 MiB: about 2,450 flows fit T, and from index 3000 on flows carry 100x
        the bytes. Ranked by byte rate alone the heavy ones are promoted and lead; with the light
        flows 2600-2699 (never tracked at first) on a 1000x asset, discovery keeps them, promotion
        compares effective scores, and they lead in bounded mode instead."""
        lists = ("none", [])
        environment = {"FM_TEST_MODE": "assets_late", "FM_TEST_COUNT": "4000", "FM_TEST_INTERVAL": "2",
                       "FM_TEST_CLASS_DIR": self.tables}
        light = {f"9.0.{n >> 8}.{n & 255}" for n in range(2600, 2700)}
        tops = []
        for rules in ((), [(cidr, 1000) for cidr in ("10.0.10.40/29", "10.0.10.48/28", "10.0.10.64/26",
                                                             "10.0.10.128/29", "10.0.10.136/30")]):
            engine = self.engine(self.custom(assets=rules, byte_rate=100))
            with patch.dict(os.environ, environment):
                results = [engine.sample(*CONTEXT, memory=64 << 20, classification=lists) for _ in range(4)]
            self.assertEqual(results[1]["regime"], "bounded")
            tops.append({row["key"][1] for row in results[3]["flows"][:100]})
        self.assertFalse(tops[0] & light)
        self.assertEqual(tops[1], light)

    def test_heavy_untracked_flows_are_promoted(self):
        engine = self.engine()
        environment = {"FM_TEST_MODE": "late", "FM_TEST_COUNT": "4000", "FM_TEST_INTERVAL": "2",
                       "FM_TEST_CLASS_DIR": self.tables}
        with patch.dict(os.environ, environment):
            results = [engine.sample(*CONTEXT, memory=64 << 20) for _ in range(4)]
        promoting = results[1]
        self.assertEqual(promoting["regime"], "bounded")
        self.assertGreater(promoting["telemetry"]["promoted"], 0)
        # the next sample tracks them: the heavy flows (index 3000 on: 9.0.11.184 and up) lead the map
        top = [row["key"][1] for row in results[3]["flows"][:20]]
        self.assertTrue(all(tuple(map(int, remote.split(".")))[1:] >= (0, 11, 184) for remote in top), top)

    def test_threat_summary_priority_and_remote_cap(self):
        engine = self.engine()
        with patch.dict(os.environ, FM_TEST_MODE="unique", FM_TEST_COUNT="500", FM_TEST_INTERVAL="2",
                        FM_TEST_CLASS_DIR=self.tables):
            engine.sample(*CONTEXT)
            rows, _ = collector._context_rows(*CONTEXT)
            text = ("FMCONF2\nBUDGET {memory} 16 100\nTHREATS\nEVIDENCE 9.0.1.200 16 0 0 0\n"
                    "CLASS 0 T threats_all\nCLASSGEN all\n{rows}RUN\n".format(
                memory=collector.memory_budget(), rows="".join(row + "\n" for row in rows)))
            summary = engine._request(text, lambda stream, process: collector._decode(
                stream, process, (), True, categories=["T"]))
        remotes = [remote["address"] for remote in summary["threat_remotes"]]
        self.assertEqual(len(remotes), 100)
        self.assertEqual(summary["telemetry"]["threat_remotes_omitted"], 400)
        self.assertEqual(remotes[0], "9.0.1.200")  # explicit evidence first, whatever its bytes
        # then locally initiated remotes by bytes, largest first
        sizes = [remote["bytes"] for remote in summary["threat_remotes"][1:]]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_threat_summary_keeps_only_flagged_remotes(self):
        """Focus-independent: the summary is what the threat lists and evidence name, not the
        long tail; country sets classify without making a remote a threat."""
        classification = ("some", [("T", "threats_some"), ("C", "country"), ("T", "absent")])
        (_, last), _ = self.run_mode("unique", 1000, threat_summary=True,
                                     evidence={"9.0.2.7": evidence.facts(reputation=True)},
                                     classification=classification, classify=["9.0.0.5", "9.0.0.200", "9.0.3.1"])
        remotes = {remote["address"]: remote["classes"] for remote in last["threat_remotes"]}
        # 9.0.0.0/24 without its negated upper half, plus the evidence remote
        self.assertEqual(set(remotes), {f"9.0.0.{n}" for n in range(128)} | {"9.0.2.7"})
        self.assertEqual(remotes["9.0.0.5"], 0b011)
        self.assertEqual(remotes["9.0.2.7"], 0b010)
        self.assertEqual(last["telemetry"]["threat_remotes_omitted"], 0)
        self.assertEqual(last["classified"], {"9.0.0.5": 0b011, "9.0.0.200": 0b010, "9.0.3.1": 0b010})
        self.assertEqual([(row["status"], row["entries"]) for row in last["class_sets"]],
                         [("ok", 2), ("ok", 1), ("missing", 0)])
        self.assertGreater(last["telemetry"]["classifier_bytes"], 0)
        by_remote = {flow["key"][1]: flow["classes"] for flow in last["flows"]}
        self.assertTrue(all(mask == (0b011 if int(remote.split(".")[3]) < 128 and remote.startswith("9.0.0.")
                                     else 0b010 if remote.startswith("9.0.") else 0)
                            for remote, mask in by_remote.items()))

    def test_classifier_is_reloaded_only_when_its_configuration_changes(self):
        engine = self.engine()
        environment = {"FM_TEST_MODE": "unique", "FM_TEST_COUNT": "300", "FM_TEST_INTERVAL": "2",
                       "FM_TEST_CLASS_DIR": self.tables}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, environment):
            table = Path(directory) / "changing.txt"
            table.write_text("9.0.0.1\n")
            os.environ["FM_TEST_CLASS_DIR"] = directory
            first = engine.sample(*CONTEXT, classification=("g1", [("T", "changing")]), classify=["9.0.0.2"])
            table.write_text("9.0.0.2\n")
            same = engine.sample(*CONTEXT, classification=("g1", [("T", "changing")]), classify=["9.0.0.2"])
            changed = engine.sample(*CONTEXT, classification=("g2", [("T", "changing")]), classify=["9.0.0.2"])
            cleared = engine.sample(*CONTEXT, classify=["9.0.0.2"])
        self.assertEqual((first["classified"], same["classified"]), ({}, {}))
        self.assertEqual(changed["classified"], {"9.0.0.2": 1})
        self.assertEqual((cleared["classified"], cleared["class_sets"]), ({}, []))
        self.assertEqual(cleared["telemetry"]["classifier_bytes"], 0)

    def test_classifier_comes_off_the_state_admission(self):
        (_, plain), _ = self.run_mode("unique", 100, memory=64 << 20)
        (_, classified), _ = self.run_mode("unique", 100, memory=64 << 20, classification=THREATS_ALL)
        used = classified["telemetry"]["classifier_bytes"]
        self.assertEqual(plain["telemetry"]["state_limit"], state_limit(64 << 20))
        self.assertEqual(classified["telemetry"]["state_limit"], state_limit((64 << 20) - used))

    def test_output_is_identical_under_any_hash_key(self):
        keys = ("00" * 16, "0123456789abcdeffedcba9876543210")
        outputs = []
        for key in keys:
            results, _ = self.run_mode("mixed", 3000, samples=3, key=key, threat_summary=True,
                                       event_queries=[QUERY])
            outputs.append([{name: result[name] for name in ("flows", "candidates", "matches", "threat_remotes",
                                                             "threat_candidates", "counts")}
                            for result in results])
        self.assertEqual(outputs[0], outputs[1])

    def test_structured_and_scattered_addresses_cost_the_same(self):
        """Sequential, low-entropy addresses (one remote network) against scattered ones: with a
        keyed hash neither shape can concentrate the maps' buckets. (No collision corpus for the
        retired unkeyed hash is kept or generated.)"""
        _, structured = self.run_mode("unique", 60000, samples=3)
        _, scattered = self.run_mode("many", 60000, samples=3)
        print(f"\n  60000 states: structured {structured:.3f} s, scattered {scattered:.3f} s")
        self.assertLess(structured, max(scattered, 0.05) * 4)

    def test_correlation_is_skipped_when_nothing_consumes_it(self):
        (_, with_correlation), _ = self.run_mode("unique", 50000)
        (_, without), _ = self.run_mode("unique", 50000, correlation=False)
        self.assertEqual(without["matches"], {})
        self.assertLess(without["telemetry"]["heap_peak"], with_correlation["telemetry"]["heap_peak"])
        self.assertEqual(without["flows"], with_correlation["flows"])


if __name__ == "__main__":
    unittest.main()
