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


"""CrowdSec bans for Firewall Map+ (lib/crowdsec.py): reading them with cscli, what each address
carries, the CrowdSec evidence fact and the ban and unban commands."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from support import BLOCKLISTS, CROWDSEC, EVIDENCE, THREATS  # noqa: E402
from lib import collector as STATE_COLLECTOR  # noqa: E402

NOW = 1_800_000_000.0


_IDS = iter(range(1000, 100000))


def decision(value, origin="CAPI", scenario="ssh:bruteforce", duration="24h0m0s", scope="Ip", **extra):
    return {"value": value, "origin": origin, "scenario": scenario, "duration": duration, "scope": scope,
            "type": "ban", "id": next(_IDS), "simulated": False, **extra}


# the shape of `cscli decisions list -a -o json`: alerts, each with its decisions
ALERTS = [
    {"scenario": "update : +3/-0 IPs", "decisions": [
        decision("185.220.101.1", scenario="tcp:scan", duration="165h23m57.5s"),
        decision("45.56.79.53", scenario="http:bruteforce"),
        decision("2001:db8::/32", scope="Range", scenario="generic:scan"),
    ]},
    {"scenario": "firewallservices/pf-scan-multi_ports", "decisions": [
        decision("45.56.79.53", origin="crowdsec", scenario="firewallservices/pf-scan-multi_ports", duration="3h59m1s"),
    ]},
    {"scenario": "manual", "decisions": [
        decision("94.154.43.203", origin="cscli", scenario="firewallmap: banned from Firewall Map+", duration="4h"),
        decision("94.154.43.204", origin="cscli", duration="-1m3s"),          # expired
        decision("94.154.43.205", simulated=True),                            # only logged
        decision("someone", scope="Username"),                                # not an address
        decision("not-an-ip"),
    ]},
    "not an alert",
]


class DurationTest(unittest.TestCase):
    def test_go_durations(self):
        self.assertEqual(CROWDSEC.duration_seconds("165h23m57.5s"), 165 * 3600 + 23 * 60 + 57.5)
        self.assertEqual(CROWDSEC.duration_seconds("4h"), 14400)
        self.assertEqual(CROWDSEC.duration_seconds("1m30s500ms"), 90.5)
        for bad in ("-1m3s", "", "4 h", "4x", None, 14400, "h"):
            self.assertIsNone(CROWDSEC.duration_seconds(bad), bad)


class ParseTest(unittest.TestCase):
    def test_strongest_ban_per_address(self):
        addresses, ranges = CROWDSEC.parse_decisions(ALERTS, NOW)
        self.assertEqual(set(addresses), {"185.220.101.1", "45.56.79.53", "94.154.43.203"})
        # detected here outranks the community blocklist, whatever ends later
        self.assertEqual(addresses["45.56.79.53"], {
            "reason": "firewallservices/pf-scan-multi_ports", "origin": "local", "type": "ban",
            "until": round(NOW + 3 * 3600 + 59 * 60 + 1), "id": addresses["45.56.79.53"]["id"], "bans": 2})
        self.assertEqual((addresses["185.220.101.1"]["origin"], addresses["185.220.101.1"]["reason"]),
                         ("community", "tcp:scan"))
        self.assertEqual(addresses["94.154.43.203"]["origin"], "manual")
        ((network, ban),) = ranges
        self.assertEqual((str(network), ban["reason"]), ("2001:db8::/32", "generic:scan"))

    def test_bad_answers_give_nothing(self):
        for answer in (None, {}, "x", [None], [{"decisions": "x"}]):
            self.assertEqual(CROWDSEC.parse_decisions(answer, NOW), ({}, []))


def flat(alerts):
    """The stream's shape: decisions, not alerts."""
    return [item for alert in alerts if isinstance(alert, dict) for item in alert.get("decisions") or []]


class FakeStream:
    """CrowdSec's decision stream: every ban on startup, then the queued changes."""

    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.queued = {"new": [], "deleted": []}
        self.calls = []
        self.refuse = False

    def __call__(self, key, startup):
        self.calls.append((key, startup))
        if self.refuse:
            self.refuse = False
            raise CROWDSEC.StreamRefused("HTTP 403")
        if startup:
            self.queued = {"new": [], "deleted": []}
            return {"new": list(self.decisions), "deleted": []}
        changes, self.queued = self.queued, {"new": [], "deleted": []}
        return changes


class SourceTest(unittest.TestCase):
    @staticmethod
    def source(answer=ALERTS, streamer=None):
        keys = iter(f"key{n:020d}" for n in range(100))
        streamer = streamer or FakeStream(flat(answer))
        source = CROWDSEC.CrowdSec(streamer=streamer, registrar=lambda: next(keys), key_reader=lambda: None,
                                   reader=lambda: answer, clock=lambda: NOW)
        with mock.patch.object(CROWDSEC, "available", return_value=True):
            source.configure(True)
        source.refresh(wait=True)
        return source

    def test_lookup_detected_and_status(self):
        source = SourceTest.source()
        self.assertEqual(source.lookup("185.220.101.1")["origin"], "community")
        self.assertEqual(source.lookup("2001:db8::25")["reason"], "generic:scan")
        self.assertIsNone(source.lookup("192.0.2.1"))
        self.assertTrue(source.detected("45.56.79.53"))
        self.assertFalse(source.detected("185.220.101.1"))
        with mock.patch.object(CROWDSEC, "available", return_value=True):
            status = source.status()
        self.assertEqual({key: status[key] for key in ("enabled", "mode", "bans", "ranges", "local", "updated", "error")},
                         {"enabled": True, "mode": "stream", "bans": 3, "ranges": 1, "local": 1, "updated": NOW,
                          "error": None})

    def test_the_stream_sends_only_changes(self):
        stream = FakeStream(flat(ALERTS))
        source = SourceTest.source(streamer=stream)
        before = source.bans
        local_ban = next(item for item in flat(ALERTS) if item["origin"] == "crowdsec")
        stream.queued = {"new": [decision("203.0.114.9", origin="cscli", duration="1h", id=99)],
                         "deleted": [local_ban]}
        source.refresh(now=NOW + CROWDSEC.STREAM_SECONDS, wait=True)
        self.assertEqual(stream.calls[-1], ("key00000000000000000000", False))
        self.assertEqual(source.lookup("203.0.114.9")["origin"], "manual")
        # the local detection ended: the community ban of the same address speaks for it now
        self.assertEqual(source.lookup("45.56.79.53")["origin"], "community")
        self.assertFalse(source.detected("45.56.79.53"))
        # the changes went into a copy: what the collector was iterating did not change under it
        self.assertIn("45.56.79.53", before.local)
        self.assertIsNot(source.bans, before)
        # nothing changed: no new copy
        current = source.bans
        source.refresh(now=NOW + 2 * CROWDSEC.STREAM_SECONDS, wait=True)
        self.assertIs(source.bans, current)
        # everything again after RESYNC_SECONDS
        source.clock = lambda: NOW + CROWDSEC.RESYNC_SECONDS + 1
        source.refresh(now=NOW + CROWDSEC.RESYNC_SECONDS + 1, wait=True)
        self.assertEqual(stream.calls[-1][1], True)

    def test_a_refused_key_registers_again(self):
        stream = FakeStream(flat(ALERTS))
        source = SourceTest.source(streamer=stream)
        stream.refuse = True
        source.refresh(now=NOW + CROWDSEC.STREAM_SECONDS, wait=True)
        self.assertEqual(stream.calls[-1], ("key00000000000000000001", True))
        self.assertEqual((source.mode, source.error), ("stream", None))

    def test_without_the_local_api_every_ban_is_read_with_cscli(self):
        def down(key, startup):
            raise CROWDSEC.CrowdSecError("the local API did not answer")
        source = SourceTest.source(streamer=down)
        self.assertEqual((source.mode, source.error), ("cscli", None))
        self.assertEqual(source.lookup("185.220.101.1")["origin"], "community")
        self.assertTrue(source.detected("45.56.79.53"))

    def test_a_ban_that_ended_is_not_in_force(self):
        source = SourceTest.source()
        source.clock = lambda: NOW + 5 * 3600
        self.assertIsNone(source.lookup("45.56.79.53"))
        self.assertFalse(source.detected("45.56.79.53"))

    def test_off_or_without_cscli_reads_nothing(self):
        calls = []
        source = CROWDSEC.CrowdSec(reader=lambda: calls.append(1) or ALERTS, streamer=lambda *a: calls.append(2),
                                   clock=lambda: NOW)
        with mock.patch.object(CROWDSEC, "available", return_value=False):
            source.configure(True)
        source.refresh(wait=True)
        self.assertEqual((calls, source.enabled, source.lookup("185.220.101.1")), ([], False, None))

    def test_turning_it_off_removes_the_registration(self):
        source = SourceTest.source()
        with mock.patch.object(CROWDSEC, "available", return_value=True), \
                mock.patch.object(CROWDSEC.os.path, "exists", return_value=True), \
                mock.patch.object(CROWDSEC, "unregister") as unregister:
            source.configure(False)
        unregister.assert_called_once_with()
        self.assertEqual((source.enabled, source.lookup("185.220.101.1"), source.mode), (False, None, None))

    def test_a_failed_read_keeps_the_last_bans_and_is_retried_sooner(self):
        source = SourceTest.source(streamer=lambda key, startup: (_ for _ in ()).throw(CROWDSEC.CrowdSecError("down")))

        def fail():
            raise CROWDSEC.CrowdSecError("cscli did not answer")
        source.reader = fail
        source.refresh(now=NOW + CROWDSEC.REFRESH_SECONDS, wait=True)
        self.assertEqual(source.error, "cscli did not answer")
        self.assertEqual(source.lookup("185.220.101.1")["origin"], "community")
        source.reader = lambda: []
        source.refresh(now=NOW + CROWDSEC.REFRESH_SECONDS + 1, wait=True)       # not yet due
        self.assertIsNotNone(source.error)
        source.refresh(now=NOW + CROWDSEC.REFRESH_SECONDS + CROWDSEC.RETRY_SECONDS, wait=True)
        self.assertEqual((source.error, source.lookup("185.220.101.1")), (None, None))


class KeyTest(unittest.TestCase):
    def test_key_file_is_root_only_and_registration_replaces_a_lost_one(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "crowdsec.key")
            with mock.patch.object(CROWDSEC.subprocess, "run") as run:
                run.return_value = mock.Mock(returncode=0, stdout="AbCdEf0123456789abcdef0123\n", stderr="")
                self.assertEqual(CROWDSEC.register(path), "AbCdEf0123456789abcdef0123")
            self.assertEqual([call.args[0][1:3] for call in run.call_args_list],
                             [["bouncers", "delete"], ["bouncers", "add"]])
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(CROWDSEC.read_key(path), "AbCdEf0123456789abcdef0123")
            with mock.patch.object(CROWDSEC, "available", return_value=True), \
                    mock.patch.object(CROWDSEC.subprocess, "run") as run:
                self.assertTrue(CROWDSEC.unregister(path))
            self.assertEqual(run.call_args.args[0], [CROWDSEC.CSCLI, "bouncers", "delete", CROWDSEC.BOUNCER])
            self.assertFalse(os.path.exists(path))
            self.assertFalse(CROWDSEC.unregister(path))

    def test_api_address_from_the_crowdsec_configuration(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("api:\n  server:\n    enable: true\n    listen_uri: 127.0.0.1:8081\n")
        try:
            self.assertEqual(CROWDSEC.api_address(handle.name), "127.0.0.1:8081")
        finally:
            os.unlink(handle.name)
        self.assertEqual(CROWDSEC.api_address("/nonexistent"), CROWDSEC.DEFAULT_API)


class ThreatFactsTest(unittest.TestCase):
    def test_lists_fields_labels_and_evidence(self):
        source = SourceTest.source()
        self.assertEqual(BLOCKLISTS.threat_lists_for("45.56.79.53", None, None, crowdsec=source),
                         [CROWDSEC.LOCAL_LIST])
        self.assertEqual(BLOCKLISTS.threat_lists_for("185.220.101.1", None, None, crowdsec=source), [])
        fields = BLOCKLISTS.threat_fields("185.220.101.1", None, None, source)
        self.assertEqual(fields["crowdsec"], {"reason": "tcp:scan", "origin": "community", "type": "ban",
                                              "until": round(NOW + 165 * 3600 + 23 * 60 + 57.5), "bans": 1})
        self.assertNotIn("crowdsec", BLOCKLISTS.threat_fields("192.0.2.1", None, None, source))
        self.assertEqual([BLOCKLISTS.list_label(table) for table in CROWDSEC.TABLES], ["CrowdSec", "CrowdSec"])
        facts = EVIDENCE.gather(crowdsec=source)
        self.assertEqual(facts, {"45.56.79.53": (EVIDENCE.CROWDSEC, 0, 0, 0)})
        self.assertEqual(EVIDENCE.names(EVIDENCE.CROWDSEC), ["crowdsec"])

    def test_use_crowdsec_always_counts_its_tables(self):
        tables = ["crowdsec_blocklists", "crowdsec6_blocklists", "Office"]
        with mock.patch.object(BLOCKLISTS, "pf_tables", return_value=tables):
            self.assertEqual(BLOCKLISTS.chosen_threat_lists("Office")[0], {"Office"})
            self.assertEqual(BLOCKLISTS.chosen_threat_lists("Office", crowdsec=True)[0],
                             {"Office", "crowdsec_blocklists", "crowdsec6_blocklists"})


class RecordingTest(unittest.TestCase):
    def test_a_crowdsec_detection_is_an_evidence_row_of_its_own(self):
        (row,) = STATE_COLLECTOR._evidence_rows({"45.56.79.53": EVIDENCE.facts(crowdsec=True)})
        self.assertEqual(row, f"EVIDENCE 45.56.79.53 {EVIDENCE.CROWDSEC} 0 0 0")

    def test_threat_history_keeps_the_latest_ban(self):
        db = THREATS.connect(":memory:")
        entry = {"lists": ["CrowdSec"], "inbound": 0, "outbound": 1, "targets": [], "inside": [], "services": [],
                 "bytes": 10, "youngest": 5, "service_ports": {}, "disposition": "firewall_blocked"}
        first = {"reason": "tcp:scan", "origin": "community", "type": "ban", "until": NOW + 3600}
        THREATS.record(db, {"45.56.79.53": {**entry, "crowdsec": first}}, now=NOW)
        THREATS.record(db, {"45.56.79.53": dict(entry)}, now=NOW + 60)          # a sample without the ban keeps it
        self.assertEqual(THREATS.listing(db, "all")["rows"][0]["crowdsec"], first)
        later = {**first, "reason": "ssh:bruteforce", "origin": "local"}
        THREATS.record(db, {"45.56.79.53": {**entry, "crowdsec": later}}, now=NOW + 120)
        (row,) = THREATS.listing(db, "all")["rows"]
        self.assertEqual(row["crowdsec"]["reason"], "ssh:bruteforce")
        self.assertIn("45.56.79.53", [item["address"] for item in THREATS.listing(db, "all", query="bruteforce")["rows"]])
        db.close()


class CommandTest(unittest.TestCase):
    def run_with(self, function, *args, stdout=""):
        with mock.patch.object(CROWDSEC.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=stdout, stderr="")
            result = function(*args)
        return result, run.call_args.args[0]

    def test_ban_and_unban(self):
        result, command = self.run_with(CROWDSEC.ban, "45.56.79.53", "24h", "")
        self.assertEqual(command, [CROWDSEC.CSCLI, "decisions", "add", "-i", "45.56.79.53", "-d", "24h",
                                   "-t", "ban", "-R", CROWDSEC.BAN_REASON])
        self.assertEqual(result["reason"], CROWDSEC.BAN_REASON)
        result, command = self.run_with(CROWDSEC.unban, "2606:4700:4700::1111",
                                        stdout="INFO[0000] 2 decision(s) deleted\n")
        self.assertEqual(command, [CROWDSEC.CSCLI, "decisions", "delete", "-i", "2606:4700:4700::1111"])
        self.assertEqual(result["removed"], 2)

    def test_investigate_lists_each_ban_once_and_what_was_detected(self):
        answers = {
            "decisions": [{"decisions": [decision("198.211.110.53", scenario="tcp:scan", duration="1h")]},
                          {"decisions": [decision("198.211.110.53", scenario="tcp:scan", duration="2h")]}],
            "alerts": [{"scenario": "firewallservices/pf-scan-multi_ports", "events_count": 12,
                        "start_at": "2026-10-20T10:00:00Z", "stop_at": "2026-10-20T10:01:00Z",
                        "source": {"as_name": "DIGITALOCEAN-ASN", "cn": "US"}}],
        }
        with mock.patch.object(CROWDSEC, "run_cscli", side_effect=lambda arguments: answers[arguments[0]]):
            result = CROWDSEC.alerts_for("198.211.110.53", now=NOW)
        self.assertEqual(result["bans"], [{"reason": "tcp:scan", "origin": "community", "type": "ban", "until": NOW + 7200}])
        self.assertEqual(result["alerts"][0]["scenario"], "firewallservices/pf-scan-multi_ports")
        self.assertEqual((result["alerts"][0]["events"], result["banned"]), (12, True))

    def test_refuses_what_it_must_not_ban(self):
        for address, duration in (("192.168.1.2", "4h"), ("10.0.0.1", "4h"), ("example.com", "4h"),
                                  ("45.56.79.53", "1000h"), ("45.56.79.53 -d 1h", "4h")):
            with mock.patch.object(CROWDSEC.subprocess, "run") as run, self.assertRaises(CROWDSEC.CrowdSecError):
                CROWDSEC.ban(address, duration)
            run.assert_not_called()

    def test_cscli_failure_is_reported(self):
        with mock.patch.object(CROWDSEC.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="level=fatal msg=\"no LAPI\"\n")
            with self.assertRaisesRegex(CROWDSEC.CrowdSecError, "no LAPI"):
                CROWDSEC.unban("45.56.79.53")


if __name__ == "__main__":
    unittest.main()
