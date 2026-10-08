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

"""FMAGG4/FMFAIL1 decoder contract tests with hand-built responses (PROTOCOL.md)."""

import os
import struct
import sys
import unittest
import unittest.mock
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "opnsense", "scripts", "OPNsense", "FirewallMap"))
from lib import collector  # noqa: E402


def frame(record):
    return struct.pack("!I", len(record)) + record


def address(value):
    parsed = __import__("ipaddress").ip_address(value)
    return bytes([parsed.version]) + parsed.packed.ljust(16, b"\0")


def header(threats=False, version=collector.PROTOCOL_VERSION):
    return b"\x00" + struct.pack("!II", version, int(threats))


def flow(rank=0, local="192.168.1.2", remote="203.0.113.3", rate=4.0, classes=0):
    return b"".join((b"\x01", struct.pack("!I", rank), address(local), address(remote),
                     struct.pack("!QQQIIQQQQQQQ", 1, 400, 200, 20, 2, 1, 0, 9, 40, 20, 2, classes),
                     struct.pack("!BBIIB", 0, 0, 0, 0, 0),
                     struct.pack("!ddddd", rate, 2.0, 0.2, 0.5, 3.0)))


def candidate(owner=0, kind=1, value=b"\x06"):
    return b"\x02" + struct.pack("!IBQQQH", owner, kind, 5, 1, 0, len(value)) + value


def threat_remote(index=0, classes=0):
    return b"".join((b"\x03", struct.pack("!I", index), address("203.0.113.3"),
                     struct.pack("!QQQQI", 1, 0, 600, classes, 2)))


def threat_candidate(owner=0, kind=2):
    value = address("192.168.1.2")
    return b"\x04" + struct.pack("!IBQQH", owner, kind, 5, 1, len(value)) + value


QUERY = ("tcp", "198.51.100.2", "443", "203.0.113.3", "5555")


def event(query=0, protocol=6, flags=b"\x01\x01"):
    return b"".join((
        b"\x05", struct.pack("!HBB", query, 1, protocol), address("198.51.100.2"),
        struct.pack("!H", 443), address("203.0.113.3"), struct.pack("!H", 5555),
        b"\x01", address("192.168.1.2"), struct.pack("!H", 8080),
        struct.pack("!QI", 99, 7), b"\x00", struct.pack("!IQQQQ", 3, 1000, 500, 10, 5),
        flags, b"igb0".ljust(16, b"\0"), b"rule-label".ljust(64, b"\0")))


def classified(value="203.0.113.3", mask=1, evidence=0, security_class=0, states=0):
    return b"\x07" + address(value) + struct.pack("!QBBQ", mask, evidence, security_class, states)


def class_set(set_id=0, category="T", status=0, entries=12):
    return b"\x08" + struct.pack("!BBBQ", set_id, ord(category), status, entries)


def telemetry(interval=2.0, quality=(0,) * 26):
    values = (42, 7, interval, 0.01, 0.002, 1.0, 0.5, 1 << 20, 4096, 8192, 10, 0, 100000, 0, 0, 0, 0, 0, 0, 0, 0,
              *quality)
    return b"\x06" + struct.pack("!IQddddd" + "Q" * 40, *values)


def response(records, outcome=(0, 0, 0, 0), counts=None, corrupt=0, magic=b"FMAGG4\0\0", footer=True):
    body, checksum = b"", 0
    for record in records:
        encoded = frame(record)
        body += encoded
        checksum = zlib.crc32(encoded, checksum)
    kinds = [record[0] for record in records if record]
    sent = counts or (kinds.count(1), kinds.count(2), kinds.count(5), kinds.count(3), kinds.count(4),
                      kinds.count(7), kinds.count(8), kinds.count(10))
    seen = (1, 1, 1, sent[0])
    tail = b"\xff" + struct.pack("!IIQQQQQQQQQQQQQQI", *outcome, *seen, *sent, (checksum + corrupt) & 0xffffffff)
    return magic + body + (frame(tail) if footer else b"")


VALID = [header(True), flow(), candidate(), threat_remote(), threat_candidate(), event(), telemetry()]


class Process:
    @staticmethod
    def poll():
        return 0


class CollectorProtocolTest(unittest.TestCase):
    def decode(self, data, query_keys=(QUERY,), require_threat_summary=False, categories=(),
               asked=frozenset()):
        read_fd, write_fd = os.pipe()
        with os.fdopen(write_fd, "wb") as output:
            output.write(data)
        stream = os.fdopen(read_fd, "rb", buffering=0)
        try:
            return collector._decode(stream, Process(), query_keys, require_threat_summary,
                                     categories=categories, asked=asked)
        finally:
            stream.close()

    def test_accepts_complete_empty_sample(self):
        result = self.decode(response([header(), telemetry(-1.0)]))
        self.assertEqual(result["counts"]["states"], 1)
        self.assertEqual(result["flows"], [])
        self.assertTrue(result["baseline"])
        self.assertIsNone(result["refused"])
        self.assertFalse(result["threat_summary"])

    def test_decodes_every_record_kind(self):
        result = self.decode(response(VALID), require_threat_summary=True)
        flow_row = result["flows"][0]
        self.assertEqual(flow_row["key"], ("192.168.1.2", "203.0.113.3"))
        self.assertEqual((flow_row["rate_from_remote"], flow_row["bytes_from_remote"]), (4.0, 400))
        self.assertEqual(result["candidates"], [(0, 1, 5, 1, 0, b"\x06")])
        self.assertEqual(result["threat_remotes"][0]["remote_initiated_states"], 1)
        self.assertEqual(result["threat_candidates"][0][0:4], (0, 2, 5, 1))
        match = result["matches"][QUERY]
        self.assertEqual((match["inside"], match["rule"], match["bytes_in"], match["bytes_out"]),
                         ("192.168.1.2", "rule-label", 1000, 500))
        self.assertTrue(match["remote_initiated"] and match["remote_started"])
        self.assertEqual(result["telemetry"]["pid"], 42)
        self.assertFalse(result["baseline"])

    def test_decodes_a_refusal(self):
        result = self.decode(response([header(), telemetry(-1.0)], outcome=(2, ord("N"), 9000, 8192)))
        self.assertEqual(result["refused"], {"reason": "refused_context", "kind": "N", "actual": 9000,
                                             "limit": 8192})

    def test_rejects_every_malformed_response(self):
        bad_label = event()[:130] + b"\xff" * 64
        cases = {
            "truncated": response(VALID)[:-1],
            "bytes past the footer": response(VALID) + b"\0",
            "checksum": response(VALID, corrupt=1),
            "unexpected magic": response(VALID, magic=b"FMSTATE2"),
            "header version 0": response([header(version=0), telemetry()]),
            "header version 2": response([header(version=2), telemetry()]),
            "header flags": response([b"\x00" + struct.pack("!II", collector.PROTOCOL_VERSION, 2), telemetry()]),
            "no footer": response(VALID, footer=False),
            "missing header": response(VALID[1:]),
            "missing telemetry": response(VALID[:-1]),
            "record after telemetry": response(VALID + [flow(1)]),
            "kind order": response([header(True), candidate(), flow()]),
            "rank order": response([header(), flow(1), telemetry()]),
            "candidate owner": response([header(), flow(), candidate(owner=1), telemetry()]),
            "candidate kind": response([header(), flow(), candidate(kind=9), telemetry()]),
            "threat without flag": response([header(False), threat_remote(), telemetry()]),
            "threat candidate kind": response([header(True), threat_remote(), threat_candidate(kind=1),
                                               telemetry()]),
            "event tuple": response([header(), event(protocol=17), telemetry()]),
            "event query id": response([header(), event(query=3), telemetry()]),
            "event flags": response([header(), event(flags=b"\x02\x00"), telemetry()]),
            "count mismatch": response(VALID, counts=(2, 1, 1, 1, 1, 0, 0, 0)),
            "refusal with records": response(VALID, outcome=(1, 0, 10, 5)),
            "unknown outcome": response([header(), telemetry()], outcome=(9, 0, 0, 0)),
            "unknown record": response([header(), b"\x09" + b"x", telemetry()]),
            "nan rate": response([header(), flow(rate=float("nan")), telemetry()]),
            "empty frame": response([header(), b"", telemetry()]),
            "oversized frame": b"FMAGG4\0\0" + struct.pack("!I", collector.MAX_FRAME + 1),
        }
        for name, data in cases.items():
            with self.subTest(case=name), self.assertRaises(collector.CollectorError):
                self.decode(data)
        # the label bytes are invalid UTF-8: decoded with replacement, never an error
        result = self.decode(response([header(), bad_label, telemetry()]))
        self.assertEqual(result["matches"][QUERY]["rule"], "\ufffd" * 64)

    def test_decodes_classification(self):
        records = [header(True), flow(classes=2), threat_remote(classes=3), classified(mask=3),
                   class_set(0, "T"), class_set(1, "C", status=1, entries=0), telemetry()]
        result = self.decode(response(records), categories=("T", "C"), asked={"203.0.113.3"})
        self.assertEqual(result["flows"][0]["classes"], 2)
        self.assertEqual(result["threat_remotes"][0]["classes"], 3)
        self.assertEqual(result["classified"], {"203.0.113.3": 3})
        self.assertEqual(result["remotes"], {"203.0.113.3": {"classes": 3, "evidence": 0, "security_class": "S0",
                                                             "states": 0}})
        self.assertEqual(result["class_sets"], [
            {"id": 0, "category": "T", "status": "ok", "entries": 12},
            {"id": 1, "category": "C", "status": "missing", "entries": 0}])

    def test_rejects_malformed_classification(self):
        sets = [class_set(0, "T"), class_set(1, "C")]
        cases = {
            "flow mask outside the sets": [header(), flow(classes=4), *sets, telemetry()],
            "threat mask outside the sets": [header(True), threat_remote(classes=8), *sets, telemetry()],
            "address not asked": [header(), classified("198.51.100.9"), *sets, telemetry()],
            "nothing set": [header(), classified(mask=0), *sets, telemetry()],
            "class without evidence": [header(), classified(security_class=2), *sets, telemetry()],
            "evidence without class": [header(), classified(evidence=2), *sets, telemetry()],
            "unknown evidence bit": [header(), classified(evidence=64, security_class=1), *sets, telemetry()],
            "duplicate address": [header(), classified(), classified(), *sets, telemetry()],
            "set order": [header(), class_set(1, "C"), class_set(0, "T"), telemetry()],
            "set category": [header(), class_set(0, "C"), telemetry()],
            "set status": [header(), class_set(0, "T", status=9), telemetry()],
            "entries of a missing set": [header(), class_set(0, "T", status=1, entries=5), telemetry()],
            "unrequested set": [header(), *sets, class_set(2, "T"), telemetry()],
            "classification before events": [header(), classified(), event(), *sets, telemetry()],
        }
        for name, records in cases.items():
            with self.subTest(case=name), self.assertRaises(collector.CollectorError):
                self.decode(response(records), categories=("T", "C"), asked={"203.0.113.3"})

    def test_classification_request_rows(self):
        rows, categories, asked = collector._class_rows(
            ("g1", [("T", "FWMAP_Feodo"), ("C", "Country_CN")]), ["203.0.113.3", "203.0.113.3", "fe80::1"])
        self.assertEqual(rows, ["CLASS 0 T FWMAP_Feodo", "CLASS 1 C Country_CN", "CLASSGEN g1",
                                "K 203.0.113.3"])
        self.assertEqual((categories, asked), (["T", "C"], {"203.0.113.3"}))
        for invalid in (("g", [("X", "a")]), ("g", [("T", "bad name")]), ("g", [("T", "a"), ("C", "a")]),
                        ("has space", [("T", "a")]), ("g", [("T", "a" * 32)])):
            with self.subTest(invalid=invalid), self.assertRaises(collector.CollectorError):
                collector._class_rows(invalid, ())

    def test_failure_report_carries_its_class(self):
        message = b"PF state ABI version 2, collector built for 1"
        failure = b"FMFAIL1\0" + frame(b"\xfe" + struct.pack("!Ii", 3, 71) + message)
        with self.assertRaises(collector.CollectorError) as raised:
            self.decode(failure)
        self.assertEqual(raised.exception.failure_class, "incompatible")
        self.assertIn("collector built for 1", str(raised.exception))

    def test_timeout(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        stream = os.fdopen(read_fd, "rb", buffering=0)
        self.addCleanup(stream.close)
        with unittest.mock.patch.object(collector, "READ_TIMEOUT", 0.05), \
                self.assertRaises(collector.CollectorError) as raised:
            collector._decode(stream, Process(), (), False)
        self.assertIn("timed out", str(raised.exception))

    def test_build_configd_and_client_agree_on_the_installed_collector(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        self.assertEqual(collector.HELPER, "/usr/local/libexec/firewallmap-collector")
        with open(os.path.join(root, "..", "..", "tools", "build.sh")) as handle:
            build = handle.read()
        # the package installs src/ under /usr/local
        self.assertIn('-o "${WORK}/${PLUGIN}/src/libexec/firewallmap-collector"', build)
        self.assertIn('"${WORK}/${PLUGIN}"/collector/*.c', build)
        with open(os.path.join(root, "src/opnsense/service/conf/actions.d/actions_firewallmap.conf")) as handle:
            actions = handle.read()
        for action, option in (("collector.selftest", "--selftest"), ("collector.version", "--version")):
            self.assertIn(f"[{action}]\ncommand:{collector.HELPER} {option}\n", actions)

    def test_helper_detection_requires_executable(self):
        self.assertFalse(collector.available("/definitely/not/a/firewallmap-helper"))


if __name__ == "__main__":
    unittest.main()
