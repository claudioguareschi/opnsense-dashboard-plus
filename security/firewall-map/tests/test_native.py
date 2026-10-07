# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Unit tests for the native worker protocol boundary."""

import os
import struct
import sys
import unittest
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "opnsense", "scripts", "OPNsense", "FirewallMap"))
from lib import native  # noqa: E402


def response(corrupt=False):
    capability = b"\x00" + struct.pack("!II", 3, 5)
    cap_size = struct.pack("!I", len(capability))
    checksum = zlib.crc32(cap_size)
    checksum = zlib.crc32(capability, checksum)
    footer = b"\xff" + struct.pack(
        "!QQQQQQQQQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, checksum + int(corrupt))
    return b"FMAGG3\0\0" + cap_size + capability + struct.pack("!I", len(footer)) + footer


def frame(record):
    return struct.pack("!I", len(record)) + record


def address(value):
    parsed = __import__("ipaddress").ip_address(value)
    return bytes([parsed.version]) + parsed.packed.ljust(16, b"\0")


def populated_response():
    records = []
    capability = b"\x00" + struct.pack("!II", 3, 7)
    records.append(capability)
    flow = b"".join((
        b"\x01", struct.pack("!I", 0), address("192.168.1.2"), address("203.0.113.3"),
        struct.pack("!QQQIIQQQ", 1, 400, 200, 20, 2, 1, 0, 9),
        struct.pack("!QQQ", 40, 20, 2), struct.pack("!ddddd", 4.0, 2.0, 0.2, 0.5, 3.0)))
    records.append(flow)
    records.append(b"\x02" + struct.pack("!IBQQQH", 0, 1, 5, 1, 0, 1) + b"\x06")
    records.append(b"".join((b"\x03", struct.pack("!I", 0), address("203.0.113.3"),
                             struct.pack("!QQQI", 1, 0, 600, 2))))
    records.append(b"".join((b"\x04", struct.pack("!IBQQH", 0, 2, 5, 1, 17),
                             address("192.168.1.2"))))
    event = b"".join((
        b"\x05", struct.pack("!HBB", 0, 1, 6), address("198.51.100.2"),
        struct.pack("!H", 443), address("203.0.113.3"), struct.pack("!H", 5555),
        b"\x01", address("192.168.1.2"), struct.pack("!H", 8080),
        struct.pack("!QI", 99, 7), b"\x00", struct.pack("!IQQ", 3, 1000, 500),
        b"\x01", b"igb0".ljust(16, b"\0"), b"rule-label".ljust(64, b"\0")))
    records.append(event)
    checksum = 0
    body = b""
    for record in records:
        encoded = frame(record)
        body += encoded
        checksum = zlib.crc32(encoded[:4], checksum)
        checksum = zlib.crc32(record, checksum)
    footer = b"\xff" + struct.pack("!QQQQQQQQQQ", 1, 1, 1, 1, 1, 1, 1, 1, 1, checksum)
    return b"FMAGG3\0\0" + body + frame(footer)


class Process:
    @staticmethod
    def poll():
        return 0


class NativeProtocolTest(unittest.TestCase):
    def decode(self, data, query_keys=(), require_threat_summary=False):
        read_fd, write_fd = os.pipe()
        with os.fdopen(write_fd, "wb") as output:
            output.write(data)
        stream = os.fdopen(read_fd, "rb", buffering=0)
        try:
            return native._decode(stream, Process(), query_keys, require_threat_summary)
        finally:
            stream.close()

    def test_accepts_complete_empty_ranked_sample(self):
        result = self.decode(response())
        self.assertEqual(result["counts"]["states"], 0)
        self.assertEqual(result["flows"], [])
        self.assertEqual(result["matches"], {})
        self.assertFalse(result["threat_summary"])

    def test_rejects_incomplete_or_bad_checksum_sample(self):
        for data in (response()[:-1], response(corrupt=True)):
            with self.subTest(data_length=len(data)), self.assertRaises(native.NativeError):
                self.decode(data)

    def test_decodes_ranked_flow_threat_summary_and_event_match(self):
        query = ("tcp", "198.51.100.2", "443", "203.0.113.3", "5555")
        result = self.decode(populated_response(), [query], require_threat_summary=True)
        self.assertEqual(result["flows"][0]["key"], ("192.168.1.2", "203.0.113.3"))
        self.assertEqual(result["flows"][0]["rate_in"], 4.0)
        self.assertEqual(result["candidates"], [(0, 1, 5, 1, 0, b"\x06")])
        self.assertEqual(result["threat_remotes"][0]["bytes"], 600)
        self.assertEqual(result["threat_candidates"][0][0:4], (0, 2, 5, 1))
        self.assertEqual(result["matches"][query]["inside"], "192.168.1.2")
        self.assertEqual(result["matches"][query]["rule"], "rule-label")

    def test_helper_detection_requires_executable(self):
        self.assertFalse(native.available("/definitely/not/a/firewallmap-helper"))


if __name__ == "__main__":
    unittest.main()
