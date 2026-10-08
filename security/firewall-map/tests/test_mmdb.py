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

"""Unit tests for the in-process MaxMind DB reader (lib/mmdb.py)."""

import os
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import CACHE  # noqa: E402
from lib import mmdb  # noqa: E402


def encode(value):
    """The MaxMind DB encoding of a value (strings, maps, arrays, doubles, unsigned integers)."""
    def control(kind, size):
        extended = kind > 7
        head = bytes([((0 if extended else kind) << 5) | size]) + (bytes([kind - 7]) if extended else b"")
        return head
    if isinstance(value, str):
        data = value.encode()
        return control(2, len(data)) + data
    if isinstance(value, float):
        return control(3, 8) + struct.pack(">d", value)
    if isinstance(value, int):
        data = value.to_bytes(4, "big").lstrip(b"\0")
        return control(6, len(data)) + data
    if isinstance(value, list):
        return control(11, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        return control(7, len(value)) + b"".join(encode(key) + encode(item) for key, item in value.items())
    raise TypeError(value)


def database(path, prefix, prefix_length, record, ip_version=4):
    """A database holding `record` for one IPv4 prefix (24-bit records)."""
    bits = int.from_bytes(bytes(int(part) for part in prefix.split(".")), "big")
    depth = prefix_length + (96 if ip_version == 6 else 0)
    node_count = depth
    data = encode(record)
    tree = b""
    for index in range(depth):
        bit = 0 if index < depth - prefix_length else (bits >> (31 - (index - (depth - prefix_length)))) & 1
        child = index + 1 if index + 1 < depth else node_count + 16  # the last step points at the data
        records = [node_count, node_count]
        records[bit] = child
        tree += b"".join(value.to_bytes(3, "big") for value in records)
    metadata = {"node_count": node_count, "record_size": 24, "ip_version": ip_version, "database_type": "Test-City",
                "binary_format_major_version": 2, "binary_format_minor_version": 0}
    with open(path, "wb") as handle:
        handle.write(tree + b"\0" * 16 + data + mmdb.METADATA_MARKER + encode(metadata))


RECORD = {"city": {"names": {"en": "Mountain View"}}, "country": {"iso_code": "US"},
          "location": {"latitude": 37.386, "longitude": -122.0838, "accuracy_radius": 1000},
          "subdivisions": [{"names": {"en": "California"}}]}


class ReaderTest(unittest.TestCase):
    def test_finds_the_record_of_an_address_in_the_prefix(self):
        for ip_version in (4, 6):
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "city.mmdb")
                database(path, "8.8.8.0", 24, RECORD, ip_version)
                reader = mmdb.Reader(path)
                self.assertEqual(reader.get("8.8.8.8"), RECORD)
                self.assertIsNone(reader.get("1.1.1.1"))
                reader.close()

    def test_flattened_as_the_collector_reads_it(self):
        values = mmdb.flatten(RECORD)
        self.assertEqual(values[("city", "names", "en")], "Mountain View")
        self.assertEqual(float(values[("location", "longitude")]), -122.0838)
        self.assertEqual(values[("subdivisions", "names", "en")], "California")

    def test_a_file_that_is_not_a_database_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "broken.mmdb")
            with open(path, "wb") as handle:
                handle.write(b"not a database" * 100)
            with self.assertRaises(mmdb.InvalidDatabaseError):
                mmdb.Reader(path)
            # for the collector a broken file is a transient lookup failure, never cached as a miss
            with self.assertRaises(LookupError):
                CACHE.mmdb_lookup(path, "8.8.8.8")

    def test_damaged_data_is_an_invalid_database(self):
        # a truncated string, a pointer to itself, a pointer to a pointer: only InvalidDatabaseError
        truncated = bytes([(2 << 5) | 20]) + b"short"
        self_pointer = bytes([(1 << 5) | 0, 0])
        pointer_to_pointer = bytes([(1 << 5) | 0, 2, (1 << 5) | 0, 0])
        # a map whose two values point back at the map: exponential work within the depth limit
        fan_out = bytes([(7 << 5) | 2, (2 << 5) | 1]) + b"a" + bytes([1 << 5, 0, (2 << 5) | 1]) + b"b" + bytes([1 << 5, 0])
        for data in (truncated, self_pointer, pointer_to_pointer, fan_out):
            decoder = mmdb.Decoder(data, 0, len(data))
            with self.assertRaises(mmdb.InvalidDatabaseError):
                decoder.decode(0)
        with tempfile.TemporaryDirectory() as directory:
            empty = os.path.join(directory, "empty.mmdb")
            open(empty, "wb").close()
            with self.assertRaises(mmdb.InvalidDatabaseError):
                mmdb.Reader(empty)
            with self.assertRaises(LookupError):
                CACHE.mmdb_lookup(empty, "8.8.8.8")

    def test_hostile_values_are_an_invalid_database(self):
        # a map key that is a map (unhashable), and pointer fan-out over one large string
        map_key = bytes([(7 << 5) | 1]) + encode({"a": "b"}) + encode("x")
        # a 70000-byte string: size 31 with three extra bytes (65821 + 4179)
        string = bytes([(2 << 5) | 31]) + (70000 - 65821).to_bytes(3, "big") + b"y" * 70000
        pointers = b"".join(bytes([(1 << 5) | 0, 0]) for _ in range(40))  # 40 pointers to offset 0
        fan_out = string + bytes([(0 << 5) | 29, 11 - 7, 40 - 29]) + pointers
        for data, start in ((map_key, 0), (fan_out, len(string))):
            decoder = mmdb.Decoder(data, 0, len(data))
            with self.assertRaises(mmdb.InvalidDatabaseError):
                decoder.decode(start)

    def test_hostile_location_values_are_rejected_or_left_out(self):
        cases = (
            ({"location": {"latitude": float("nan"), "longitude": 1.0}}, None),
            ({"location": {"latitude": 91.0, "longitude": 1.0}}, None),
            ({"location": {"latitude": 1.0, "longitude": float("inf")}}, None),
            ({"location": {"latitude": 1.0, "longitude": 2.0, "accuracy_radius": "far"}}, {"accuracy_km": None}),
        )
        with tempfile.TemporaryDirectory() as directory:
            city = os.path.join(directory, "city.mmdb")
            asn = os.path.join(directory, "asn.mmdb")
            for record, expected in cases:
                with self.subTest(record=record):
                    database(city, "8.8.8.0", 24, record)
                    database(asn, "8.8.8.0", 24, {"autonomous_system_number": "AS-oops"})
                    location = CACHE.lookup_location("8.8.8.8", city, asn)
                    if expected is None:
                        self.assertIsNone(location)
                    else:
                        self.assertEqual(location["accuracy_km"], expected["accuracy_km"])
                        self.assertNotIn("asn", location)  # a malformed AS number is left out

    def test_location_from_the_database(self):
        with tempfile.TemporaryDirectory() as directory:
            city = os.path.join(directory, "city.mmdb")
            database(city, "8.8.8.0", 24, RECORD)
            with mock.patch.object(CACHE.os.path, "exists", lambda path: False):
                location = CACHE.lookup_location("8.8.8.8", city, os.path.join(directory, "asn.mmdb"))
            self.assertEqual((location["city"], location["country"], location["region"], location["accuracy_km"]),
                             ("Mountain View", "US", "California", 1000))
            self.assertIsNone(CACHE.lookup_location("1.1.1.1", city, os.path.join(directory, "asn.mmdb")))


if __name__ == "__main__":
    unittest.main()
