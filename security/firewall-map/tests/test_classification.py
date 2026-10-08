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

"""The plugin-owned address classification table (lib/classification.py)."""

import ipaddress
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "opnsense", "scripts", "OPNsense",
                                "FirewallMap"))
from lib import classification as C  # noqa: E402
from lib import common  # noqa: E402

# Declared differences from the classification derived from Python's ipaddress module:
# IPv4-mapped addresses follow their IPv4 meaning for shared address space too.
DECLARED = {"::ffff:100.64.0.0", "::ffff:100.127.255.255"}


class ClassificationTest(unittest.TestCase):
    def test_examples(self):
        expected = {
            "8.8.8.8": C.PUBLIC, "10.1.2.3": C.PRIVATE, "100.64.1.1": C.PRIVATE, "127.0.0.1": 0,
            "224.0.0.18": 0, "192.0.0.9": C.PUBLIC, "192.0.0.8": C.PRIVATE, "169.254.1.1": C.PRIVATE,
            "2606:4700::1": C.PUBLIC, "fe80::1": C.PRIVATE, "fd00::1": C.PRIVATE, "2001:db8::1": C.PRIVATE,
            "3fff::1": C.PRIVATE, "::1": 0, "ff02::1": 0, "2001:3::1": C.PUBLIC, "::ffff:8.8.8.8": C.PUBLIC,
            "::ffff:10.0.0.1": C.PRIVATE, "not an address": 0,
        }
        for address, flags in expected.items():
            with self.subTest(address=address):
                self.assertEqual(C.address_flags(address), flags)
                self.assertEqual(common.public_ip(address), flags == C.PUBLIC)
                self.assertEqual(common.private_ip(address), flags == C.PRIVATE)

    def test_ranges_are_sorted_disjoint_and_cover_the_space(self):
        for version, size in ((4, 32), (6, 128)):
            ranges = C.RANGES[version]
            self.assertEqual(ranges[0][0], 0)
            self.assertEqual(ranges[-1][1], (1 << size) - 1)
            for (low, high, flags), (next_low, _, next_flags) in zip(ranges, ranges[1:]):
                self.assertLessEqual(low, high)
                self.assertEqual(high + 1, next_low)
                self.assertNotEqual(flags, next_flags)  # adjacent equal ranges are merged
        self.assertLess(len(C.rows()), 1024)  # the helper's R row maximum

    def test_matches_the_runtime_ipaddress_module_except_declared(self):
        """Documents agreement with this interpreter's ipaddress; production never uses it."""
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        for row in C.rows():
            for text in row.split()[1:3]:
                address = ipaddress.ip_address(text)
                runtime = int(address.is_global and not address.is_multicast) | 2 * int(
                    (address.is_private or (address.version == 4 and address in cgnat)) and not address.is_loopback)
                if text in DECLARED or (address.version == 6 and address.ipv4_mapped is not None
                                        and str(address.ipv4_mapped) in ("100.64.0.0", "100.127.255.255")):
                    continue
                with self.subTest(address=text):
                    self.assertEqual(C.address_flags(text), runtime)


if __name__ == "__main__":
    unittest.main()
