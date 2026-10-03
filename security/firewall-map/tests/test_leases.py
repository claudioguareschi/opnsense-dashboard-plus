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

"""Unit tests for names of addresses: reverse DNS (fwmap_leases)."""

import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import CACHE, LEASES  # noqa: E402


class ImmediatePool:
    """Runs lookups at once, so a test sees their results on the next update."""

    class Done:
        def __init__(self, value):
            self.value = value

        def done(self):
            return True

        def result(self):
            return self.value

    def submit(self, function, *args):
        return self.Done(function(*args))


class HostnameResolverTest(unittest.TestCase):
    def resolver(self, store=None, per_sample=2, ttl=100):
        resolver = LEASES.HostnameResolver(ttl=ttl, per_sample=per_sample, store=store)
        resolver.pool = ImmediatePool()
        return resolver

    def test_looks_up_a_bounded_number_per_sample_and_caches(self):
        calls = []

        def reverse(address):
            calls.append(address)
            return f"host-{address}"
        with mock.patch.object(LEASES.HostnameResolver, "_reverse", staticmethod(reverse)):
            resolver = self.resolver()
            resolver.update(["8.8.8.8", "1.1.1.1", "9.9.9.9"], now=0.0)
            self.assertEqual(calls, ["8.8.8.8", "1.1.1.1"])
            resolver.update(["8.8.8.8", "1.1.1.1", "9.9.9.9"], now=1.0)
            self.assertEqual(calls, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
            self.assertEqual(resolver.get("8.8.8.8"), "host-8.8.8.8")
            # cached until the TTL runs out
            resolver.update(["8.8.8.8"], now=50.0)
            self.assertEqual(len(calls), 3)
            resolver.update(["8.8.8.8"], now=200.0)
            self.assertIsNone(resolver.get("8.8.8.8"))
            self.assertEqual(calls[-1], "8.8.8.8")

    def test_names_survive_a_restart_through_the_store(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cache.db")
            with mock.patch.object(LEASES.HostnameResolver, "_reverse", staticmethod(lambda address: "dns.google")):
                first = self.resolver(CACHE.CacheStore(path), ttl=3600)
                first.update(["8.8.8.8"], now=time.monotonic())
                first.update([], now=time.monotonic())
            again = self.resolver(CACHE.CacheStore(path), ttl=3600)
            self.assertEqual(again.get("8.8.8.8"), "dns.google")


if __name__ == "__main__":
    unittest.main()
