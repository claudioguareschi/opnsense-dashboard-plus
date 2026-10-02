# Copyright (C) 2026 Claudio Guareschi <cguareschi@gmail.com>
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

"""Unit tests for the geolocation database updater."""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import CACHE, GEODB  # noqa: E402


class GeoDatabaseTest(unittest.TestCase):
    def test_reads_key_from_maxmind_alias_url_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "filter_geoip.conf")
            with open(path, "w") as handle:
                handle.write("[settings]\nurl=https://download.maxmind.com/app/geoip_download"
                             "?edition_id=GeoLite2-Country-CSV&license_key=abc_123&suffix=zip\n")
            self.assertEqual(GEODB.alias_license_key(path), "abc_123")
            with open(path, "w") as handle:
                handle.write("[settings]\nurl=https://ipinfo.io/data/free/country.csv.gz?token=xyz\n")
            self.assertIsNone(GEODB.alias_license_key(path))
            self.assertIsNone(GEODB.alias_license_key(os.path.join(directory, "missing.conf")))

    def test_reads_plugin_settings_from_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.xml")
            with open(path, "w") as handle:
                handle.write("<opnsense><OPNsense><FirewallMap><general><provider>dbip</provider>"
                             "<license_key/><update_days>7</update_days></general></FirewallMap></OPNsense></opnsense>")
            self.assertEqual(GEODB.settings(path), {"provider": "dbip", "license_key": "", "update_days": 7,
                             "threat_lists": "", "record_threats": "1", "blocklist_aliases": "0"})
            self.assertEqual(GEODB.settings(os.path.join(directory, "none.xml"))["provider"], "auto")

    def test_automatic_provider_prefers_maxmind_with_a_key(self):
        with mock.patch.object(GEODB, "alias_license_key", lambda path=None: None):
            self.assertEqual(GEODB.effective_provider({"provider": "auto", "license_key": ""}), "dbip")
            self.assertEqual(GEODB.effective_provider({"provider": "auto", "license_key": "k"}), "maxmind")
        with mock.patch.object(GEODB, "alias_license_key", lambda path=None: "alias"):
            self.assertEqual(GEODB.effective_provider({"provider": "auto", "license_key": ""}), "maxmind")
            self.assertEqual(GEODB.effective_provider({"provider": "dbip", "license_key": "k"}), "dbip")

    def test_maxmind_city_and_asn_receive_ipv6(self):
        calls = []
        values = {
            ("location", "latitude"): "37.4", ("location", "longitude"): "-122.1",
            ("country", "iso_code"): "US",
        }
        asn = {("autonomous_system_number",): "13335", ("autonomous_system_organization",): "Cloudflare"}
        with mock.patch.object(CACHE, "mmdb_lookup", side_effect=lambda database, address: calls.append((database, address)) or (values if database == "city" else asn)), \
                mock.patch.object(CACHE.os.path, "exists", lambda path: True):
            result = CACHE.lookup_location("2606:4700:4700::1111", "city", "asn")
        self.assertEqual(calls, [("city", "2606:4700:4700::1111"), ("asn", "2606:4700:4700::1111")])
        self.assertEqual((result["country"], result["asn"], result["as_org"]), ("US", 13335, "Cloudflare"))


class GeoDatabaseUpdateTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = directory.name
        paths = {"city": os.path.join(self.directory, "city.mmdb"), "asn": os.path.join(self.directory, "asn.mmdb"),
                 "editions": {"city": "GeoLite2-City", "asn": "GeoLite2-ASN"}}
        for name, value in {
            "STATE_DIR": self.directory,
            "STATUS_FILE": os.path.join(self.directory, "geodb.json"),
            "LOCK_FILE": os.path.join(self.directory, "geodb.lock"),
            "GEOIP_DIR": self.directory,
            "DATABASES": {"maxmind": paths},
            "settings": lambda: {"provider": "maxmind", "license_key": "secret-key", "update_days": 3},
            "validate": lambda path, probe: None,
        }.items():
            patcher = mock.patch.object(GEODB, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def fetch(self, edition, key, workdir):
        target = os.path.join(workdir, f"{edition}.mmdb")
        with open(target, "w") as handle:
            handle.write(edition)
        return target

    def test_installs_databases_and_records_success(self):
        with mock.patch.object(GEODB, "fetch_maxmind", self.fetch):
            result = GEODB.update()
        self.assertEqual((result["result"], sorted(result["updated"])), ("ok", ["asn", "city"]))
        self.assertIsNone(GEODB.read_status()["last_error"])
        # fresh databases are not downloaded again
        with mock.patch.object(GEODB, "fetch_maxmind", self.fetch):
            self.assertEqual(GEODB.update()["updated"], [])

    def test_failure_hides_the_key_and_backs_off(self):
        def broken(edition, key, workdir):
            raise RuntimeError(f"HTTP 401 for https://download.maxmind.com/?license_key={key}")
        with mock.patch.object(GEODB, "fetch_maxmind", broken):
            result = GEODB.update()
        self.assertEqual(result["result"], "failed")
        self.assertNotIn("secret-key", json.dumps(result))
        with open(GEODB.STATUS_FILE) as handle:
            self.assertNotIn("secret-key", handle.read())
        # an automatic retry waits; a forced one runs
        with mock.patch.object(GEODB, "fetch_maxmind", self.fetch):
            self.assertEqual(GEODB.update()["result"], "backoff")
            self.assertEqual(GEODB.update(force=True)["result"], "ok")

    def test_a_second_updater_is_turned_away(self):
        import fcntl
        with open(GEODB.LOCK_FILE, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(GEODB.update(), {"result": "busy"})

    def test_missing_key_is_reported_without_backoff(self):
        with mock.patch.object(GEODB, "settings", lambda: {"provider": "maxmind", "license_key": "", "update_days": 3}), \
                mock.patch.object(GEODB, "alias_license_key", lambda path=None: None):
            self.assertEqual(GEODB.update()["error"], "maxmind_key_missing")
        self.assertFalse(GEODB.in_backoff(GEODB.read_status()))


if __name__ == "__main__":
    unittest.main()
