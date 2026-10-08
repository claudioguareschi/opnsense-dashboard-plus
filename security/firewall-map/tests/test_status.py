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

"""Unit tests for the status page overview."""

import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import STATUS  # noqa: E402


class StatusTest(unittest.TestCase):
    def test_collector_states(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(STATUS, "widget_in_use", return_value=True), \
                mock.patch.object(STATUS, "recording_wanted", return_value=True), \
                mock.patch.object(STATUS.geodb, "settings", return_value={"record_threats": "1"}):
            pidfile, marker = os.path.join(directory, "pid"), os.path.join(directory, "last_request")
            with mock.patch.object(STATUS, "PID_FILE", pidfile), mock.patch.object(STATUS, "REQUEST_MARKER", marker):
                self.assertEqual(STATUS.collector()["mode"], "stopped")
                with open(pidfile, "w") as handle:
                    handle.write(str(os.getpid()))
                self.assertEqual(STATUS.collector()["mode"], "background")
                open(marker, "w").close()
                result = STATUS.collector()
                self.assertEqual((result["running"], result["mode"], result["recording"]), (True, "live", True))
                self.assertEqual(STATUS.collector(now=time.time() + STATUS.IDLE_SECONDS + 1)["mode"], "background")

    def test_feeds_and_blacklist_never_show_the_key(self):
        with tempfile.TemporaryDirectory() as directory:
            feeds_file, abuse_file = os.path.join(directory, "feeds.json"), os.path.join(directory, "abuse.json")
            with open(feeds_file, "w") as handle:
                json.dump({"FWMAP_Feodo": {"count": 5, "updated": 1000.0, "error": None}}, handle)
            with open(abuse_file, "w") as handle:
                json.dump({"count": 3, "updated": 2000.0, "key_id": "0123456789abcdef"}, handle)
            with mock.patch.object(STATUS.feeds, "STATUS_FILE", feeds_file), \
                    mock.patch.object(STATUS.feeds, "feeds_in_use", return_value=[{"name": "FWMAP_Feodo"}]), \
                    mock.patch.object(STATUS.abuseipdb, "STATUS_FILE", abuse_file), \
                    mock.patch.object(STATUS, "abuseipdb_key", return_value="secret"):
                feodo = next(feed for feed in STATUS.threat_feeds() if feed["name"] == "FWMAP_Feodo")
                self.assertEqual((feodo["in_use"], feodo["count"]), (True, 5))
                self.assertFalse(any(feed["in_use"] for feed in STATUS.threat_feeds() if feed["name"] != "FWMAP_Feodo"))
                blacklist = STATUS.blacklist()
                self.assertEqual((blacklist["configured"], blacklist["count"]), (True, 3))
                self.assertNotIn("key_id", json.dumps(blacklist))
                self.assertNotIn("secret", json.dumps(blacklist))

    def test_native_engine_status_and_version_warning(self):
        timing = {"native": {"helper": {"pid": 7, "starts": 2, "pf_state_version": 20230404,
                                        "freebsd_version": 1403000},
                             "state_limit": 372363, "telemetry": {"sequence": 9}}}
        for kernel, warning in ((1403000, False), (1500000, True), (None, False)):
            with self.subTest(kernel=kernel), mock.patch.object(STATUS, "kernel_version", return_value=kernel):
                engine = STATUS.native_engine(timing)
                self.assertEqual((engine["version_warning"], engine["state_limit"]), (warning, 372363))
        with mock.patch.object(STATUS, "kernel_version", return_value=None):
            self.assertEqual(STATUS.native_engine(None)["version_warning"], False)

    def test_last_sample_while_running(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(STATUS, "widget_in_use", return_value=True), \
                mock.patch.object(STATUS, "recording_wanted", return_value=True), \
                mock.patch.object(STATUS.geodb, "settings", return_value={}):
            pidfile, timings = os.path.join(directory, "pid"), os.path.join(directory, "timings.json")
            with open(timings, "w") as handle:
                json.dump({"at": 1000.0, "states": 1225, "wall": 0.042, "cpu": 0.03, "programs": 0.01,
                           "phases": {"walk": 0.02}, "background": False}, handle)
            with mock.patch.object(STATUS, "PID_FILE", pidfile), mock.patch.object(STATUS, "COLLECTOR_TIMINGS", timings), \
                    mock.patch.object(STATUS, "REQUEST_MARKER", os.path.join(directory, "last_request")):
                self.assertIsNone(STATUS.collector()["last_sample"])
                with open(pidfile, "w") as handle:
                    handle.write(str(os.getpid()))
                sample = STATUS.collector()["last_sample"]
                self.assertEqual((sample["wall"], sample["cpu"], sample["states"]), (0.042, 0.03, 1225))
                self.assertIsNone(STATUS.collector()["timing"])
                timing = {"generation": "process-one", "revision": 3, "phase": "collecting",
                          "sample_completed_at": 1000.0, "heartbeat_at": 1030.0}
                with open(timings, "w") as handle:
                    json.dump({"collector": timing}, handle)
                result = STATUS.collector()
                self.assertEqual(result["timing"], timing)
                self.assertIsNone(result["last_sample"])


if __name__ == "__main__":
    unittest.main()
