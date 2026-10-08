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

"""Unit tests for the map's poll: flow_summary.sh and the API's FlowSummary.php.

The shell script runs with its paths moved to a temporary directory and flow_summary.py replaced
by a stand-in that says it answered; FlowSummary.php runs in the PHP command line when installed.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import SCRIPTS, SUMMARY  # noqa: E402

SCRIPT = SCRIPTS / "flow_summary.sh"
FLOW_SUMMARY_PHP = Path(__file__).resolve().parents[1] / "src/opnsense/mvc/app/models/OPNsense/FirewallMap/FlowSummary.php"
PAYLOAD = {"status": "ok", "sampled_at": "2026-10-04T12:00:00.250000+00:00", "flows": [{"dest": "8.8.8.8"}],
           "hostnames": {"8.8.8.8": "dns.google"}, "blocks": [{"source": "45.1.1.1", "hits": 1},
                                                              {"source": "45.1.1.2", "hits": 7}, {"source": "45.1.1.3"}],
           "provider": "dbip"}


class ShellTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.run_dir, self.state_dir = self.directory / "run", self.directory / "db"
        self.state_dir.mkdir()
        python = self.directory / "flow_summary_stand_in.sh"
        python.write_text('printf \'{"status":"python","arguments":"%s"}\\n\' "$*"\n')
        script = SCRIPT.read_text()
        for name, value in (("RUN_DIR", self.run_dir), ("STATE_DIR", self.state_dir), ("PYTHON", "/bin/sh"),
                            ("FLOW_SUMMARY", python)):
            line = next(line for line in script.splitlines() if line.startswith(f"{name}="))
            script = script.replace(line, f"{name}={value}", 1)
        self.script = self.directory / "flow_summary.sh"
        self.script.write_text(script)

    def poll(self, *arguments):
        result = subprocess.run(["/bin/sh", str(self.script), *arguments], capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def write(self, payload, age=0.0):
        self.run_dir.mkdir(exist_ok=True)
        path = self.run_dir / "flows.json"
        path.write_text(json.dumps(payload, separators=(",", ":")))
        os.utime(path, (time.time() - age, time.time() - age))

    def geodb(self, status):
        (self.state_dir / "geodb.json").write_text(json.dumps(status, separators=(",", ":")))

    def test_is_posix_sh_and_executable(self):
        subprocess.run(["/bin/sh", "-n", str(SCRIPT)], check=True)
        self.assertTrue(SCRIPT.stat().st_mode & stat.S_IXUSR)

    def test_without_a_summary_python_answers_and_starts_the_collector(self):
        result = self.poll("plain")
        self.assertEqual(result, {"summary": {"status": "python", "arguments": "plain"}})
        # the markers flow_summary.py sets, with the same modes
        self.assertEqual(stat.S_IMODE((self.run_dir / "last_request").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.run_dir.stat().st_mode), 0o750)
        self.assertFalse((self.run_dir / "hostnames_request").exists())

    def test_a_fresh_summary_is_printed_as_written(self):
        self.write(PAYLOAD)
        before = (self.run_dir / "last_request").stat().st_mtime if (self.run_dir / "last_request").exists() else 0
        result = self.poll("hostnames")
        self.assertEqual(result["summary"], PAYLOAD)
        self.assertEqual(result["modified"], int((self.run_dir / "flows.json").stat().st_mtime))
        self.assertGreaterEqual((self.run_dir / "last_request").stat().st_mtime, before)
        self.assertTrue((self.run_dir / "hostnames_request").exists())

    def test_an_old_summary_goes_to_python(self):
        self.write(PAYLOAD, age=20)
        self.assertEqual(self.poll("plain")["summary"]["status"], "python")
        self.write(PAYLOAD, age=5)
        self.assertEqual(self.poll("plain")["summary"], PAYLOAD)

    def test_a_missing_database_goes_to_python(self):
        self.write({"status": "no_database", "reason": "database_missing", "flows": []})
        self.assertEqual(self.poll("plain")["summary"]["status"], "python")
        self.write({"status": "too_many_states", "count": 50000, "flows": []})
        self.assertEqual(self.poll("plain")["summary"]["status"], "too_many_states")

    def test_download_errors_go_to_python(self):
        self.write(PAYLOAD)
        quiet = [
            {"state": "idle", "errors": None, "last_error": None},
            {"state": "idle", "errors": [], "fallback": {"provider": "dbip", "active": True, "errors": []}},
            {"state": "idle", "last_error": "maxmind_key_missing", "provider": "maxmind"},
            {"state": "downloading", "progress": {"done": 10, "total": 100}},
        ]
        failing = [
            {"state": "idle", "errors": [{"kind": "city", "code": "http", "message": "HTTP 401"}], "next_retry": 1},
            {"state": "idle", "errors": [], "fallback": {"provider": "dbip", "active": False,
                                                         "errors": [{"message": "timed out"}]}},
            {"state": "idle", "last_error": "HTTP Error 429: Too Many Requests"},
            {"state": "idle", "errors": "unexpected"},
        ]
        for status in quiet:
            self.geodb(status)
            self.assertEqual(self.poll("plain")["summary"], PAYLOAD, status)
        for status in failing:
            self.geodb(status)
            self.assertEqual(self.poll("plain")["summary"]["status"], "python", status)

    def test_the_download_states_that_go_to_python_are_those_flow_summary_shows(self):
        """Every geolocation status the shell lets through is one flow_summary.py adds nothing for."""
        self.write(PAYLOAD)
        statuses = [
            {}, {"state": "idle", "errors": None}, {"state": "idle", "errors": []},
            {"state": "idle", "last_error": "maxmind_key_missing"}, {"state": "idle", "last_error": "boom"},
            {"state": "idle", "errors": [{"message": "boom"}], "next_retry": time.time() + 600},
            {"state": "downloading", "progress": {"updated": time.time()}, "errors": [{"message": "boom"}]},
            {"state": "downloading", "progress": {"updated": 0}, "errors": [{"message": "boom"}]},
        ]
        for status in statuses:
            self.geodb(status)
            shell = self.poll("plain")["summary"]
            if shell.get("status") != "python":
                with mock.patch.object(SUMMARY, "GEODB_STATUS", str(self.state_dir / "geodb.json")), \
                        mock.patch.object(SUMMARY, "OUTPUT_FILE", str(self.run_dir / "flows.json")), \
                        mock.patch.object(SUMMARY, "REQUEST_MARKER", str(self.directory / "marker")), \
                        mock.patch.object(SUMMARY, "fetch_database") as fetch:
                    python = SUMMARY.main(want_hostnames=True)
                self.assertNotIn("geodb", python, status)
                self.assertFalse(fetch.called, status)


def php(code):
    result = subprocess.run(["php", "-r", f"require {json.dumps(str(FLOW_SUMMARY_PHP))}; {code}"],
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class ApiTest(unittest.TestCase):
    NOW = datetime(2026, 10, 4, 12, 0, 3, tzinfo=timezone.utc).timestamp()

    def from_backend(self, output, hostnames, minimum, now=None):
        return php(f"echo json_encode(OPNsense\\FirewallMap\\FlowSummary::fromBackend({json.dumps(json.dumps(output))}, "
                   f"{'true' if hostnames else 'false'}, {minimum}, {now or self.NOW}));")

    def test_the_viewer_gets_what_flow_summary_py_returned(self):
        """The same document, filtered here, as flow_summary.py filtered it before."""
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "flows.json")
            with open(path, "w") as handle:
                json.dump(PAYLOAD, handle)
            with mock.patch.object(SUMMARY, "OUTPUT_FILE", path), \
                    mock.patch.object(SUMMARY, "REQUEST_MARKER", os.path.join(directory, "marker")), \
                    mock.patch.object(SUMMARY, "HOSTNAME_MARKER", os.path.join(directory, "hostnames")), \
                    mock.patch.object(SUMMARY, "GEODB_STATUS", os.path.join(directory, "geodb.json")):
                for hostnames, minimum in ((False, 1), (False, 5), (True, 2), (True, 100)):
                    before = SUMMARY.main(want_hostnames=hostnames, block_minimum=minimum)
                    shell = self.from_backend({"modified": int(self.NOW) - 3, "summary": PAYLOAD}, hostnames, minimum)
                    python = self.from_backend({"summary": SUMMARY.main(want_hostnames=hostnames)}, hostnames, minimum)
                    for result in (shell, python):
                        self.assertEqual(list(result), list(before))
                        self.assertEqual({**result, "age": None}, {**before, "age": None})

    def test_age_from_the_summary_or_the_file(self):
        # written at 12:00:00.25 (the summary's time stamp), polled at 12:00:03
        self.assertEqual(self.from_backend({"modified": int(self.NOW) - 3, "summary": PAYLOAD}, True, 1)["age"], 2.8)
        undated = {key: value for key, value in PAYLOAD.items() if key != "sampled_at"}
        self.assertEqual(self.from_backend({"modified": int(self.NOW) - 3, "summary": undated}, True, 1)["age"], 3.0)
        self.assertEqual(self.from_backend({"modified": int(self.NOW) + 5, "summary": undated}, True, 1)["age"], 0.0)
        # flow_summary.py's own age is kept
        self.assertEqual(self.from_backend({"summary": {**PAYLOAD, "age": 1.5}}, True, 1)["age"], 1.5)

    def test_the_viewer_gets_only_its_focus(self):
        flows = [{"origin": "10.0.0.1", "dest": f"203.0.113.{n}"} for n in range(4)]
        summary = {**PAYLOAD, "flows": flows, "profiles": [{"key": "classic"}, {"key": "security"}],
                   "focus": {"classic": [0, 1, 2], "security": [3, 1]}, "focus_default": "classic"}

        def focus(value):
            return php("echo json_encode(OPNsense\\FirewallMap\\FlowSummary::fromBackend("
                       f"{json.dumps(json.dumps({'summary': summary}))}, false, 1, {self.NOW}, "
                       f"{json.dumps(value)}));")
        security = focus("security")
        self.assertEqual(([flow["dest"] for flow in security["flows"]], security["focus"]),
                         (["203.0.113.3", "203.0.113.1"], "security"))
        self.assertNotIn("focus_default", security)
        self.assertEqual(security["profiles"], summary["profiles"])
        # absent or unknown: the configured default
        for value in (None, "nonexistent"):
            result = focus(value)
            self.assertEqual(([flow["dest"] for flow in result["flows"]], result["focus"]),
                             (["203.0.113.0", "203.0.113.1", "203.0.113.2"], "classic"))

    def test_nothing_usable_is_a_failure(self):
        for output in ("", "not json", '{"status":"ok"}', '{"summary":"text"}'):
            result = php(f"echo json_encode(OPNsense\\FirewallMap\\FlowSummary::fromBackend({json.dumps(output)}, false, 1));")
            self.assertEqual(result, {"status": "failed", "flows": []})
        starting = self.from_backend({"summary": {"status": "starting", "flows": [], "locations": []}}, False, 3)
        self.assertEqual(starting, {"status": "starting", "flows": [], "locations": []})


if __name__ == "__main__":
    unittest.main()
