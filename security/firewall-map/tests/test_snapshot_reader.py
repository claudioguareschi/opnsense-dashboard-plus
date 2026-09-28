"""Unit tests for the snapshot reader the dashboard API calls."""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import SNAPSHOT  # noqa: E402


class SnapshotReaderTest(unittest.TestCase):
    def test_reads_fresh_and_rejects_stale_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "flows.json")
            with open(path, "w") as handle:
                json.dump({"status": "ok", "flows": []}, handle)
            self.assertEqual(SNAPSHOT.read_snapshot(path)["status"], "ok")
            self.assertIsNone(SNAPSHOT.read_snapshot(path, now=time.time() + 60))


class SnapshotMainTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = directory.name
        self.started = []
        for name, value in {
            "OUTPUT_FILE": os.path.join(self.directory, "flows.json"),
            "REQUEST_MARKER": os.path.join(self.directory, "last_request"),
            "HOSTNAME_MARKER": os.path.join(self.directory, "hostnames_request"),
            "FETCH_MARKER": os.path.join(self.directory, "fetch_started"),
            "start_collector": lambda: self.started.append(True),
        }.items():
            patcher = mock.patch.object(SNAPSHOT, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, payload):
        with open(SNAPSHOT.OUTPUT_FILE, "w") as handle:
            json.dump(payload, handle)

    def test_starts_the_collector_when_there_is_no_snapshot(self):
        payload = SNAPSHOT.main()
        self.assertEqual((payload["status"], self.started), ("starting", [True]))
        self.assertTrue(os.path.exists(SNAPSHOT.REQUEST_MARKER))
        self.assertFalse(os.path.exists(SNAPSHOT.HOSTNAME_MARKER))

    def test_filters_blocks_and_hostnames_for_the_viewer(self):
        self.write({"status": "ok", "flows": [], "hostnames": {"8.8.8.8": "dns.google"},
                    "blocks": [{"hits": 1}, {"hits": 5}]})
        payload = SNAPSHOT.main(block_minimum=2)
        self.assertNotIn("hostnames", payload)
        self.assertEqual((len(payload["blocks"]), payload["blocks_below"]), (1, 1))
        payload = SNAPSHOT.main(want_hostnames=True)
        self.assertEqual(payload["hostnames"], {"8.8.8.8": "dns.google"})
        self.assertTrue(os.path.exists(SNAPSHOT.HOSTNAME_MARKER))
        self.assertEqual(self.started, [])

    def test_missing_database_is_fetched_at_most_once_a_minute(self):
        self.write({"status": "no_database", "reason": "database_missing", "flows": []})
        with mock.patch.object(SNAPSHOT.subprocess, "Popen") as popen:
            SNAPSHOT.main()
            SNAPSHOT.main()
        self.assertEqual(popen.call_count, 1)


if __name__ == "__main__":
    unittest.main()
