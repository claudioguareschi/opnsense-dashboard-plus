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

"""Unit tests for saved map snapshots."""

import base64
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import COMMON, SNAPSHOTS  # noqa: E402

SUMMARY = {"status": "ok", "flows": [{"dest": "192.0.2.1", "threat": True}, {"dest": "192.0.2.2"}],
           "blocks": [{"source": "198.51.100.1", "hits": 1, "lists": []}, {"source": "198.51.100.2", "hits": 9, "lists": ["x"]}],
           "locations": []}


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = directory.name
        self.snapshots = os.path.join(self.root, "snapshots")
        self.requests = os.path.join(self.root, "requests")
        self.summary = os.path.join(self.root, "flows.json")
        marker = mock.patch.object(SNAPSHOTS, "REQUEST_MARKER", os.path.join(self.root, "last_request"))
        marker.start()
        self.addCleanup(marker.stop)

    def save(self, collector=None, now=None):
        """Take a snapshot; `collector` (a callable) plays the running collector answering the request."""
        if collector:
            thread = threading.Thread(target=collector)
            thread.start()
        result = SNAPSHOTS.save("admin", now=now, wait=2.0 if collector else 0.2, directory=self.snapshots, requests=self.requests,
                                summary_file=self.summary)
        if collector:
            thread.join()
        return result

    def answer(self, payload):
        def collector():
            for _ in range(100):
                names = os.listdir(self.requests) if os.path.isdir(self.requests) else []
                if names:
                    snapshot_id = names[0][:-len(".request")]
                    COMMON.write_json(os.path.join(self.snapshots, f"{snapshot_id}.json"), payload)
                    return
                time.sleep(0.02)
        return collector

    def test_the_collector_answers_with_a_full_snapshot(self):
        result = self.save(self.answer({**SUMMARY, "full": True}))
        self.assertEqual(result["result"], "saved")
        meta = result["snapshot"]
        self.assertTrue(SNAPSHOTS.valid_id(meta["id"]))
        self.assertEqual((meta["flows"], meta["blocks"], meta["flagged"], meta["partial"]), (2, 2, 2, False))
        self.assertEqual(meta["user"], "admin")
        self.assertEqual([item["id"] for item in SNAPSHOTS.metas(self.snapshots)], [meta["id"]])

    def test_without_a_collector_the_current_summary_is_kept_as_partial(self):
        COMMON.write_json(self.summary, SUMMARY)
        result = self.save()
        self.assertEqual(result["result"], "saved")
        self.assertTrue(result["snapshot"]["partial"])
        self.assertFalse(os.listdir(self.requests))

    def test_without_current_data_nothing_is_saved(self):
        result = self.save()
        self.assertEqual(result["result"], "failed")
        self.assertEqual(SNAPSHOTS.metas(self.snapshots), [])

    def test_get_applies_the_viewers_block_threshold(self):
        COMMON.write_json(self.summary, SUMMARY)
        snapshot_id = self.save()["snapshot"]["id"]
        result = SNAPSHOTS.get(snapshot_id, 3, directory=self.snapshots)
        self.assertEqual([block["source"] for block in result["data"]["blocks"]], ["198.51.100.2"])
        self.assertEqual(result["data"]["blocks_below"], 1)
        self.assertEqual(SNAPSHOTS.get("../../etc/passwd", directory=self.snapshots)["result"], "failed")

    def test_notes_and_deletion(self):
        COMMON.write_json(self.summary, SUMMARY)
        snapshot_id = self.save()["snapshot"]["id"]
        note = base64.urlsafe_b64encode("Odd traffic to Frankfurt".encode()).decode().rstrip("=")
        self.assertEqual(SNAPSHOTS.set_note(snapshot_id, SNAPSHOTS.decode_text(note, 500), directory=self.snapshots)["result"], "saved")
        self.assertEqual(SNAPSHOTS.metas(self.snapshots)[0]["note"], "Odd traffic to Frankfurt")
        self.assertTrue(SNAPSHOTS.remove(snapshot_id, self.snapshots))
        self.assertEqual(os.listdir(self.snapshots), [])

    def test_prune_keeps_the_newest_and_drops_old_ones(self):
        COMMON.write_json(self.summary, SUMMARY)
        now = time.time()
        with mock.patch.object(SNAPSHOTS, "KEEP_SNAPSHOTS", 3):
            old = self.save(now=now - 40 * 86400)["snapshot"]["id"]
            # the old one goes at once (older than 30 days); then only the newest three stay
            self.assertEqual(SNAPSHOTS.metas(self.snapshots), [])
            ids = [self.save(now=now + index)["snapshot"]["id"] for index in range(5)]
        kept = [meta["id"] for meta in SNAPSHOTS.metas(self.snapshots)]
        self.assertEqual(kept, list(reversed(ids))[:3])
        self.assertNotIn(old, kept)

    def test_main_rejects_bad_ids_and_decodes_the_user(self):
        self.assertEqual(SNAPSHOTS.main(["delete", "x/../y"])["result"], "failed")
        self.assertEqual(SNAPSHOTS.decode_text(base64.urlsafe_b64encode("rené".encode()).decode().rstrip("="), 64), "rené")
        self.assertEqual(SNAPSHOTS.decode_text("-", 64), "")
        self.assertEqual(SNAPSHOTS.decode_text("!!!", 64), "")


if __name__ == "__main__":
    unittest.main()
