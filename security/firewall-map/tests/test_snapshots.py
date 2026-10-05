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
from pathlib import Path
import shutil
import subprocess
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
SNAPSHOTS_CONTROLLER = Path(__file__).resolve().parents[1] / "src/opnsense/mvc/app/controllers/OPNsense/FirewallMap/Api/SnapshotsController.php"
MAP_PAGE = Path(__file__).resolve().parents[1] / "src/opnsense/www/js/firewall-map-page.js"


def controller_get(may_show_states):
    """Run getAction with the smallest OPNsense stubs needed to exercise its ACL boundary."""
    code = r'''
namespace OPNsense\Base {
    class ApiControllerBase { public $request; public function getUserName() { return "map-user"; } }
}
namespace OPNsense\Core {
    class Backend {
        public static $response;
        public function configdpRun($action, $parameters) { return json_encode(self::$response); }
    }
    class ACL {
        public static $mayShowStates;
        public function isPageAccessible($user, $path) { return self::$mayShowStates; }
    }
}
namespace OPNsense\FirewallMap {
    class AuditLog { public static function record($user, $message) {} }
    class ConfigdArgument {
        public static function isSnapshotId($id) { return is_string($id) && preg_match('/^\\d{8}T\\d{6}Z-[0-9a-f]{4}$/', $id); }
        public static function text($value, $length) { return $value; }
    }
}
namespace {
    require $argv[1];
    \OPNsense\Core\ACL::$mayShowStates = $argv[2] === "1";
    \OPNsense\Core\Backend::$response = [
        "result" => "ok", "snapshot" => ["id" => "20261005T010203Z-1a2b"],
        "data" => ["flows" => [["dest" => "192.0.2.44"]], "states" => ["192.0.2.44" => [["src_addr" => "10.0.0.5"]]]]
    ];
    $controller = new \OPNsense\FirewallMap\Api\SnapshotsController();
    $controller->request = new class { public function get($key) { return 1; } };
    echo json_encode($controller->getAction("20261005T010203Z-1a2b"));
}
'''
    result = subprocess.run(
        ["php", "-r", code, str(SNAPSHOTS_CONTROLLER), "1" if may_show_states else "0"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


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
        if now is not None and os.path.exists(self.summary):
            # the map's summary is current at the simulated time
            os.utime(self.summary, (now, now))
        result = SNAPSHOTS.save("admin", now=now, wait=2.0 if collector else 0.2, directory=self.snapshots, requests=self.requests,
                                summary_file=self.summary)
        if collector:
            thread.join()
        return result

    def answer(self, payload):
        def collector():
            for _ in range(100):
                names = [name for name in (os.listdir(self.requests) if os.path.isdir(self.requests) else []) if name.endswith(".request")]
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
        self.assertFalse([name for name in os.listdir(self.requests) if name.endswith(".request")])

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
            step = SNAPSHOTS.MIN_INTERVAL_SECONDS + 1
            ids = [self.save(now=now + index * step)["snapshot"]["id"] for index in range(5)]
        kept = [meta["id"] for meta in SNAPSHOTS.metas(self.snapshots)]
        self.assertEqual(kept, list(reversed(ids))[:3])
        self.assertNotIn(old, kept)

    def test_a_failed_save_gives_its_slot_back(self):
        now = time.time()
        self.assertEqual(self.save(now=now)["error"], "no current map data")
        COMMON.write_json(self.summary, SUMMARY)
        self.assertEqual(self.save(now=now + 1)["result"], "saved")

    def test_one_snapshot_per_interval(self):
        COMMON.write_json(self.summary, SUMMARY)
        now = time.time()
        first = self.save(now=now)["snapshot"]["id"]
        again = self.save(now=now + 3)
        self.assertEqual((again["result"], again["error"], again["snapshot"]["id"]), ("failed", "too_soon", first))
        self.assertEqual(self.save(now=now + SNAPSHOTS.MIN_INTERVAL_SECONDS + 1)["result"], "saved")

    def test_saves_that_take_the_lock_out_of_order_share_one_slot(self):
        # the save that read the clock later reaches the lock first
        os.makedirs(self.requests)
        now = time.time()
        self.assertIsNotNone(SNAPSHOTS.reserve(now + 0.05, self.requests))
        self.assertIsNone(SNAPSHOTS.reserve(now, self.requests))

    def test_main_rejects_bad_ids_and_decodes_the_user(self):
        self.assertEqual(SNAPSHOTS.main(["delete", "x/../y"])["result"], "failed")
        self.assertEqual(SNAPSHOTS.decode_text(base64.urlsafe_b64encode("rené".encode()).decode().rstrip("="), 64), "rené")
        self.assertEqual(SNAPSHOTS.decode_text("-", 64), "")
        self.assertEqual(SNAPSHOTS.decode_text("!!!", 64), "")

    @unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
    def test_snapshot_get_redacts_states_without_native_show_states_privilege(self):
        viewer = controller_get(False)
        operator = controller_get(True)
        self.assertNotIn("states", viewer["data"])
        self.assertEqual(operator["data"]["states"]["192.0.2.44"][0]["src_addr"], "10.0.0.5")

    def test_snapshot_page_never_offers_saved_states_without_the_capability(self):
        page = MAP_PAGE.read_text()
        self.assertNotIn('state.can.states || state.mode === "snapshot"', page)
        self.assertIn('state.mode === "snapshot" && state.can.states', page)


if __name__ == "__main__":
    unittest.main()
