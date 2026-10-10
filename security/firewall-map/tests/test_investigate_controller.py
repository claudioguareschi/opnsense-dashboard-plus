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
# POSSIBILITY OF SUCH DAMAGE.

"""Investigate an address: the page encodes it as a path segment and OPNsense's router hands the
segment over still percent-encoded, so the controller decodes it, validates the decoded value and
passes only a validated address to configd."""

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "src/opnsense/mvc/app/controllers/OPNsense/FirewallMap/Api/InvestigateController.php"

HARNESS = r"""
namespace OPNsense\Base {
    class Request {
        public function isPost() { return true; }
        public function getPost($name) { return null; }
    }
    class ApiControllerBase {
        public $request;
        public function __construct() { $this->request = new Request(); }
        public function getUserName() { return 'tester'; }
    }
}
namespace OPNsense\Core {
    class Backend {
        public static $calls = [];
        public function configdpRun($action, $params = []) {
            self::$calls[] = [$action, $params];
            return '{"status":"ok"}';
        }
    }
}
namespace OPNsense\FirewallMap {
    class AuditLog {
        public static function record($user, $message) {}
    }
}
namespace {
    require getenv('CONTROLLER');
    $answers = [];
    foreach (json_decode(file_get_contents('php://stdin')) as $address) {
        OPNsense\Core\Backend::$calls = [];
        $result = (new OPNsense\FirewallMap\Api\InvestigateController())->addressAction($address);
        $answers[] = ['result' => $result, 'calls' => OPNsense\Core\Backend::$calls];
    }
    echo json_encode($answers);
}
"""


def investigate(addresses):
    """addressAction for each path parameter: its result and the configd calls it made."""
    result = subprocess.run(["php", "-r", HARNESS], input=json.dumps(addresses), capture_output=True, text=True,
                            check=True, env=dict(os.environ, CONTROLLER=str(CONTROLLER)))
    return json.loads(result.stdout)


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class InvestigateAddressTest(unittest.TestCase):
    def test_the_decoded_address_reaches_configd(self):
        cases = {"2601%3A740%3A8500%3A%3A1": "2601:740:8500::1", "2001:db8::1": "2001:db8::1",
                 "8.8.8.8": "8.8.8.8"}
        for (path, address), answer in zip(cases.items(), investigate(list(cases)), strict=True):
            with self.subTest(path=path):
                self.assertEqual(answer["result"], {"status": "ok"})
                self.assertEqual(answer["calls"], [["firewallmap investigate", [address, "all"]]])

    def test_anything_but_an_address_is_refused_before_configd(self):
        paths = ["2601%3A740%3A8500%3A%3A1%2F64", "not-an-ip", "8.8.8.8%0Aextra", ""]
        for path, answer in zip(paths, investigate(paths), strict=True):
            with self.subTest(path=path):
                self.assertEqual(answer["result"], {"status": "failed", "error": "not an IP address"})
                self.assertEqual(answer["calls"], [])


if __name__ == "__main__":
    unittest.main()
