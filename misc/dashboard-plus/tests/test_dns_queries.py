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

"""DNS Health+ live rate: dns/queries reads only Unbound's query total (unbound-control
stats_noreset through configd), not the full statistics."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).parents[1] / "src/opnsense"
CONTROLLER = ROOT / "mvc/app/controllers/OPNsense/DashboardPlus/Api/DnsController.php"

HARNESS = r"""
namespace OPNsense\Base {
    class ApiControllerBase {}
}
namespace OPNsense\Core {
    class Backend {
        public static $actions = [];
        public function configdRun($action) { self::$actions[] = $action; return getenv('OUTPUT'); }
    }
}
namespace {
    require getenv('CONTROLLER');
    $result = (new OPNsense\DashboardPlus\Api\DnsController())->queriesAction();
    echo json_encode(['result' => $result, 'actions' => OPNsense\Core\Backend::$actions]);
}
"""

STATS = """thread0.num.queries=4000
thread0.num.queries_ip_ratelimited=0
total.num.queries=7153
total.num.queries_ip_ratelimited=0
total.num.cachehits=6000
time.now=1791660520.699783
"""


def queries(output):
    result = subprocess.run(["php", "-r", HARNESS], capture_output=True, text=True, check=True,
                            env=dict(os.environ, CONTROLLER=str(CONTROLLER), OUTPUT=output))
    return json.loads(result.stdout)


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class QueriesTest(unittest.TestCase):
    def test_the_total_query_counter(self):
        answer = queries(STATS)
        self.assertEqual(answer["result"], {"status": "ok", "queries": 7153, "at": 1791660520.699783})
        # without Unbound's clock the counter alone
        self.assertEqual(queries("total.num.queries=5\n")["result"], {"status": "ok", "queries": 5})
        self.assertEqual(answer["actions"], ["dashboardplus dns queries"])

    def test_unbound_not_answering(self):
        for output in ("", "error: connect failed\n", "Execute error", "total.num.queries=lots\n"):
            with self.subTest(output=output):
                self.assertEqual(queries(output)["result"], {"status": "failed"})


class ActionTest(unittest.TestCase):
    def test_the_counter_never_resets_unbound_statistics(self):
        # `stats` would reset the counters OPNsense's own Unbound reporting reads
        actions = (ROOT / "service/conf/actions.d/actions_dashboardplus.conf").read_text()
        self.assertIn("[dns.queries]\ncommand:/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf "
                      "stats_noreset\nparameters:\n", actions)
        # configd hands one read to every viewer for a second; "at" keeps the rate exact
        block = actions[actions.index("[dns.queries]"):].split("\n\n")[0]
        self.assertIn("\ncache_ttl:1", block)
        acl = (ROOT / "mvc/app/models/OPNsense/DashboardPlus/ACL/ACL.xml").read_text()
        dns = acl[acl.index("<page-dashboard-widget-dashboard-plus-dns-health>"):]
        self.assertIn("<pattern>api/dashboardplus/dns/queries</pattern>", dns[:dns.index("</patterns>")])


if __name__ == "__main__":
    unittest.main()
