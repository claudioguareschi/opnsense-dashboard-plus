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

"""CARP+: carp.sh and carp_history.sh (run here with stand-in commands and logs) and
models/OPNsense/DashboardPlus/Carp.php, which joins their output with the configuration."""

from datetime import datetime
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).parents[1] / "src/opnsense"
SCRIPTS = ROOT / "scripts/OPNsense/DashboardPlus"
MODELS = ROOT / "mvc/app/models/OPNsense/DashboardPlus"

IFCONFIG = """igb0: flags=1008943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tdescription: WAN (wan)
\tether 00:00:5e:00:53:01
\tinet 198.51.100.2 netmask 0xffffff00 broadcast 198.51.100.255
\tinet 198.51.100.10 netmask 0xffffff00 broadcast 198.51.100.255 vhid 1
\tcarp: BACKUP vhid 1 advbase 1 advskew 100
\tstatus: active
ix0: flags=1008943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 192.0.2.250 netmask 0xffffff00 broadcast 192.0.2.255 vhid 2
\tinet6 fe80::1%ix0 prefixlen 64 scopeid 0x2
\tinet6 2001:db8:0:2::250 prefixlen 64 vhid 3
\tcarp: BACKUP vhid 2 advbase 1 advskew 100
\tcarp: MASTER vhid 3 advbase 2 advskew 0
igb4: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 203.0.113.2 netmask 0xfffffffc broadcast 203.0.113.3
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
"""

SYSCTL = """net.inet.carp.ifdown_demotion_factor: 240
net.inet.carp.senderr_demotion_factor: 0
net.inet.carp.demotion: 0
net.inet.carp.log: 1
net.inet.carp.preempt: 1
net.inet.carp.dscp: 56
net.inet.carp.allow: 1
"""

PFSYNC = """pfsync0: flags=1000041<UP,RUNNING,LOWER_UP> metric 0 mtu 1500
\toptions=0
\tsyncdev: igb4 syncpeer: 203.0.113.1 maxupd: 128 defer: off version: 1500
\tsyncok: 1
\tgroups: pfsync
"""

CARP_STATS = json.dumps({"statistics": {"carp": {
    "received-inet-packets": 835247, "received-inet6-packets": 83533, "dropped-wrong-ttl": 1,
    "dropped-bad-checksum": 2, "dropped-bad-vhid": 50, "sent-inet-packets": 4, "sent-inet6-packets": 1,
    "send-failed-memory-error": 3}}})


def histogram(**counts):
    return [{"name": name.replace("_", "-"), "count": count} for name, count in counts.items()]


PFSYNC_STATS = json.dumps({"statistics": {"pfsync": {
    "received-inet-packets": 12635569, "received-inet6-packets": 0,
    "input-histogram": histogram(compressed_state_update=1000, state_insert=200, compressed_state_delete=30,
                                 bulk_update_mark=2, end_of_frame_mark=900),
    "dropped-bad-ttl": 1, "dropped-bad-action": 35220, "dropped-stale-state": 34656,
    "dropped-failed-lookup": 275174, "sent-inet-packets": 1266416, "send-inet6-packets": 4,
    "output-histogram": histogram(compressed_state_update=500, state_update=7, end_of_frame_mark=400),
    "discarded-no-memory": 2, "send-errors": 5}}})

HISTORY = """<13>1 2026-10-09T21:15:58-04:00 fw kernel - - [meta sequenceId="530"] <6>[60] carp: 2@ix0: MASTER -> BACKUP (more frequent advertisement received)
<13>1 2026-10-09T21:16:03-04:00 fw kernel - - [meta sequenceId="565"] <6>[64] carp: 1@igb0: INIT -> BACKUP (initialization complete)
<13>1 2026-10-09T21:17:38-04:00 fw kernel - - [meta sequenceId="646"] <6>[160] carp: 3@ix0: BACKUP -> MASTER
"""

CONFIG = {
    "hostname": "fw-b.example.org",
    "interfaces": {"wan": {"if": "igb0", "descr": "WAN"}, "lan": {"if": "ix0", "descr": ""},
                   "opt10": {"if": "igb4", "descr": "HA_SYNC"}},
    "vips": [{"interface": "wan", "vhid": "1", "descr": "WAN VIP"},
             {"interface": "lan", "vhid": "2", "descr": "LAN VIP"}],
    "hasync": {"pfsyncinterface": "opt10", "pfsyncpeerip": "203.0.113.1", "synchronizetoip": ""},
}


def output(ifconfig=IFCONFIG, sysctl=SYSCTL, pfsync=PFSYNC, carpstats=CARP_STATS, pfsyncstats=PFSYNC_STATS):
    return (f"@@ifconfig\n{ifconfig}@@sysctl\n{sysctl}@@pfsync\n{pfsync}"
            f"@@carpstats\n{carpstats}\n@@pfsyncstats\n{pfsyncstats}\n")


PARSE = r"""
require getenv('MODELS') . '/Metrics.php';
require getenv('MODELS') . '/Carp.php';
$in = json_decode(file_get_contents('php://stdin'), true);
$out = [];
foreach ($in as $call) {
    $out[] = call_user_func_array(['OPNsense\\DashboardPlus\\Carp', $call[0]], $call[1]);
}
echo json_encode($out);
"""


def php(*calls):
    result = subprocess.run(["php", "-r", PARSE], input=json.dumps(calls), capture_output=True, text=True,
                            check=True, env=dict(os.environ, MODELS=str(MODELS)))
    return json.loads(result.stdout)


def one(name, *arguments):
    return php([name, list(arguments)])[0]


def summary(text=None, history=HISTORY, config=CONFIG, now=1000.5):
    return one("summary", output() if text is None else text, history, config, now)


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class ParseTest(unittest.TestCase):
    def test_carp_entries_and_their_addresses_by_device(self):
        self.assertEqual(one("interfaces", IFCONFIG), {
            "igb0": {"addresses": {"1": ["198.51.100.10/24"]},
                     "carp": {"1": {"state": "backup", "advbase": 1, "advskew": 100}}},
            "ix0": {"addresses": {"2": ["192.0.2.250/24"], "3": ["2001:db8:0:2::250/64"]},
                    "carp": {"2": {"state": "backup", "advbase": 1, "advskew": 100},
                             "3": {"state": "master", "advbase": 2, "advskew": 0}}},
        })

    def test_sysctls(self):
        values = one("sysctls", SYSCTL)
        self.assertEqual((values["allow"], values["preempt"], values["demotion"], values["log"]), (1, 1, 0, 1))
        self.assertEqual(one("sysctls", "net.inet.carp.demotion: 240\n")["demotion"], 240)

    def test_pfsync(self):
        self.assertEqual(one("pfsync", PFSYNC), {"up": True, "syncdev": "igb4", "peer": "203.0.113.1",
                                                 "maxupd": 128, "defer": "off", "version": 1500, "syncok": True})
        pending = one("pfsync", PFSYNC.replace("syncok: 1", "syncok: 0").replace("flags=1000041<UP,RUNNING,LOWER_UP>",
                                                                               "flags=0<>"))
        self.assertEqual((pending["up"], pending["syncok"]), (False, False))

    def test_pfsync_without_a_sync_device(self):
        info = one("pfsync", "pfsync0: flags=0<> metric 0 mtu 1500\n\tgroups: pfsync\n")
        self.assertEqual((info["syncdev"], info["peer"], info["syncok"]), ("", "", None))
        self.assertIsNone(one("pfsync", ""))

    def test_counters_count_messages_not_framing_and_only_real_errors(self):
        self.assertEqual(one("counters", CARP_STATS, PFSYNC_STATS), {
            "carp_received": 835247 + 83533, "carp_sent": 5,
            "carp_errors": 1 + 2 + 3,
            "pfsync_received": 12635569, "pfsync_sent": 1266416 + 4,
            "pfsync_updates_in": 1000 + 200 + 30, "pfsync_updates_out": 500 + 7,
            "pfsync_errors": 1 + 2 + 5,
        })

    def test_counters_without_statistics_are_zero(self):
        self.assertEqual(set(one("counters", "", "not json").values()), {0})

    def test_transitions_newest_first(self):
        changes = one("transitions", HISTORY + "unrelated line\n")
        self.assertEqual([(c["vhid"], c["device"], c["from"], c["to"]) for c in changes],
                         [(3, "ix0", "backup", "master"), (1, "igb0", "init", "backup"), (2, "ix0", "master", "backup")])
        self.assertEqual(changes[0]["reason"], "")
        self.assertEqual(changes[2]["reason"], "more frequent advertisement received")
        self.assertEqual(changes[1]["time"], int(datetime.fromisoformat("2026-10-09T21:16:03-04:00").timestamp()))


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class SummaryTest(unittest.TestCase):
    def test_what_the_widget_shows(self):
        result = summary()
        self.assertTrue(result["available"])
        self.assertEqual((result["hostname"], result["sampled_at"]), ("fw-b.example.org", 1000.5))
        self.assertEqual(result["carp"], {"allow": 1, "preempt": 1, "demotion": 0, "log": 1})
        self.assertEqual(result["summary"], {"state": "split", "total": 3, "master": 1, "backup": 2, "init": 0})
        self.assertEqual(result["vips"][0], {
            "name": "WAN", "identifier": "wan", "device": "igb0", "vhid": 1, "addresses": ["198.51.100.10/24"],
            "state": "backup", "advbase": 1, "advskew": 100, "description": "WAN VIP"})
        self.assertEqual([(v["vhid"], v["name"], v["description"]) for v in result["vips"]],
                         [(1, "WAN", "WAN VIP"), (2, "LAN", "LAN VIP"), (3, "LAN", "")])
        self.assertEqual((result["pfsync"]["syncdev_name"], result["pfsync"]["peer"]), ("HA_SYNC", "203.0.113.1"))
        self.assertEqual(result["config_sync"], {"target": ""})
        self.assertEqual([(c["name"], c["vhid"]) for c in result["transitions"]], [("LAN", 3), ("WAN", 1), ("LAN", 2)])

    def test_the_role_over_all_vips(self):
        def state(ifconfig):
            return summary(output(ifconfig=ifconfig))["summary"]["state"]
        backup = IFCONFIG.replace("MASTER", "BACKUP")
        self.assertEqual(state(backup), "backup")
        self.assertEqual(state(IFCONFIG.replace("BACKUP", "MASTER")), "master")
        self.assertEqual(state(backup.replace("BACKUP vhid 1", "INIT vhid 1")), "init")
        self.assertEqual(state(IFCONFIG), "split")
        self.assertEqual(state("lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384\n"), "none")

    def test_without_carp_the_widget_is_unavailable(self):
        result = summary(output(ifconfig="", pfsync="", carpstats="", pfsyncstats=""), history="")
        self.assertFalse(result["available"])
        self.assertEqual((result["vips"], result["transitions"], result["pfsync"]), ([], [], None))

    def test_the_configured_peer_stands_in_when_pfsync_names_none(self):
        text = output(pfsync=PFSYNC.replace(" syncpeer: 203.0.113.1", ""))
        self.assertEqual(summary(text)["pfsync"]["peer"], "203.0.113.1")

    def test_the_master_names_its_config_sync_target(self):
        config = dict(CONFIG, hasync=dict(CONFIG["hasync"], synchronizetoip="203.0.113.2"))
        self.assertEqual(summary(config=config)["config_sync"], {"target": "203.0.113.2"})

    def test_an_unassigned_device_keeps_its_own_name(self):
        result = summary(config=dict(CONFIG, interfaces={}, vips=[]))
        self.assertEqual([v["name"] for v in result["vips"]], ["igb0", "ix0", "ix0"])
        self.assertEqual(result["pfsync"]["syncdev_name"], "igb4")


STUB = """#!/bin/sh
echo "$(basename "$0") $*" >> "{log}"
case "$*" in
{cases}
esac
"""


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class ScriptTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.log = self.root / "calls.log"
        files = {"ifconfig": IFCONFIG, "pfsync": PFSYNC, "sysctl": SYSCTL, "carpstats": CARP_STATS,
                 "pfsyncstats": PFSYNC_STATS}
        data = self.root / "data"
        data.mkdir()
        for name, text in files.items():
            (data / name).write_text(text)
        r = data
        stubs = {
            "ifconfig": f'"-L") cat "{r}/ifconfig" ;;\n"pfsync0") cat "{r}/pfsync" ;;',
            "sysctl": f'"net.inet.carp") cat "{r}/sysctl" ;;',
            "netstat": f'*"-p carp"*) cat "{r}/carpstats" ;;\n*"-p pfsync"*) cat "{r}/pfsyncstats" ;;',
        }
        self.env = dict(os.environ)
        for name, cases in stubs.items():
            path = self.root / name
            path.write_text(STUB.format(log=self.log, cases=cases))
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
            self.env[f"DASHBOARDPLUS_{name.upper()}"] = str(path)

    def tearDown(self):
        self.directory.cleanup()

    def run_script(self, name, **env):
        return subprocess.run(["sh", str(SCRIPTS / name)], capture_output=True, text=True, check=True,
                              env=dict(self.env, **env)).stdout

    def test_one_read_of_each_command_gives_the_whole_widget(self):
        result = summary(self.run_script("carp.sh"))
        self.assertEqual(result["summary"]["total"], 3)
        self.assertEqual(result["counters"]["pfsync_updates_in"], 1230)
        self.assertEqual(result["pfsync"]["syncok"], True)
        self.assertEqual(sorted(self.log.read_text().splitlines()), [
            "ifconfig -L", "ifconfig pfsync0", "netstat -s -p carp --libxo json",
            "netstat -s -p pfsync --libxo json", "sysctl net.inet.carp"])

    def test_without_carp_the_script_still_succeeds(self):
        empty = self.root / "empty"
        empty.mkdir()
        for name in ("ifconfig", "sysctl", "netstat"):
            stub = empty / name
            stub.write_text("#!/bin/sh\nexit 1\n")
            stub.chmod(0o755)
        text = self.run_script("carp.sh", **{f"DASHBOARDPLUS_{n.upper()}": str(empty / n)
                                             for n in ("ifconfig", "sysctl", "netstat")})
        self.assertFalse(summary(text, history="")["available"])

    def test_history_from_the_two_newest_system_logs(self):
        logs = self.root / "system"
        logs.mkdir()
        (logs / "system_20261007.log").write_text("<13>1 2026-10-07T10:00:00-04:00 fw kernel - - carp: 9@ix0: INIT -> BACKUP\n")
        (logs / "system_20261008.log").write_text(HISTORY.splitlines()[0] + "\nother kernel line\n")
        (logs / "system_20261009.log").write_text("\n".join(HISTORY.splitlines()[1:]) + "\n")
        text = self.run_script("carp_history.sh", DASHBOARDPLUS_SYSTEM_LOGS=str(logs))
        self.assertEqual([c["vhid"] for c in one("transitions", text)], [3, 1, 2])
        text = self.run_script("carp_history.sh", DASHBOARDPLUS_SYSTEM_LOGS=str(logs), DASHBOARDPLUS_CARP_HISTORY="1")
        self.assertEqual([c["vhid"] for c in one("transitions", text)], [3])

    def test_history_without_logs_is_empty(self):
        self.assertEqual(self.run_script("carp_history.sh", DASHBOARDPLUS_SYSTEM_LOGS=str(self.root / "none")), "")

    def test_the_actions_and_the_privilege(self):
        actions = (ROOT / "service/conf/actions.d/actions_dashboardplus.conf").read_text()
        status = actions[actions.index("[system.carp]"):].split("\n\n")[0]
        history = actions[actions.index("[system.carp_history]"):].split("\n\n")[0]
        self.assertIn("\ncommand:/usr/local/opnsense/scripts/OPNsense/DashboardPlus/carp.sh\n", status)
        self.assertNotIn("cache_ttl", status)
        self.assertIn("\ncommand:/usr/local/opnsense/scripts/OPNsense/DashboardPlus/carp_history.sh\n", history)
        self.assertIn("\ncache_ttl:30", history)
        for block in (status, history):
            self.assertIn("\nallowed_groups:wheel,wwwonly", block)
        for name in ("carp.sh", "carp_history.sh"):
            self.assertTrue(os.access(SCRIPTS / name, os.X_OK))
        acl = (ROOT / "mvc/app/models/OPNsense/DashboardPlus/ACL/ACL.xml").read_text()
        self.assertIn("<pattern>api/dashboardplus/system/carp</pattern>", acl)

    def test_no_action_is_shadowed_by_a_shorter_one(self):
        """configd walks an action name dot by dot and stops at the first action it finds, passing the
        rest as parameters: with [system.carp] present, [system.carp.history] could never be called."""
        actions = (ROOT / "service/conf/actions.d/actions_dashboardplus.conf").read_text()
        names = [line[1:-1] for line in actions.splitlines() if line.startswith("[") and line.endswith("]")]
        for name in names:
            for other in names:
                with self.subTest(name=name, other=other):
                    self.assertFalse(other.startswith(name + "."), f"[{other}] is shadowed by [{name}]")
        controllers = "".join(path.read_text() for path in (ROOT / "mvc/app/controllers").rglob("*.php"))
        for called in set(re.findall(r"configdp?Run\('dashboardplus ([^' ]+) ([^' ]+)", controllers)):
            with self.subTest(called=called):
                self.assertIn(".".join(called), names)


if __name__ == "__main__":
    unittest.main()
