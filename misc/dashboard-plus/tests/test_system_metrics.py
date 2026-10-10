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

"""System Metrics+, Thermal Sensors+ and System Information+: metrics.sh reads (run here with
stand-in commands) and models/OPNsense/DashboardPlus/Metrics.php parses."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).parents[1] / "src/opnsense"
SCRIPT = ROOT / "scripts/OPNsense/DashboardPlus/metrics.sh"
MODEL = ROOT / "mvc/app/models/OPNsense/DashboardPlus/Metrics.php"

BOOTTIME = "{ sec = 1727000000, usec = 123456 } Sun Sep 22 12:13:20 2024"

VALUES = {
    "kern.boottime": BOOTTIME,
    "hw.physmem": "34199543808",
    "vm.stats.vm.v_page_count": "8169349",
    "vm.stats.vm.v_inactive_count": "1000000",
    "vm.stats.vm.v_cache_count": "0",
    "vm.stats.vm.v_free_count": "5000000",
    "kstat.zfs.misc.arcstats.size": "4294967296",
    "vm.loadavg": "{ 0.52 0.48 0.45 }",
    "dev.cpu.0.freq": "2200",
    "dev.cpu.0.freq_levels": "2200/45000 2100/41000 1600/28000",
    "hw.clockrate": "2200",
    "dev.cpu.0.temperature": "45.0C",
    "dev.cpu.1.temperature": "47.0C",
}

SYSCTL_FORMATS = """kern.ostype: A
dev.cpu.0.temperature: IK
dev.cpu.0.coretemp.tjmax: IK
dev.cpu.0.coretemp.delta: I
dev.cpu.1.temperature: IK
hw.acpi.thermal.tz0.temperature: IK
hw.acpi.thermal.tz0._PSV: IK
hw.acpi.thermal.tz0._CRT: IK
dev.amdtemp.0.core0.sensor0: IK
dev.ixl.0.temperature: I
dev.cpu.0.temperature: IK
"""

PFCTL_INFO = """Status: Enabled for 12 days 03:04:05           Debug: Urgent

State Table                          Total             Rate
  current entries                     1225
  searches                       123456789          117.0/s
"""

PFCTL_MEMORY = """states        hard limit  3237000
src-nodes     hard limit  3237000
frags         hard limit     5000
"""

SWAPINFO = """Device          1K-blocks     Used    Avail Capacity
/dev/gpt/swap0    2097152    10240  2086912     0%
/dev/gpt/swap1    2097152        0  2097152     0%
Total             4194304    10240  4184064     0%
"""

DF = json.dumps({"storage-system-information": {"filesystem": [
    {"name": "zroot/ROOT/default", "type": "zfs", "blocks": "11G", "used": "1.6G",
     "available": "9.4G", "used-percent": 15, "mounted-on": "/"},
    {"name": "zroot/ROOT/default", "type": "zfs", "blocks": "11G", "used": "1.6G",
     "available": "9.4G", "used-percent": 15, "mounted-on": "/"},
    {"name": "tmpfs", "type": "tmpfs", "blocks": "1.0G", "used": "236M",
     "available": "788M", "used-percent": 23, "mounted-on": "/var/log"},
]}})

NETSTAT = json.dumps({"mbuf-statistics": {"cluster-current": 2048, "cluster-cache": 1018,
                                          "cluster-total": 3066, "cluster-max": 1000000}})

PARSE = r"""
require getenv('MODEL');
$m = 'OPNsense\\DashboardPlus\\Metrics';
$in = json_decode(file_get_contents('php://stdin'), true);
$out = [];
foreach ($in as $call) {
    $out[] = call_user_func_array([$m, $call[0]], $call[1]);
}
echo json_encode($out);
"""


def php(*calls):
    result = subprocess.run(["php", "-r", PARSE], input=json.dumps(calls), capture_output=True, text=True,
                            check=True, env=dict(os.environ, MODEL=str(MODEL)))
    return json.loads(result.stdout)


def one(name, *arguments):
    return php([name, list(arguments)])[0]


STUB = """#!/bin/sh
echo "$(basename "$0") $*" >> "{log}"
case "$(basename "$0") $*" in
{cases}
esac
"""


class Firewall:
    """Stand-ins for sysctl, pfctl, netstat, swapinfo and df in a temporary directory."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.cache = self.directory / "cache"
        self.log = self.directory / "calls.log"
        self.values = dict(VALUES)
        self.write()

    def write(self):
        (self.directory / "values").write_text("".join(f"{k}={v}\n" for k, v in self.values.items()))
        (self.directory / "formats").write_text(SYSCTL_FORMATS)
        files = {"pfinfo": PFCTL_INFO, "pfmemory": PFCTL_MEMORY, "swap": SWAPINFO, "df": DF, "netstat": NETSTAT}
        for name, text in files.items():
            (self.directory / name).write_text(text)
        d = self.directory
        stubs = {
            "sysctl": f'"sysctl -aF") cat "{d}/formats" ;;\n'
                      f'"sysctl -i -e "*) shift 2; for name in "$@"; do grep "^$name=" "{d}/values"; done ;;',
            "pfctl": f'"pfctl -si") cat "{d}/pfinfo" ;;\n"pfctl -sm") cat "{d}/pfmemory" ;;',
            "netstat": f'*) cat "{d}/netstat" ;;',
            "swapinfo": f'*) cat "{d}/swap" ;;',
            "df": f'*) cat "{d}/df" ;;',
        }
        for name, cases in stubs.items():
            path = self.bin / name
            path.write_text(STUB.format(log=self.log, cases=cases))
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run(self, now=1000):
        env = dict(os.environ, DASHBOARDPLUS_CACHE=str(self.cache), DASHBOARDPLUS_NOW=str(now),
                   **{f"DASHBOARDPLUS_{name.upper()}": str(self.bin / name)
                      for name in ("sysctl", "pfctl", "netstat", "swapinfo", "df")})
        result = subprocess.run(["sh", str(SCRIPT)], capture_output=True, text=True, check=True, env=env)
        return result.stdout

    def calls(self, command=None):
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        self.log.unlink(missing_ok=True)
        return [line for line in lines if command is None or line.split()[0] == command]


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class ParseTest(unittest.TestCase):
    def test_memory_is_computed_as_the_core_system_resources_endpoint(self):
        # round(((pages - (inactive + cache + free)) / pages) * physmem), then whole MiB
        used = round((8169349 - 6000000) / 8169349 * 34199543808)
        self.assertEqual(one("memory", VALUES), {"total_mib": 32615, "used_mib": used // 1024 // 1024,
                                                 "arc_mib": 4096})

    def test_memory_without_page_counts_or_arc(self):
        self.assertIsNone(one("memory", {"hw.physmem": "1073741824"}))
        self.assertEqual(one("memory", {"hw.physmem": "1073741824", "vm.stats.vm.v_page_count": "262144",
                                        "vm.stats.vm.v_free_count": "131072"}),
                         {"total_mib": 1024, "used_mib": 512, "arc_mib": 0})

    def test_load_and_cpu_frequency(self):
        self.assertEqual(php(["load", ["{ 0.52 0.48 0.45 }"]], ["load", [""]]), ["0.52, 0.48, 0.45", ""])
        self.assertEqual(one("cpu", "2200", "2200/45000 2100/41000 1600/28000"),
                         {"current_mhz": 2200, "maximum_mhz": 2200})
        self.assertEqual(one("cpu", None, ""), {"current_mhz": None, "maximum_mhz": None})

    def test_temperature_readings_have_the_fields_of_the_core_endpoint(self):
        readings = one("temperatures",
                       ["dev.cpu.3.temperature", "hw.acpi.thermal.tz1.temperature", "dev.cpu.9.temperature",
                        "dev.cpu.4.temperature"],
                       {"dev.cpu.3.temperature": "51.0C", "hw.acpi.thermal.tz1.temperature": "27.9C",
                        "dev.cpu.4.temperature": "-1"})
        self.assertEqual(readings, [
            {"device": "dev.cpu.3.temperature", "device_seq": "3", "temperature": "51.0", "type": "cpu"},
            {"device": "hw.acpi.thermal.tz1.temperature", "device_seq": "1", "temperature": "27.9", "type": "zone"},
            {"device": "dev.cpu.4.temperature", "device_seq": "4", "temperature": "-1", "type": "cpu"},
        ])

    def test_swapinfo_devices_without_the_total_line(self):
        self.assertEqual(one("swap", SWAPINFO), [
            {"device": "/dev/gpt/swap0", "total": 2097152, "used": 10240},
            {"device": "/dev/gpt/swap1", "total": 2097152, "used": 0},
        ])
        self.assertEqual(one("swap", "Device 1K-blocks Used Avail Capacity\n"), [])

    def test_df_filesystems_with_the_fields_of_the_core_endpoint(self):
        self.assertEqual(one("filesystems", DF), [
            {"device": "zroot/ROOT/default", "type": "zfs", "blocks": "11G", "used": "1.6G",
             "available": "9.4G", "used_pct": 15, "mountpoint": "/"},
            {"device": "tmpfs", "type": "tmpfs", "blocks": "1.0G", "used": "236M",
             "available": "788M", "used_pct": 23, "mountpoint": "/var/log"},
        ])
        self.assertEqual(one("filesystems", "df: /missing: No such file or directory"), [])

    def test_netstat_mbuf_clusters(self):
        self.assertEqual(one("mbufs", NETSTAT), {"current": 3066, "limit": 1000000})
        self.assertEqual(php(["mbufs", ["{}"]], ["mbufs", ["not json"]]), [None, None])

    def test_missing_readings_are_a_failure_not_zeros(self):
        self.assertIsNone(one("parse", ""))
        self.assertIsNone(one("parse", "Execute error"))


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class ScriptTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.firewall = Firewall(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def parse(self, output):
        return one("parse", output)

    def test_the_metrics_the_widgets_draw(self):
        metrics = self.parse(self.firewall.run())
        self.assertEqual(metrics["load"], "0.52, 0.48, 0.45")
        self.assertEqual(metrics["cpu"], {"current_mhz": 2200, "maximum_mhz": 2200})
        self.assertEqual(metrics["states"], {"current": 1225, "limit": 3237000})
        self.assertEqual(metrics["mbufs"], {"current": 3066, "limit": 1000000})
        self.assertEqual([device["device"] for device in metrics["swap"]], ["/dev/gpt/swap0", "/dev/gpt/swap1"])
        self.assertEqual([device["mountpoint"] for device in metrics["filesystems"]], ["/", "/var/log"])
        # sensors found by format and name; settings in the same format and other formats left out
        self.assertEqual([reading["device"] for reading in metrics["temperatures"]],
                         ["dev.cpu.0.temperature", "dev.cpu.1.temperature"])
        self.assertEqual(metrics["memory"]["total_mib"], 32615)

    def test_sensor_discovery_by_format_and_name(self):
        self.firewall.run()
        listed = (self.firewall.cache / "sensors.list").read_text().split()
        self.assertEqual(listed, ["1727000000", "dev.cpu.0.temperature", "dev.cpu.1.temperature",
                                  "hw.acpi.thermal.tz0.temperature", "dev.amdtemp.0.core0.sensor0"])

    def test_one_sysctl_call_once_the_sensors_are_known(self):
        self.firewall.run()
        self.assertEqual(len(self.firewall.calls("sysctl")), 3)   # values, the walk, the new sensors
        self.firewall.run(now=1010)
        calls = self.firewall.calls("sysctl")
        self.assertEqual(len(calls), 1)
        self.assertIn("dev.cpu.1.temperature", calls[0])

    def test_a_reboot_finds_the_sensors_again(self):
        self.firewall.run()
        self.firewall.values["kern.boottime"] = BOOTTIME.replace("1727000000", "1728000000")
        del self.firewall.values["dev.cpu.1.temperature"]
        self.firewall.write()
        self.firewall.calls()
        metrics = self.parse(self.firewall.run(now=1010))
        self.assertIn("sysctl -aF", self.firewall.calls("sysctl"))
        self.assertEqual((self.firewall.cache / "sensors.list").read_text().split()[0], "1728000000")
        self.assertEqual([reading["device"] for reading in metrics["temperatures"]], ["dev.cpu.0.temperature"])

    def test_a_damaged_sensor_cache_is_replaced(self):
        self.firewall.cache.mkdir()
        (self.firewall.cache / "sensors.list").write_text("{not a list")
        self.firewall.run()
        self.assertEqual((self.firewall.cache / "sensors.list").read_text().split()[0], "1727000000")

    def test_slow_readings_are_read_again_after_a_minute(self):
        self.firewall.run(now=1000)
        self.assertEqual(len(self.firewall.calls("netstat")), 1)
        self.firewall.run(now=1059)
        self.assertEqual(self.firewall.calls("netstat"), [])
        self.firewall.run(now=1060)
        self.assertEqual(len(self.firewall.calls("netstat")), 1)
        # a clock set back does not keep the cached readings forever
        self.firewall.run(now=500)
        self.assertEqual(len(self.firewall.calls("netstat")), 1)

    def test_an_unwritable_cache_only_costs_the_caching(self):
        blocker = Path(self.directory.name) / "file"
        blocker.write_text("")
        self.firewall.cache = blocker / "cache"
        metrics = self.parse(self.firewall.run())
        self.assertEqual(metrics["states"], {"current": 1225, "limit": 3237000})
        self.assertEqual([reading["device"] for reading in metrics["temperatures"]],
                         ["dev.cpu.0.temperature", "dev.cpu.1.temperature"])

    def test_the_action_runs_the_script_and_configd_shares_it(self):
        actions = (ROOT / "service/conf/actions.d/actions_dashboardplus.conf").read_text()
        self.assertIn("[system.metrics]\ncommand:/usr/local/opnsense/scripts/OPNsense/DashboardPlus/metrics.sh\n",
                      actions)
        block = actions[actions.index("[system.metrics]"):].split("\n\n")[0]
        self.assertIn("\ncache_ttl:5", block)
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
