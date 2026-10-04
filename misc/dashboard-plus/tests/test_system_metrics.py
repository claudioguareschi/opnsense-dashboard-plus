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

"""Unit tests for the Dashboard Plus live metrics."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/DashboardPlus/system_info.py"
SPEC = importlib.util.spec_from_file_location("dashboard_plus_system_metrics", SCRIPT)
SYSTEM_INFO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYSTEM_INFO)

BOOTTIME = "{ sec = 1727000000, usec = 123456 } Sun Sep 22 12:13:20 2024"

SYSCTL_OUTPUT = f"""kern.boottime={BOOTTIME}
hw.physmem=34199543808
vm.stats.vm.v_page_count=8169349
vm.stats.vm.v_inactive_count=1000000
vm.stats.vm.v_cache_count=0
vm.stats.vm.v_free_count=5000000
kstat.zfs.misc.arcstats.size=4294967296
vm.loadavg={{ 0.52 0.48 0.45 }}
dev.cpu.0.freq=2200
dev.cpu.0.freq_levels=2200/45000 2100/41000 1600/28000
hw.clockrate=2200
dev.cpu.0.temperature=45.0C
dev.cpu.1.temperature=47.0C
"""

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


class Commands:
    """Stand-ins for sysctl and the other commands, recording what was run."""

    def __init__(self, sysctl_output=SYSCTL_OUTPUT):
        self.values = SYSTEM_INFO.parse_sysctl_values(sysctl_output)
        self.sysctl_calls = []
        self.discoveries = 0
        self.slow_calls = 0

    def sysctls(self, names):
        self.sysctl_calls.append(list(names))
        return {name: self.values[name] for name in names if name in self.values}

    def discover(self, boottime, cache_path):
        self.discoveries += 1
        oids = SYSTEM_INFO.parse_temperature_oids(SYSCTL_FORMATS)
        oids = [oid for oid in oids if oid in self.values]
        SYSTEM_INFO.write_json(cache_path, {"boottime": boottime, "oids": oids})
        return oids

    def slow(self, now, cache_path):
        self.slow_calls += 1
        return {"mbufs": None, "swap": [], "filesystems": []}

    @staticmethod
    def command(command):
        return {"-si": PFCTL_INFO, "-sm": PFCTL_MEMORY}.get(command[-1], "")


class SystemMetricsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.sensors_cache = str(Path(self.directory.name) / "dashboardplus/sensors.json")
        self.slow_cache = str(Path(self.directory.name) / "dashboardplus/metrics.json")

    def tearDown(self):
        self.directory.cleanup()

    def collect(self, commands, now=1000.0):
        return SYSTEM_INFO.collect_metrics(
            now=now,
            sensors_cache=self.sensors_cache,
            slow_cache=self.slow_cache,
            sysctls=commands.sysctls,
            discover=commands.discover,
            slow=commands.slow,
            command=commands.command,
        )

    def test_memory_is_computed_as_the_core_system_resources_endpoint(self):
        values = SYSTEM_INFO.parse_sysctl_values(SYSCTL_OUTPUT)
        memory = SYSTEM_INFO.memory_metrics(values)
        # round(((pages - (inactive + cache + free)) / pages) * physmem), then whole MiB
        used = round((8169349 - 6000000) / 8169349 * 34199543808)
        self.assertEqual(memory, {
            "total_mib": 32615,
            "used_mib": used // 1024 // 1024,
            "arc_mib": 4096,
        })

    def test_memory_without_page_counts_or_arc(self):
        self.assertIsNone(SYSTEM_INFO.memory_metrics({"hw.physmem": "1073741824"}))
        memory = SYSTEM_INFO.memory_metrics({
            "hw.physmem": "1073741824",
            "vm.stats.vm.v_page_count": "262144",
            "vm.stats.vm.v_free_count": "131072",
        })
        self.assertEqual(memory, {"total_mib": 1024, "used_mib": 512, "arc_mib": 0})

    def test_php_round_rounds_half_away_from_zero(self):
        self.assertEqual(SYSTEM_INFO.php_round(2.5), 3)
        self.assertEqual(SYSTEM_INFO.php_round(3.5), 4)
        self.assertEqual(SYSTEM_INFO.php_round(2.4), 2)

    def test_sysctl_values_boottime_and_load(self):
        values = SYSTEM_INFO.parse_sysctl_values(SYSCTL_OUTPUT)
        self.assertEqual(SYSTEM_INFO.parse_boottime(values["kern.boottime"]), 1727000000)
        self.assertIsNone(SYSTEM_INFO.parse_boottime(""))
        self.assertEqual(SYSTEM_INFO.load_average(values["vm.loadavg"]), "0.52, 0.48, 0.45")
        self.assertEqual(SYSTEM_INFO.load_average(None), "")

    def test_temperature_sensors_are_found_by_format_and_name(self):
        self.assertEqual(SYSTEM_INFO.parse_temperature_oids(SYSCTL_FORMATS), [
            "dev.cpu.0.temperature",
            "dev.cpu.1.temperature",
            "hw.acpi.thermal.tz0.temperature",
            "dev.amdtemp.0.core0.sensor0",
        ])
        # the format may be printed beside the value
        self.assertEqual(
            SYSTEM_INFO.parse_temperature_oids("dev.cpu.0.temperature: IK 45.0C\nvm.loadavg: S,loadavg { 0.1 }\n"),
            ["dev.cpu.0.temperature"],
        )

    def test_temperature_readings_have_the_fields_of_the_core_endpoint(self):
        readings = SYSTEM_INFO.temperature_readings(
            ["dev.cpu.3.temperature", "hw.acpi.thermal.tz1.temperature", "dev.cpu.9.temperature", "dev.cpu.4.temperature"],
            {
                "dev.cpu.3.temperature": "51.0C",
                "hw.acpi.thermal.tz1.temperature": "27.9C",
                "dev.cpu.4.temperature": "-1",
            },
        )
        self.assertEqual(readings, [
            {"device": "dev.cpu.3.temperature", "device_seq": "3", "temperature": "51.0", "type": "cpu"},
            {"device": "hw.acpi.thermal.tz1.temperature", "device_seq": "1", "temperature": "27.9", "type": "zone"},
            {"device": "dev.cpu.4.temperature", "device_seq": "4", "temperature": "-1", "type": "cpu"},
        ])

    def test_pf_states_and_limit(self):
        self.assertEqual(SYSTEM_INFO.parse_pf_info(PFCTL_INFO), 1225)
        self.assertEqual(SYSTEM_INFO.parse_pf_memory(PFCTL_MEMORY), 3237000)
        self.assertIsNone(SYSTEM_INFO.parse_pf_info(""))
        self.assertIsNone(SYSTEM_INFO.parse_pf_memory(""))

    def test_swapinfo_devices_without_the_total_line(self):
        output = """Device          1K-blocks     Used    Avail Capacity
/dev/gpt/swap0    2097152    10240  2086912     0%
/dev/gpt/swap1    2097152        0  2097152     0%
Total             4194304    10240  4184064     0%
"""
        self.assertEqual(SYSTEM_INFO.parse_swapinfo(output), [
            {"device": "/dev/gpt/swap0", "total": 2097152, "used": 10240},
            {"device": "/dev/gpt/swap1", "total": 2097152, "used": 0},
        ])
        self.assertEqual(SYSTEM_INFO.parse_swapinfo("Device 1K-blocks Used Avail Capacity\n"), [])

    def test_df_filesystems_with_the_fields_of_the_core_endpoint(self):
        output = json.dumps({"storage-system-information": {"filesystem": [
            {"name": "zroot/ROOT/default", "type": "zfs", "blocks": "11G", "used": "1.6G",
             "available": "9.4G", "used-percent": 15, "mounted-on": "/"},
            {"name": "zroot/ROOT/default", "type": "zfs", "blocks": "11G", "used": "1.6G",
             "available": "9.4G", "used-percent": 15, "mounted-on": "/"},
            {"name": "tmpfs", "type": "tmpfs", "blocks": "1.0G", "used": "236M",
             "available": "788M", "used-percent": 23, "mounted-on": "/var/log"},
        ]}})
        self.assertEqual(SYSTEM_INFO.parse_df(output), [
            {"device": "zroot/ROOT/default", "type": "zfs", "blocks": "11G", "used": "1.6G",
             "available": "9.4G", "used_pct": 15, "mountpoint": "/"},
            {"device": "tmpfs", "type": "tmpfs", "blocks": "1.0G", "used": "236M",
             "available": "788M", "used_pct": 23, "mountpoint": "/var/log"},
        ])
        self.assertEqual(SYSTEM_INFO.parse_df("df: /missing: No such file or directory"), [])

    def test_netstat_mbuf_clusters(self):
        output = json.dumps({"mbuf-statistics": {"cluster-current": 2048, "cluster-cache": 1018,
                                                 "cluster-total": 3066, "cluster-max": 1000000}})
        self.assertEqual(SYSTEM_INFO.parse_netstat_mbufs(output), {"current": 3066, "limit": 1000000})
        self.assertIsNone(SYSTEM_INFO.parse_netstat_mbufs("{}"))
        self.assertIsNone(SYSTEM_INFO.parse_netstat_mbufs("not json"))

    def test_one_sysctl_call_once_the_sensors_are_known(self):
        commands = Commands()
        first = self.collect(commands)
        self.assertEqual(commands.discoveries, 1)
        self.assertEqual(len(commands.sysctl_calls), 2)
        self.assertEqual([reading["device"] for reading in first["temperatures"]],
                         ["dev.cpu.0.temperature", "dev.cpu.1.temperature"])

        commands.sysctl_calls.clear()
        second = self.collect(commands)
        self.assertEqual(commands.discoveries, 1)
        self.assertEqual(len(commands.sysctl_calls), 1)
        self.assertIn("dev.cpu.1.temperature", commands.sysctl_calls[0])
        self.assertEqual(second["temperatures"], first["temperatures"])
        self.assertEqual(second["load"], "0.52, 0.48, 0.45")
        self.assertEqual(second["cpu"], {"current_mhz": 2200, "maximum_mhz": 2200})
        self.assertEqual(second["states"], {"current": 1225, "limit": 3237000})

    def test_a_reboot_finds_the_sensors_again(self):
        commands = Commands()
        self.collect(commands)
        rebooted = SYSCTL_OUTPUT.replace("sec = 1727000000", "sec = 1728000000")
        rebooted = rebooted.replace("dev.cpu.1.temperature=47.0C\n", "")
        commands.values = SYSTEM_INFO.parse_sysctl_values(rebooted)
        metrics = self.collect(commands)
        self.assertEqual(commands.discoveries, 2)
        self.assertEqual([reading["device"] for reading in metrics["temperatures"]], ["dev.cpu.0.temperature"])
        cache = SYSTEM_INFO.read_json(self.sensors_cache)
        self.assertEqual(cache, {"boottime": 1728000000, "oids": ["dev.cpu.0.temperature"]})

    def test_a_damaged_sensor_cache_is_replaced(self):
        Path(self.sensors_cache).parent.mkdir(parents=True)
        Path(self.sensors_cache).write_text("{not json", encoding="utf-8")
        commands = Commands()
        self.collect(commands)
        self.assertEqual(commands.discoveries, 1)
        self.assertEqual(SYSTEM_INFO.read_json(self.sensors_cache)["boottime"], 1727000000)

    def test_slow_metrics_are_read_again_after_a_minute(self):
        calls = []

        def collector():
            calls.append(1)
            return {"mbufs": {"current": len(calls), "limit": 10}, "swap": [], "filesystems": []}

        first = SYSTEM_INFO.slow_metrics(1000.0, self.slow_cache, collector)
        cached = SYSTEM_INFO.slow_metrics(1059.0, self.slow_cache, collector)
        self.assertEqual(len(calls), 1)
        self.assertEqual(cached, first)
        renewed = SYSTEM_INFO.slow_metrics(1060.0, self.slow_cache, collector)
        self.assertEqual(len(calls), 2)
        self.assertEqual(renewed["mbufs"]["current"], 2)
        # a clock set back does not keep the cached numbers forever
        SYSTEM_INFO.slow_metrics(500.0, self.slow_cache, collector)
        self.assertEqual(len(calls), 3)

    def test_an_unwritable_cache_is_only_a_cache_miss(self):
        blocker = Path(self.directory.name) / "file"
        blocker.write_text("", encoding="utf-8")
        SYSTEM_INFO.write_json(str(blocker / "sensors.json"), {"boottime": 1})
        self.assertIsNone(SYSTEM_INFO.read_json(str(blocker / "sensors.json")))


if __name__ == "__main__":
    unittest.main()
