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

"""Unit tests for QuickAssist+ sysctl parsing and collection."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/DashboardPlus/system_info.py"
SPEC = importlib.util.spec_from_file_location("dashboard_plus_system_info", SCRIPT)
SYSTEM_INFO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYSTEM_INFO)


def counters(aes):
    return "\n".join(
        f"AE {number}\nFirmware Responses: {responses}\nFirmware Requests: {requests}"
        for number, responses, requests in aes
    )


class QuickAssistTest(unittest.TestCase):
    def test_normal_three_device_ten_ae_topology_aggregates_every_counter(self):
        units = ("0", "3", "7")
        discovery = "\n".join(f"dev.qat.{unit}.state=up" for unit in units)
        lines = []
        for unit in units:
            prefix = f"dev.qat.{unit}"
            lines.extend((
                f"{prefix}.state=up", f"{prefix}.fw_counters=" + counters([
                    (number, 100 + number, 100 + number) for number in range(10)
                ]),
            ))
        with tempfile.TemporaryDirectory() as directory:
            result = SYSTEM_INFO.collect_qat_live(
                now=100, cache_path=f"{directory}/qat.json", discover=lambda: discovery,
                sysctls=lambda names: "\n".join(lines),
            )
        self.assertEqual(len(result["devices"]), 3)
        self.assertEqual(sum(device["ae_count"] for device in result["devices"]), 30)
        self.assertEqual(sum(device["responses"] for device in result["devices"]), 3135)

    def test_parse_firmware_counters_ignores_headers_nuls_and_partial_ae(self):
        parsed = SYSTEM_INFO.parse_qat_fw_counters(
            "\x00decorative heading\n" + counters([(0, 12, 14), (1, 20, 21)])
            + "\nAE 2\nFirmware Responses: 99\n"
        )
        self.assertEqual(parsed, [
            {"ae": 0, "responses": 12, "requests": 14},
            {"ae": 1, "responses": 20, "requests": 21},
        ])
        self.assertEqual(SYSTEM_INFO.qat_totals(parsed), {"responses": 32, "requests": 35})

    def test_collects_non_contiguous_devices_and_actual_ae_counts(self):
        discovery = "\n".join((
            "dev.qat.1.state=up", "dev.qat.4.state=up", "dev.qat_ocf.9.enable=1",
        ))
        sample = "\n".join((
            "dev.qat.1.%desc=Intel C6xx", "dev.qat.1.frequency=685000000",
            "dev.qat.1.cfg_services=sym;dc", "dev.qat.1.state=up",
            "dev.qat.1.heartbeat=1", "dev.qat.1.heartbeat_failed=4",
            "dev.qat.1.fw_counters=" + counters([(0, 10, 11), (1, 20, 22)]),
            "dev.qat.4.%desc=Intel C6xx", "dev.qat.4.frequency=700000000",
            "dev.qat.4.cfg_services=sym;dc", "dev.qat.4.state=up",
            "dev.qat.4.heartbeat=1", "dev.qat.4.heartbeat_failed=0",
            "dev.qat.4.fw_counters=" + counters([(0, 30, 31)]),
            "dev.qat_ocf.9.enable=1",
        ))
        with tempfile.TemporaryDirectory() as directory:
            result = SYSTEM_INFO.collect_qat_live(
                now=100, cache_path=f"{directory}/qat.json", discover=lambda: discovery,
                sysctls=lambda names: sample,
            )
        self.assertTrue(result["available"])
        self.assertEqual([device["unit"] for device in result["devices"]], ["1", "4"])
        self.assertEqual([device["ae_count"] for device in result["devices"]], [2, 1])
        self.assertEqual(result["devices"][0]["responses"], 30)
        self.assertEqual(result["devices"][1]["requests"], 31)
        self.assertEqual(result["ocf"], {"present": True, "enabled": True})

    def test_missing_optional_sysctls_and_disappeared_device_are_safe(self):
        discovery = "dev.qat.0.state=up\ndev.qat.3.state=up\ndev.qat_ocf.0.enable=0\n"
        sample = "\n".join((
            "dev.qat.0.state=up", "dev.qat.0.fw_counters=" + counters([(0, 1, 1)]),
            "dev.qat_ocf.0.enable=0",
        ))
        with tempfile.TemporaryDirectory() as directory:
            result = SYSTEM_INFO.collect_qat_live(
                now=100, cache_path=f"{directory}/qat.json", discover=lambda: discovery,
                sysctls=lambda names: sample,
            )
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(result["devices"][0]["frequency_hz"], 0)
        self.assertEqual(result["devices"][0]["ae_count"], 1)
        self.assertFalse(result["ocf"]["enabled"])

    def test_empty_discovery_reports_no_hardware(self):
        with tempfile.TemporaryDirectory() as directory:
            result = SYSTEM_INFO.collect_qat_live(
                now=100, cache_path=f"{directory}/qat.json", discover=lambda: "", sysctls=lambda names: "",
            )
        self.assertEqual(result, {
            "available": False, "sampled_at": 100, "devices": [],
            "ocf": {"present": False, "enabled": False},
        })
