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

"""QuickAssist+ live sample: the QAT sysctl tree (one `sysctl -i -e dev.qat dev.qat_ocf` through
configd) parsed by models/OPNsense/DashboardPlus/QuickAssist.php."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).parents[1] / "src/opnsense"
MODEL = ROOT / "mvc/app/models/OPNsense/DashboardPlus/QuickAssist.php"
SCRIPT = ROOT / "scripts/OPNsense/DashboardPlus/system_info.py"
SPEC = importlib.util.spec_from_file_location("dashboard_plus_system_info", SCRIPT)
SYSTEM_INFO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYSTEM_INFO)

HARNESS = r"""
namespace {
    require getenv('MODEL');
    $input = json_decode(file_get_contents('php://stdin'), true);
    $c = 'OPNsense\\DashboardPlus\\QuickAssist';
    echo json_encode([
        'sample' => $c::sample($input['sysctl'], 100),
        'counters' => $c::counters($input['sysctl']),
        'algorithms' => $c::OCF_ALGORITHMS,
        'bits' => $c::CAPABILITY_BITS,
    ]);
}
"""


def php(sysctl):
    result = subprocess.run(["php", "-r", HARNESS], input=json.dumps({"sysctl": sysctl}), capture_output=True,
                            text=True, check=True, env=dict(os.environ, MODEL=str(MODEL)))
    return json.loads(result.stdout)


def sample(sysctl):
    return php(sysctl)["sample"]


def counters(aes):
    return "\n".join(
        f"AE {number}\nFirmware Responses: {responses}\nFirmware Requests: {requests}"
        for number, responses, requests in aes
    )


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class QuickAssistTest(unittest.TestCase):
    def test_normal_three_device_ten_ae_topology_aggregates_every_counter(self):
        lines = []
        for unit in ("0", "3", "7"):
            prefix = f"dev.qat.{unit}"
            lines.extend((
                f"{prefix}.state=up", f"{prefix}.fw_counters=" + counters([
                    (number, 100 + number, 100 + number) for number in range(10)
                ]),
            ))
        result = sample("\n".join(lines))
        self.assertEqual([device["unit"] for device in result["devices"]], ["0", "3", "7"])
        self.assertEqual(sum(device["ae_count"] for device in result["devices"]), 30)
        self.assertEqual(sum(device["responses"] for device in result["devices"]), 3135)

    def test_parse_firmware_counters_ignores_headers_nuls_and_partial_ae(self):
        parsed = php("\x00decorative heading\n" + counters([(0, 12, 14), (1, 20, 21)])
                     + "\nAE 2\nFirmware Responses: 99\n")["counters"]
        self.assertEqual(parsed, [
            {"ae": 0, "responses": 12, "requests": 14},
            {"ae": 1, "responses": 20, "requests": 21},
        ])

    def test_collects_non_contiguous_devices_and_actual_ae_counts(self):
        result = sample("\n".join((
            "dev.qat.1.%desc=Intel C6xx", "dev.qat.1.frequency=685000000",
            "dev.qat.1.cfg_services=sym;dc", "dev.qat.1.dev_cfg=Device_Capabilities_Mask = 0x23", "dev.qat.1.state=up",
            "dev.qat.1.heartbeat=1", "dev.qat.1.heartbeat_failed=4",
            "dev.qat.1.fw_counters=" + counters([(0, 10, 11), (1, 20, 22)]),
            "dev.qat.10.%desc=Intel C6xx", "dev.qat.10.frequency=700000000",
            "dev.qat.10.cfg_services=sym;dc", "dev.qat.10.state=up",
            "dev.qat.10.heartbeat=1", "dev.qat.10.heartbeat_failed=0",
            "dev.qat.10.fw_counters=" + counters([(0, 30, 31)]),
            "dev.qat.4.state=up",
            "dev.qat_ocf.9.enable=1",
        )))
        self.assertTrue(result["available"])
        # in unit order (numeric, not text), every unit the tree names
        self.assertEqual([device["unit"] for device in result["devices"]], ["1", "4", "10"])
        self.assertEqual([device["ae_count"] for device in result["devices"]], [2, 0, 1])
        first = result["devices"][0]
        self.assertEqual({key: first[key] for key in ("description", "frequency_hz", "services", "state", "heartbeat",
                                                      "heartbeat_failed", "counters_available", "requests",
                                                      "responses")},
                         {"description": "Intel C6xx", "frequency_hz": 685000000, "services": "sym;dc",
                          "state": "up", "heartbeat": 1, "heartbeat_failed": 4, "counters_available": True,
                          "requests": 33, "responses": 30})
        self.assertEqual(first["capabilities"], ["symmetric cryptography", "asymmetric cryptography", "compression"])
        self.assertFalse(result["devices"][1]["counters_available"])
        self.assertEqual(result["ocf"], {"present": True, "enabled": True,
                                         "algorithms": list(SYSTEM_INFO.QAT_OCF_ALGORITHMS)})

    def test_missing_optional_values_are_safe(self):
        result = sample("\n".join((
            "dev.qat.0.state=up", "dev.qat.0.fw_counters=" + counters([(0, 1, 1)]),
            "dev.qat.0.heartbeat=not a number", "dev.qat_ocf.0.enable=0",
        )))
        device = result["devices"][0]
        self.assertEqual((device["frequency_hz"], device["heartbeat"], device["heartbeat_failed"], device["ae_count"],
                          device["description"], device["capabilities"]), (0, None, 0, 1, "", []))
        self.assertEqual(result["ocf"], {"present": True, "enabled": False, "algorithms": []})

    def test_algorithms_only_while_a_symmetric_device_is_up(self):
        down = sample("dev.qat.0.state=down\ndev.qat.0.cfg_services=sym;dc\ndev.qat_ocf.0.enable=1")
        self.assertEqual(down["ocf"]["algorithms"], [])
        compression = sample("dev.qat.0.state=up\ndev.qat.0.cfg_services=dc\ndev.qat_ocf.0.enable=1")
        self.assertEqual(compression["ocf"]["algorithms"], [])

    def test_no_hardware(self):
        self.assertEqual(sample(""), {
            "available": False, "sampled_at": 100, "devices": [],
            "ocf": {"present": False, "enabled": False, "algorithms": []},
        })
        # the error text configd returns for a failed action is no hardware either
        self.assertFalse(sample("Execute error")["available"])

    def test_multiline_reports_stay_with_their_oid(self):
        # a real driver prints tables under cnv_error and dev_cfg; they must not leak into other values
        result = sample("\n".join((
            "dev.qat.0.cnv_error=", "+----+", "| CNV Error Freq Statistics |", "+----+",
            "dev.qat.0.dev_cfg=[GENERAL]", "ServicesEnabled = sym;dc", "Device_Capabilities_Mask = 0x2",
            "dev.qat.0.state=up",
        )))
        device = result["devices"][0]
        self.assertEqual((device["state"], device["capabilities"]), ("up", ["asymmetric cryptography"]))

    def test_driver_level_oids_end_the_previous_value(self):
        # reading the whole dev.qat prefix also returns dev.qat.%parent (no unit), seen on FW2
        result = sample("\n".join((
            "dev.qat.0.%desc=Intel dh895xcc QuickAssist", "dev.qat.%parent=", "dev.qat.0.state=up",
            "dev.qat_ocf.%parent=", "dev.qat_ocf.0.enable=1",
        )))
        self.assertEqual((result["devices"][0]["description"], result["devices"][0]["state"]),
                         ("Intel dh895xcc QuickAssist", "up"))
        self.assertTrue(result["ocf"]["enabled"])

    def test_constants_match_the_hardware_details(self):
        constants = php("")
        self.assertEqual(constants["algorithms"], list(SYSTEM_INFO.QAT_OCF_ALGORITHMS))
        self.assertEqual({int(bit): label for bit, label in constants["bits"].items()},
                         dict(SYSTEM_INFO.QAT_CAPABILITY_BITS))


class ActionTest(unittest.TestCase):
    def test_the_sample_reads_the_qat_tree_directly(self):
        actions = (ROOT / "service/conf/actions.d/actions_dashboardplus.conf").read_text()
        self.assertIn("[system.qat]\ncommand:/sbin/sysctl -i -e dev.qat dev.qat_ocf\nparameters:\n", actions)
        self.assertFalse(hasattr(SYSTEM_INFO, "collect_qat_live"))


if __name__ == "__main__":
    unittest.main()
