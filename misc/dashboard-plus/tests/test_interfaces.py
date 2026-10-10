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

"""Interfaces+ status (interfaces.php): `ifconfig -L` parsed into the structure OPNsense's primary
address functions read, and one row per assigned interface as the interfaces overview gives it."""

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/DashboardPlus/interfaces.php"

IFCONFIG = """\
ix0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\toptions=4e53fbb<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,JUMBO_MTU>
\tether 90:e2:ba:00:00:01
\tinet 192.168.1.248 netmask 0xffffff00 broadcast 192.168.1.255
\tinet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255 vhid 1
\tinet6 fe80::92e2:baff:fe00:1%ix0 prefixlen 64 scopeid 0x1
\tinet6 2601:740:8500:5e78::1 prefixlen 64 pltime 3600 vltime 7200
\tinet6 2601:740:8500:5e78::99 prefixlen 64 deprecated autoconf pltime 0 vltime 300
\tcarp: MASTER vhid 1 advbase 1 advskew 0
\tmedia: Ethernet autoselect (10Gbase-SR <full-duplex,rxpause,txpause>)
\tstatus: active
\tnd6 options=21<PERFORMNUD,AUTO_LINKLOCAL>
igb0: flags=8822<BROADCAST,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether 00:1b:21:00:00:02
\tmedia: Ethernet autoselect
\tstatus: no carrier
wg0: flags=10080c1<UP,RUNNING,NOARP,MULTICAST,LOWER_UP> metric 0 mtu 1420
\tinet 10.74.109.115 netmask 0xffffffff
\tgroups: wg wireguard
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
gif0: flags=1008051<UP,POINTOPOINT,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 1280
\ttunnel inet 73.180.73.118 --> 216.66.22.2
\tinet6 2001:470:1f06::2 --> 2001:470:1f06::1 prefixlen 128
"""

CONFIG = {
    "lan": {"if": "ix0", "descr": "LAN", "enable": "1"},
    "opt1": {"if": "igb0", "descr": "", "enable": ""},
    "opt9": {"if": "wg0", "descr": "MULLVAD", "enable": "1"},
    "lo0": {"if": "lo0", "descr": "Loopback", "enable": "1", "virtual": "1"},
    "opt2": {"if": "igb7", "descr": "Gone", "enable": "1"},
    "opt3": {"if": "gif0", "descr": "HE_TUNNEL", "enable": "1"},
}

HARNESS = r"""
require getenv('SCRIPT');
$input = json_decode(file_get_contents('php://stdin'), true);
$details = dashboardplus_ifconfig_details(explode("\n", $input['ifconfig']));
// OPNsense's primary address functions, stood in for: the first IPv4 address without a CARP vhid,
// the first IPv6 one that is neither link-local nor deprecated (the real ones read the same keys)
$primary = function ($family) use ($input, $details) {
    return function ($identifier) use ($family, $input, $details) {
        foreach ($details[$input['config'][$identifier]['if']][$family] ?? [] as $address) {
            if (empty($address['vhid']) && empty($address['link-local']) && empty($address['deprecated'])) {
                return [$address['ipaddr'], null, $address['subnetbits'], null];
            }
        }
        return [null, null, null, null];
    };
};
echo json_encode(['details' => $details,
                  'rows' => dashboardplus_interface_rows($input['config'], $details, $primary('ipv4'), $primary('ipv6'))]);
"""


def run(ifconfig, config):
    result = subprocess.run(["php", "-r", HARNESS], input=json.dumps({"ifconfig": ifconfig, "config": config}),
                            capture_output=True, text=True, check=True, env=dict(os.environ, SCRIPT=str(SCRIPT)))
    return json.loads(result.stdout)


@unittest.skipUnless(shutil.which("php"), "needs the PHP command line")
class InterfacesTest(unittest.TestCase):
    def test_details_carry_what_the_primary_address_functions_read(self):
        details = run(IFCONFIG, CONFIG)["details"]
        self.assertEqual(sorted(details), ["gif0", "igb0", "ix0", "lo0", "wg0"])
        ix0 = details["ix0"]
        self.assertIn("up", ix0["flags"])
        self.assertEqual(ix0["media"], "10Gbase-SR <full-duplex,rxpause,txpause>")
        self.assertEqual(ix0["status"], "active")
        self.assertEqual([(a["ipaddr"], a["subnetbits"], a.get("vhid")) for a in ix0["ipv4"]],
                         [("192.168.1.248", 24, None), ("192.168.1.1", 24, "1")])
        # link-local last, the rest in kernel order; flags and lifetimes as legacy_interfaces_details
        self.assertEqual([a["ipaddr"] for a in ix0["ipv6"]],
                         ["2601:740:8500:5e78::1", "2601:740:8500:5e78::99", "fe80::92e2:baff:fe00:1"])
        self.assertEqual((ix0["ipv6"][0]["pltime"], ix0["ipv6"][0]["vltime"], ix0["ipv6"][0]["deprecated"]),
                         ("3600", "7200", False))
        self.assertTrue(ix0["ipv6"][1]["deprecated"] and ix0["ipv6"][1]["autoconf"])
        self.assertTrue(ix0["ipv6"][2]["link-local"])
        tunnel = details["gif0"]["ipv6"][0]
        self.assertEqual((tunnel["tunnel"], tunnel["endpoint"], tunnel["subnetbits"]), (True, "2001:470:1f06::1", 128))
        self.assertEqual(details["wg0"]["ipv4"][0]["subnetbits"], 32)

    def test_one_row_per_assigned_interface_present(self):
        rows = {row["identifier"]: row for row in run(IFCONFIG, CONFIG)["rows"]}
        # in configuration order; an assigned device that is not on the system is left out
        self.assertEqual(list(rows), ["lan", "opt1", "opt9", "lo0", "opt3"])
        self.assertEqual(rows["lan"], {
            "identifier": "lan", "description": "LAN", "device": "ix0", "enabled": True, "virtual": False,
            "status": "up", "media": "10Gbase-SR <full-duplex,rxpause,txpause>", "macaddr": "90:e2:ba:00:00:01",
            "addr4": "192.168.1.248/24", "addr6": "2601:740:8500:5e78::1/64"})
        # down, the current ifconfig status, the identifier when there is no description
        self.assertEqual((rows["opt1"]["status"], rows["opt1"]["description"], rows["opt1"]["enabled"]),
                         ("no carrier", "OPT1", False))
        self.assertEqual((rows["opt9"]["media"], rows["opt9"]["macaddr"], rows["opt9"]["addr4"], rows["opt9"]["addr6"]),
                         ("", "", "10.74.109.115/32", ""))
        self.assertEqual(rows["opt1"]["macaddr"], "00:1b:21:00:00:02")
        self.assertTrue(rows["lo0"]["virtual"])
        self.assertEqual(rows["opt3"]["addr6"], "2001:470:1f06::2/128")

    def test_nothing_to_parse(self):
        self.assertEqual(run("", CONFIG), {"details": [], "rows": []})
        self.assertEqual(run(IFCONFIG, {})["rows"], [])

    def test_the_action_reads_ifconfig_without_v(self):
        # -v reads every SFP module over I2C (about 200 ms of CPU each); nothing shown needs it
        source = SCRIPT.read_text()
        self.assertIn("exec('/sbin/ifconfig -L 2> /dev/null'", source)
        self.assertNotIn("-Lmv", source.replace("`ifconfig -Lmv`", ""))
        actions = (SCRIPT.parents[3] / "service/conf/actions.d/actions_dashboardplus.conf").read_text()
        self.assertIn("[system.interfaces]\ncommand:/usr/local/opnsense/scripts/OPNsense/DashboardPlus/interfaces.php",
                      actions)
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
