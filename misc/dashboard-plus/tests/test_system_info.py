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

"""Unit tests for Dashboard Plus hardware parsing."""

import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/DashboardPlus/system_info.py"
SPEC = importlib.util.spec_from_file_location("dashboard_plus_system_info", SCRIPT)
SYSTEM_INFO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYSTEM_INFO)


class SystemInfoTest(unittest.TestCase):
    def test_parse_dmi_and_filter_placeholders(self):
        output = """Handle 0x0001, DMI type 1, 27 bytes
System Information
        Manufacturer: Example Corp
        Product Name: Edge 1000
        Version: Default string
        Serial Number: ABC123
"""
        record = SYSTEM_INFO.parse_dmi_records(output)[0]
        self.assertEqual(record["Manufacturer"], "Example Corp")
        self.assertEqual(record["Product Name"], "Edge 1000")
        self.assertEqual(record["Version"], "")
        self.assertEqual(record["Serial Number"], "ABC123")

    def test_active_integrated_qat(self):
        pciconf = """qat0@pci0:0:4:0: class=0x0b4000 card=0x00000000 chip=0x19e28086 rev=0x11 hdr=0x00
    vendor     = 'Intel Corporation'
    device     = 'C3xxx QuickAssist Technology'
"""
        sysctls = """dev.qat.0.state: up
dev.qat.0.cfg_services: sym;asym
dev.qat.0.dev_cfg: [GENERAL]
Device_Capabilities_Mask = 0x0001020f
dev.qat_ocf.0.%parent: nexus0
dev.qat_ocf.0.enable: 1
"""
        result = SYSTEM_INFO.collect_qat(pciconf, sysctls, "")["devices"][0]
        self.assertEqual(result["integration"], "Integrated")
        self.assertTrue(result["ocf_active"])
        self.assertIn("symmetric cryptography", result["capabilities"])
        self.assertIn("SHA-3", result["capabilities"])
        self.assertIn("AES-GCM single-pass", result["capabilities"])
        self.assertIn("AES-GCM", result["algorithms"])

    def test_dmi_slot_marks_qat_as_discrete(self):
        pciconf = """qat0@pci0:59:0:0: class=0x0b4000 card=0x00000000 chip=0x49408086 rev=0x01 hdr=0x00
    vendor     = 'Intel Corporation'
    device     = 'QuickAssist Technology'
"""
        slots = """Handle 0x0020, DMI type 9, 17 bytes
System Slot Information
        Designation: PCIe Slot 2
        Bus Address: 0000:3b:00.0
"""
        result = SYSTEM_INFO.collect_qat(pciconf, "", slots)["devices"][0]
        self.assertEqual(result["integration"], "Discrete (PCIe Slot 2)")
        self.assertFalse(result["ocf_active"])
        self.assertEqual(result["algorithms"], [])

    def test_current_pciconf_format_and_nexus_qat_ocf_are_detected(self):
        pciconf = """qat0@pci0:8:0:0: class=0x0b4000 rev=0x00 hdr=0x00 vendor=0x8086 device=0x0435
    vendor     = 'Intel Corporation'
    device     = 'DH895XCC Series QAT'
"""
        sysctls = """dev.qat.0.state: up
dev.qat.0.cfg_services: sym;dc
dev.qat_ocf.0.%parent: nexus0
dev.qat_ocf.0.enable: 1
"""
        result = SYSTEM_INFO.collect_qat(pciconf, sysctls, "")["devices"][0]
        self.assertEqual(result["model"], "Intel QAT DH895XCC")
        self.assertEqual(result["integration"], "Discrete")
        self.assertTrue(result["ocf_active"])
        self.assertIn("AES-GCM", result["algorithms"])

    C62X_PCICONF = """qat0@pci0:8:0:0: class=0x0b4000 rev=0x04 hdr=0x00 vendor=0x8086 device=0x37c8
    vendor     = 'Intel Corporation'
    device     = 'C620 Series Chipset Family QAT'
qat1@pci0:9:0:0: class=0x0b4000 rev=0x04 hdr=0x00 vendor=0x8086 device=0x37c8
    vendor     = 'Intel Corporation'
    device     = 'C620 Series Chipset Family QAT'
qat2@pci0:10:0:0: class=0x0b4000 rev=0x04 hdr=0x00 vendor=0x8086 device=0x37c8
    vendor     = 'Intel Corporation'
    device     = 'C620 Series Chipset Family QAT'
"""

    @staticmethod
    def qat_sysctls(devices, ocf_enable="1"):
        lines = []
        for unit, (state, services) in enumerate(devices):
            lines += [
                f"dev.qat.{unit}.state: {state}",
                f"dev.qat.{unit}.cfg_services: {services}",
                f"dev.qat.{unit}.cfg_mode: ks",
            ]
        if ocf_enable is not None:
            lines += ["dev.qat_ocf.0.%desc: QAT engine", "dev.qat_ocf.0.%parent: nexus0", f"dev.qat_ocf.0.enable: {ocf_enable}"]
        return "\n".join(lines) + "\n"

    def collect_states(self, pciconf, sysctls):
        return [
            (device["ocf_active"], bool(device["algorithms"]))
            for device in SYSTEM_INFO.collect_qat(pciconf, sysctls, "")["devices"]
        ]

    def test_one_qat_ocf_provider_serves_every_started_c62x_device(self):
        sysctls = self.qat_sysctls([("up", "sym;dc")] * 3)
        self.assertEqual(self.collect_states(self.C62X_PCICONF, sysctls), [(True, True)] * 3)

    def test_single_qat_device_with_qat_ocf_is_active(self):
        pciconf = "\n".join(self.C62X_PCICONF.splitlines()[:3]) + "\n"
        sysctls = self.qat_sysctls([("up", "sym;dc")])
        self.assertEqual(self.collect_states(pciconf, sysctls), [(True, True)])

    def test_disabled_or_missing_qat_ocf_leaves_qat_inactive(self):
        for ocf_enable in ("0", None):
            sysctls = self.qat_sysctls([("up", "sym;dc")] * 3, ocf_enable)
            devices = SYSTEM_INFO.collect_qat(self.C62X_PCICONF, sysctls, "")["devices"]
            self.assertEqual([device["state"] for device in devices], ["up"] * 3)
            self.assertEqual(self.collect_states(self.C62X_PCICONF, sysctls), [(False, False)] * 3)

    def test_a_down_qat_device_does_not_take_part(self):
        sysctls = self.qat_sysctls([("up", "sym;dc"), ("down", "sym;dc"), ("up", "sym;dc")])
        self.assertEqual(
            self.collect_states(self.C62X_PCICONF, sysctls),
            [(True, True), (False, False), (True, True)],
        )

    def test_devices_without_kernel_symmetric_instances_do_not_take_part(self):
        sysctls = self.qat_sysctls([("up", "dc"), ("up", "asym"), ("up", "cy;dc")])
        self.assertEqual(
            self.collect_states(self.C62X_PCICONF, sysctls),
            [(False, False), (False, False), (True, True)],
        )
        user_only = sysctls.replace("dev.qat.2.cfg_mode: ks", "dev.qat.2.cfg_mode: us")
        self.assertEqual(self.collect_states(self.C62X_PCICONF, user_only)[2], (False, False))
        both_modes = sysctls.replace("dev.qat.2.cfg_mode: ks", "dev.qat.2.cfg_mode: ks;us")
        self.assertEqual(self.collect_states(self.C62X_PCICONF, both_modes)[2], (True, True))

    def test_qat_virtual_function_takes_part_like_a_physical_device(self):
        pciconf = """qat0@pci0:3:0:1: class=0x0b4000 rev=0x00 hdr=0x00 vendor=0x8086 device=0x4941
    vendor     = 'Intel Corporation'
    device     = '4xxx Series QAT VF'
"""
        sysctls = self.qat_sysctls([("up", "sym;asym")])
        device = SYSTEM_INFO.collect_qat(pciconf, sysctls, "")["devices"][0]
        self.assertEqual(device["integration"], "Virtual function")
        self.assertTrue(device["ocf_active"])
        self.assertIn("AES-GCM", device["algorithms"])

    def test_unclaimed_qat_does_not_claim_acceleration(self):
        pciconf = """none3@pci0:1:0:0: class=0x0b4000 card=0x00000000 chip=0x37c88086 rev=0x04 hdr=0x00
    vendor     = 'Intel Corporation'
    device     = 'C62x QuickAssist Technology'
"""
        result = SYSTEM_INFO.collect_qat(pciconf, "", "")["devices"][0]
        self.assertEqual(result["state"], "unclaimed")
        self.assertFalse(result["ocf_active"])
        self.assertEqual(result["algorithms"], [])

    def test_cpu_algorithms_require_an_attached_aesni_driver(self):
        dmesg = "[1] aesni0: <AES-CBC,AES-CCM,AES-GCM,AES-ICM,AES-XTS,SHA1,SHA256> on motherboard\n"
        algorithms = SYSTEM_INFO.collect_cpu_crypto(dmesg)
        self.assertEqual(algorithms[:5], ["AES-CBC", "AES-CCM", "AES-GCM", "AES-ICM", "AES-XTS"])
        self.assertEqual(SYSTEM_INFO.collect_cpu_crypto(""), [])

    def test_dmesg_feature_fallback_detects_cpu_crypto_capabilities(self):
        dmesg = "Features2=0x1<PCLMULQDQ,AESNI,RDRAND>\n"
        tokens = set(__import__("re").findall(r"[A-Z0-9_]+", dmesg.upper()))
        self.assertTrue({"AESNI", "PCLMULQDQ", "RDRAND"}.issubset(tokens))

    def test_efi_runtime_overrides_an_inconsistent_kernel_boot_label(self):
        self.assertEqual(SYSTEM_INFO.boot_method("BIOS", True, ""), "UEFI")
        self.assertEqual(SYSTEM_INFO.boot_method("BIOS", False, ""), "BIOS")
        self.assertEqual(SYSTEM_INFO.boot_method("", False, ""), "")

    def test_parse_zfs_boot_environment(self):
        environments = SYSTEM_INFO.collect_boot_environments("default\tNR\t/\t1.64G\t2026-09-20 10:21\n")
        self.assertEqual(environments, {"current": "default", "next": "default"})

    def test_cpu_package_count_falls_back_to_the_smp_boot_record(self):
        self.assertEqual(SYSTEM_INFO.cpu_package_count("", "FreeBSD/SMP: 1 package(s) x 4 core(s)\n"), 1)

    def test_cpu_frequency_uses_the_highest_available_level_as_maximum(self):
        self.assertEqual(
            SYSTEM_INFO.cpu_frequency("1600", "2200/35000 1600/25000 800/12000"),
            {"current_mhz": 1600, "maximum_mhz": 2200},
        )

    def test_active_hardware_algorithms_are_de_duplicated(self):
        providers = SYSTEM_INFO.collect_crypto_hardware(
            True,
            ["AES-CBC", "AES-GCM"],
            [{"model": "Intel QAT C3xxx", "ocf_active": True, "algorithms": ["AES-GCM", "AES-XTS"]}],
        )
        self.assertEqual(providers[0]["feature"], "AES-NI")
        self.assertEqual(providers[0]["state"], "available")
        self.assertEqual(providers[1]["provider"], "Intel QAT C3xxx")
        self.assertEqual(
            SYSTEM_INFO.collect_accelerated_algorithms(providers),
            ["AES-GCM", "AES-XTS"],
        )

    def test_ipsec_status_reports_active_hardware_not_packet_offload(self):
        self.assertEqual(SYSTEM_INFO.collect_ipsec_status([]), "unavailable")
        self.assertEqual(SYSTEM_INFO.collect_ipsec_status([{"active": True}]), "active")

    def test_mitigation_state_returns_codes_for_the_ui_to_translate(self):
        self.assertEqual(SYSTEM_INFO.mitigation_state("1"), "enabled")
        self.assertEqual(SYSTEM_INFO.mitigation_state("0"), "disabled")
        self.assertEqual(SYSTEM_INFO.mitigation_state("VERW"), "VERW")
        self.assertEqual(SYSTEM_INFO.mitigation_state(""), "")

    def test_qat_endpoints_of_one_model_and_state_are_one_row(self):
        sysctls = self.qat_sysctls([("up", "sym;dc")] * 3)
        devices = SYSTEM_INFO.collect_qat(self.C62X_PCICONF, sysctls, "")["devices"]
        providers = SYSTEM_INFO.collect_crypto_hardware(False, [], devices)
        self.assertEqual(
            [(provider["provider"], provider["state"], provider["count"]) for provider in providers],
            [("Intel QAT C62x", "active", 3)],
        )
        self.assertIn("AES-GCM", SYSTEM_INFO.collect_accelerated_algorithms(providers))
        self.assertEqual(SYSTEM_INFO.collect_ipsec_status(providers), "active")

    def test_qat_endpoints_in_different_states_keep_separate_rows(self):
        sysctls = self.qat_sysctls([("up", "sym;dc"), ("down", "sym;dc"), ("up", "sym;dc")])
        devices = SYSTEM_INFO.collect_qat(self.C62X_PCICONF, sysctls, "")["devices"]
        providers = SYSTEM_INFO.collect_crypto_hardware(True, ["AES-GCM"], devices)
        self.assertEqual(
            [(provider["feature"], provider["state"], provider.get("count")) for provider in providers],
            [("AES-NI", "available", None), ("QuickAssist", "active", 2), ("QuickAssist", "inactive", 1)],
        )

    RESOLV_LOCAL = """# This file was automatically generated by system_resolvconf_generate()
domain example.org
nameserver 127.0.0.1
search example.org
"""
    SOCKSTAT_UNBOUND = """USER    COMMAND      PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
unbound unbound    46635  5 udp6  *:53                  *:*
unbound unbound    46635  7 udp4  *:53                  *:*
"""

    def test_parse_resolv_nameservers(self):
        text = "nameserver 127.0.0.1\n# nameserver 10.0.0.1\nnameserver 1.1.1.1 # upstream\nsearch x\n"
        self.assertEqual(SYSTEM_INFO.parse_resolv_nameservers(text), ["127.0.0.1", "1.1.1.1"])

    def test_unbound_recursive_ignores_domain_forward_zones(self):
        unbound = """server:
  do-ip4: yes
forward-zone:
  name: "bh.example.org"
  forward-addr: 192.168.90.250@53
"""
        dns = SYSTEM_INFO.collect_dns(self.RESOLV_LOCAL, self.SOCKSTAT_UNBOUND, unbound)
        self.assertEqual(
            (dns["resolver"], dns["running"], dns["mode"], dns["forwarders"], dns["servers"]),
            ("Unbound", True, "recursive", [], []),
        )

    def test_unbound_forwarding_over_tls(self):
        unbound = """forward-zone:
  name: "."
  forward-tls-upstream: yes
  forward-addr: 1.1.1.1@853#cloudflare-dns.com
  forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com
  forward-addr: 1.1.1.1@853
"""
        resolv = self.RESOLV_LOCAL + "nameserver 9.9.9.9\n"
        dns = SYSTEM_INFO.collect_dns(resolv, self.SOCKSTAT_UNBOUND, unbound)
        self.assertEqual(dns["mode"], "forwarding")
        self.assertEqual(dns["forwarders"], ["1.1.1.1", "2606:4700:4700::1111"])
        self.assertTrue(dns["tls"])
        self.assertEqual(dns["servers"], ["9.9.9.9"])

    def test_other_local_resolvers_and_stopped_resolver(self):
        dnsmasq = "root dnsmasq 1234 4 udp4 *:53 *:*\n"
        self.assertEqual(SYSTEM_INFO.collect_dns(self.RESOLV_LOCAL, dnsmasq, "")["resolver"], "Dnsmasq")
        named = "bind named 1234 4 udp4 127.0.0.1:53 *:*\n"
        self.assertEqual(SYSTEM_INFO.collect_dns(self.RESOLV_LOCAL, named, "")["resolver"], "BIND")
        stopped = SYSTEM_INFO.collect_dns(self.RESOLV_LOCAL, "", "")
        self.assertEqual((stopped["resolver"], stopped["running"]), ("local", False))

    def test_upstream_servers_or_nothing_set(self):
        dns = SYSTEM_INFO.collect_dns("nameserver 1.1.1.1\nnameserver 9.9.9.9\n", "", "")
        self.assertEqual((dns["resolver"], dns["servers"]), ("", ["1.1.1.1", "9.9.9.9"]))
        empty = SYSTEM_INFO.collect_dns("search example.org\n", "", "")
        self.assertEqual((empty["resolver"], empty["servers"]), ("", []))

    def test_dns_display_lines(self):
        recursive = SYSTEM_INFO.collect_dns(self.RESOLV_LOCAL, self.SOCKSTAT_UNBOUND, "")
        self.assertEqual(SYSTEM_INFO.dns_display_lines(recursive), ["Unbound (local, recursive)"])
        unbound = 'forward-zone:\n  name: "."\n  forward-addr: 1.1.1.1\n  forward-addr: 9.9.9.9\n'
        forwarding = SYSTEM_INFO.collect_dns(self.RESOLV_LOCAL, self.SOCKSTAT_UNBOUND, unbound)
        self.assertEqual(
            SYSTEM_INFO.dns_display_lines(forwarding), ["Unbound (local), forwarding to 1.1.1.1, 9.9.9.9"]
        )
        upstream = SYSTEM_INFO.collect_dns("nameserver 1.1.1.1\n", "", "")
        self.assertEqual(SYSTEM_INFO.dns_display_lines(upstream), ["1.1.1.1"])
        self.assertEqual(SYSTEM_INFO.dns_display_lines(SYSTEM_INFO.collect_dns("", "", "")), [])


if __name__ == "__main__":
    unittest.main()


def zpool(pools):
    return json.dumps({"output_version": {"command": "zpool status", "vers_major": 0, "vers_minor": 1},
                       "pools": pools})


def disk(name, errors=(0, 0, 0), kind="disk", **extra):
    return {"name": name, "vdev_type": kind, "class": "normal", "state": "ONLINE", "read_errors": errors[0],
            "write_errors": errors[1], "checksum_errors": errors[2], **extra}


def pool(name, children, state="ONLINE", error_count=0, scan=None, size=1000, allocated=487):
    root = {"name": name, "vdev_type": "root", "state": state, "total_space": size, "alloc_space": allocated,
            "read_errors": 0, "write_errors": 0, "checksum_errors": 0,
            "vdevs": {child["name"]: child for child in children}}
    result = {"name": name, "state": state, "vdevs": {name: root}, "error_count": error_count}
    if scan is not None:
        result["scan_stats"] = scan
    return result


class ZfsTest(unittest.TestCase):
    """zpool status -j --json-int (OpenZFS 2.3 and later) for the ZFS section of System Information+."""

    def test_a_single_disk_pool_never_scrubbed_as_on_firewall2(self):
        output = ('{"output_version":{"command":"zpool status","vers_major":0,"vers_minor":1},"pools":{"zroot":'
                  '{"name":"zroot","state":"ONLINE","pool_guid":15055133742887778497,"txg":19784,"spa_version":5000,'
                  '"zpl_version":5,"vdevs":{"zroot":{"name":"zroot","vdev_type":"root","guid":15055133742887778497,'
                  '"class":"normal","state":"ONLINE","alloc_space":1960869888,"total_space":229780750336,'
                  '"def_space":229780750336,"read_errors":0,"write_errors":0,"checksum_errors":0,"vdevs":{"ada0p4":'
                  '{"name":"ada0p4","vdev_type":"disk","guid":4002880333967051339,"path":"/dev/ada0p4","class":"normal",'
                  '"state":"ONLINE","alloc_space":1960869888,"total_space":229780750336,"read_errors":0,'
                  '"write_errors":0,"checksum_errors":0,"slow_ios":0}}}},"error_count":0}}}')
        self.assertEqual(SYSTEM_INFO.parse_zpool_status(output), [{
            "name": "zroot", "state": "ONLINE", "layout": "single", "device_errors": 0, "data_errors": 0,
            "size": 229780750336, "allocated": 1960869888, "capacity": 0, "scan": None,
        }])

    def test_layouts(self):
        layouts = {
            "mirror": [{**disk("mirror-0", kind="mirror"), "vdevs": {"a": disk("a"), "b": disk("b")}}],
            "raidz2": [{**disk("raidz2-0", kind="raidz"), "vdevs": {"a": disk("a")}},
                       {**disk("log0"), "class": "log"}, {**disk("special0", kind="mirror"), "class": "special"}],
            "stripe": [disk("ada0"), disk("ada1")],
            "mixed": [{**disk("mirror-0", kind="mirror")}, {**disk("raidz1-1", kind="raidz")}],
            "draid": [{**disk("draid2:4d:1c:0s-0", kind="draid")}],
        }
        pools = {name: pool(name, children) for name, children in layouts.items()}
        parsed = {item["name"]: item["layout"] for item in SYSTEM_INFO.parse_zpool_status(zpool(pools))}
        self.assertEqual(parsed, {name: name for name in layouts})

    def test_errors_capacity_and_the_last_scrub(self):
        scan = {"function": "SCRUB", "state": "FINISHED", "start_time": 1759633200, "end_time": 1759633212,
                "to_examine": 4000, "examined": 4000, "issued": 4000, "processed": 1536, "errors": 0}
        mirror = {**disk("mirror-0", kind="mirror", errors=(1, 0, 0)),
                  "vdevs": {"a": disk("a", errors=(0, 0, 3)), "b": disk("b")}}
        parsed = SYSTEM_INFO.parse_zpool_status(zpool({"tank": pool("tank", [mirror], state="DEGRADED",
                                                                          error_count=2, scan=scan)}))[0]
        self.assertEqual((parsed["state"], parsed["device_errors"], parsed["data_errors"], parsed["capacity"]),
                         ("DEGRADED", 4, 2, 48))
        self.assertEqual(parsed["scan"], {"function": "scrub", "state": "finished", "start": 1759633200,
                                          "end": 1759633212, "errors": 0, "repaired": 1536, "progress": 100})

    def test_a_scan_under_way_and_none_at_all(self):
        running = {"function": "RESILVER", "state": "SCANNING", "start_time": 1759633200, "end_time": 0,
                   "to_examine": 1000, "issued": 420, "processed": 0, "errors": 0}
        pools = {"a": pool("a", [disk("ada0")], scan=running),
                 "b": pool("b", [disk("ada1")], scan={"function": "NONE", "state": "NONE"})}
        parsed = {item["name"]: item["scan"] for item in SYSTEM_INFO.parse_zpool_status(zpool(pools))}
        self.assertEqual((parsed["a"]["function"], parsed["a"]["state"], parsed["a"]["progress"]),
                         ("resilver", "scanning", 42))
        self.assertIsNone(parsed["b"])

    def test_no_pools_or_no_json(self):
        self.assertEqual(SYSTEM_INFO.parse_zpool_status(zpool({})), [])
        for output in ("", "no pools available", "[]", "null", '{"pools": []}'):
            with self.subTest(output=output):
                self.assertEqual(SYSTEM_INFO.parse_zpool_status(output), [])
