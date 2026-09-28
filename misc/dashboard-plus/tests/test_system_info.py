"""Unit tests for Dashboard Plus hardware parsing."""

import importlib.util
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
dev.qat_ocf.0.%parent: qat0
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


if __name__ == "__main__":
    unittest.main()
