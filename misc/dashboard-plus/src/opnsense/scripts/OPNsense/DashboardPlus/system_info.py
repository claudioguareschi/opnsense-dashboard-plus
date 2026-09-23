#!/usr/local/bin/python3

"""Collect static system information for the Dashboard Plus widget."""

import json
import re
import subprocess


DMIDECODE = "/usr/local/sbin/dmidecode"
PCICONF = "/usr/sbin/pciconf"
SYSCTL = "/sbin/sysctl"
DMESG = "/sbin/dmesg"

QAT_DEVICES = {
    0x0435: ("Intel QAT DH895XCC", "discrete", False),
    0x0443: ("Intel QAT DH895XCC VF", "virtual function", True),
    0x37C8: ("Intel QAT C62x", "integrated", False),
    0x37C9: ("Intel QAT C62x VF", "virtual function", True),
    0x19E2: ("Intel QAT C3xxx", "integrated", False),
    0x19E3: ("Intel QAT C3xxx VF", "virtual function", True),
    0x18EE: ("Intel QAT 200xx", "integrated", False),
    0x18EF: ("Intel QAT 200xx VF", "virtual function", True),
    0x6F54: ("Intel QAT D15xx", "integrated", False),
    0x6F55: ("Intel QAT D15xx VF", "virtual function", True),
    0x18A0: ("Intel QAT C4xxx", "integrated", False),
    0x18A1: ("Intel QAT C4xxx VF", "virtual function", True),
    0x4940: ("Intel QAT 4xxx", "unknown", False),
    0x4941: ("Intel QAT 4xxx VF", "virtual function", True),
    0x4942: ("Intel QAT 401xx", "unknown", False),
    0x4943: ("Intel QAT 401xx VF", "virtual function", True),
    0x4944: ("Intel QAT 402xx", "unknown", False),
    0x4945: ("Intel QAT 402xx VF", "virtual function", True),
}

CPU_CRYPTO_FEATURES = (
    "AESNI",
    "VAES",
    "PCLMULQDQ",
    "VPCLMULQDQ",
    "SHA",
    "RDRAND",
    "RDSEED",
)

QAT_OCF_ALGORITHMS = (
    "AES-CBC",
    "AES-CTR",
    "AES-XTS",
    "AES-GCM",
    "AES-GMAC",
    "SHA-1",
    "SHA-2 256/384/512",
    "HMAC-SHA-1",
    "HMAC-SHA-2 256/384/512",
)

QAT_CAPABILITY_BITS = (
    (0, "symmetric cryptography"),
    (1, "asymmetric cryptography"),
    (2, "cipher"),
    (3, "authentication"),
    (5, "compression"),
    (7, "random number generation"),
    (8, "ZUC"),
    (9, "SHA-3"),
    (10, "key protection"),
    (12, "HKDF"),
    (13, "Edwards/Montgomery curves"),
    (15, "extended SHA-3"),
    (16, "AES-GCM single-pass"),
    (17, "ChaCha20-Poly1305"),
    (18, "SM2"),
    (19, "SM3"),
    (20, "SM4"),
    (21, "inline processing"),
    (22, "compression integrity"),
    (23, "64-bit compression integrity"),
    (24, "LZ4 compression"),
    (25, "LZ4S compression"),
    (26, "AES v2"),
)

PLACEHOLDER_VALUES = {
    "",
    "default string",
    "not specified",
    "system product name",
    "to be filled by o.e.m.",
    "unknown",
}


def run(command):
    """Run a fixed command without invoking a shell."""
    try:
        result = subprocess.run(command, capture_output=True, check=False, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def clean(value):
    """Remove DMI placeholders while preserving legitimate values."""
    value = value.strip() if value else ""
    return "" if value.lower() in PLACEHOLDER_VALUES else value


def parse_dmi_records(output):
    """Parse dmidecode records into dictionaries."""
    records = []
    current = {}
    for line in output.splitlines():
        if line.startswith("Handle "):
            if current:
                records.append(current)
            current = {}
            continue
        match = re.match(r"^\s*([^:]+):\s*(.*)$", line)
        if match:
            current[match.group(1).strip()] = clean(match.group(2))
    if current:
        records.append(current)
    return records


def sysctl_value(name):
    return run([SYSCTL, "-n", name])


def int_value(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def pci_tuple(address, dmi=False):
    """Normalize pciconf and DMI bus addresses for comparison."""
    if dmi:
        match = re.fullmatch(r"([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)\.([0-9a-fA-F]+)", address)
        base = 16
    else:
        match = re.fullmatch(r"pci(\d+):(\d+):(\d+):(\d+)", address)
        base = 10
    if not match:
        return None
    return tuple(int(part, base) for part in match.groups())


def parse_slots(output):
    slots = {}
    for record in parse_dmi_records(output):
        address = pci_tuple(record.get("Bus Address", ""), dmi=True)
        if address:
            slots[address] = record.get("Designation") or "system slot"
    return slots


def parse_sysctls(output):
    values = {}
    for line in output.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            values[key] = value.strip()
    return values


def parse_pciconf(output):
    devices = []
    current = None
    header = re.compile(r"^(?P<driver>[^@\s]+)@(?P<address>pci\d+:\d+:\d+:\d+):(?P<details>.*)$")
    for line in output.splitlines():
        match = header.match(line)
        if match:
            if current:
                devices.append(current)
            details = match.group("details")
            chip_match = re.search(r"\bchip=0x([0-9a-fA-F]{8})", details)
            vendor_match = re.search(r"\bvendor=0x([0-9a-fA-F]{4})", details)
            device_match = re.search(r"\bdevice=0x([0-9a-fA-F]{4})", details)
            if chip_match:
                chip = int(chip_match.group(1), 16)
                vendor_id = chip & 0xFFFF
                device_id = chip >> 16
            elif vendor_match and device_match:
                vendor_id = int(vendor_match.group(1), 16)
                device_id = int(device_match.group(1), 16)
            else:
                current = None
                continue
            current = {
                "driver": match.group("driver"),
                "pci_address": match.group("address"),
                "vendor_id": vendor_id,
                "device_id": device_id,
            }
            continue
        if current:
            detail = re.match(r"^\s*(vendor|device)\s*=\s*'([^']*)'", line)
            if detail:
                current[detail.group(1)] = detail.group(2)
    if current:
        devices.append(current)
    return devices


def qat_capabilities(services):
    service_set = set(filter(None, re.split(r"[;,]", services.lower())))
    if "cy" in service_set:
        service_set.update(("sym", "asym"))
    labels = []
    for key, label in (
        ("sym", "symmetric cryptography"),
        ("asym", "asymmetric cryptography"),
        ("dc", "compression"),
    ):
        if key in service_set:
            labels.append(label)
    return labels, service_set


def qat_hardware_capabilities(sysctl_output, unit):
    """Decode the running driver's fuse-adjusted QAT capability mask."""
    pattern = rf"^dev\.qat\.{unit}\.dev_cfg:\s*(.*?)(?=^[^\s=][^=\n]*:\s|\Z)"
    match = re.search(pattern, sysctl_output, re.MULTILINE | re.DOTALL)
    if not match:
        return []
    mask_match = re.search(r"^Device_Capabilities_Mask\s*=\s*(0x[0-9a-fA-F]+|\d+)", match.group(1), re.MULTILINE)
    if not mask_match:
        return []
    mask = int(mask_match.group(1), 0)
    return [label for bit, label in QAT_CAPABILITY_BITS if mask & (1 << bit)]


def collect_qat(pciconf_output, sysctl_output, slot_output):
    sysctls = parse_sysctls(sysctl_output)
    slots = parse_slots(slot_output)
    result = []

    ocf_by_parent = {}
    ocf_by_unit = {}
    for key, parent in sysctls.items():
        match = re.fullmatch(r"dev\.qat_ocf\.(\d+)\.%parent", key)
        if match:
            unit = match.group(1)
            enabled = sysctls.get(f"dev.qat_ocf.{unit}.enable") == "1"
            ocf_by_parent[parent] = enabled
            ocf_by_unit[unit] = enabled

    for device in parse_pciconf(pciconf_output):
        description = device.get("device", "")
        known = QAT_DEVICES.get(device["device_id"])
        looks_like_qat = "quickassist" in description.lower() or re.search(r"\bqat\b", description.lower())
        if device["vendor_id"] != 0x8086 or (known is None and not looks_like_qat):
            continue

        model, integration, is_vf = known or (description or "Intel QuickAssist Technology", "unknown", False)
        address = pci_tuple(device["pci_address"])
        if address in slots and not is_vf:
            integration = f"discrete ({slots[address]})"

        driver = device["driver"]
        unit_match = re.fullmatch(r"qat(\d+)", driver)
        unit = None
        if unit_match:
            unit = unit_match.group(1)
            prefix = f"dev.qat.{unit}"
            state = sysctls.get(f"{prefix}.state", "attached")
            services = sysctls.get(f"{prefix}.cfg_services", "")
            hardware_capabilities = qat_hardware_capabilities(sysctl_output, unit)
        else:
            state = "unclaimed"
            services = ""
            hardware_capabilities = []

        service_capabilities, service_set = qat_capabilities(services)
        capabilities = hardware_capabilities or service_capabilities
        ocf_active = (
            (ocf_by_parent.get(driver, False) or ocf_by_unit.get(unit, False))
            and state.lower() in ("up", "started", "attached")
        )
        algorithms = list(QAT_OCF_ALGORITHMS) if ocf_active and service_set.intersection(("sym", "cy")) else []

        result.append({
            "integration": integration[:1].upper() + integration[1:],
            "model": model,
            "pci_address": device["pci_address"],
            "driver": driver,
            "state": state,
            "ocf_active": ocf_active,
            "capabilities": capabilities,
            "algorithms": algorithms,
        })

    return {"devices": result}


def collect_cpu_crypto(dmesg_output):
    """Return AES-NI modes only when the kernel driver actually attached.

    CPU instruction flags establish capability, but do not prove that the
    OpenCrypto provider was enabled.  The aesni driver's attach message lists
    the modes it registered, which is the least-invasive reliable signal
    available to a plugin without adding a new kernel API.
    """
    match = re.search(
        r"^(?:\[\d+\]\s*)?aesni\d+:\s*<([^>]+)>",
        dmesg_output,
        re.MULTILINE | re.IGNORECASE,
    )
    if not match:
        return []
    return [mode.strip() for mode in match.group(1).split(",") if mode.strip()]


def collect_accelerated_algorithms(cpu_algorithms, qat_devices):
    """Describe registered providers, never packet-offload activity."""
    providers = []
    if cpu_algorithms:
        providers.append({"provider": "CPU AES-NI", "algorithms": cpu_algorithms})
    for device in qat_devices:
        if device["algorithms"]:
            providers.append({
                "provider": f"{device['model']} ({device['pci_address']})",
                "algorithms": device["algorithms"],
            })
    return providers


def mitigation_state(value, enabled="Enabled", disabled="Disabled"):
    if value == "1":
        return enabled
    if value == "0":
        return disabled
    return value or "Unavailable"


def collect():
    system_records = parse_dmi_records(run([DMIDECODE, "-t", "system"]))
    bios_records = parse_dmi_records(run([DMIDECODE, "-t", "bios"]))
    slot_output = run([DMIDECODE, "-t", "slot"])
    system = system_records[0] if system_records else {}
    bios = bios_records[0] if bios_records else {}

    product = clean(system.get("Product Name"))
    product_version = clean(system.get("Version"))
    if product_version and product_version.lower() not in product.lower():
        product = f"{product} {product_version}".strip()

    dmesg_output = run([DMESG])
    feature_values = " ".join(
        sysctl_value(name)
        for name in (
            "machdep.cpu.features",
            "machdep.cpu.features2",
            "machdep.cpu.leaf7_features",
            "machdep.cpu.leaf7_extfeatures",
            "machdep.cpu.extfeatures",
        )
    ) + " " + dmesg_output
    feature_tokens = set(re.findall(r"[A-Z0-9_]+", feature_values.upper()))
    cpu_crypto = [feature for feature in CPU_CRYPTO_FEATURES if feature in feature_tokens]

    pti = mitigation_state(sysctl_value("vm.pmap.pti"))
    mds = sysctl_value("machdep.mitigations.mds.state") or sysctl_value("hw.mds_disable_state")

    accelerator = collect_qat(
        run([PCICONF, "-lv"]),
        run([SYSCTL, "-a"]),
        slot_output,
    )
    cpu_algorithms = collect_cpu_crypto(dmesg_output)

    return {
        "hardware": {
            "manufacturer": clean(system.get("Manufacturer")),
            "model": product,
            "serial": clean(system.get("Serial Number")),
        },
        "bios": {
            "vendor": clean(bios.get("Vendor")),
            "version": clean(bios.get("Version")),
            "date": clean(bios.get("Release Date")),
            "boot_method": sysctl_value("machdep.bootmethod") or "Unavailable",
        },
        "cpu": {
            "model": sysctl_value("hw.model") or "Unavailable",
            "cores": int_value(sysctl_value("kern.smp.cores")),
            "threads": int_value(sysctl_value("kern.smp.cpus") or sysctl_value("hw.ncpu")),
            "threads_per_core": int_value(sysctl_value("kern.smp.threads_per_core")),
            "crypto_capabilities": cpu_crypto,
        },
        "accelerator": accelerator,
        "accelerated_algorithms": collect_accelerated_algorithms(cpu_algorithms, accelerator["devices"]),
        "mitigations": {
            "pti": pti,
            "mds": mds or "Unavailable",
        },
    }


if __name__ == "__main__":
    print(json.dumps(collect(), sort_keys=True))
