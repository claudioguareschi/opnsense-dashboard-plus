#!/usr/local/bin/python3

"""Collect static system information for the Dashboard Plus widget."""

import glob
import json
import re
import subprocess
import sys


DMIDECODE = "/usr/local/sbin/dmidecode"
PCICONF = "/usr/sbin/pciconf"
SYSCTL = "/sbin/sysctl"
DMESG = "/sbin/dmesg"
MOUNT = "/sbin/mount"
BECTL = "/sbin/bectl"
SOCKSTAT = "/usr/bin/sockstat"
RESOLV_CONF = "/etc/resolv.conf"
UNBOUND_CONF = "/var/unbound/unbound.conf"
UNBOUND_INCLUDES = "/var/unbound/etc/*.conf"

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
    "none",
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


def cpu_frequency(current, levels):
    """Return the current and highest CPU frequencies reported by cpufreq."""
    available = [
        int(match.group(1))
        for match in re.finditer(r"(?:^|\s)(\d+)(?:/\d+)?", levels or "")
    ]
    return {
        "current_mhz": int_value(current),
        "maximum_mhz": max(available) if available else None,
    }


def collect_cpu_frequency():
    """Collect the small dynamic subset needed for a live widget refresh."""
    return cpu_frequency(
        sysctl_value("dev.cpu.0.freq") or sysctl_value("hw.clockrate"),
        sysctl_value("dev.cpu.0.freq_levels"),
    )


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

    # qat_ocf is one OpenCrypto provider attached to nexus0, not a per-device
    # child: when enabled it starts the interrupt-mode crypto instances of every
    # started qatN.  Its unit number says nothing about which qatN it uses.
    ocf_enabled = any(
        value == "1"
        for key, value in sysctls.items()
        if re.fullmatch(r"dev\.qat_ocf\.\d+\.enable", key)
    )

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
            mode = sysctls.get(f"{prefix}.cfg_mode", "")
            hardware_capabilities = qat_hardware_capabilities(sysctl_output, unit)
        else:
            state = "unclaimed"
            services = ""
            mode = ""
            hardware_capabilities = []

        service_capabilities, service_set = qat_capabilities(services)
        capabilities = hardware_capabilities or service_capabilities
        # A device feeds qat_ocf only when it is started ("up") and has
        # interrupt-mode kernel symmetric instances, which the driver creates
        # for the "sym" or "cy" service in kernel ("ks") mode.
        mode_set = set(filter(None, re.split(r"[;,]", mode.lower())))
        ocf_active = (
            ocf_enabled
            and state.lower() == "up"
            and "sym" in service_set
            and (not mode_set or "ks" in mode_set)
        )
        algorithms = list(QAT_OCF_ALGORITHMS) if ocf_active else []

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


def collect_crypto_hardware(cpu_has_aesni, cpu_algorithms, qat_devices):
    """Describe detected AES-NI and QuickAssist providers and their state."""
    providers = []
    qat_active = any(device["ocf_active"] for device in qat_devices)
    if cpu_has_aesni:
        providers.append({
            "feature": "AES-NI",
            "provider": "CPU",
            "active": bool(cpu_algorithms) and not qat_active,
            "state": "available" if cpu_algorithms and qat_active else "active" if cpu_algorithms else "inactive",
            "algorithms": cpu_algorithms,
        })
    # Several endpoints of one model (the three of a C62x, an adapter's devices, VFs) in
    # the same state are one row with a count; a device in another state keeps its own row.
    grouped = {}
    for device in qat_devices:
        state = "active" if device["ocf_active"] else "inactive"
        key = (device["model"], state)
        if key in grouped:
            grouped[key]["count"] += 1
            continue
        grouped[key] = {
            "feature": "QuickAssist",
            "provider": device["model"],
            "active": device["ocf_active"],
            "state": state,
            "algorithms": device["algorithms"],
            "count": 1,
        }
    providers.extend(grouped.values())
    return providers


def collect_accelerated_algorithms(providers):
    """Return the de-duplicated algorithms of active hardware providers only."""
    return sorted({
        algorithm
        for provider in providers
        if provider["active"]
        for algorithm in provider["algorithms"]
    })


def collect_ipsec_status(providers):
    """Report whether IPsec has an active hardware crypto provider (a state code the UI translates)."""
    return "active" if any(provider["active"] for provider in providers) else "unavailable"


def parse_resolv_nameservers(text):
    """Return the nameserver addresses of a resolv.conf in order."""
    servers = []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            servers.append(fields[1])
    return servers


def parse_dns_listeners(sockstat_output):
    """Return the commands listening on port 53, in order of appearance."""
    commands = []
    for line in sockstat_output.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[5].endswith(":53") and fields[1] not in commands:
            commands.append(fields[1])
    return commands


def parse_unbound_forwarders(text):
    """Return the forward-addr entries of Unbound's root forward zone and whether it uses TLS."""
    addresses = []
    tls = False
    zone = None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip().strip('"')
        if key in ("forward-zone", "server", "stub-zone", "remote-control", "auth-zone"):
            zone = "" if key == "forward-zone" else None
        elif zone is not None and key == "name":
            zone = value
        elif zone == "." and key == "forward-addr":
            address = value.split("#", 1)[0].split("@", 1)[0]
            if address and address not in addresses:
                addresses.append(address)
        elif zone == "." and key == "forward-tls-upstream":
            tls = value.lower() == "yes"
    return addresses, tls


DNS_RESOLVERS = {"unbound": "Unbound", "dnsmasq": "Dnsmasq", "named": "BIND"}


def collect_dns(resolv_conf, sockstat_output, unbound_conf):
    """Describe how the firewall itself resolves names: a local resolver or upstream servers."""
    nameservers = parse_resolv_nameservers(resolv_conf)
    local = [server for server in nameservers if server in ("127.0.0.1", "::1")]
    servers = [server for server in nameservers if server not in local]
    dns = {"resolver": "", "running": False, "mode": "", "forwarders": [], "tls": False, "servers": servers}
    if not local:
        return dns
    listeners = parse_dns_listeners(sockstat_output)
    command = listeners[0] if listeners else ""
    dns["resolver"] = DNS_RESOLVERS.get(command, command) or "local"
    dns["running"] = bool(command)
    if command == "unbound":
        forwarders, tls = parse_unbound_forwarders(unbound_conf)
        dns.update(mode="forwarding" if forwarders else "recursive", forwarders=forwarders, tls=tls)
    return dns


def read_text(*paths):
    """Concatenate the readable files among paths; missing files are skipped."""
    parts = []
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                parts.append(handle.read())
        except OSError:
            pass
    return "\n".join(parts)


def boot_method(kernel_method, efi_runtime, mount_output):
    """Prefer live EFI runtime evidence over an inconsistent kernel label; empty when unknown."""
    if efi_runtime or re.search(r"\b(?:efi|efiboot)\b", mount_output, re.IGNORECASE):
        return "UEFI"
    return kernel_method


def collect_boot_environments(output):
    """Collect the current and next ZFS boot environments when bectl is available."""
    environments = {"current": "", "next": ""}
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        name, state = fields[0], fields[1]
        if "N" in state:
            environments["current"] = name
        if "R" in state:
            environments["next"] = name
    return environments


def cpu_package_count(sysctl_packages, dmesg_output):
    """Use the FreeBSD SMP boot record when the package sysctl is absent."""
    packages = int_value(sysctl_packages)
    if packages is not None:
        return packages
    match = re.search(r"(\d+) package\(s\)", dmesg_output, re.IGNORECASE)
    return int(match.group(1)) if match else None


def mitigation_state(value):
    """Map a 0/1 sysctl to a state code the UI translates; other values pass through."""
    if value == "1":
        return "enabled"
    if value == "0":
        return "disabled"
    return value


def collect():
    system_records = parse_dmi_records(run([DMIDECODE, "-t", "system"]))
    bios_records = parse_dmi_records(run([DMIDECODE, "-t", "bios"]))
    slot_output = run([DMIDECODE, "-t", "slot"])
    system = system_records[0] if system_records else {}
    bios = bios_records[0] if bios_records else {}

    product = system.get("Product Name", "")
    product_version = system.get("Version", "")
    if product_version and product_version.lower() not in product.lower():
        product = f"{product} {product_version}".strip()

    dmesg_output = run([DMESG])
    # AES-NI capability; collect_cpu_crypto then checks that the driver attached.
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

    pti = mitigation_state(sysctl_value("vm.pmap.pti"))
    mds = sysctl_value("machdep.mitigations.mds.state") or sysctl_value("hw.mds_disable_state")
    kernel_boot_method = sysctl_value("machdep.bootmethod")
    boot_environments = collect_boot_environments(run([BECTL, "list", "-H"]))

    accelerator = collect_qat(
        run([PCICONF, "-lv"]),
        run([SYSCTL, "-a"]),
        slot_output,
    )
    cpu_algorithms = collect_cpu_crypto(dmesg_output)
    crypto_hardware = collect_crypto_hardware("AESNI" in feature_tokens, cpu_algorithms, accelerator["devices"])
    frequency = collect_cpu_frequency()

    return {
        "hardware": {
            "manufacturer": system.get("Manufacturer", ""),
            "model": product,
            "serial": system.get("Serial Number", ""),
        },
        "bios": {
            "vendor": bios.get("Vendor", ""),
            "version": bios.get("Version", ""),
            "date": bios.get("Release Date", ""),
            "boot_method": boot_method(
                kernel_boot_method,
                bool(sysctl_value("hw.efi.poweroff")),
                run([MOUNT]),
            ),
        },
        "boot_environment": boot_environments,
        "cpu": {
            "model": sysctl_value("hw.model"),
            "packages": cpu_package_count(sysctl_value("kern.smp.packages"), dmesg_output),
            "cores": int_value(sysctl_value("kern.smp.cores")),
            "threads": int_value(sysctl_value("kern.smp.cpus") or sysctl_value("hw.ncpu")),
            "threads_per_core": int_value(sysctl_value("kern.smp.threads_per_core")),
            **frequency,
        },
        "crypto_hardware": crypto_hardware,
        "ipsec": collect_ipsec_status(crypto_hardware),
        "accelerated_algorithms": collect_accelerated_algorithms(crypto_hardware),
        "dns": collect_dns(
            read_text(RESOLV_CONF),
            run([SOCKSTAT, "-46l", "-p", "53"]),
            read_text(UNBOUND_CONF, *sorted(glob.glob(UNBOUND_INCLUDES))),
        ),
        "mitigations": {
            "pti": pti,
            "mds": mds,
        },
    }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "frequency":
        print(json.dumps(collect_cpu_frequency(), sort_keys=True))
    else:
        print(json.dumps(collect(), sort_keys=True))
