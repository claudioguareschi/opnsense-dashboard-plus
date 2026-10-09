#!/usr/local/bin/python3
"""Usage: collector_profile_live.py <collector> [scripts_dir] [samples]

Devel check of the ranking profiles on a real firewall (read-only: PF states are only read). The
collector runs with each built-in profile and a worst-case custom profile (4,096 asset rules
over the firewall's own networks and random prefixes); each run takes `samples` samples (default
5) and prints the per-state processing cost, the heap peak, the regime and the selection, so the
cost of profile scoring and asset lookups can be compared."""
import ipaddress
import random
import sys
import tempfile
import time

sys.path.insert(0, sys.argv[2] if len(sys.argv) > 2 else "/usr/local/opnsense/scripts/OPNsense/FirewallMap")
from lib import collector, config, pf, profiles  # noqa: E402


def asset_profile(networks):
    """Balanced with 4,096 asset rules: the firewall's networks at 3x, a host in each at 10x, then
    random /24 and /48 prefixes (never matching) up to the cap."""
    rng = random.Random(7)
    rules, seen = [], set()

    def add(network, multiplier):
        if network not in seen and len(rules) < profiles.ASSET_RULES_MAX:
            seen.add(network)
            rules.append({"cidr": str(network), "multiplier": multiplier})
    for text in networks:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        add(network, 3)
        add(ipaddress.ip_network(f"{network.network_address + 1}/{network.max_prefixlen}"), 10)
    while len(rules) < profiles.ASSET_RULES_MAX:
        if rng.random() < 0.5:
            add(ipaddress.ip_network((rng.getrandbits(24) << 8, 24)), 2)
        else:
            add(ipaddress.ip_network((rng.getrandbits(48) << 80, 48)), 2)
    base = profiles.BY_UUID[profiles.BALANCED]
    return profiles.validate(dict(base, uuid="00000000-0000-4000-8000-000000000001", name="Assets (devel)",
                                  builtin=False, assets=rules))


def main():
    samples = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    local, _role, networks, interfaces = pf.host_info()
    wan = config.topology().get("primary_wan_device")
    runs = [(p["name"], profiles.validate(p)) for p in profiles.BUILTINS]
    runs.append(("4,096 asset rules", asset_profile([str(network) for network, _device in networks])))
    for name, profile in runs:
        engine = collector.CollectorEngine(sys.argv[1], profile=profile, profile_dir=tempfile.gettempdir())
        try:
            costs, last = [], None
            for _ in range(samples):
                started = time.perf_counter()
                last = engine.sample(local, networks, interfaces, wan, threat_summary=True)
                elapsed = time.perf_counter() - started
                telemetry = last["telemetry"]
                states = max(1, last["counts"]["states"])
                costs.append((telemetry["processing_seconds"] / states * 1e6,
                              (telemetry["dump_seconds"] + telemetry["processing_seconds"]) / states * 1e6, elapsed,
                              telemetry["heap_peak"]))
            # the first sample is a baseline: report the rest
            steady = costs[1:] or costs
            processing = sorted(cost[0] for cost in steady)[len(steady) // 2]
            total = sorted(cost[1] for cost in steady)[len(steady) // 2]
            print(f"{name:20} states {last['counts']['states']:7}  flows {last['counts']['flows']:6}  "
                  f"processing {processing:.3f} us/state  dump+processing {total:.3f} us/state  "
                  f"heap peak {max(cost[3] for cost in steady) >> 20} MiB  regime {last['regime']}  "
                  f"ranked {len(last['flows'])}  top {[flow['key'][1] for flow in last['flows'][:3]]}")
        finally:
            engine.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
