#!/usr/local/bin/python3
"""Usage: collector_classify_live.py <collector> [scripts_dir]

Devel check of PF-table classification on a real firewall (read-only: PF states and table
contents are only read). Every PF table (at most 64; chosen threat lists as category T, the rest
O) is classified by the collector; its masks for flow remotes and probe addresses must equal a
longest-prefix match over `pfctl -t TABLE -T show` (negated entries excluded), and a few
addresses are spot-checked with `pfctl -T test` too. Prints the reload cost and snapshot size."""
import ipaddress
import random
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, sys.argv[2] if len(sys.argv) > 2 else "/usr/local/opnsense/scripts/OPNsense/FirewallMap")
from lib import blocklists, collector, config, pf, profiles  # noqa: E402

PFCTL = "/sbin/pfctl"


def show(table):
    output = subprocess.run([PFCTL, "-t", table, "-T", "show"], capture_output=True, text=True).stdout
    entries = []
    for line in output.split():
        negated = line.startswith("!")
        try:
            entries.append((ipaddress.ip_network(line.lstrip("!"), strict=False), negated))
        except ValueError:
            pass
    return entries


class Reference:
    """Longest-prefix membership per table, by (version, prefix length) buckets."""

    def __init__(self, entries):
        self.buckets = {}
        for network, negated in entries:
            self.buckets.setdefault((network.version, network.prefixlen), {})[int(network.network_address)] = negated
        self.count = len(entries)

    def member(self, address):
        parsed = ipaddress.ip_address(address)
        bits = parsed.max_prefixlen
        value = int(parsed)
        for length in range(bits, -1, -1):
            bucket = self.buckets.get((parsed.version, length))
            if bucket is None:
                continue
            key = value >> (bits - length) << (bits - length) if length else 0
            if key in bucket:
                return not bucket[key]
        return False


def main():
    tables = sorted(pf.pf_tables())[:collector.CLASS_MAX_SETS]
    threat, _unavailable = blocklists.chosen_threat_lists("")
    sets = [("T" if table in threat else "O", table) for table in tables]
    references = {}
    started = time.perf_counter()
    for _category, table in sets:
        references[table] = Reference(show(table))
    print(f"{len(sets)} tables, {sum(r.count for r in references.values())} entries "
          f"(pfctl show + Python index {time.perf_counter() - started:.2f} s)")
    # probes: each table's first entries (network address, and one inside), and random addresses
    rng = random.Random(7)
    probes = set()
    for table, reference in references.items():
        for (version, length), bucket in list(reference.buckets.items())[:6]:
            for key in list(bucket)[:3]:
                bits = 32 if version == 4 else 128
                address = ipaddress.ip_address(key) if version == 4 else ipaddress.IPv6Address(key)
                probes.add(str(address))
                if length < bits:
                    probes.add(str(ipaddress.ip_address(key + rng.randrange(1, 1 << min(bits - length, 24)))
                                   if version == 4 else ipaddress.IPv6Address(key + rng.randrange(1, 1 << 24))))
    probes.update(str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(300))
    # as the client sends them: loopback and link-local addresses never take part in a state
    probes = sorted(address for address in probes if collector._context_address(address))[:collector.CLASS_MAX_ADDRESSES]

    local, _role, networks, interfaces = pf.host_info()
    wan = config.topology().get("primary_wan_device")
    # the shipped default profile: this check is about classification, not ranking
    engine = collector.CollectorEngine(sys.argv[1], profile=profiles.validate(profiles.BY_UUID[profiles.BALANCED]),
                                       profile_dir=tempfile.gettempdir())
    failures = 0
    try:
        engine._start()
        timings = []
        for generation in ("g1", "g1", "g2"):
            started = time.perf_counter()
            result = engine.sample(local, networks, interfaces, wan, threat_summary=True,
                                   classification=(generation, sets), classify=probes)
            timings.append((generation, time.perf_counter() - started, result["telemetry"]))
        for generation, seconds, telemetry in timings:
            print(f"sample {generation}: {seconds:.3f} s (dump {telemetry['dump_seconds']:.3f}, processing "
                  f"{telemetry['processing_seconds']:.3f}), classifier {telemetry['classifier_bytes'] >> 10} KiB, "
                  f"heap peak {telemetry['heap_peak'] >> 20} MiB, state limit {telemetry['state_limit']}")

        def expected(address):
            return sum(1 << bit for bit, (_category, table) in enumerate(sets) if references[table].member(address))

        for row in result["class_sets"]:
            table = sets[row["id"]][1]
            if row["status"] != "ok" or row["entries"] != references[table].count:
                print(f"set {table}: {row['status']} {row['entries']} entries, pfctl shows {references[table].count}")
                failures += 1
        checked = 0
        for flow in result["flows"]:
            want = expected(flow["key"][1])
            checked += 1
            if flow["classes"] != want:
                print(f"flow remote {flow['key'][1]}: mask {flow['classes']:#x}, want {want:#x}")
                failures += 1
        for remote in result["threat_remotes"]:
            want = expected(remote["address"])
            checked += 1
            if remote["classes"] != want:
                print(f"threat remote {remote['address']}: mask {remote['classes']:#x}, want {want:#x}")
                failures += 1
        for address in probes:
            want = expected(address)
            checked += 1
            if result["classified"].get(address, 0) != want:
                print(f"probe {address}: mask {result['classified'].get(address, 0):#x}, want {want:#x}")
                failures += 1
        threat_mask = sum(1 << bit for bit, (category, _table) in enumerate(sets) if category == "T")
        flagged = [remote for remote in result["threat_remotes"] if not remote["classes"] & threat_mask]
        print(f"{checked} addresses compared, {len(result['threat_remotes'])} threat remotes "
              f"({len(flagged)} evidence-only), {sum(1 for value in result['classified'].values() if value)} "
              f"probes classified")
        # PF itself, for a few classified probes
        for address, mask in list(result["classified"].items())[:15]:
            for bit, (_category, table) in enumerate(sets):
                if mask >> bit & 1:
                    test = subprocess.run([PFCTL, "-t", table, "-T", "test", address], capture_output=True, text=True)
                    if "1/1" not in test.stderr:
                        print(f"pfctl -T test disagrees: {address} in {table}: {test.stderr.strip()}")
                        failures += 1
    finally:
        engine.close()
    print("ok" if not failures else f"{failures} mismatches")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
