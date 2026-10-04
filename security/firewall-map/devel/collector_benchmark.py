#!/usr/bin/env python3

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

"""Measure the collector's CPU cost per sample on a synthetic state table, off the firewall.

Runs the real Collector.step() against generated `pfctl -vv -s state` output (outbound NAT pairs,
DNS from the firewall, port forwards, WireGuard, routed IPv6, ICMP and LAN-internal states), with
counters that move, connections that open and close, blocked attempts in the filter log and a few
Suricata alerts. The clock is simulated (2 s per sample), so threat recording and the periodic
refreshes fall where they would on the firewall, and two runs of the same seed write the same
documents.

    collector_benchmark.py [--states 1200] [--samples 60] [--profile] [--dump DIR] [--src DIR]

--dump writes every sample's flows.json and the threat history to DIR, to compare two versions of
the code (run each with --src pointing at its scripts directory, and PYTHONHASHSEED=0).
"""

import argparse
import cProfile
import ipaddress
import io
import json
import os
import pstats
import random
import resource
import shutil
import sys
import tempfile
import time
import zlib
from pathlib import Path
from unittest import mock

LOCAL4 = "1.2.3.163"
LOCAL6 = "2a01:4f8:1:2::1"
WAN_NET6 = "2a01:4f8:1:2::/64"
LAN_NET6 = "2a01:4f8:1:3::/64"
WALL_START = 1790000000.0
REMOTE_RANGES = ("34.0.0.0/8", "52.0.0.0/8", "104.16.0.0/12", "142.250.0.0/15", "151.101.0.0/16",
                 "185.199.108.0/22", "13.32.0.0/15", "20.0.0.0/8")
REMOTE_RANGES6 = ("2606:4700::/32", "2a00:1450::/32", "2620:fe::/48")
LAN_RULE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
NAT_RULE = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
WG_RULE = "11112222333344445555666677778888"
FORWARD_RULE = "99998888777766665555444433332222"


class Clock:
    """The collector's time: 2 s per sample, monotonic and wall clock together."""

    def __init__(self):
        self.offset = 0.0

    def monotonic(self):
        return 1000.0 + self.offset

    def time(self):
        return WALL_START + self.offset


class StateTable:
    """A synthetic, evolving PF state table."""

    KINDS = (("nat_tcp", 40), ("nat_udp", 12), ("own_dns", 8), ("forward", 6), ("wireguard", 2),
             ("routed6", 10), ("icmp", 2), ("lan", 20))

    def __init__(self, size, seed=1):
        self.random = random.Random(seed)
        self.next_id = 1
        self.remotes4 = [self._address(REMOTE_RANGES) for _ in range(max(50, size // 4))]
        self.remotes6 = [self._address(REMOTE_RANGES6) for _ in range(max(20, size // 20))]
        self.scanners = [self._address(("45.0.0.0/8", "185.0.0.0/8", "193.0.0.0/8")) for _ in range(200)]
        self.listed = set(self.random.sample(self.remotes4, len(self.remotes4) // 20)) | set(self.scanners[:50])
        self.connections = []
        while self._states() < size:
            self.connections.append(self._connection())

    def _address(self, ranges):
        network = ipaddress.ip_network(self.random.choice(ranges))
        while True:
            address = network[self.random.randrange(1, min(network.num_addresses - 1, 2 ** 32))]
            if address.is_global:
                return str(address)

    def _remote(self, pool):
        # a few remotes carry many connections (CDNs, push services), most only one or two
        if self.random.random() < 0.6:
            return self.random.choice(pool)
        return pool[min(len(pool) - 1, int(self.random.paretovariate(1.2)) - 1)]

    def _states(self):
        return sum(len(connection["states"]) for connection in self.connections)

    def _id(self):
        value = self.next_id
        self.next_id += 1
        return f"{value:016x}"

    def _connection(self):
        kind = self.random.choices([kind for kind, _ in self.KINDS], [weight for _, weight in self.KINDS])[0]
        host = f"192.168.1.{self.random.randrange(2, 250)}"
        port = str(self.random.randrange(30000, 65000))
        nat_port = str(self.random.randrange(1024, 65000))
        remote = self._remote(self.remotes4)
        if kind == "nat_tcp":
            service = self.random.choice(("443", "443", "443", "80", "993", "8883", "5223"))
            states = [
                (f"all tcp {host}:{port} -> {remote}:{service}", "ESTABLISHED:ESTABLISHED", LAN_RULE, "igb0"),
                (f"all tcp {LOCAL4}:{nat_port} ({host}:{port}) -> {remote}:{service}", "ESTABLISHED:ESTABLISHED",
                 NAT_RULE, "igb1"),
            ]
        elif kind == "nat_udp":
            service = self.random.choice(("443", "123", "3478", "19302"))
            states = [
                (f"all udp {host}:{port} -> {remote}:{service}", "MULTIPLE:SINGLE", LAN_RULE, "igb0"),
                (f"all udp {LOCAL4}:{nat_port} ({host}:{port}) -> {remote}:{service}", "MULTIPLE:SINGLE", NAT_RULE,
                 "igb1"),
            ]
        elif kind == "own_dns":
            resolver = self.random.choice(("9.9.9.9", "149.112.112.112", "1.1.1.1"))
            states = [(f"all udp {LOCAL4}:{nat_port} -> {resolver}:53", "MULTIPLE:SINGLE", None, "igb1")]
        elif kind == "forward":
            far = self._remote(self.scanners if self.random.random() < 0.3 else self.remotes4)
            states = [
                (f"all tcp {LOCAL4}:443 (192.168.1.10:443) <- {far}:{port}", "ESTABLISHED:ESTABLISHED", FORWARD_RULE,
                 "igb1"),
                (f"all tcp {far}:{port} -> 192.168.1.10:443", "ESTABLISHED:ESTABLISHED", FORWARD_RULE, "igb0"),
            ]
        elif kind == "wireguard":
            far = self._remote(self.remotes4)
            states = [(f"all udp {LOCAL4}:51820 <- {far}:{port}", "MULTIPLE:MULTIPLE", WG_RULE, "igb1")]
        elif kind == "routed6":
            inside = f"2a01:4f8:1:3::{self.random.randrange(2, 4000):x}"
            far = self._remote(self.remotes6)
            states = [
                (f"all tcp {inside}[{port}] -> {far}[443]", "ESTABLISHED:ESTABLISHED", LAN_RULE, "igb0"),
                (f"all tcp {inside}[{port}] -> {far}[443]", "ESTABLISHED:ESTABLISHED", LAN_RULE, "igb1"),
            ]
        elif kind == "icmp":
            states = [(f"all icmp {LOCAL4}:{nat_port} -> {remote}:{nat_port}", "0:0", None, "igb1")]
        else:
            states = [(f"all tcp {host}:{port} -> 192.168.2.{self.random.randrange(2, 250)}:445",
                       "ESTABLISHED:ESTABLISHED", LAN_RULE, "igb0")]
        return {
            "states": [{"header": header, "state": state, "rule": rule, "origif": origif, "id": self._id(),
                        "age": self.random.randrange(0, 20000), "counters": [self.random.randrange(1, 500),
                                                                             self.random.randrange(1, 500),
                                                                             self.random.randrange(100, 10 ** 6),
                                                                             self.random.randrange(100, 10 ** 6)]}
                       for header, state, rule, origif in states],
            "active": self.random.random() < 0.3,
        }

    def advance(self, seconds):
        """Counters move on active connections, some close and new ones open."""
        for index, connection in enumerate(self.connections):
            if self.random.random() < 0.03:
                fresh = self._connection()
                for state in fresh["states"]:
                    state["age"] = self.random.randrange(0, 2)
                self.connections[index] = fresh
                continue
            for state in connection["states"]:
                state["age"] += seconds
                if connection["active"]:
                    packets = self.random.randrange(1, 50)
                    state["counters"][0] += packets
                    state["counters"][1] += packets
                    state["counters"][2] += packets * self.random.randrange(60, 1400)
                    state["counters"][3] += packets * self.random.randrange(60, 1400)
            if self.random.random() < 0.1:
                connection["active"] = not connection["active"]

    def text(self):
        lines = []
        for connection in self.connections:
            for state in connection["states"]:
                age = state["age"]
                packets_in, packets_out, bytes_in, bytes_out = state["counters"]
                lines.append(f"{state['header']}       {state['state']}\n")
                if " tcp " in state["header"]:
                    lines.append("   [1531214283 + 65535] wscale 7  [3092385910 + 64256] wscale 7\n")
                rule = f", rule 12, rlabel {state['rule']}" if state["rule"] else ""
                lines.append(f"   age {age // 3600:02d}:{age // 60 % 60:02d}:{age % 60:02d}, expires in 23:59:58, "
                             f"{packets_in}:{packets_out} pkts, {bytes_in}:{bytes_out} bytes{rule}\n")
                lines.append(f"   id: {state['id']} creatorid: 2ec5c347\n")
                lines.append(f"   origif: {state['origif']}\n")
        return "".join(lines)

    def flagged(self, address):
        return address in self.listed

    def connection_tuple(self):
        """(remote, remote port, firewall port) of a NATed outbound connection, for an alert."""
        for connection in self.random.sample(self.connections, min(50, len(self.connections))):
            header = connection["states"][-1]["header"]
            if header.startswith(f"all tcp {LOCAL4}:") and "(" in header:
                parts = header.split()
                remote, remote_port = parts[-1].rsplit(":", 1)
                return remote, remote_port, parts[2].rsplit(":", 1)[1]
        return None


class Location:
    """A stand-in for the geolocation cache: a stable location per address."""

    def __init__(self, store=None, database=None, asn_database=None):
        self.database = database
        self.database_mtime = None
        self.pending = {}
        self.known = {}

    @staticmethod
    def _database_mtime():
        return None

    def forget_old_databases(self):
        pass

    def resolve(self, addresses):
        pass

    def get(self, address):
        # the real cache returns the location it keeps in memory
        location = self.known.get(address)
        if location is None:
            crc = zlib.crc32(str(address).encode())
            location = self.known[address] = {
                "lat": crc % 140 - 70.0, "lon": crc % 360 - 180.0, "country": "US", "country_name": "United States",
                "city": f"City {crc % 97}", "asn": 64500 + crc % 50, "as_org": f"Network {crc % 50}"}
        return location

    def save(self, force=False):
        pass


def block_lines(table, wall, count):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(wall))
    lines = []
    for _ in range(count):
        source = table._remote(table.scanners)
        port = table.random.choice(("22", "23", "445", "3389", "8080"))
        lines.append(f'<134>1 {stamp} fw filterlog 31386 - [meta sequenceId="1"] 15,,,ecd3a310894625657c6591b80daa956a,'
                     f'igb1,match,block,in,4,0x0,,244,54321,0,none,6,tcp,40,{source},{LOCAL4},51234,{port},0,S,1,,1024,,\n')
    return lines


def alert_line(table, wall):
    found = table.connection_tuple()
    if found is None:
        return None
    remote, remote_port, local_port = found
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(wall))
    return json.dumps({
        "timestamp": stamp, "flow_id": table.random.randrange(10 ** 12), "event_type": "alert", "src_ip": LOCAL4,
        "src_port": int(local_port), "dest_ip": remote, "dest_port": int(remote_port), "proto": "TCP",
        "alert": {"action": "allowed", "signature_id": 2013028, "signature": "ET POLICY curl User-Agent Outbound",
                  "category": "Attempted Information Leak", "severity": 2},
        "flow": {"pkts_toserver": 5, "pkts_toclient": 4, "bytes_toserver": 600, "bytes_toclient": 900, "start": stamp},
    }) + "\n"


def run(arguments):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(arguments.src).resolve()))
    import syslog
    syslog.syslog = lambda *values: None
    import firewallmap_collector as collector_module
    from lib import pf

    clock = Clock()
    table = StateTable(arguments.states, arguments.seed)
    # pfctl's output, made before each measured step (pfctl is a separate program on the firewall)
    sample = [""]
    work = tempfile.mkdtemp(prefix="fwmap-benchmark-")
    filter_log, eve_log = os.path.join(work, "filter.log"), os.path.join(work, "eve.json")
    for path in (filter_log, eve_log):
        open(path, "w").close()
    networks = pf.interface_networks(
        "igb0: flags=1008843<UP> metric 0 mtu 1500\n\tinet 192.168.1.1 netmask 0xffffff00\n"
        f"\tinet6 2a01:4f8:1:3::1 prefixlen 64\n"
        "igb1: flags=1008843<UP> metric 0 mtu 1500\n\tinet 1.2.3.163 netmask 0xffffff00\n"
        f"\tinet6 {LOCAL6} prefixlen 64\n")
    patches = [
        mock.patch("time.time", clock.time), mock.patch("time.monotonic", clock.monotonic),
        mock.patch.object(collector_module, "OUTPUT_FILE", os.path.join(work, "flows.json")),
        # older versions have no timings file
        mock.patch.object(collector_module, "COLLECTOR_TIMINGS", os.path.join(work, "timings.json"), create=True),
        mock.patch.object(collector_module, "SNAPSHOT_REQUEST_DIR", os.path.join(work, "requests")),
        mock.patch.object(collector_module, "sample_states", lambda: pf.parse_states(io.StringIO(sample[0]))),
        mock.patch.object(collector_module, "host_info", lambda: ({LOCAL4, LOCAL6}, None, networks)),
        mock.patch.object(collector_module, "recording_wanted", lambda values=None: True),
        mock.patch.object(collector_module, "database_state", lambda values: ("city.mmdb", "asn.mmdb", None)),
        mock.patch.object(collector_module, "rule_descriptions", lambda: {
            LAN_RULE: "LAN to Internet", NAT_RULE: "Outbound NAT", FORWARD_RULE: "Web server"}),
        mock.patch.object(collector_module, "interface_names", lambda: {"igb0": "LAN", "igb1": "WAN"}),
        mock.patch.object(collector_module, "lease_names", lambda: {"192.168.1.10": "web"}),
        mock.patch.object(collector_module, "port_forwards", list),
        mock.patch.object(collector_module, "chosen_threat_lists", lambda setting: set()),
        mock.patch.object(collector_module, "idle", lambda started: False),
        mock.patch.object(collector_module, "requested", lambda marker, seconds: False),
        mock.patch.object(collector_module, "reload_token", lambda: None),
        mock.patch.object(collector_module, "GeoCache", Location),
        mock.patch.object(collector_module.geodb, "settings", lambda: {"provider": "dbip", "threat_lists": ""}),
    ]
    for patch in patches:
        patch.start()
    try:
        collector = collector_module.Collector(store=collector_module.CacheStore(os.path.join(work, "cache.db")))
        collector.log = collector_module.FilterLogTail(filter_log)
        collector.eve = collector_module.FilterLogTail(eve_log)
        collector.recorder = collector_module.ThreatRecorder(os.path.join(work, "threats.db"))
        collector.blocklists.index = collector_module.BlocklistIndex.build({"Test list": sorted(table.listed)})
        collector.checked["blocklists"] = clock.monotonic()
        profile = cProfile.Profile() if arguments.profile else None
        costs, walls = [], []
        if arguments.dump:
            os.makedirs(arguments.dump, exist_ok=True)
        for number in range(arguments.samples + 2):
            with open(filter_log, "a") as handle:
                handle.writelines(block_lines(table, clock.time(), 5))
            if number % 5 == 4:
                line = alert_line(table, clock.time())
                if line:
                    with open(eve_log, "a") as handle:
                        handle.write(line)
            sample[0] = table.text()
            measured = number >= 2
            if measured and profile:
                profile.enable()
            cpu, wall = time.process_time(), time.perf_counter()
            collector.step()
            cpu, wall = time.process_time() - cpu, time.perf_counter() - wall
            if measured and profile:
                profile.disable()
            if measured:
                costs.append(cpu)
                walls.append(wall)
            if arguments.dump:
                shutil.copy(collector_module.OUTPUT_FILE, os.path.join(arguments.dump, f"flows-{number:03d}.json"))
            clock.offset += 2.0
            table.advance(2)
        collector.close()
        if arguments.dump:
            import firewallmap_threats as threats
            listing = threats.listing(threats.connect(os.path.join(work, "threats.db")), limit=10000)
            with open(os.path.join(arguments.dump, "threats.json"), "w") as handle:
                json.dump(listing, handle, sort_keys=True, indent=1, default=str)
    finally:
        for patch in reversed(patches):
            patch.stop()
        shutil.rmtree(work)
    costs.sort()
    walls.sort()
    print(f"{arguments.states} states ({len(collector.tracker.counters)} drawn), {len(costs)} samples: "
          f"CPU per sample median {1000 * costs[len(costs) // 2]:.1f} ms, mean {1000 * sum(costs) / len(costs):.1f} ms, "
          f"max {1000 * costs[-1]:.1f} ms; wall median {1000 * walls[len(walls) // 2]:.1f} ms; "
          f"peak RSS {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024} MB")
    timings = getattr(collector, "timings", None)
    if timings:
        print("last sample:", ", ".join(f"{name} {1000 * value:.1f} ms" for name, value in timings["phases"].items()))
    if profile:
        for order, count in (("cumulative", 40), ("tottime", 25)):
            text = io.StringIO()
            pstats.Stats(profile, stream=text).strip_dirs().sort_stats(order).print_stats(count)
            print("\n".join(line.rstrip()[:160] for line in text.getvalue().splitlines() if line.strip()))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--states", type=int, default=1200)
    parser.add_argument("--samples", type=int, default=60)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--dump")
    parser.add_argument("--src", default=str(Path(__file__).resolve().parents[1] / "src/opnsense/scripts/OPNsense/FirewallMap"))
    run(parser.parse_args())


if __name__ == "__main__":
    main()
