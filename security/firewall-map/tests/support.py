"""Shared by the Firewall Map+ tests: the script modules and fixtures.

The scripts import each other by module name from their own directory, so the tests import
them the same way: there is one copy of each module, and patching it affects every caller.
"""

import sys
from pathlib import Path

# never leave bytecode next to the scripts (it would ship in the package)
sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1] / "src/opnsense/scripts/OPNsense/FirewallMap"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import firewallmap_abuseipdb as ABUSEIPDB  # noqa: E402,F401
import firewallmap_collector as COLLECTOR  # noqa: E402,F401
import firewallmap_geodb as GEODB  # noqa: E402,F401
import firewallmap_investigate as INVESTIGATE  # noqa: E402,F401
import firewallmap_threats as THREATS  # noqa: E402,F401
import flow_snapshot as SNAPSHOT  # noqa: E402,F401
import fwmap_blocklists as BLOCKLISTS  # noqa: E402,F401
import fwmap_blocks as BLOCKS  # noqa: E402,F401
import fwmap_cache as CACHE  # noqa: E402,F401
import fwmap_common as COMMON  # noqa: E402,F401
import fwmap_ids as IDS  # noqa: E402,F401
import fwmap_leases as LEASES  # noqa: E402,F401
import fwmap_pf as PF  # noqa: E402,F401

NAT_STATE = """all tcp 198.13.91.163:443 (192.168.1.2:443) <- 45.56.79.53:35799       ESTABLISHED:ESTABLISHED
   [123 + 456] wscale 9  [789 + 101112] wscale 6
   age 00:10:05, expires in 23:59:48, {pkts_in}:{pkts_out} pkts, {bytes_in}:{bytes_out} bytes
   id: f501b86a00000000 creatorid: 2ec5c347
   origif: vlan01
"""

# an outbound NAT state from an inside host
NAT_OUT = """all tcp 198.13.91.163:19421 (192.168.30.30:51858) -> 34.209.15.107:8883       ESTABLISHED:ESTABLISHED
   [499210651 + 65535]  [1522661447 + 31469]
   age 21:44:28, expires in 23:59:37, 429:258 pkts, 27391:18836 bytes, allow-opts
   id: 5415dc6a00000000 creatorid: fc08c4c0
   origif: igb1
"""

# an inbound block from the filter log
BLOCK_LINE = ('<134>1 2026-09-25T21:27:07-04:00 fw filterlog 31386 - [meta sequenceId="1"] '
              '15,,,ecd3a310894625657c6591b80daa956a,igb1,match,block,in,4,0x0,,244,54321,0,none,6,tcp,40,'
              '45.56.79.53,198.13.91.163,51234,23,0,S,1,,1024,,')


def nat_state(bytes_in, bytes_out, pkts_in=8, pkts_out=12):
    return NAT_STATE.format(bytes_in=bytes_in, bytes_out=bytes_out, pkts_in=pkts_in, pkts_out=pkts_out)


class Geo:
    """A GeoCache stand-in that knows every address."""

    def __init__(self, location=None):
        self.location = location or {"lat": 1.0, "lon": 2.0, "country": "US", "country_name": "United States"}
        self.pending = {}

    def resolve(self, addresses):
        pass

    def get(self, address):
        return self.location

    def save(self, force=False):
        pass
