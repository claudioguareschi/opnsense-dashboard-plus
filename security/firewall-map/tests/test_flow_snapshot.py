"""Unit tests for the Firewall Map PF-state parser."""

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "src/opnsense/scripts/OPNsense/FirewallMap/flow_snapshot.py"
SPEC = importlib.util.spec_from_file_location("firewall_map_flow_snapshot", SCRIPT)
FLOW_SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLOW_SNAPSHOT)


class FlowSnapshotTest(unittest.TestCase):
    def test_parses_counter_record(self):
        output = """all tcp 198.13.91.163:443 (192.168.1.2:443) <- 45.56.79.53:35799       ESTABLISHED:ESTABLISHED
   [123 + 456] [789 + 101112]
   age 00:10:05, expires in 23:59:48, 8:12 pkts, 368:5072 bytes
"""
        records = FLOW_SNAPSHOT.state_snapshot(output)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["interface"], "all")
        self.assertEqual(records[0]["protocol"], "tcp")
        self.assertEqual(records[0]["bytes_out"], 5072)
        self.assertEqual(records[0]["packets_in"], 8)

    def test_bounds_records(self):
        output = "\n".join(
            f"all udp 192.0.2.{index}:53 -> 198.51.100.{index}:53 SINGLE:SINGLE\n"
            "   age 00:00:01, expires in 00:00:59, 1:2 pkts, 3:4 bytes"
            for index in range(1, 4)
        )
        self.assertEqual(len(FLOW_SNAPSHOT.state_snapshot(output, 2)), 2)


if __name__ == "__main__":
    unittest.main()
