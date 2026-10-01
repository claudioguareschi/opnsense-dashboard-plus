"""Unit tests for inbound blocks and the log tail (fwmap_blocks)."""

import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import BLOCKS, SNAPSHOT, Geo  # noqa: E402


class BlockTest(unittest.TestCase):
    LINE = ('<134>1 2026-09-25T21:27:07-04:00 fw filterlog 31386 - [meta sequenceId="1"] '
            '15,,,ecd3a310894625657c6591b80daa956a,igb1,match,block,in,4,0x0,,244,54321,0,none,6,tcp,40,'
            '45.56.79.53,198.13.91.163,51234,23,0,S,1,,1024,,')

    def test_parses_inbound_block(self):
        event = BLOCKS.parse_block(self.LINE)
        self.assertEqual(event["source"], "45.56.79.53")
        self.assertEqual(event["destination"], "198.13.91.163")
        self.assertEqual((event["protocol"], event["port"], event["interface"]), ("tcp", "23", "igb1"))
        self.assertIsNone(BLOCKS.parse_block(self.LINE.replace(",block,in,", ",pass,in,")))
        self.assertIsNone(BLOCKS.parse_block(self.LINE.replace(",block,in,", ",block,out,")))

    def test_parses_inbound_ipv6_block(self):
        line = ('<134>1 2026-09-25T21:27:07-04:00 fw filterlog 31386 - [meta sequenceId="2"] '
                '15,,,tracker,igb1,match,block,in,6,0x00,0x12345,64,tcp,6,40,'
                '2001:4860:4860:0:0:0:0:8888,2606:4700:4700:0:0:0:0:1111,51234,443,0,S,1,,1024,,')
        event = BLOCKS.parse_block(line)
        self.assertEqual(event["source"], "2001:4860:4860::8888")
        self.assertEqual(event["destination"], "2606:4700:4700::1111")
        self.assertEqual((event["protocol"], event["port"]), ("tcp", "443"))

    def test_block_snapshot_names_services(self):
        class Geo:
            def resolve(self, addresses):
                pass

            def get(self, address):
                return {"lat": 1.0, "lon": 2.0, "country": "NL", "country_name": "The Netherlands"}
        blocks = BLOCKS.BlockTracker(fade=6, show=60, window=600)
        event = BLOCKS.parse_block(self.LINE)
        blocks.add(event, now=0.0)
        blocks.add(event, now=30.0)
        (block,) = BLOCKS.block_snapshot(blocks, Geo(), {"198.13.91.163"}, "198.13.91.163", 30.0, {}, {})
        self.assertEqual(block["services"], [{"name": "Telnet", "port": "23/tcp", "hits": 2}])
        self.assertEqual((block["port_count"], block["seconds"], block["country"]), (1, 30, "The Netherlands"))

    def test_tracks_hits_fades_and_flags_threats(self):
        blocks = BLOCKS.BlockTracker(fade=6, show=60, window=600)
        event = BLOCKS.parse_block(self.LINE)
        for second in range(BLOCKS.THREAT_HITS_PER_MINUTE):
            blocks.add(event, now=float(second))
        now = float(BLOCKS.THREAT_HITS_PER_MINUTE - 1)
        (address, entry), = blocks.visible(now)
        self.assertEqual(blocks.per_minute(entry, now), BLOCKS.THREAT_HITS_PER_MINUTE)
        self.assertEqual(blocks.activity(entry, now), 1.0)
        self.assertAlmostEqual(blocks.activity(entry, now + 3), 0.5)
        # quiet for over a minute: no longer drawn, but its hits still count toward the window
        self.assertEqual(blocks.visible(now + 61), [])
        blocks.add(event, now=now + 300)
        (address, entry), = blocks.visible(now + 300)
        self.assertEqual(blocks.hits(entry), BLOCKS.THREAT_HITS_PER_MINUTE + 1)
        self.assertEqual(blocks.per_minute(entry, now + 300), 1)
        # and they age out of the 10-minute window
        self.assertEqual(blocks.visible(now + 1000), [])
        self.assertEqual(blocks.sources, {})

    def test_eviction_keeps_recently_hit_sources(self):
        blocks = BLOCKS.BlockTracker(max_sources=2)
        event = BLOCKS.parse_block(self.LINE)
        blocks.add({**event, "source": "45.56.79.1"}, now=1.0)
        blocks.add({**event, "source": "45.56.79.2"}, now=2.0)
        blocks.add({**event, "source": "45.56.79.1"}, now=3.0)
        blocks.add({**event, "source": "45.56.79.3"}, now=4.0)
        self.assertEqual(sorted(blocks.sources), ["45.56.79.1", "45.56.79.3"])

    def test_bounded_under_a_flood(self):
        blocks = BLOCKS.BlockTracker(max_sources=3)
        event = BLOCKS.parse_block(self.LINE)
        for index in range(10):
            blocks.add({**event, "source": f"45.56.79.{index}", "port": str(index)}, now=float(index))
        self.assertEqual(sorted(blocks.sources), ["45.56.79.7", "45.56.79.8", "45.56.79.9"])
        for port in range(100):
            blocks.add({**event, "port": str(port)}, now=20.0)
        self.assertEqual(len(blocks.sources["45.56.79.53"]["ports"]), BLOCKS.MAX_PORTS_PER_SOURCE)

    def test_log_tail_returns_complete_lines_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "latest.log")
            with open(path, "w") as handle:
                handle.write("old line\n")
            tail = BLOCKS.FilterLogTail(path)
            self.assertEqual(tail.lines(), [])
            with open(path, "a") as handle:
                handle.write("first\nsec")
            self.assertEqual(tail.lines(), ["first"])
            with open(path, "a") as handle:
                handle.write("ond\n")
            self.assertEqual(tail.lines(), ["second"])

    def test_log_tail_follows_the_daily_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "latest.log")
            with open(path, "w") as handle:
                handle.write("before\n")
            tail = BLOCKS.FilterLogTail(path)
            tail.lines()
            with open(path, "a") as handle:
                handle.write("last of the old file\n")
            # rotation: the old file moves away and a new one starts
            os.rename(path, path + ".1")
            with open(path, "w") as handle:
                handle.write("first of the new file\n")
            # the rest of the old file first, then the new file from its start: nothing is lost
            self.assertEqual(tail.lines(), ["last of the old file"])
            with open(path, "a") as handle:
                handle.write("next\n")
            self.assertEqual(tail.lines(), ["first of the new file", "next"])

    def test_a_log_without_newlines_does_not_grow_the_buffer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "latest.log")
            open(path, "w").close()
            tail = BLOCKS.FilterLogTail(path)
            tail.lines()
            for _ in range(5):
                with open(path, "a") as handle:
                    handle.write("x" * (BLOCKS.MAX_LINE_BYTES // 2))
                tail.lines()
            self.assertLessEqual(len(tail.pending), BLOCKS.MAX_LINE_BYTES)

    def test_old_log_lines_do_not_count_as_current(self):
        wall = BLOCKS.log_time(self.LINE)
        self.assertEqual(BLOCKS.block_event_time(self.LINE, 100.0, wall + 30), 70.0)
        self.assertIsNone(BLOCKS.block_event_time(self.LINE, 100.0, wall + 3600))

    def test_reads_log_timestamps(self):
        self.assertEqual(BLOCKS.log_time(self.LINE),
                         datetime.fromisoformat("2026-09-25T21:27:07-04:00").timestamp())
        self.assertIsNone(BLOCKS.log_time("garbage"))

    def test_reader_applies_viewer_threshold(self):
        payload = {"blocks": [{"hits": 1}, {"hits": 3}, {"hits": 7}]}
        result = SNAPSHOT.apply_block_threshold(payload, 3)
        self.assertEqual([block["hits"] for block in result["blocks"]], [3, 7])
        self.assertEqual(result["blocks_below"], 1)


if __name__ == "__main__":
    unittest.main()
