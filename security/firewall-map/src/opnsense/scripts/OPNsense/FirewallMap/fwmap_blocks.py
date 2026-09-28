#!/usr/local/bin/python3

"""Inbound firewall blocks for Firewall Map+: the filter log tail and per-source hit tracking."""

import os
from datetime import datetime

from fwmap_blocklists import threat_fields
from fwmap_common import location_fields, public_ipv4, service_name


FILTER_LOG = "/var/log/filter/latest.log"
# a blocked source fades this long after its last hit and is reported while hit in the last minute;
# hits are counted over a longer window so slow scanners still reach a viewer's display threshold
BLOCK_FADE_SECONDS = 6
BLOCK_SHOW_SECONDS = 60
BLOCK_WINDOW_SECONDS = 600
# a source hitting at least this often per minute is drawn as a threat
THREAT_HITS_PER_MINUTE = 30
MAX_BLOCK_SOURCES = 300
MAX_LOG_BYTES_PER_SAMPLE = 4 * 1024 * 1024
# bounded memory under floods: tracked blocked sources and ports remembered per source
MAX_TRACKED_SOURCES = 5000
MAX_PORTS_PER_SOURCE = 20
BLOCK_BUCKET_SECONDS = 10
# read back this much of the log when the collector starts, so the 10-minute hit window is full
BACKLOG_BYTES = 2 * 1024 * 1024


class FilterLogTail:
    """Follow the firewall log from its current end, surviving the daily rotation of latest.log.

    Only complete lines are returned; a line still being written is kept until its newline arrives.
    """

    def __init__(self, path=FILTER_LOG):
        self.path = path
        self.handle = None
        self.inode = None
        self.pending = b""

    def _open(self, at_end):
        try:
            handle = open(self.path, "rb")
            inode = os.fstat(handle.fileno()).st_ino
        except OSError:
            return
        if at_end:
            handle.seek(0, os.SEEK_END)
        if self.handle:
            self.handle.close()
        self.handle, self.inode, self.pending = handle, inode, b""

    def backlog(self, max_bytes=BACKLOG_BYTES):
        """Lines from the end of the current log, used once at start to fill the hit window."""
        self._open(at_end=True)
        if self.handle is None:
            return []
        end = self.handle.tell()
        self.handle.seek(max(0, end - max_bytes))
        data = self.handle.read(end - self.handle.tell())
        if end > max_bytes:
            data = data.split(b"\n", 1)[-1]  # drop the partial first line
        return [line.decode("utf-8", "replace") for line in data.split(b"\n") if line]

    def lines(self, limit_bytes=MAX_LOG_BYTES_PER_SAMPLE):
        if self.handle is None:
            self._open(at_end=True)
            return []
        data = self.handle.read(limit_bytes)
        if len(data) >= limit_bytes:
            # a burst larger than we can draw: skip ahead instead of falling behind, keeping only
            # whole lines (the pending fragment no longer lines up with what follows)
            self.handle.seek(0, os.SEEK_END)
            data = data.split(b"\n", 1)[-1] if self.pending else data
            self.pending = b""
            data = data.rsplit(b"\n", 1)[0] + b"\n"
        parts = (self.pending + data).split(b"\n")
        self.pending = parts.pop()
        try:
            if os.stat(self.path).st_ino != self.inode:
                # rotated: finish the old file, then read the new one from its start
                # (old lines are dropped by their timestamps)
                rest = (self.pending + self.handle.read(limit_bytes)).split(b"\n")
                parts.extend(line for line in rest if line)
                self._open(at_end=False)
        except OSError:
            pass
        return [line.decode("utf-8", "replace") for line in parts if line]


def log_time(line):
    """Wall-clock time of a syslog line (RFC 5424 timestamp, second field)."""
    try:
        return datetime.fromisoformat(line.split(" ", 2)[1]).timestamp()
    except (IndexError, ValueError):
        return None


def parse_block(line):
    """Parse an inbound block from an OPNsense filterlog line (CSV after the syslog header)."""
    marker = line.find("] ")
    if " filterlog " not in line or marker < 0:
        return None
    fields = line[marker + 2:].strip().split(",")
    if len(fields) < 20 or fields[6] != "block" or fields[7] != "in":
        return None
    if fields[8] == "4":
        protocol, source, destination = fields[16], fields[18], fields[19]
        ports = fields[20:22] if protocol in ("tcp", "udp") and len(fields) > 21 else [None, None]
    elif fields[8] == "6" and len(fields) > 17:
        protocol, source, destination = fields[12], fields[15], fields[16]
        ports = fields[17:19] if protocol in ("tcp", "udp") and len(fields) > 18 else [None, None]
    else:
        return None
    return {
        "rule": fields[3] or fields[0],
        "interface": fields[4],
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "port": ports[1] or None,
        "source_port": ports[0] or None,
    }


class BlockTracker:
    """Inbound firewall blocks per public source: recent hits, ports tried, rule and interface.

    Memory is bounded even under a spoofed-source flood: hits are kept as 10-second bucket
    counts, ports per source are capped, and the least recently seen sources are evicted.
    """

    def __init__(self, fade=BLOCK_FADE_SECONDS, show=BLOCK_SHOW_SECONDS, window=BLOCK_WINDOW_SECONDS,
                 max_sources=MAX_TRACKED_SOURCES):
        self.fade = fade
        self.show = show
        self.window = window
        self.max_sources = max_sources
        self.sources = {}

    def add(self, event, now):
        if not public_ipv4(event["source"]):
            return
        # dict order doubles as recency order: a hit moves the source to the end, so the least
        # recently hit source is always first and eviction is O(1)
        entry = self.sources.pop(event["source"], None)
        if entry is None:
            if len(self.sources) >= self.max_sources:
                del self.sources[next(iter(self.sources))]
            entry = {"buckets": {}, "total": 0, "ports": {}, "first": now}
        self.sources[event["source"]] = entry
        bucket = int(now // BLOCK_BUCKET_SECONDS)
        entry["buckets"][bucket] = entry["buckets"].get(bucket, 0) + 1
        entry["total"] += 1
        entry["last"] = max(now, entry.get("last", now))
        entry["destination"] = event["destination"]
        entry["rule"] = event["rule"]
        entry["interface"] = event["interface"]
        port = f'{event["protocol"]}/{event["port"]}' if event["port"] else event["protocol"]
        if port in entry["ports"] or len(entry["ports"]) < MAX_PORTS_PER_SOURCE:
            entry["ports"][port] = entry["ports"].get(port, 0) + 1

    def hits(self, entry):
        return sum(entry["buckets"].values())

    def per_minute(self, entry, now):
        first = int((now - 60) // BLOCK_BUCKET_SECONDS) + 1
        return sum(count for bucket, count in entry["buckets"].items() if bucket >= first)

    def visible(self, now, limit=MAX_BLOCK_SOURCES):
        """Sources hit within the last `show` seconds, most persistent first."""
        oldest_bucket = int((now - self.window) // BLOCK_BUCKET_SECONDS) + 1
        recent = []
        for address in list(self.sources):
            entry = self.sources[address]
            for bucket in [bucket for bucket in entry["buckets"] if bucket < oldest_bucket]:
                del entry["buckets"][bucket]
            if not entry["buckets"]:
                del self.sources[address]
            elif now - entry["last"] <= self.show:
                recent.append((address, entry))
        recent.sort(key=lambda item: (-self.hits(item[1]), -item[1]["last"]))
        return recent[:limit]

    def activity(self, entry, now):
        return max(0.0, 1.0 - (now - entry["last"]) / self.fade)


def _service(port, hits):
    """{"name", "port", "hits"} for a "tcp/22" (or bare "icmp") key of BlockTracker's ports."""
    protocol, _, number = port.partition("/")
    return {"name": service_name(protocol, number or None), "port": f"{number}/{protocol}" if number else None,
            "hits": hits}


def block_snapshot(blocks, geo, local_addresses, origin, now, descriptions, interfaces, blocklists=None,
                   reputation=None, alerts=None):
    """Map-ready blocked sources; each arc ends at the firewall address that was hit."""
    visible = blocks.visible(now)
    geo.resolve([address for address, _ in visible])
    result = []
    for address, entry in visible:
        location = geo.get(address)
        if location is None:
            continue
        target = entry["destination"]
        per_minute = blocks.per_minute(entry, now)
        result.append({
            "source": address,
            "target": target,
            "activity": round(blocks.activity(entry, now), 3),
            "hits": blocks.hits(entry),
            "window_minutes": blocks.window // 60,
            "hits_per_minute": per_minute,
            "total": entry["total"],
            "threat": per_minute >= THREAT_HITS_PER_MINUTE,
            "ports": [name for name, _ in sorted(entry["ports"].items(), key=lambda item: -item[1])][:5],
            # the same service names and ports as permitted flows, busiest first
            "services": [_service(port, hits) for port, hits in sorted(entry["ports"].items(), key=lambda item: -item[1])][:5],
            "port_count": len(entry["ports"]),
            "seconds": round(now - entry.get("first", now)),
            "rule": descriptions.get(entry["rule"], ""),
            "interface": interfaces.get(entry["interface"], entry["interface"]),
            **location_fields(location),
            "accuracy_km": location.get("accuracy_km"),
            **threat_fields(address, blocklists, reputation),
            "ids": alerts.summary(address) if alerts is not None else None,
        })
    return result


def block_event_time(line, now, wall):
    """Monotonic time of a log line from its own timestamp (None when outside the hit window)."""
    stamp = log_time(line)
    if stamp is None:
        return now
    age = wall - stamp
    if age > BLOCK_WINDOW_SECONDS:
        return None
    return now - max(0.0, age)
