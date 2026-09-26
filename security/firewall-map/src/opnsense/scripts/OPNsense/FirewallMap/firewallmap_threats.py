#!/usr/local/bin/python3

"""Threat review queue for Firewall Map+.

    firewallmap_threats.py list [status]                  JSON list, newest activity first
    firewallmap_threats.py set <address> <status> [note]  note is base64url-encoded UTF-8

The collector records every permitted connection (a firewall state exists) to or from an
address in a threat list, AbuseIPDB's blacklist, a cached AbuseIPDB verdict or the
FWMAP_Watchlist alias. The operator reviews each address and sets its status; nothing here
changes firewall rules.
"""

import base64
import binascii
import ipaddress
import json
import os
import sqlite3
import sys
import time

DATABASE = "/var/db/firewallmap/cache.db"
STATUSES = ("new", "reviewed", "dismissed", "blocked")
KEEP_SECONDS = 90 * 86400
KEEP_ROWS = 5000
MAX_ITEMS = 8  # per list kept for one address (targets, inside hosts, services, lists)
MAX_NOTE = 1000


def connect(path=DATABASE):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute(
        "CREATE TABLE IF NOT EXISTS threats (address TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, "
        "samples INTEGER, data TEXT, status TEXT DEFAULT 'new', note TEXT DEFAULT '', status_changed REAL)"
    )
    return db


def merge(old, new):
    """Union of short ranked lists: the newest entries first, bounded."""
    result = list(new)
    for item in old:
        if item not in result:
            result.append(item)
    return result[:MAX_ITEMS]


def observe(records, flow_endpoints, lists_for, local_addresses, inside_endpoint, service_name, orientation):
    """Group the current states that touch a flagged address: {remote: summary}."""
    seen = {}
    for record in records:
        pair = flow_endpoints(record, local_addresses)
        if pair is None:
            continue
        remote = pair[1]
        lists = lists_for(remote)
        if not lists:
            continue
        entry = seen.setdefault(remote, {
            "lists": lists, "inbound": 0, "outbound": 0, "targets": [], "inside": [], "services": [], "bytes": 0,
            "youngest": None, "service_ports": {},
        })
        if record.get("age") is not None:
            entry["youngest"] = record["age"] if entry["youngest"] is None else min(entry["youngest"], record["age"])
        inside = inside_endpoint(record)
        remote_started, service_port = orientation(record, remote)
        if remote_started:
            entry["inbound"] += 1
            if record["src"]["address"] != remote:
                port = service_port or ""  # a reply state: the server's own port
            elif record["protocol"] in ("icmp", "ipv6-icmp"):
                port = ""
            else:
                port = (inside or record["dst"])["port"] or ""
            target = f'{record["protocol"]}|{inside["address"] if inside else pair[0]}|{port}'
            if target not in entry["targets"]:
                entry["targets"].append(target)
        else:
            entry["outbound"] += 1
        if inside and inside["address"] not in entry["inside"]:
            entry["inside"].append(inside["address"])
        service = service_name(record["protocol"], service_port)
        if service not in entry["services"]:
            entry["services"].append(service)
            if record["protocol"] not in ("icmp", "ipv6-icmp") and service_port:
                entry["service_ports"][service] = f'{service_port}/{record["protocol"]}'
        entry["bytes"] += record.get("bytes_in", 0) + record.get("bytes_out", 0)
    return seen


def record(db, seen, now=None):
    """Upsert what was seen, in one transaction so an operator's concurrent status change is kept."""
    now = time.time() if now is None else now
    db.execute("BEGIN IMMEDIATE")
    try:
        _record(db, seen, now)
    except BaseException:
        db.execute("ROLLBACK")
        raise
    db.execute("COMMIT")


# states created within this long of a block may predate it (the sample and the click race)
BLOCK_SLACK_SECONDS = 30


def _record(db, seen, now):
    for address, entry in seen.items():
        row = db.execute("SELECT data, status, status_changed FROM threats WHERE address = ?", (address,)).fetchone()
        if row is None:
            data = {**entry, "inbound": entry["inbound"] > 0, "outbound": entry["outbound"] > 0,
                    "peak_bytes": entry["bytes"]}
            data.pop("bytes")
            data.pop("youngest")
            data["remote"] = entry.get("remote") or {}
            db.execute(
                "INSERT INTO threats (address, first_seen, last_seen, samples, data, status, note, status_changed) "
                "VALUES (?, ?, ?, 1, ?, 'new', '', NULL)", (address, now, now, json.dumps(data)))
            continue
        try:
            data = json.loads(row[0])
        except ValueError:
            data = {}
        data["lists"] = merge(data.get("lists", []), entry["lists"])
        data["targets"] = merge(data.get("targets", []), entry["targets"])
        data["inside"] = merge(data.get("inside", []), entry["inside"])
        data["services"] = merge(data.get("services", []), entry["services"])
        data["service_ports"] = {**data.get("service_ports", {}), **entry["service_ports"]}
        data["service_ports"] = {name: port for name, port in data["service_ports"].items() if name in data["services"]}
        data["inbound"] = bool(data.get("inbound")) or entry["inbound"] > 0
        data["outbound"] = bool(data.get("outbound")) or entry["outbound"] > 0
        data["peak_bytes"] = max(data.get("peak_bytes", 0), entry["bytes"])
        # newer facts win, but a sample without them never erases what was recorded
        data["remote"] = {**data.get("remote", {}), **(entry.get("remote") or {})}
        status = row[1]
        # only a connection opened after the block reopens it; existing and closing states
        # (TIME_WAIT lingers for a minute or more) are not new traffic
        youngest = entry.get("youngest")
        if (status == "blocked" and youngest is not None
                and now - youngest > (row[2] or 0) + BLOCK_SLACK_SECONDS):
            data["seen_after_block"] = True
            status = "new"
        db.execute("UPDATE threats SET last_seen = ?, samples = samples + 1, data = ?, status = ? WHERE address = ?",
                   (now, json.dumps(data), status, address))


def prune(db, now=None):
    now = time.time() if now is None else now
    db.execute("DELETE FROM threats WHERE last_seen < ?", (now - KEEP_SECONDS,))
    db.execute("DELETE FROM threats WHERE address NOT IN (SELECT address FROM threats ORDER BY last_seen DESC LIMIT ?)",
               (KEEP_ROWS,))


def service_name(protocol, port):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import firewallmap_collector  # noqa: E402  (imported lazily: the collector imports this module)
    return firewallmap_collector.service_name(protocol, port)


def listing(db, status=None):
    counts = dict(db.execute("SELECT status, count(*) FROM threats GROUP BY status").fetchall())
    counts = {name: counts.get(name, 0) for name in STATUSES}
    if status == "counts":
        return {"status": "ok", "rows": [], "counts": counts}
    sql = "SELECT address, first_seen, last_seen, samples, data, status, note, status_changed FROM threats"
    parameters = ()
    if status in STATUSES:
        sql += " WHERE status = ?"
        parameters = (status,)
    rows = []
    for address, first, last, samples, data, current, note, changed in db.execute(sql + " ORDER BY last_seen DESC", parameters):
        try:
            data = json.loads(data)
        except ValueError:
            data = {}
        row = {"address": address, "first_seen": first, "last_seen": last, "samples": samples,
               "status": current, "note": note or "", "status_changed": changed, **data}
        # name each inbound target's service (entries recorded before ports were kept have none)
        row["target_services"] = {}
        for target in data.get("targets", []):
            protocol, port = str(target).split("|")[0], str(target).split("|")[-1]
            row["target_services"][target] = service_name(protocol, port or None)
        rows.append(row)
    return {"status": "ok", "rows": rows, "counts": counts}


def set_status(db, address, status, note=None, now=None):
    try:
        address = str(ipaddress.IPv4Address(address))
    except ValueError:
        return {"result": "failed", "error": "not an IPv4 address"}
    if status not in STATUSES:
        return {"result": "failed", "error": "unknown status"}
    now = time.time() if now is None else now
    # a new decision clears the "seen after block" warning
    clear = "json_remove(data, '$.seen_after_block')"
    if note is None:
        cursor = db.execute(f"UPDATE threats SET status = ?, status_changed = ?, data = {clear} WHERE address = ?",
                            (status, now, address))
    else:
        cursor = db.execute(f"UPDATE threats SET status = ?, status_changed = ?, note = ?, data = {clear} WHERE address = ?",
                            (status, now, note[:MAX_NOTE], address))
    return {"result": "saved"} if cursor.rowcount else {"result": "failed", "error": "not in the review queue"}


def decode_note(value):
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def main(arguments, path=DATABASE):
    command = arguments[0] if arguments else "list"
    db = connect(path)
    if command == "set" and len(arguments) >= 3:
        note = decode_note(arguments[3]) if len(arguments) > 3 and arguments[3] != "-" else None
        return set_status(db, arguments[1], arguments[2], note)
    return listing(db, arguments[1] if len(arguments) > 1 else None)


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1:])))
