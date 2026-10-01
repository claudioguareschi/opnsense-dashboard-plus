#!/usr/local/bin/python3

"""Threat history for Firewall Map+, organized by observed disposition.

    firewallmap_threats.py list [status]                  JSON list, newest activity first
    firewallmap_threats.py set <address> <status> [note]  note is base64url-encoded UTF-8

The collector records passed states, firewall blocks and IPS drops for flagged addresses.
Disposition is evidence from PF/state/log/IPS data; operator workflow (open, reviewed,
dismissed or manually blocked) is kept separately in ``status``.
"""

import base64
import binascii
import ipaddress
import json
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwmap_common import CACHE_DB, is_icmp, remote_target, secure_umask, service_name  # noqa: E402
from fwmap_leases import lease_names  # noqa: E402
from fwmap_pf import flow_endpoints, inside_endpoint, orientation  # noqa: E402

DATABASE = CACHE_DB
STATUSES = ("new", "reviewed", "dismissed", "blocked")
DISPOSITIONS = ("passed", "firewall_blocked", "ips_dropped")
VIEWS = (*DISPOSITIONS, "all", "reviewed", "dismissed")
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
        "samples INTEGER, data TEXT, status TEXT DEFAULT 'new', note TEXT DEFAULT '', status_changed REAL, "
        "disposition TEXT DEFAULT 'passed')"
    )
    columns = {row[1] for row in db.execute("PRAGMA table_info(threats)")}
    if "disposition" not in columns:
        db.execute("ALTER TABLE threats ADD COLUMN disposition TEXT DEFAULT 'passed'")
    # Releases before disposition tabs used status=dropped for IPS evidence.
    db.execute("UPDATE threats SET disposition = 'ips_dropped', status = 'new' WHERE status = 'dropped'")
    db.execute("CREATE INDEX IF NOT EXISTS threats_view ON threats(status, disposition, last_seen DESC)")
    return db


def merge(old, new):
    """Union of short ranked lists: the newest entries first, bounded."""
    result = list(new)
    for item in old:
        if item not in result:
            result.append(item)
    return result[:MAX_ITEMS]


def observe(records, lists_for, local_addresses, networks=None):
    """Group the current states that touch a flagged address: {remote: summary}."""
    seen = {}
    for record in records:
        pair = flow_endpoints(record, local_addresses, networks)
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
        inside = inside_endpoint(record, networks, local_addresses)
        remote_started, service_port = orientation(record, remote, networks, local_addresses)
        if remote_started:
            entry["inbound"] += 1
            target = remote_target(record, remote, pair[0], inside, service_port)
            if target not in entry["targets"]:
                entry["targets"].append(target)
        else:
            entry["outbound"] += 1
        if inside and inside["address"] not in entry["inside"]:
            entry["inside"].append(inside["address"])
        service = service_name(record["protocol"], service_port)
        if service not in entry["services"]:
            entry["services"].append(service)
            if not is_icmp(record["protocol"]) and service_port:
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
    rank = {"firewall_blocked": 0, "ips_dropped": 1, "passed": 2}
    for address, entry in seen.items():
        row = db.execute("SELECT data, status, status_changed, disposition FROM threats WHERE address = ?",
                         (address,)).fetchone()
        disposition = entry.get("disposition") or "passed"
        if disposition not in DISPOSITIONS:
            disposition = "passed"
        if row is None:
            data = {**entry, "inbound": entry["inbound"] > 0, "outbound": entry["outbound"] > 0,
                    "peak_bytes": entry["bytes"]}
            data.pop("bytes")
            data.pop("youngest")
            data.pop("status_hint", None)
            data.pop("disposition", None)
            status = "new"
            data["connections"] = merge_connections([], entry.get("connections") or [])
            data["remote"] = entry.get("remote") or {}
            if not data.get("ids"):
                data.pop("ids", None)
            db.execute(
                "INSERT INTO threats (address, first_seen, last_seen, samples, data, status, note, status_changed, disposition) "
                "VALUES (?, ?, ?, 1, ?, ?, '', NULL, ?)", (address, now, now, json.dumps(data), status, disposition))
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
        data["connections"] = merge_connections(data.get("connections") or [], entry.get("connections") or [])
        if entry.get("ids"):
            data["ids"] = entry["ids"]  # the latest Suricata picture for this address
        status = row[1]
        disposition = max((row[3] or "passed", disposition), key=lambda value: rank.get(value, -1))
        # only a connection opened after the block reopens it; existing and closing states
        # (TIME_WAIT lingers for a minute or more) are not new traffic
        youngest = entry.get("youngest")
        if (status == "blocked" and youngest is not None
                and now - youngest > (row[2] or 0) + BLOCK_SLACK_SECONDS):
            data["seen_after_block"] = True
            status = "new"
        db.execute("UPDATE threats SET last_seen = ?, samples = samples + 1, data = ?, status = ?, disposition = ? "
                   "WHERE address = ?", (now, json.dumps(data), status, disposition, address))


MAX_CONNECTIONS = 8


def merge_connections(old, new):
    """Keep the latest picture of each connection; IDS-linked ones first, then the most recent."""
    merged = {item["key"]: item for item in old if isinstance(item, dict) and item.get("key")}
    for item in new:
        previous = merged.get(item["key"], {})
        if previous.get("ids") and not item.get("ids"):
            item = {**item, "ids": previous["ids"]}
        merged[item["key"]] = item
    ordered = sorted(merged.values(), key=lambda item: (not item.get("ids"), -(item.get("seen") or 0)))
    return ordered[:MAX_CONNECTIONS]


def prune(db, now=None):
    now = time.time() if now is None else now
    db.execute("DELETE FROM threats WHERE last_seen < ?", (now - KEEP_SECONDS,))
    # over the row limit, blocked and dropped attempts go first: a flood of them (scanners hitting
    # block rules) must not push out the flagged traffic that got through
    db.execute("DELETE FROM threats WHERE address NOT IN (SELECT address FROM threats "
               "ORDER BY disposition = 'passed' DESC, last_seen DESC LIMIT ?)", (KEEP_ROWS,))


def cached_country(db, address):
    """Country code of an address from the collector's local GeoIP cache (same database file)."""
    try:
        found = db.execute("SELECT value FROM cache WHERE kind LIKE 'geo:%' AND key = ? ORDER BY stored DESC LIMIT 1",
                           (address,)).fetchone()
        return (json.loads(found[0]) or {}).get("country") if found else None
    except (sqlite3.Error, ValueError, AttributeError):
        return None


def inside_names():
    """DHCP names of inside hosts, so entries read "mail" rather than 192.168.1.2."""
    try:
        return lease_names()
    except Exception:  # names are a nicety; the queue works without them
        return {}


PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
MAX_QUERY = 200


def _view_clause(view):
    if view in DISPOSITIONS:
        return "status = 'new' AND disposition = ?", (view,)
    if view in ("reviewed", "dismissed"):
        return "status = ?", (view,)
    return "status != 'dismissed'", ()


def _stored_rows(db, view=None):
    """Every entry of a disposition/workflow view, most recent activity first."""
    clause, parameters = _view_clause(view)
    sql = ("SELECT address, first_seen, last_seen, samples, data, status, note, status_changed, disposition "
           f"FROM threats WHERE {clause} ORDER BY last_seen DESC")
    for address, first, last, samples, data, current, note, changed, disposition in db.execute(sql, parameters):
        try:
            data = json.loads(data)
        except ValueError:
            data = {}
        yield {"address": address, "first_seen": first, "last_seen": last, "samples": samples,
               "status": current, "disposition": disposition or "passed", "note": note or "",
               "status_changed": changed, **(data if isinstance(data, dict) else {})}


def search_text(row, names):
    """What the queue shows for an entry, lower-cased: the text a search should find it by.

    Only displayed values count, never the JSON key names (searching "status" must not match
    every entry).
    """
    remote = row.get("remote") or {}
    parts = [row["address"], row.get("note"), *(row.get("lists") or []),
             *(name.replace("FWMAP_", "").replace("_", " ") for name in row.get("lists") or []),
             *(remote.get(key) for key in ("hostname", "org", "country", "country_code", "city")),
             *(row.get("services") or [])]
    for address in row.get("inside") or []:
        parts += [address, names.get(address)]
    for target in row.get("targets") or []:
        protocol, address, port = (str(target).split("|") + ["", "", ""])[:3]
        parts += [address, names.get(address), f"{protocol}/{port}" if port else protocol]
    for connection in row.get("connections") or []:
        parts += [connection.get(key) for key in ("inside", "inside_name", "remote", "public", "rule", "interface")]
    return " ".join(str(part) for part in parts if part).lower()


def matching(db, view, query, names=None):
    """Entries of `view` whose displayed text contains every word of `query`."""
    names = inside_names() if names is None else names
    words = str(query or "").lower().split()
    for row in _stored_rows(db, view):
        if not words or all(word in search_text(row, names) for word in words):
            yield row


def _decorate(db, row):
    # name each inbound target's service (entries recorded before ports were kept have none)
    row["target_services"] = {}
    for target in row.get("targets", []):
        protocol, port = str(target).split("|")[0], str(target).split("|")[-1]
        row["target_services"][target] = service_name(protocol, port or None)
    remote = row.setdefault("remote", {})
    if not remote.get("country_code"):
        # entries recorded before the code was kept: take it from the local geolocation cache
        code = cached_country(db, row["address"])
        if code:
            remote["country_code"] = code
    return row


def listing(db, view=None, offset=0, limit=PAGE_SIZE, query=None):
    """One page of threat history; tab counts use indexed disposition/workflow columns."""
    counts = {
        disposition: db.execute(
            "SELECT count(*) FROM threats WHERE status = 'new' AND disposition = ?", (disposition,)
        ).fetchone()[0] for disposition in DISPOSITIONS
    }
    counts.update({status: db.execute("SELECT count(*) FROM threats WHERE status = ?", (status,)).fetchone()[0]
                   for status in ("reviewed", "dismissed")})
    counts["all"] = db.execute("SELECT count(*) FROM threats WHERE status != 'dismissed'").fetchone()[0]
    if view == "counts":
        return {"status": "ok", "rows": [], "counts": counts}
    names = inside_names()
    rows = list(matching(db, view, query, names))
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or PAGE_SIZE), MAX_PAGE_SIZE))
    page = [_decorate(db, row) for row in rows[offset:offset + limit]]
    return {"status": "ok", "rows": page, "total": len(rows), "offset": offset, "counts": counts, "names": names}


def set_status(db, address, status, note=None, now=None):
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        return {"result": "failed", "error": "not an IP address"}
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
    return {"result": "saved"} if cursor.rowcount else {"result": "failed", "error": "not in threat history"}


def decode_note(value):
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def _addresses(db, view, query):
    return [row["address"] for row in matching(db, view, query)] if query else None


def bulk_status(db, current, status, query=None, now=None):
    """Move every entry with one status (and matching the search, when there is one) to another,
    e.g. dismiss all new entries; reversible."""
    if current not in VIEWS or status not in STATUSES:
        return {"result": "failed", "error": "unknown status"}
    now = time.time() if now is None else now
    clear = "json_remove(data, '$.seen_after_block')"
    addresses = _addresses(db, current, query)
    if addresses is None:
        clause, parameters = _view_clause(current)
        cursor = db.execute(f"UPDATE threats SET status = ?, status_changed = ?, data = {clear} WHERE {clause}",
                            (status, now, *parameters))
        return {"result": "saved", "changed": cursor.rowcount}
    changed = 0
    for address in addresses:
        changed += db.execute(f"UPDATE threats SET status = ?, status_changed = ?, data = {clear} "
                              "WHERE address = ?", (status, now, address)).rowcount
    return {"result": "saved", "changed": changed}


def purge(db, status, query=None):
    """Delete the entries of one status (and matching the search) for good; only dismissed or reviewed ones."""
    if status not in ("dismissed", "reviewed"):
        return {"result": "failed", "error": "only dismissed or reviewed entries can be deleted"}
    addresses = _addresses(db, status, query)
    if addresses is None:
        return {"result": "deleted", "deleted": db.execute("DELETE FROM threats WHERE status = ?", (status,)).rowcount}
    deleted = 0
    for address in addresses:
        deleted += db.execute("DELETE FROM threats WHERE status = ? AND address = ?", (status, address)).rowcount
    return {"result": "deleted", "deleted": deleted}


def decode_query(value):
    """A search sent as base64url ("-" for none), bounded in length."""
    if not value or value == "-":
        return None
    text = decode_note(value)
    return text[:MAX_QUERY] if text else None


def main(arguments, path=DATABASE):
    command = arguments[0] if arguments else "list"
    argument = lambda index: arguments[index] if len(arguments) > index else None  # noqa: E731
    db = connect(path)
    if command == "set" and len(arguments) >= 3:
        note = decode_note(arguments[3]) if len(arguments) > 3 and arguments[3] != "-" else None
        return set_status(db, arguments[1], arguments[2], note)
    if command == "bulk" and len(arguments) >= 3:
        return bulk_status(db, arguments[1], arguments[2], decode_query(argument(3)))
    if command == "purge" and len(arguments) >= 2:
        return purge(db, arguments[1], decode_query(argument(2)))
    offset = argument(2)
    limit = argument(3)
    return listing(db, argument(1), int(offset) if offset and offset.isdigit() else 0,
                   int(limit) if limit and limit.isdigit() else PAGE_SIZE, decode_query(argument(4)))


if __name__ == "__main__":
    secure_umask()
    print(json.dumps(main(sys.argv[1:])))
