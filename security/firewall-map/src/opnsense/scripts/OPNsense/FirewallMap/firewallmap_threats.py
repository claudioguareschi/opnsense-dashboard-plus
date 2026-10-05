#!/usr/local/bin/python3

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

"""Threat history for Firewall Map+, organized by observed disposition.

    firewallmap_threats.py list [status]                  JSON list, newest activity first
    firewallmap_threats.py set <address> <status> [note]  note is base64url-encoded UTF-8

The collector records passed states, firewall blocks and IPS drops for flagged addresses.
Disposition is evidence from PF/state/log/IPS data; operator workflow (open, reviewed,
dismissed or manually blocked) is kept separately in ``status``.
"""

import base64
import binascii
import contextlib
import ipaddress
import json
import os
import sqlite3
import sys
import time

from lib.common import CACHE_DB, THREATS_DB, is_icmp, log_error, secure_umask, service_name
from lib.leases import host_names
from lib.pf import StateFacts

DATABASE = THREATS_DB
STATUSES = ("new", "reviewed", "dismissed", "blocked")
DISPOSITIONS = ("passed", "firewall_blocked", "ips_dropped")
VIEWS = (*DISPOSITIONS, "all", "reviewed", "dismissed")
KEEP_SECONDS = 90 * 86400
KEEP_ROWS = 5000
# entries the operator touched (reviewed, dismissed, blocked or annotated) have their own room, so
# a flood of new entries never pushes out a decision or a note
KEEP_TOUCHED = 1000
TOUCHED = "(status != 'new' OR coalesce(note, '') != '')"
# a touched entry ages from its last sighting or its last status change, whichever is later
TOUCHED_AGE = "max(last_seen, coalesce(status_changed, 0))"
MAX_ITEMS = 8  # per list kept for one address (targets, inside hosts, services, lists)
MAX_NOTE = 1000
SCHEMA_VERSION = 1


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
    # one-time steps, recorded in user_version (not repeated on every connection, which is every
    # list request)
    if db.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
        db.execute("CREATE INDEX IF NOT EXISTS threats_view ON threats(status, disposition, last_seen DESC)")
        # a move that failed (cache.db locked or unreadable) is tried again on the next connection
        if path != DATABASE or move_from_cache(db):
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return db


def move_from_cache(db, cache=None):
    """Earlier releases kept the history in cache.db: copy it here once, then drop it there. True
    when done or when there is nothing to move, False when it has to be tried again. Rows recorded
    here since (after an earlier failed try) are kept: INSERT OR IGNORE lets them win."""
    cache = cache or CACHE_DB
    if not os.path.exists(cache):
        return True
    try:
        db.execute("ATTACH DATABASE ? AS old", (cache,))
    except sqlite3.Error as error:
        log_error(f"could not open the cache to move the threat history out of it: {error}")
        return False
    try:
        if not db.execute("SELECT 1 FROM old.sqlite_master WHERE type = 'table' AND name = 'threats'").fetchone():
            return True
        here = [row[1] for row in db.execute("PRAGMA main.table_info(threats)")]
        there = {row[1] for row in db.execute("PRAGMA old.table_info(threats)")}
        columns = ", ".join(column for column in here if column in there)
        db.execute("BEGIN IMMEDIATE")
        if {"status", "note", "status_changed"} <= there:
            # an address recorded again before an earlier failed move keeps the operator's decision
            db.execute(
                "UPDATE main.threats SET "
                "status = (SELECT o.status FROM old.threats o WHERE o.address = main.threats.address), "
                "note = (SELECT o.note FROM old.threats o WHERE o.address = main.threats.address), "
                "status_changed = (SELECT o.status_changed FROM old.threats o WHERE o.address = main.threats.address) "
                "WHERE status = 'new' AND coalesce(note, '') = '' AND address IN "
                "(SELECT address FROM old.threats WHERE status != 'new' OR coalesce(note, '') != '')"
            )
        db.execute(f"INSERT OR IGNORE INTO main.threats ({columns}) SELECT {columns} FROM old.threats")
        db.execute("DROP TABLE old.threats")
        db.execute("COMMIT")
        return True
    except sqlite3.Error as error:
        if db.in_transaction:
            db.execute("ROLLBACK")
        log_error(f"could not move the threat history out of the cache: {error}")
        return False
    finally:
        db.execute("DETACH DATABASE old")


def merge(old, new):
    """Union of short ranked lists: the newest entries first, bounded."""
    result = list(new)
    for item in old:
        if item not in result:
            result.append(item)
    return result[:MAX_ITEMS]


def observe(records, lists_for, local_addresses, networks=None, sample=None):
    """Group the current states that touch a flagged address: {remote: summary}. sample:
    StateFacts.view() of records, when the caller already has it."""
    seen = {}
    # an address appears in many states: ask the lists once per address and sample
    verdicts = {}
    views, _ = sample if sample is not None else StateFacts().view(records, local_addresses, networks)
    for record, facts in views:
        pair = facts.pair
        if pair is None:
            continue
        remote = pair[1]
        if remote not in verdicts:
            verdicts[remote] = lists_for(remote)
        lists = verdicts[remote]
        if not lists:
            continue
        entry = seen.setdefault(remote, {
            "lists": lists, "inbound": 0, "outbound": 0, "targets": [], "inside": [], "services": [], "bytes": 0,
            "youngest": None, "service_ports": {},
        })
        if record.age is not None:
            entry["youngest"] = record.age if entry["youngest"] is None else min(entry["youngest"], record.age)
        inside, service_port = facts.inside, facts.service_port
        if facts.remote_started:
            entry["inbound"] += 1
            if facts.target not in entry["targets"]:
                entry["targets"].append(facts.target)
        else:
            entry["outbound"] += 1
        if inside and inside.address not in entry["inside"]:
            entry["inside"].append(inside.address)
        service = facts.service
        if service not in entry["services"]:
            entry["services"].append(service)
            if not is_icmp(record.protocol) and service_port:
                entry["service_ports"][service] = f"{service_port}/{record.protocol}"
        entry["bytes"] += record.bytes_in + record.bytes_out
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
        stored = row[3] or "passed"
        # a blocked attempt from an address that once got through adds its facts after the ones
        # that got through, so the bounded lists (and the card's headline) keep the passed traffic
        weaker = rank.get(disposition, -1) < rank.get(stored, -1)
        ranked = (lambda old, new: merge(new, old)) if weaker else merge
        data["lists"] = merge(data.get("lists", []), entry["lists"])
        data["targets"] = ranked(data.get("targets", []), entry["targets"])
        data["inside"] = ranked(data.get("inside", []), entry["inside"])
        data["services"] = ranked(data.get("services", []), entry["services"])
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
        disposition = max((stored, disposition), key=lambda value: rank.get(value, -1))
        # only a connection opened after the block reopens it; existing and closing states
        # (TIME_WAIT lingers for a minute or more) are not new traffic
        youngest = entry.get("youngest")
        blocked_since = (row[2] or 0) + BLOCK_SLACK_SECONDS
        if status == "blocked" and youngest is not None and now - youngest > blocked_since:
            data["seen_after_block"] = True
            status = "new"
        db.execute("UPDATE threats SET last_seen = ?, samples = samples + 1, data = ?, status = ?, disposition = ? "
                   "WHERE address = ?", (now, json.dumps(data), status, disposition, address))


MAX_CONNECTIONS = 8


def merge_connections(old, new):
    """Keep the latest picture of each connection: IDS-linked ones first, then those PF let through
    (a flood of blocked attempts must not push them out), then the most recent."""
    merged = {item["key"]: item for item in old if isinstance(item, dict) and item.get("key")}
    for item in new:
        previous = merged.get(item["key"], {})
        if previous.get("ids") and not item.get("ids"):
            item = {**item, "ids": previous["ids"]}
        merged[item["key"]] = item
    ordered = sorted(merged.values(),
                     key=lambda item: (not item.get("ids"), item.get("decision") == "block", -(item.get("seen") or 0)))
    return ordered[:MAX_CONNECTIONS]


def prune(db, now=None):
    now = time.time() if now is None else now
    cutoff = now - KEEP_SECONDS
    db.execute(f"DELETE FROM threats WHERE NOT {TOUCHED} AND last_seen < ?", (cutoff,))
    db.execute(f"DELETE FROM threats WHERE {TOUCHED} AND {TOUCHED_AGE} < ?", (cutoff,))
    # over the row limit, blocked and dropped attempts go first: a flood of them (scanners hitting
    # block rules) must not push out the flagged traffic that got through
    db.execute(f"DELETE FROM threats WHERE NOT {TOUCHED} AND address NOT IN (SELECT address FROM threats "
               f"WHERE NOT {TOUCHED} ORDER BY disposition = 'passed' DESC, last_seen DESC LIMIT ?)", (KEEP_ROWS,))
    db.execute(f"DELETE FROM threats WHERE {TOUCHED} AND address NOT IN (SELECT address FROM threats "
               f"WHERE {TOUCHED} ORDER BY {TOUCHED_AGE} DESC LIMIT ?)", (KEEP_TOUCHED,))


def inside_names():
    """DHCP names, then still-fresh PTR fallbacks, for inside-host display."""
    try:
        return host_names()
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


def _stored_rows(db, view=None, offset=0, limit=None):
    """The entries of a disposition/workflow view, most recent activity first (a page of them
    when `limit` is given)."""
    clause, parameters = _view_clause(view)
    sql = ("SELECT address, first_seen, last_seen, samples, data, status, note, status_changed, disposition "
           f"FROM threats WHERE {clause} ORDER BY last_seen DESC")
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        parameters = (*parameters, limit, offset)
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
    row.setdefault("remote", {})
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
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or PAGE_SIZE), MAX_PAGE_SIZE))
    if str(query or "").strip():
        # a search matches what the queue displays (decoded rows), so it reads the whole view
        rows = list(matching(db, view, query, names))
        total, rows = len(rows), rows[offset:offset + limit]
    else:
        # no search: SQL pages it, only one page is decoded
        clause, parameters = _view_clause(view)
        total = db.execute(f"SELECT count(*) FROM threats WHERE {clause}", parameters).fetchone()[0]
        rows = list(_stored_rows(db, view, offset, limit))
    page = [_decorate(db, row) for row in rows]
    return {"status": "ok", "rows": page, "total": total, "offset": offset, "counts": counts, "names": names}


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


@contextlib.contextmanager
def transaction(db):
    """One commit for many statements (the connection autocommits each one otherwise)."""
    db.execute("BEGIN")
    try:
        yield
    except BaseException:
        db.execute("ROLLBACK")
        raise
    db.execute("COMMIT")


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
    with transaction(db):
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
    with transaction(db):
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

    def argument(index):
        return arguments[index] if len(arguments) > index else None

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
