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

"""Saved map snapshots for Firewall Map+.

    firewallmap_snapshots.py save <user>             take one (user is base64url-encoded UTF-8)
    firewallmap_snapshots.py list                    JSON list, newest first
    firewallmap_snapshots.py get <id> [block_min]    one snapshot with its metadata
    firewallmap_snapshots.py note <id> <note>        set the note (base64url, "-" clears it)
    firewallmap_snapshots.py delete <id>

Taking a snapshot leaves a request for the running collector, which writes every tracked flow
(not just the capped summary the map polls) plus the PF states behind them. When the collector
does not answer in time, the current summary is saved instead and marked partial.
Each snapshot is two files in SNAPSHOT_DIR: the document and a small metadata file, so the list
and note edits never read or rewrite the large one.
"""

import base64
import binascii
import fcntl
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone

from lib.common import (
    OUTPUT_FILE, REQUEST_MARKER, SNAPSHOT_DIR, SNAPSHOT_REQUEST_DIR, read_json, secure_umask, write_json,
)

ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{4}$")
KEEP_SNAPSHOTS = 50
KEEP_SECONDS = 30 * 86400
KEEP_BYTES = 100 * 1024 * 1024
MAX_NOTE = 500
MAX_USER = 64
# the collector samples every 2 s while a map is open; allow for one slow sample
WAIT_SECONDS = 8.0
WAIT_STEP = 0.2
# a summary older than this is not "what the map shows now"
FRESH_SECONDS = 10
# one snapshot per this many seconds, from anyone: each is a full capture, and only KEEP_SNAPSHOTS
# are kept, so a held-down camera button must not push everyone else's out
MIN_INTERVAL_SECONDS = 10


def valid_id(snapshot_id):
    return bool(ID_PATTERN.match(snapshot_id or ""))


def new_id(now=None):
    stamp = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc)
    return f"{stamp.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(2)}"


def decode_text(value, limit):
    """base64url (no padding) to text; "-" or anything undecodable is empty."""
    if not value or value == "-":
        return ""
    try:
        text = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""
    return text.strip()[:limit]


def document_path(snapshot_id, directory=SNAPSHOT_DIR):
    return os.path.join(directory, f"{snapshot_id}.json")


def meta_path(snapshot_id, directory=SNAPSHOT_DIR):
    return os.path.join(directory, f"{snapshot_id}.meta.json")


def summarize(payload):
    """The counts the snapshot list shows."""
    flows = payload.get("flows") or []
    blocks = payload.get("blocks") or []
    flagged = sum(1 for flow in flows if flow.get("threat")) + sum(1 for block in blocks if block.get("lists"))
    return {"flows": len(flows), "blocks": len(blocks), "flagged": flagged,
            "ids": len(payload.get("ids_flows") or []) + len(payload.get("alerts") or [])}


def request_full(snapshot_id, user, wait=WAIT_SECONDS, directory=SNAPSHOT_DIR, requests=SNAPSHOT_REQUEST_DIR):
    """Ask the collector for a full snapshot; True once it has written the document."""
    os.makedirs(requests, exist_ok=True)
    write_json(os.path.join(requests, f"{snapshot_id}.request"), {"user": user})
    # keep the collector in its foreground pace while it answers
    try:
        with open(REQUEST_MARKER, "a"):
            os.utime(REQUEST_MARKER)
    except OSError:
        pass
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if os.path.exists(document_path(snapshot_id, directory)):
            return True
        time.sleep(WAIT_STEP)
    try:
        os.remove(os.path.join(requests, f"{snapshot_id}.request"))
    except OSError:
        pass
    return os.path.exists(document_path(snapshot_id, directory))


def save(user, now=None, wait=WAIT_SECONDS, directory=SNAPSHOT_DIR, requests=SNAPSHOT_REQUEST_DIR,
         summary_file=OUTPUT_FILE):
    now = time.time() if now is None else now
    os.makedirs(directory, exist_ok=True)
    os.makedirs(requests, exist_ok=True)
    if not reserve(now, requests):
        newest = metas(directory)[:1]
        return {"result": "failed", "error": "too_soon", "snapshot": newest[0] if newest else None}
    snapshot_id = new_id(now)
    partial = False
    if not request_full(snapshot_id, user, wait, directory, requests):
        # the collector did not answer: keep what the map shows, when it is current
        try:
            fresh = now - os.stat(summary_file).st_mtime < FRESH_SECONDS
        except OSError:
            fresh = False
        payload = read_json(summary_file) if fresh else {}
        if payload.get("status") != "ok":
            return {"result": "failed", "error": "no current map data"}
        write_json(document_path(snapshot_id, directory), payload)
        partial = True
    payload = read_json(document_path(snapshot_id, directory))
    meta = {"id": snapshot_id, "taken": now, "user": user, "note": "", "partial": partial, **summarize(payload),
            "size": os.path.getsize(document_path(snapshot_id, directory))}
    write_json(meta_path(snapshot_id, directory), meta)
    prune(directory=directory)
    return {"result": "saved", "snapshot": meta}


def reserve(now, directory=SNAPSHOT_REQUEST_DIR):
    """Take the save slot (at most one save every MIN_INTERVAL_SECONDS): checked and taken under a
    lock, since a save then waits seconds for the collector and configd runs requests in parallel."""
    with open(os.path.join(directory, "last_save"), "a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        try:
            last = float(handle.read().strip() or 0)
        except ValueError:
            last = 0.0
        if 0 <= now - last < MIN_INTERVAL_SECONDS:
            return False
        handle.seek(0)
        handle.truncate()
        handle.write(f"{now}\n")
    return True


def metas(directory=SNAPSHOT_DIR):
    """Every snapshot's metadata, newest first; a document without metadata is not listed."""
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    result = []
    for name in names:
        if not name.endswith(".meta.json"):
            continue
        snapshot_id = name[:-len(".meta.json")]
        meta = read_json(os.path.join(directory, name))
        if valid_id(snapshot_id) and meta.get("id") == snapshot_id and os.path.exists(document_path(snapshot_id, directory)):
            result.append(meta)
    result.sort(key=lambda meta: meta.get("taken") or 0, reverse=True)
    return result


def remove(snapshot_id, directory=SNAPSHOT_DIR):
    removed = False
    for path in (document_path(snapshot_id, directory), meta_path(snapshot_id, directory)):
        try:
            os.remove(path)
            removed = True
        except OSError:
            pass
    return removed


def prune(now=None, directory=SNAPSHOT_DIR):
    """Keep the newest KEEP_SNAPSHOTS, none older than KEEP_SECONDS, at most KEEP_BYTES in all."""
    now = time.time() if now is None else now
    kept_bytes = 0
    listed = metas(directory)
    for index, meta in enumerate(listed):
        kept_bytes += meta.get("size") or 0
        if index >= KEEP_SNAPSHOTS or now - (meta.get("taken") or 0) > KEEP_SECONDS or (index and kept_bytes > KEEP_BYTES):
            remove(meta["id"], directory)
    # leftovers of an interrupted save (a document without metadata) once they are old
    listed_ids = {meta["id"] for meta in metas(directory)}
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        path = os.path.join(directory, name)
        stem = name[:-len(".json")] if name.endswith(".json") and not name.endswith(".meta.json") else None
        if stem and stem not in listed_ids:
            try:
                if now - os.stat(path).st_mtime > 600:
                    os.remove(path)
            except OSError:
                pass


def get(snapshot_id, block_minimum=1, directory=SNAPSHOT_DIR):
    if not valid_id(snapshot_id):
        return {"result": "failed", "error": "unknown snapshot"}
    meta = read_json(meta_path(snapshot_id, directory))
    payload = read_json(document_path(snapshot_id, directory))
    if not meta or not payload:
        return {"result": "failed", "error": "unknown snapshot"}
    blocks = payload.get("blocks")
    if blocks is not None:
        # the viewer's threshold, as for the live map
        shown = [block for block in blocks if block.get("hits", 1) >= block_minimum]
        payload["blocks"] = shown
        payload["blocks_below"] = len(blocks) - len(shown)
    payload["age"] = 0
    return {"result": "ok", "snapshot": meta, "data": payload}


def set_note(snapshot_id, note, directory=SNAPSHOT_DIR):
    if not valid_id(snapshot_id):
        return {"result": "failed", "error": "unknown snapshot"}
    meta = read_json(meta_path(snapshot_id, directory))
    if not meta:
        return {"result": "failed", "error": "unknown snapshot"}
    meta["note"] = note
    write_json(meta_path(snapshot_id, directory), meta)
    return {"result": "saved", "snapshot": meta}


def main(arguments):
    secure_umask()
    command = arguments[0] if arguments else ""
    if command == "save":
        user = decode_text(arguments[1] if len(arguments) > 1 else "", MAX_USER) or "unknown"
        return save(user)
    if command == "list":
        return {"result": "ok", "snapshots": metas(), "keep": KEEP_SNAPSHOTS, "keep_days": KEEP_SECONDS // 86400}
    if command == "get" and len(arguments) > 1:
        minimum = int(arguments[2]) if len(arguments) > 2 and arguments[2].isdigit() else 1
        return get(arguments[1], max(1, min(minimum, 100)))
    if command == "note" and len(arguments) > 2:
        return set_note(arguments[1], decode_text(arguments[2], MAX_NOTE))
    if command == "delete" and len(arguments) > 1:
        if not valid_id(arguments[1]):
            return {"result": "failed", "error": "unknown snapshot"}
        return {"result": "deleted" if remove(arguments[1]) else "failed"}
    return {"result": "failed", "error": "unknown command"}


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1:]), separators=(",", ":")))
