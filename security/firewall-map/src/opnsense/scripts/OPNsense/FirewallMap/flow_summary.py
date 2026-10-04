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

"""Return the latest Firewall Map flow summary written by the collector.

The dashboard polls through configd every 2 seconds. flow_summary.sh answers most polls without
Python (it marks the collector as in use and prints the summary while it is fresh); it runs this
script when there is more to do: the summary is old or missing (the collector is started, it stops
by itself when no dashboard has asked for a while), or the geolocation database is missing or its
download reports errors. The API applies the viewer's block threshold and host name setting.

    flow_summary.py [hostnames] [minimum]    minimum: apply the block threshold here (older API)
"""

import json
import os
import subprocess
import sys
import time

from lib.common import (
    GEODB_STATUS, HOSTNAME_MARKER, OUTPUT_FILE, RC_SCRIPT, REQUEST_MARKER, RUN_DIR, geodb_retry_due, geodb_view, read_json,
    secure_umask,
)

GEODB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewallmap_geodb.py")
STALE_SECONDS = 10


def start_collector():
    try:
        subprocess.run([RC_SCRIPT, "onestart"], capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def read_summary(path=None, now=None):
    path = path or OUTPUT_FILE
    try:
        age = (now or time.time()) - os.stat(path).st_mtime
        with open(path) as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    if age > STALE_SECONDS:
        return None
    payload["age"] = round(max(0.0, age), 1)
    return payload


def mark_request(path=None):
    """Tell the collector a dashboard is watching, so it keeps running."""
    path = path or REQUEST_MARKER
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a"):
            os.utime(path)
    except OSError:
        pass


FETCH_MARKER = f"{RUN_DIR}/fetch_started"
# the updater itself waits out failures (retry steps); this only keeps polls from starting one
# each while it decides
FETCH_EVERY_SECONDS = 10


def fetch_database(marker=None, now=None):
    """A missing (or failed) database is downloaded in the background, at most every few seconds."""
    marker = marker or FETCH_MARKER
    try:
        if (now or time.time()) - os.stat(marker).st_mtime < FETCH_EVERY_SECONDS:
            return
    except OSError:
        pass
    mark_request(marker)
    try:
        subprocess.Popen(
            ["/usr/local/bin/python3", GEODB, "update"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
    except OSError:
        pass


def apply_block_threshold(payload, minimum):
    """Keep blocked sources with at least `minimum` hits in the window; count the rest."""
    blocks = payload.get("blocks")
    if blocks is None:
        return payload
    shown = [block for block in blocks if block.get("hits", 1) >= minimum]
    payload["blocks"] = shown
    payload["blocks_below"] = len(blocks) - len(shown)
    return payload


def main(want_hostnames=False, block_minimum=None):
    mark_request()
    if want_hostnames:
        mark_request(HOSTNAME_MARKER)
    payload = read_summary()
    if payload is None:
        start_collector()
        payload = {"status": "starting", "flows": [], "locations": []}
    geodb = read_json(GEODB_STATUS)
    # the download's progress or its errors (a failed AS database also while the map works). A
    # download that died midway (a reboot, a kill) stops counting as running once its progress is
    # stale, so the next poll starts it again; the updater's lock refuses a second one that runs.
    view = geodb_view(geodb)
    missing = payload.get("status") == "no_database" and payload.get("reason") == "database_missing"
    if (missing and view["state"] != "downloading" and not geodb.get("errors")) or geodb_retry_due(geodb):
        fetch_database()
    if payload.get("status") == "no_database" or view["state"] == "failed":
        payload["geodb"] = view
    if not want_hostnames:
        payload.pop("hostnames", None)
    # the API applies the viewer's threshold (FlowSummary.php), to this document as to the shell's
    return payload if block_minimum is None else apply_block_threshold(payload, block_minimum)


if __name__ == "__main__":
    # often the first script to create /var/run/firewallmap (the first dashboard poll): 0750 like
    # everything else here, not configd's default
    secure_umask()
    arguments = sys.argv[1:]
    minimum = next((int(value) for value in arguments if value.isdigit()), None)
    print(json.dumps(main(want_hostnames="hostnames" in arguments,
                          block_minimum=None if minimum is None else max(1, min(minimum, 100))),
                     separators=(",", ":")))
