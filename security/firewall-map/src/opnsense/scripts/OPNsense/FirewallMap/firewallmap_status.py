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

"""What Reporting: Firewall Map: Status shows, as JSON: the installed version, the collector and
its state collector, the geolocation database and the threat-list downloads. Reads status files
only; it downloads nothing.

    firewallmap_status.py
"""

import json
import os
import time

import firewallmap_abuseipdb as abuseipdb
import firewallmap_feeds as feeds
import firewallmap_geodb as geodb
from firewallmap_collector import IDLE_SECONDS, recording_wanted
from lib.config import abuseipdb_key, settings, widget_in_use
from lib.blocklists import FEEDS
from lib.common import COLLECTOR_TIMINGS, OUTPUT_FILE, REQUEST_MARKER, geodb_view, read_json, secure_umask
from lib.collector import PROTOCOL_VERSION, kernel_version

PID_FILE = "/var/run/firewallmap.pid"
# written by the plugins framework from the package's PLUGIN_VERSION
VERSION_FILE = "/usr/local/opnsense/version/firewall-map"


def installed_version():
    """The installed Firewall Map package version (e.g. 0.59 or the development build 0.59.1)."""
    version = read_json(VERSION_FILE).get("product_version")
    return version if isinstance(version, str) and version else None


def modified(path):
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def collector(now=None):
    """Running or not, and what for: a map being watched (live) or background threat recording."""
    now = time.time() if now is None else now
    pid = None
    try:
        with open(PID_FILE) as handle:
            pid = int(handle.read().strip())
        os.kill(pid, 0)
    except (OSError, ValueError):
        pid = None
    requested = modified(REQUEST_MARKER)
    watched = requested is not None and now - requested < IDLE_SECONDS
    timings = read_json(COLLECTOR_TIMINGS) if pid is not None else {}
    return {
        "running": pid is not None,
        "mode": ("live" if watched else "background") if pid is not None else "stopped",
        "last_viewed": requested,
        "last_map_update": modified(OUTPUT_FILE),
        "recording": settings().get("record_threats", "1") != "0",
        "widget_in_use": widget_in_use(),
        "recording_wanted": recording_wanted(),
        # Absent on older collectors; PID liveness and the existing reader policies still apply.
        "timing": timings.get("collector"),
        # how long the last sample took (written by a running collector every few seconds)
        "last_sample": {key: timings.get(key) for key in
                        ("at", "states", "wall", "cpu", "programs", "phases", "generation", "revision")}
        if timings.get("wall") is not None else None,
    }


def state_collector(timing):
    """The state collector as the running service last saw it: state (running, incompatible,
    failed, starting, or stopped with the service), protocol (announced, or None when unknown)
    and the expected one, process and build ABI, the admission limit its budget derives, the
    last sample's cost, omissions, skips, refusals and errors. A collector built for another
    FreeBSD version is only a warning: the PF state ABI check decides compatibility."""
    status = dict((timing or {}).get("state_collector") or {})
    helper = status.get("helper") or {}
    incompatible = status.get("incompatible")
    if timing is None:
        state = "stopped"
    elif incompatible:
        state = "incompatible"
    elif status.get("last_error_at") and status["last_error_at"] >= (status.get("last_sample_at") or 0):
        state = "failed"
    else:
        state = "running" if status.get("last_sample_at") else "starting"
    status["state"] = state
    status["protocol"] = incompatible["protocol"] if incompatible else helper.get("protocol")
    status["expected_protocol"] = PROTOCOL_VERSION
    kernel = kernel_version()
    built = helper.get("freebsd_version")
    status["kernel_version"] = kernel
    status["version_warning"] = bool(kernel and built and kernel != built)
    return status


def database():
    status = geodb.status()
    # while MaxMind keeps failing, the map looks addresses up in the DB-IP Lite stand-in: show its files
    looked_up = geodb.lookup_provider(settings())
    if looked_up != status["active_provider"]:
        status.update(active_provider=looked_up, standin=True,
                      city=geodb.file_info(geodb.DATABASES[looked_up]["city"]),
                      asn=geodb.file_info(geodb.DATABASES[looked_up]["asn"]))
    paths = geodb.DATABASES[status["active_provider"]]
    for kind in ("city", "asn"):
        if status.get(kind):
            status[kind].update({"edition": paths["editions"][kind], "built": geodb.built(paths[kind])})
    # a download that died midway is not shown as running (its progress went stale)
    status["state"] = geodb_view(geodb.read_status())["state"]
    return status


def threat_feeds():
    in_use = {feed["name"] for feed in feeds.feeds_in_use()}
    downloaded = read_json(feeds.STATUS_FILE)
    return [{"name": feed["name"], "label": feed["label"], "in_use": feed["name"] in in_use,
             **{key: downloaded.get(feed["name"], {}).get(key) for key in ("count", "updated", "error")}}
            for feed in FEEDS]


def blacklist():
    status = abuseipdb.read_status()
    return {"configured": bool(abuseipdb_key()),
            **{key: status.get(key) for key in ("count", "count_v4", "count_v6", "updated", "attempted", "error")}}


def overview():
    state = collector()
    return {"version": installed_version(), "collector": state, "state_collector": state_collector(state.get("timing")),
            "database": database(),
            "feeds": threat_feeds(), "abuseipdb": blacklist(), "now": time.time()}


if __name__ == "__main__":
    secure_umask()
    print(json.dumps(overview()))
