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

"""CrowdSec for Firewall Map+: its bans (decisions) per address, read with cscli.

The CrowdSec plugin bans addresses through its own PF tables (crowdsec_blocklists,
crowdsec6_blocklists), which classify like any threat list. This module adds why: each ban's
reason (scenario), where it came from (detected on this firewall, banned by hand, a blocklist
CrowdSec subscribes to, or CrowdSec's community blocklist), its type and when it ends.

cscli reads CrowdSec's local API with the credentials the plugin set up, so Firewall Map+
registers nothing with CrowdSec. All the bans are read in one call (about a second for 20,000),
in a thread, every REFRESH_SECONDS; a lookup answers from the last read.
"""

import ipaddress
import json
import os
import re
import subprocess
import threading
import time

from .common import log_warning, public_ip

CSCLI = "/usr/local/bin/cscli"
# the CrowdSec plugin's PF tables
TABLES = ("crowdsec_blocklists", "crowdsec6_blocklists")
LIST = "CrowdSec"
# an address CrowdSec banned for what it detected on this firewall: evidence of its own
LOCAL_LIST = "CrowdSec (detected here)"
REFRESH_SECONDS = 300
# a failed read is tried again sooner
RETRY_SECONDS = 60
TIMEOUT_SECONDS = 60
# what a read keeps at most, whatever cscli returns
MAX_DECISIONS = 500000
MAX_RANGES = 10000
MAX_TEXT = 200
# where a ban came from, strongest first (cscli's origins)
ORIGINS = {"crowdsec": "local", "cscli": "manual", "console": "manual", "cscli-import": "manual",
           "lists": "list", "CAPI": "community"}
STRENGTH = {"local": 4, "manual": 3, "list": 2, "community": 1, "other": 0}
# a ban made from the map: its reason names where it was made
BAN_REASON = "firewallmap: banned from Firewall Map+"
DURATIONS = ("1h", "4h", "24h", "168h", "720h")
_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|h|m|s)")
_WHOLE_DURATION = re.compile(r"(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|h|m|s))+")
_UNITS = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 1e-3, "us": 1e-6, "µs": 1e-6, "ns": 1e-9}


class CrowdSecError(Exception):
    pass


def available():
    return os.access(CSCLI, os.X_OK)


def duration_seconds(text):
    """A Go duration as cscli prints it ("165h23m57.5s"), in seconds; None when unreadable or
    negative (an expired decision)."""
    if not isinstance(text, str) or not _WHOLE_DURATION.fullmatch(text):
        return None
    return sum(float(number) * _UNITS[unit] for number, unit in _DURATION.findall(text))


def _text(value):
    return value[:MAX_TEXT] if isinstance(value, str) else ""


def origin_kind(origin):
    return ORIGINS.get(origin, "other")


def parse_decisions(alerts, now):
    """({address: ban}, [(network, ban)]) from `cscli decisions list -a -o json`.

    Each address keeps its strongest ban (where it came from, then the latest end); a ban is
    {"reason", "origin", "type", "until", "id", "bans"} with "origin" one of local, manual, list,
    community or other, and "bans" the number of bans the address has. Simulated decisions
    (CrowdSec only logs them) and scopes other than addresses and ranges are left out."""
    addresses, ranges = {}, {}
    count = 0
    for alert in alerts if isinstance(alerts, list) else []:
        if not isinstance(alert, dict):
            continue
        for decision in alert.get("decisions") or []:
            if not isinstance(decision, dict) or decision.get("simulated"):
                continue
            count += 1
            if count > MAX_DECISIONS:
                break
            scope = str(decision.get("scope") or "").lower()
            value = decision.get("value")
            remaining = duration_seconds(decision.get("duration"))
            if not isinstance(value, str) or remaining is None or remaining <= 0:
                continue
            ban = {"reason": _text(decision.get("scenario")), "origin": origin_kind(decision.get("origin")),
                   "type": _text(decision.get("type")) or "ban", "until": round(now + remaining),
                   "id": decision.get("id") if isinstance(decision.get("id"), int) else None}
            try:
                if scope == "ip":
                    target, key = addresses, str(ipaddress.ip_address(value))
                elif scope == "range":
                    network = ipaddress.ip_network(value, strict=False)
                    if network.num_addresses == 1:
                        target, key = addresses, str(network.network_address)
                    else:
                        target, key = ranges, network
                else:
                    continue
            except ValueError:
                continue
            if target is ranges and key not in ranges and len(ranges) >= MAX_RANGES:
                continue
            old = target.get(key)
            ban["bans"] = (old["bans"] if old else 0) + 1
            if old is None or (STRENGTH[ban["origin"]], ban["until"]) > (STRENGTH[old["origin"]], old["until"]):
                target[key] = ban
            else:
                old["bans"] = ban["bans"]
    return addresses, sorted(ranges.items(), key=lambda item: -item[0].prefixlen)


def run_cscli(arguments, timeout=TIMEOUT_SECONDS):
    """cscli's JSON answer to `arguments` (raises CrowdSecError)."""
    try:
        result = subprocess.run([CSCLI, *arguments, "-o", "json"], capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CrowdSecError(f"cscli did not answer: {error}") from error
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip().splitlines()
        raise CrowdSecError(message[-1][:MAX_TEXT] if message else f"cscli exited with {result.returncode}")
    try:
        return json.loads(result.stdout or "null")
    except ValueError as error:
        raise CrowdSecError("cscli answered with invalid JSON") from error


class CrowdSec:
    """The bans CrowdSec holds now, per address, refreshed in the background."""

    def __init__(self, reader=None, clock=time.time):
        self.reader = reader or (lambda: run_cscli(["decisions", "list", "-a"]))
        self.clock = clock
        self.enabled = False
        self.addresses = {}
        self.ranges = []
        self.local = set()
        self.updated = None
        self.attempted = None
        self.error = None
        self._thread = None

    def configure(self, enabled):
        self.enabled = bool(enabled) and available()
        if not self.enabled:
            self.addresses, self.ranges, self.local = {}, [], set()

    def refresh(self, now=None, wait=False):
        """Start a read when one is due (the map keeps answering from the last one)."""
        if not self.enabled or (self._thread is not None and self._thread.is_alive()):
            return
        now = self.clock() if now is None else now
        if self.attempted is not None:
            due = RETRY_SECONDS if self.error else REFRESH_SECONDS
            if now - self.attempted < due:
                return
        self.attempted = now
        self._thread = threading.Thread(target=self._read, name="firewallmap-crowdsec", daemon=True)
        self._thread.start()
        if wait:
            self._thread.join()

    def _read(self):
        try:
            alerts = self.reader()
            addresses, ranges = parse_decisions(alerts, self.clock())
        except CrowdSecError as error:
            if self.error != str(error):
                log_warning(f"could not read the CrowdSec bans: {error}")
            self.error = str(error)
            return
        except Exception as error:  # a reader bug must not stop the collector
            self.error = f"could not read the CrowdSec bans: {error}"
            log_warning(self.error)
            return
        # one assignment each: a lookup sees either the old read or the new one
        self.addresses, self.ranges = addresses, ranges
        self.local = {address for address, ban in addresses.items() if ban["origin"] == "local"}
        self.updated, self.error = self.clock(), None

    def lookup(self, address):
        """The address's strongest ban still in force, or None."""
        if not self.enabled or not address:
            return None
        now = self.clock()
        ban = self.addresses.get(address)
        if ban is None and self.ranges:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                return None
            ban = next((item for network, item in self.ranges if ip.version == network.version and ip in network),
                       None)
        return ban if ban is not None and ban["until"] > now else None

    def detected(self, address):
        """True when CrowdSec banned the address for what it detected on this firewall."""
        ban = self.lookup(address) if address in self.local else None
        return ban is not None

    def status(self):
        return {"available": available(), "enabled": self.enabled, "bans": len(self.addresses),
                "ranges": len(self.ranges), "local": len(self.local), "updated": self.updated,
                "attempted": self.attempted, "error": self.error}


def valid_target(address):
    """The address an operator may ban or unban: one public address."""
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        raise CrowdSecError("not an IP address")
    if not public_ip(address):
        raise CrowdSecError("only public addresses can be banned")
    return address


def ban(address, duration, reason=None):
    """Ban one address with CrowdSec (origin cscli); the CrowdSec plugin applies it to its tables."""
    address = valid_target(address)
    if duration not in DURATIONS:
        raise CrowdSecError("unsupported duration")
    reason = (reason or "").strip()[:MAX_TEXT] or BAN_REASON
    try:
        result = subprocess.run([CSCLI, "decisions", "add", "-i", address, "-d", duration, "-t", "ban", "-R", reason],
                                capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CrowdSecError(f"cscli did not answer: {error}") from error
    if result.returncode != 0:
        raise CrowdSecError((result.stderr or result.stdout or "cscli failed").strip().splitlines()[-1][:MAX_TEXT])
    return {"address": address, "duration": duration, "reason": reason}


def unban(address):
    """Remove every ban CrowdSec holds for one address. A community or list ban may come back with
    the next blocklist update; CrowdSec's allowlists keep an address unbanned."""
    address = valid_target(address)
    try:
        result = subprocess.run([CSCLI, "decisions", "delete", "-i", address],
                                capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CrowdSecError(f"cscli did not answer: {error}") from error
    if result.returncode != 0:
        raise CrowdSecError((result.stderr or result.stdout or "cscli failed").strip().splitlines()[-1][:MAX_TEXT])
    match = re.search(r"(\d+) decision", (result.stdout or "") + (result.stderr or ""))
    return {"address": address, "removed": int(match.group(1)) if match else None}


MAX_ALERTS = 10


def alerts_for(address, now=None):
    """What CrowdSec saw from one address (its alerts, newest first) and the bans it holds, for
    Investigate: {"bans": [...], "alerts": [...]}."""
    address = valid_target(address)
    now = time.time() if now is None else now
    decisions = run_cscli(["decisions", "list", "-a", "-i", address]) or []
    addresses, _ranges = parse_decisions(decisions, now)
    # each blocklist update repeats its bans: one entry per reason, origin and type, ending last
    bans = {}
    for alert in decisions if isinstance(decisions, list) else []:
        for decision in (alert.get("decisions") or []) if isinstance(alert, dict) else []:
            remaining = duration_seconds(decision.get("duration")) if isinstance(decision, dict) else None
            if remaining is None or remaining <= 0 or decision.get("simulated"):
                continue
            ban = {"reason": _text(decision.get("scenario")), "origin": origin_kind(decision.get("origin")),
                   "type": _text(decision.get("type")) or "ban", "until": round(now + remaining)}
            key = (ban["reason"], ban["origin"], ban["type"])
            if key not in bans or ban["until"] > bans[key]["until"]:
                bans[key] = ban
    bans = sorted(bans.values(), key=lambda item: (-STRENGTH[item["origin"]], -item["until"]))
    seen = []
    raw = run_cscli(["alerts", "list", "-i", address, "-l", str(MAX_ALERTS)]) or []
    for alert in raw if isinstance(raw, list) else []:
        if not isinstance(alert, dict):
            continue
        source = alert.get("source") if isinstance(alert.get("source"), dict) else {}
        events = alert.get("events_count")
        seen.append({"scenario": _text(alert.get("scenario")), "message": _text(alert.get("message")),
                     "events": events if isinstance(events, int) else None,
                     "start": _text(alert.get("start_at")), "stop": _text(alert.get("stop_at")),
                     "as": _text(source.get("as_name")), "country": _text(source.get("cn"))})
    return {"bans": bans[:MAX_ALERTS], "alerts": seen[:MAX_ALERTS], "banned": address in addresses}
