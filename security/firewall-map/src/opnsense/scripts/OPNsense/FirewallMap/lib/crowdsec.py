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

"""CrowdSec for Firewall Map+: its bans (decisions) per address.

The CrowdSec plugin bans addresses through its own PF tables (crowdsec_blocklists,
crowdsec6_blocklists), which classify like any threat list. This module adds why: each ban's
reason (scenario), where it came from (detected on this firewall, banned by hand, a blocklist
CrowdSec subscribes to, or CrowdSec's community blocklist), its type and when it ends.

The bans come from CrowdSec's decision stream, the interface its bouncers use: Firewall Map+
registers itself as a bouncer named "firewallmap" (cscli bouncers add, a read-only key kept in a
root-only file), reads every ban once, then only what changed every STREAM_SECONDS (a few
milliseconds), and resynchronizes every RESYNC_SECONDS. When the local API cannot be used, all
the bans are read with cscli every REFRESH_SECONDS instead. Reads run in a thread; a lookup
answers from the last one. Banning, unbanning and Investigate use cscli.
"""

import ipaddress
import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request

from .common import STATE_DIR, log_notice, log_warning, public_ip

CSCLI = "/usr/local/bin/cscli"
# the CrowdSec plugin's PF tables
TABLES = ("crowdsec_blocklists", "crowdsec6_blocklists")
LIST = "CrowdSec"
# an address CrowdSec banned for what it detected on this firewall: evidence of its own
LOCAL_LIST = "CrowdSec (detected here)"
# with the decision stream: what changed, every STREAM_SECONDS; everything again every RESYNC_SECONDS
STREAM_SECONDS = 15
RESYNC_SECONDS = 6 * 3600
# without it: every ban, read with cscli
REFRESH_SECONDS = 300
BOUNCER = "firewallmap"
KEY_FILE = f"{STATE_DIR}/crowdsec.key"
CONFIG_FILE = "/usr/local/etc/crowdsec/config.yaml"
DEFAULT_API = "127.0.0.1:8080"
# the first answer of the stream holds every ban (2.5 MB for 20,000): far larger is not one
MAX_STREAM_BYTES = 256 * 1024 * 1024
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


def ban_of(decision, now):
    """(target, ban) of one decision: target an address string or a network; None for what the
    map does not use (simulated decisions, which CrowdSec only logs, ended ones, other scopes)."""
    if not isinstance(decision, dict) or decision.get("simulated"):
        return None
    scope = str(decision.get("scope") or "").lower()
    value = decision.get("value")
    remaining = duration_seconds(decision.get("duration"))
    if not isinstance(value, str) or remaining is None or remaining <= 0:
        return None
    try:
        if scope == "ip":
            target = str(ipaddress.ip_address(value))
        elif scope == "range":
            target = ipaddress.ip_network(value, strict=False)
            if target.num_addresses == 1:
                target = str(target.network_address)
        else:
            return None
    except ValueError:
        return None
    return target, {"reason": _text(decision.get("scenario")), "origin": origin_kind(decision.get("origin")),
                    "type": _text(decision.get("type")) or "ban", "until": round(now + remaining),
                    "id": decision.get("id") if isinstance(decision.get("id"), int) else None}


def strongest(bans):
    """The ban that speaks for a target: where it came from first, then the latest end."""
    best = max(bans, key=lambda ban: (STRENGTH[ban["origin"]], ban["until"]))
    return {**best, "bans": len(bans)}


class Bans:
    """Every ban in force, per address and per range, kept from whole reads or stream changes."""

    def __init__(self):
        self.by_target = {}   # target -> {decision id (or a counter): ban}
        self.addresses = {}   # address -> strongest ban
        self.ranges = []      # [(network, strongest ban)], narrowest first
        self.local = set()    # addresses banned for what CrowdSec detected here
        self._anonymous = 0
        self._ranges_changed = False

    def copy(self):
        """A copy to change while readers keep using this one (the containers are copied; a
        target's bans are copied when changed)."""
        other = Bans()
        other.by_target = dict(self.by_target)
        other.addresses, other.ranges, other.local = dict(self.addresses), self.ranges, set(self.local)
        other._anonymous = self._anonymous
        return other

    def add(self, decision, now):
        found = ban_of(decision, now)
        if found is None:
            return
        target, ban = found
        if isinstance(target, str) or target in self.by_target or len(self.by_target) - len(self.addresses) < MAX_RANGES:
            entry = self.by_target[target] = dict(self.by_target.get(target) or {})
            if ban["id"] is None:
                self._anonymous -= 1
            entry[ban["id"] if ban["id"] is not None else self._anonymous] = ban
            self._update(target)

    def delete(self, decision):
        """A decision the stream says was removed or ended (by id; its value names the target)."""
        if not isinstance(decision, dict):
            return
        value, scope = decision.get("value"), str(decision.get("scope") or "").lower()
        try:
            target = str(ipaddress.ip_address(value)) if scope == "ip" else ipaddress.ip_network(value, strict=False)
        except (TypeError, ValueError):
            return
        if not isinstance(target, str) and target.num_addresses == 1:
            target = str(target.network_address)
        entry = self.by_target.get(target)
        if entry is not None and decision.get("id") in entry:
            entry = self.by_target[target] = dict(entry)
            del entry[decision.get("id")]
            self._update(target)

    def _update(self, target):
        entry = self.by_target.get(target)
        if not entry:
            self.by_target.pop(target, None)
        if isinstance(target, str):
            if entry:
                self.addresses[target] = strongest(list(entry.values()))
                if self.addresses[target]["origin"] == "local":
                    self.local.add(target)
                else:
                    self.local.discard(target)
            else:
                self.addresses.pop(target, None)
                self.local.discard(target)
        else:
            self._ranges_changed = True

    def finish(self):
        """After a batch of changes: the ranges, rebuilt whole so a reader sees a complete list."""
        if self._ranges_changed:
            self.ranges = sorted(((network, strongest(list(bans.values()))) for network, bans in self.by_target.items()
                                  if not isinstance(network, str)), key=lambda item: -item[0].prefixlen)
            self._ranges_changed = False


def bans_from_alerts(alerts, now):
    """Every ban of `cscli decisions list -a -o json` (alerts, each with its decisions)."""
    bans = Bans()
    count = 0
    for alert in alerts if isinstance(alerts, list) else []:
        for decision in (alert.get("decisions") or []) if isinstance(alert, dict) else []:
            count += 1
            if count > MAX_DECISIONS:
                break
            bans.add(decision, now)
    bans.finish()
    return bans


def parse_decisions(alerts, now):
    """({address: ban}, [(network, ban)]) from `cscli decisions list -a -o json` (alerts, each
    with its decisions). Each address keeps its strongest ban (where it came from, then the latest
    end); a ban is {"reason", "origin", "type", "until", "id", "bans"} with "origin" one of local,
    manual, list, community or other, and "bans" the number of bans the address has."""
    bans = bans_from_alerts(alerts, now)
    return bans.addresses, bans.ranges


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


def api_address(path=CONFIG_FILE):
    """host:port of CrowdSec's local API (api.server.listen_uri in its configuration)."""
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                match = re.match(r"\s+listen_uri:\s*['\"]?([^'\"\s#]+)", line)
                if match:
                    return match.group(1).removeprefix("http://")
    except OSError:
        pass
    return DEFAULT_API


def read_key(path=KEY_FILE):
    try:
        with open(path) as handle:
            key = handle.read().strip()
    except OSError:
        return None
    return key if re.fullmatch(r"[A-Za-z0-9+/=_-]{16,256}", key) else None


def write_key(key, path=KEY_FILE):
    """Root-only from the start: created 0600 under a temporary name, then renamed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(key + "\n")
    os.replace(temporary, path)


def register(path=KEY_FILE):
    """Register Firewall Map+ as a bouncer (a key that can only read the bans) and keep its key.
    A registration whose key was lost is replaced."""
    try:
        subprocess.run([CSCLI, "bouncers", "delete", BOUNCER], capture_output=True, timeout=TIMEOUT_SECONDS,
                       check=False)
        result = subprocess.run([CSCLI, "bouncers", "add", BOUNCER, "-o", "raw"], capture_output=True, text=True,
                                timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CrowdSecError(f"cscli did not answer: {error}") from error
    key = (result.stdout or "").strip()
    if result.returncode != 0 or not re.fullmatch(r"[A-Za-z0-9+/=_-]{16,256}", key):
        message = (result.stderr or "").strip().splitlines()
        raise CrowdSecError(f"could not register with CrowdSec: {message[-1][:MAX_TEXT] if message else 'no key'}")
    write_key(key, path)
    log_notice(f"registered with CrowdSec as the bouncer {BOUNCER}")
    return key


def unregister(path=KEY_FILE):
    """Remove the bouncer registration and its key (Use CrowdSec turned off, plugin removed)."""
    if not os.path.exists(path):
        return False
    if available():
        subprocess.run([CSCLI, "bouncers", "delete", BOUNCER], capture_output=True, timeout=TIMEOUT_SECONDS,
                       check=False)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    log_notice(f"removed the CrowdSec bouncer {BOUNCER}")
    return True


class StreamRefused(CrowdSecError):
    """The local API refused the key (deleted or replaced registration)."""


def stream(key, startup, address=None, timeout=TIMEOUT_SECONDS):
    """One answer of the decision stream: {"new": [...], "deleted": [...]}."""
    request = urllib.request.Request(
        f"http://{address or api_address()}/v1/decisions/stream?startup={'true' if startup else 'false'}",
        headers={"X-Api-Key": key, "User-Agent": "firewallmap"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_STREAM_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise StreamRefused(f"the local API refused the key (HTTP {error.code})") from error
        raise CrowdSecError(f"the local API answered HTTP {error.code}") from error
    except (OSError, ValueError) as error:
        raise CrowdSecError(f"the local API did not answer: {error}") from error
    if len(body) > MAX_STREAM_BYTES:
        raise CrowdSecError("the local API answer is too large")
    try:
        answer = json.loads(body or b"{}")
    except ValueError as error:
        raise CrowdSecError("the local API answered with invalid JSON") from error
    if not isinstance(answer, dict):
        raise CrowdSecError("the local API answered with something else than changes")
    return {"new": answer.get("new") or [], "deleted": answer.get("deleted") or []}


class CrowdSec:
    """The bans CrowdSec holds now, per address, kept current in the background.

    `streamer(key, startup)` and `reader()` (every ban, as cscli lists them) are the two ways
    to read them; `registrar()` returns a bouncer key. The defaults talk to CrowdSec."""

    def __init__(self, reader=None, streamer=None, registrar=None, key_reader=None, clock=time.time):
        self.reader = reader or (lambda: run_cscli(["decisions", "list", "-a"]))
        self.streamer = streamer or stream
        self.registrar = registrar or register
        self.key_reader = key_reader or read_key
        self.clock = clock
        self.enabled = False
        self.bans = Bans()
        self.mode = None          # "stream" or "cscli", the way the last read was made
        self.key = None
        self.synced = None        # when the stream last sent every ban
        self.updated = None
        self.attempted = None
        self.error = None
        self._thread = None

    # what lookups read: replaced whole by the reading thread
    @property
    def addresses(self):
        return self.bans.addresses

    @property
    def ranges(self):
        return self.bans.ranges

    @property
    def local(self):
        return self.bans.local

    def configure(self, enabled):
        enabled = bool(enabled) and available()
        if self.enabled and not enabled:
            self._join()
            self.bans, self.mode, self.key, self.synced = Bans(), None, None, None
            self.attempted = self.updated = None
        if not enabled and os.path.exists(KEY_FILE):
            try:
                unregister()
            except (OSError, subprocess.SubprocessError) as error:
                log_warning(f"could not remove the CrowdSec bouncer: {error}")
        self.enabled = enabled

    def _join(self):
        if self._thread is not None:
            self._thread.join(TIMEOUT_SECONDS)

    def refresh(self, now=None, wait=False):
        """Start a read when one is due (the map keeps answering from the last one)."""
        if not self.enabled or (self._thread is not None and self._thread.is_alive()):
            return
        now = self.clock() if now is None else now
        if self.attempted is not None:
            due = RETRY_SECONDS if self.error else STREAM_SECONDS if self.mode == "stream" else REFRESH_SECONDS
            if now - self.attempted < due:
                return
        self.attempted = now
        self._thread = threading.Thread(target=self._read, name="firewallmap-crowdsec", daemon=True)
        self._thread.start()
        if wait:
            self._thread.join()

    def _read(self):
        try:
            try:
                self._read_stream()
                self.mode = "stream"
            except CrowdSecError as error:
                # the local API cannot be used: every ban through cscli, until it can
                if self.mode != "cscli":
                    log_warning(f"reading the CrowdSec bans with cscli: {error}")
                self.key, self.synced = None, None
                self._read_all()
                self.mode = "cscli"
        except CrowdSecError as error:
            if self.error != str(error):
                log_warning(f"could not read the CrowdSec bans: {error}")
            self.error = str(error)
            return
        except Exception as error:  # a reader bug must not stop the collector
            self.error = f"could not read the CrowdSec bans: {error}"
            log_warning(self.error)
            return
        self.updated, self.error = self.clock(), None

    def _read_all(self):
        self.bans = bans_from_alerts(self.reader(), self.clock())

    def _read_stream(self):
        now = self.clock()
        if self.key is None:
            self.key = self.key_reader() or self.registrar()
        startup = self.synced is None or now - self.synced >= RESYNC_SECONDS
        try:
            changes = self.streamer(self.key, startup)
        except StreamRefused:
            # a deleted or replaced registration: register again, then read everything
            self.key, startup = self.registrar(), True
            changes = self.streamer(self.key, startup)
        if startup:
            bans = Bans()
            for decision in changes["new"][:MAX_DECISIONS]:
                bans.add(decision, now)
            bans.finish()
            self.bans, self.synced = bans, now
            return
        if not changes["new"] and not changes["deleted"]:
            return
        # the changes go into a copy, swapped in whole: the collector iterates the bans meanwhile
        bans = self.bans.copy()
        for decision in changes["deleted"]:
            bans.delete(decision)
        for decision in changes["new"][:MAX_DECISIONS]:
            bans.add(decision, now)
        bans.finish()
        self.bans = bans

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
        return {"available": available(), "enabled": self.enabled, "mode": self.mode, "bans": len(self.addresses),
                "ranges": len(self.ranges), "local": len(self.local), "updated": self.updated,
                "synced": self.synced, "attempted": self.attempted, "error": self.error}


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
