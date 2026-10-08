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

"""Shared by the Firewall Map+ scripts: paths, service names, address helpers, file writing and
the log.

Kept free of heavy imports, since the dashboard's snapshot reader and threat history load it
on every request.
"""

import functools
import ipaddress
import json
import os
import syslog
import tempfile
import time

from . import classification

# ephemeral files (the snapshot, markers) and state that outlives a reboot (caches, threat history)
RUN_DIR = "/var/run/firewallmap"
STATE_DIR = "/var/db/firewallmap"
OUTPUT_FILE = f"{RUN_DIR}/flows.json"
# touched by the dashboard API on every read; the collector stops once nobody is watching
REQUEST_MARKER = f"{RUN_DIR}/last_request"
# touched only when a viewer has hostname lookups enabled; reverse DNS runs while it is fresh
HOSTNAME_MARKER = f"{RUN_DIR}/hostnames_request"
# how long the collector's last sample took, per phase (the Status page shows it)
COLLECTOR_TIMINGS = f"{RUN_DIR}/collector_timings.json"
RC_SCRIPT = "/usr/local/etc/rc.d/firewallmap"
CACHE_DB = f"{STATE_DIR}/cache.db"
# the threat review history (statuses and notes): operator data, kept apart from the caches so a
# damaged or deleted cache can never take it along
THREATS_DB = f"{STATE_DIR}/threats.db"
ABUSEIPDB_BLACKLIST = f"{STATE_DIR}/abuseipdb_blacklist.txt"
# saved map snapshots (one document and one small metadata file each), and the requests the
# camera button leaves for the collector, which holds every tracked flow in memory
SNAPSHOT_DIR = f"{STATE_DIR}/snapshots"
SNAPSHOT_REQUEST_DIR = f"{RUN_DIR}/snapshot_requests"
# the geolocation download's status (written by firewallmap_geodb.py, read on every map poll)
GEODB_STATUS = f"{STATE_DIR}/geodb.json"
# a download whose progress has not moved for this long is no longer running
GEODB_STALE_SECONDS = 30
# "Update now" downloads again even when the copy is fresh, but not again this soon after a
# successful download: repeated clicks must not spend the providers' daily download limits
FORCED_REPEAT_SECONDS = 300

PFCTL = "/sbin/pfctl"
RULES_DEBUG = "/tmp/rules.debug"
REPUTATION_MAX_AGE = 30 * 86400
# verdicts from AbuseIPDB lookups, kept longer than the full lookup results
REPUTATION_KIND = "reputation"
CGNAT = ipaddress.ip_network("100.64.0.0/10")
ICMP_PROTOCOLS = ("icmp", "ipv6-icmp")
SERVICES = {
    ("tcp", "20"): "FTP data", ("tcp", "21"): "FTP", ("tcp", "22"): "SSH", ("tcp", "25"): "SMTP",
    ("udp", "53"): "DNS", ("tcp", "53"): "DNS", ("tcp", "80"): "HTTP", ("udp", "123"): "NTP",
    ("tcp", "143"): "IMAP", ("tcp", "443"): "HTTPS", ("udp", "443"): "QUIC", ("udp", "500"): "IKE",
    ("tcp", "465"): "SMTPS", ("tcp", "587"): "Submission", ("tcp", "853"): "DNS over TLS",
    ("udp", "853"): "DNS over QUIC", ("tcp", "993"): "IMAPS", ("tcp", "995"): "POP3S",
    ("udp", "1194"): "OpenVPN", ("tcp", "1194"): "OpenVPN", ("udp", "3478"): "STUN/TURN",
    ("tcp", "3389"): "RDP", ("udp", "4500"): "IPsec NAT-T", ("tcp", "5223"): "Apple Push",
    ("tcp", "5228"): "Google Push", ("udp", "51820"): "WireGuard", ("tcp", "8080"): "HTTP alt",
    ("tcp", "8443"): "HTTPS alt", ("udp", "19302"): "Google STUN",
    # what scanners knock on most, so blocked attempts read as services too
    ("tcp", "23"): "Telnet", ("tcp", "110"): "POP3", ("tcp", "135"): "MS RPC", ("tcp", "139"): "NetBIOS",
    ("udp", "137"): "NetBIOS", ("tcp", "445"): "SMB", ("udp", "161"): "SNMP", ("tcp", "1433"): "MS SQL",
    ("tcp", "1723"): "PPTP", ("udp", "1900"): "SSDP", ("tcp", "2375"): "Docker API", ("tcp", "3306"): "MySQL",
    ("tcp", "5060"): "SIP", ("udp", "5060"): "SIP", ("tcp", "5432"): "PostgreSQL", ("tcp", "5900"): "VNC",
    ("tcp", "6379"): "Redis", ("tcp", "8291"): "MikroTik Winbox", ("tcp", "9200"): "Elasticsearch",
    ("tcp", "27017"): "MongoDB", ("udp", "11211"): "Memcached", ("tcp", "2222"): "SSH alt",
}


@functools.lru_cache(maxsize=256)
def protocol_name(number):
    """Resolve a PF protocol number using the system protocol database."""
    try:
        with open("/etc/protocols", encoding="ascii") as protocols:
            for line in protocols:
                fields = line.split("#", 1)[0].split()
                if len(fields) >= 2 and fields[1].isdigit() and int(fields[1]) == number:
                    return fields[0]
    except OSError:
        pass
    return str(number)


# files written by these scripts hold notes, host names and topology: not world-readable
FILE_MODE = 0o640


# Reporting: Firewall Map: Log File shows what the scripts send to syslog under this name. Log what
# helps someone diagnose the plugin (what started, stopped, downloaded or failed, and why), never
# once per sample, and never a key.
syslog.openlog("firewallmap", syslog.LOG_PID, syslog.LOG_DAEMON)


def log_error(message):
    syslog.syslog(syslog.LOG_ERR, message)


def log_warning(message):
    syslog.syslog(syslog.LOG_WARNING, message)


def log_notice(message):
    syslog.syslog(syslog.LOG_NOTICE, message)


def secure_umask():
    """Directories and files these scripts create: owner and group only (see FILE_MODE)."""
    os.umask(0o027)


def is_icmp(protocol):
    return protocol in ICMP_PROTOCOLS


def service_port_label(protocol, port):
    """'443/tcp' for the summary sentence; ICMP has no port."""
    if is_icmp(protocol) or not port:
        return None
    return f"{port}/{protocol}"


def service_name(protocol, port):
    """Name the responder side of a connection (the service being used)."""
    if is_icmp(protocol):
        return "ICMP"
    if port is None:
        return protocol.upper()
    return SERVICES.get((protocol, port), f"{protocol.upper()}/{port}")


@functools.lru_cache(maxsize=65536)
def ip_object(value):
    """ipaddress.ip_address(value), parsed once per address (the same few thousand addresses are
    looked up on every sample); raises ValueError for anything else, as ip_address does."""
    return ipaddress.ip_address(value)


def public_ip(value):
    """Globally reachable unicast (lib/classification.py: the plugin's own table)."""
    return classification.address_flags(value) == classification.PUBLIC


def private_ip(value):
    """Site-internal: not globally reachable, or shared address space (CGNAT, Tailscale and
    other VPN overlays); loopback is neither (lib/classification.py)."""
    return classification.address_flags(value) == classification.PRIVATE


@functools.lru_cache(maxsize=65536)
def normalize_ip(value):
    """Canonical address text, or the original value when it is not an address."""
    try:
        return str(ipaddress.ip_address(str(value).split("%", 1)[0]))
    except (TypeError, ValueError):
        return value


def write_text(path, text, durable=False):
    """Write atomically, through a unique temporary file, so readers never see a partial
    document and two writers never share a temporary name. durable: also survive a crash or
    power loss (the data and the rename reach the disk before returning), for documents kept
    as records such as saved snapshots; live, regenerated files skip the cost."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=f".{os.path.basename(path)}.")
    try:
        # mkstemp creates the file 0600; give it the mode secure_umask() means (reading the umask
        # would mean setting it, and the umask is process-wide: a thread could create a file then)
        os.fchmod(handle, FILE_MODE)
        with os.fdopen(handle, "w") as output:
            output.write(text)
            if durable:
                output.flush()
                os.fsync(output.fileno())
        os.replace(temporary, path)
        if durable:
            directory_handle = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_handle)
            finally:
                os.close(directory_handle)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_json(path, payload, durable=False):
    """NaN or infinity raise ValueError instead of producing a document JSON readers reject."""
    write_text(path, json.dumps(payload, separators=(",", ":"), allow_nan=False), durable)


def read_json(path):
    """A JSON document written by write_json, or {} when missing or damaged."""
    try:
        with open(path) as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def requested(marker, seconds, now=None):
    try:
        return (time.time() if now is None else now) - os.stat(marker).st_mtime < seconds
    except OSError:
        return False


def geodb_view(status, now=None):
    """What a map viewer is told about the geolocation download: running (with progress), failed
    (each database's error and when it is tried again) or idle. Never the license key: the messages
    were scrubbed when written."""
    now = time.time() if now is None else now
    view = {"now": now, "state": "idle"}
    progress = status.get("progress") or {}
    if status.get("state") == "downloading" and now - (progress.get("updated") or 0) < GEODB_STALE_SECONDS:
        view.update(state="downloading", edition=progress.get("edition"), done=progress.get("done") or 0,
                    total=progress.get("total"))
        return view
    errors = status.get("errors")
    if errors is None and status.get("last_error") not in (None, "maxmind_key_missing"):
        # written by an older version: one message, no classification
        errors = [{"kind": None, "edition": None, "code": "other", "message": status["last_error"]}]
    if errors:
        view.update(state="failed", errors=errors, retry_at=status.get("next_retry"), provider=status.get("provider"))
        if (status.get("fallback") or {}).get("active"):
            # the map works on DB-IP Lite meanwhile
            view["fallback"] = status["fallback"]["provider"]
    return view


def geodb_retry_due(status, now=None):
    """A failed download whose wait is over (and that is not running now)."""
    view = geodb_view(status, now)
    return view["state"] == "failed" and (view.get("retry_at") or 0) <= view["now"]


def host_port(address, port):
    """"192.0.2.1:443", "[2001:db8::1]:443", or the bare address without a port."""
    if not port:
        return address
    return f"[{address}]:{port}" if ":" in str(address) else f"{address}:{port}"


def split_host_port(text):
    """(address, port or "") from host_port()'s form; a bare address has no port."""
    text = str(text or "")
    if text.startswith("["):
        address, _, rest = text[1:].partition("]")
        return address, rest.lstrip(":")
    if text.count(":") == 1:
        address, _, port = text.partition(":")
        return address, port
    return text, ""


def connection_target(protocol, address, port):
    """'tcp|192.168.1.2|443': what a remote side connected to (an inside host or the firewall)."""
    return f"{protocol}|{address}|{'' if is_icmp(protocol) else port or ''}"


def location_fields(location):
    """The geolocation fields every map entry carries for an address."""
    return {
        "lat": location["lat"],
        "lon": location["lon"],
        "city": location.get("city") or location.get("region"),
        "country": location.get("country_name") or location.get("country"),
        "country_code": location.get("country"),
        "asn": location.get("asn"),
        "as_org": location.get("as_org"),
    }
