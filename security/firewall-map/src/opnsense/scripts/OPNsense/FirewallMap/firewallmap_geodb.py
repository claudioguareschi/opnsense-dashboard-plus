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

"""Download and update the local geolocation databases used by Firewall Map+.

    firewallmap_geodb.py status          JSON status (never includes the license key)
    firewallmap_geodb.py update [force]  download when missing or older than update_days
    firewallmap_geodb.py update retry    the same, now: no waiting out an earlier failure (a new
                                         key, or "Retry now")

MaxMind GeoLite2 needs a license key: the plugin's own key when set, otherwise the key
of a MaxMind GeoIP alias URL (Firewall > Aliases > GeoIP settings). DB-IP Lite needs no
key. Downloads go only to the provider; endpoint addresses are never sent anywhere.
"""

import errno
import fcntl
import gzip
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import socket
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ElementTree
from configparser import ConfigParser
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwmap_common import GEODB_STATUS, STATE_DIR, read_json, secure_umask, write_json  # noqa: E402


CONFIG_XML = "/conf/config.xml"
GEOIP_ALIAS_CONF = "/usr/local/etc/filter_geoip.conf"
GEOIP_DIR = "/usr/local/share/GeoIP"
STATUS_FILE = GEODB_STATUS
LOCK_FILE = f"{STATE_DIR}/geodb.lock"
MMDBLOOKUP = "/usr/local/bin/mmdblookup"
MAXMIND_URL = "https://download.maxmind.com/app/geoip_download"
DBIP_URL = "https://download.db-ip.com/free/{edition}-{month}.mmdb.gz"
TIMEOUT = 120
# after failed downloads, automatic retries wait longer each time: a new MaxMind key that takes a
# few minutes to activate works almost at once, a lasting problem is not hammered (a forced or
# retry update always runs)
RETRY_STEPS = (60, 120, 300, 900)
# progress is written at most this often while downloading
PROGRESS_SECONDS = 0.5

DATABASES = {
    "maxmind": {
        "city": f"{GEOIP_DIR}/GeoLite2-City.mmdb",
        "asn": f"{GEOIP_DIR}/GeoLite2-ASN.mmdb",
        "editions": {"city": "GeoLite2-City", "asn": "GeoLite2-ASN"},
    },
    # paid GeoIP2 City (same format, better accuracy); AS data still comes from GeoLite2-ASN
    "maxmind_paid": {
        "city": f"{GEOIP_DIR}/GeoIP2-City.mmdb",
        "asn": f"{GEOIP_DIR}/GeoLite2-ASN.mmdb",
        "editions": {"city": "GeoIP2-City", "asn": "GeoLite2-ASN"},
    },
    "dbip": {
        "city": f"{GEOIP_DIR}/dbip-city-lite.mmdb",
        "asn": f"{GEOIP_DIR}/dbip-asn-lite.mmdb",
        "editions": {"city": "dbip-city-lite", "asn": "dbip-asn-lite"},
    },
}


def settings(path=CONFIG_XML):
    """Read the plugin's firewall-wide settings straight from config.xml."""
    values = {"provider": "auto", "license_key": "", "update_days": 3, "threat_lists": "",
              "record_threats": "1", "blocklist_aliases": "0"}
    try:
        general = ElementTree.parse(path).getroot().find("./OPNsense/FirewallMap/general")
    except (OSError, ElementTree.ParseError):
        general = None
    if general is not None:
        for field in values:
            node = general.find(field)
            if node is not None and node.text:
                values[field] = node.text.strip()
    try:
        values["update_days"] = max(1, int(values["update_days"]))
    except ValueError:
        values["update_days"] = 3
    if values["provider"] not in DATABASES and values["provider"] != "auto":
        values["provider"] = "auto"
    return values


def effective_provider(values):
    """'auto' uses MaxMind GeoLite2 when a key is available, otherwise the keyless DB-IP Lite."""
    if values["provider"] != "auto":
        return values["provider"]
    return "maxmind" if license_key(values)[0] else "dbip"


def lookup_provider(values):
    """The databases to look addresses up in: the chosen provider's, or DB-IP Lite while a MaxMind
    download keeps failing and DB-IP was fetched as a stand-in (see update)."""
    provider = effective_provider(values)
    if provider.startswith("maxmind") and not os.path.exists(DATABASES[provider]["city"]) \
            and "dbip" in DATABASES and os.path.exists(DATABASES["dbip"]["city"]):
        return "dbip"
    return provider


def alias_license_key(path=GEOIP_ALIAS_CONF):
    """The key embedded in a MaxMind GeoIP alias download URL, if one is configured."""
    config = ConfigParser()
    try:
        config.read(path)
        url = config.get("settings", "url", fallback="")
    except Exception:
        return None
    parsed = urlparse(url.strip())
    if not parsed.netloc.endswith("maxmind.com"):
        return None
    key = parse_qs(parsed.query).get("license_key", [""])[0].strip()
    return key or None


def license_key(values):
    """Return (key, source) where source is 'plugin', 'alias' or None."""
    if values["license_key"]:
        return values["license_key"], "plugin"
    key = alias_license_key()
    return (key, "alias") if key else (None, None)


def file_info(path):
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return {"updated_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(), "size": stat.st_size}


def read_status():
    return read_json(STATUS_FILE)


def write_status(payload):
    write_json(STATUS_FILE, payload)


def status():
    values = settings()
    _, key_source = license_key(values)
    provider = effective_provider(values)
    paths = DATABASES[provider]
    last = read_status()
    return {
        "provider": values["provider"],
        "active_provider": provider,
        "update_days": values["update_days"],
        "key_source": key_source,
        "key_required": values["provider"].startswith("maxmind"),
        "city": file_info(paths["city"]),
        "asn": file_info(paths["asn"]),
        "last_attempt": last.get("last_attempt"),
        "last_error": last.get("last_error"),
        "errors": last.get("errors"),
        "next_retry": last.get("next_retry"),
    }


def validate(path, probe):
    """Make sure a downloaded database answers a lookup before it replaces the current one."""
    result = subprocess.run(
        [MMDBLOOKUP, "--file", path, "--ip", "8.8.8.8", *probe],
        capture_output=True, check=False, text=True, timeout=10,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("downloaded database failed validation")


def download(url, target, progress=None):
    """Fetch `url` into `target`, telling `progress(done, total)` as it goes (total may be None)."""
    request = urllib.request.Request(url, headers={"User-Agent": "OPNsense-FirewallMap"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response, open(target, "wb") as handle:
        total = int(response.headers.get("Content-Length") or 0) or None
        done = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            handle.write(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)


def fetch_maxmind(edition, key, workdir, progress=None):
    archive = os.path.join(workdir, f"{edition}.tar.gz")
    download(f"{MAXMIND_URL}?{urlencode({'edition_id': edition, 'license_key': key, 'suffix': 'tar.gz'})}", archive, progress)
    with tarfile.open(archive, "r:gz") as tar:
        member = next((item for item in tar.getmembers() if item.name.endswith(f"{edition}.mmdb")), None)
        if member is None:
            raise RuntimeError(f"{edition} archive has no database")
        source = tar.extractfile(member)
        target = os.path.join(workdir, f"{edition}.mmdb")
        with open(target, "wb") as handle:
            shutil.copyfileobj(source, handle)
    return target


def fetch_dbip(edition, workdir, progress=None):
    # DB-IP publishes the Lite databases monthly; early in a month fall back to the previous one
    now = datetime.now(timezone.utc)
    months = [now.strftime("%Y-%m"), (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")]
    compressed = os.path.join(workdir, f"{edition}.mmdb.gz")
    last_error = None
    for month in months:
        try:
            download(DBIP_URL.format(edition=edition, month=month), compressed, progress)
            break
        except Exception as error:
            last_error = error
    else:
        # the original error, so it can be explained (an HTTP status, an unreachable host)
        raise last_error
    target = os.path.join(workdir, f"{edition}.mmdb")
    with gzip.open(compressed, "rb") as source, open(target, "wb") as handle:
        shutil.copyfileobj(source, handle)
    return target


def needs_update(path, update_days, force):
    if force:
        return True
    info = os.stat(path) if os.path.exists(path) else None
    return info is None or time.time() - info.st_mtime > update_days * 86400


def in_backoff(last, now=None):
    """True while a failed download waits for its next try; a missing key is not a download failure."""
    if last.get("last_error") in (None, "maxmind_key_missing") or not last.get("last_attempt"):
        return False
    now = time.time() if now is None else now
    if last.get("next_retry"):
        return now < last["next_retry"]
    try:
        # written by an older version: no next_retry, a fixed wait
        attempted = datetime.fromisoformat(last["last_attempt"]).timestamp()
    except ValueError:
        return False
    return now - attempted < RETRY_STEPS[-1]


def retry_delay(failures):
    """Seconds before the next automatic try after `failures` failures in a row."""
    return RETRY_STEPS[min(max(failures, 1), len(RETRY_STEPS)) - 1]


def error_code(error):
    """What went wrong, in a word the page can explain."""
    if isinstance(error, urllib.error.HTTPError):
        return {401: "unauthorized", 403: "forbidden", 404: "not_found", 429: "rate_limited"}.get(error.code, "http")
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, urllib.error.URLError):
        reason = error.reason
        return "timeout" if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason) else "unreachable"
    if isinstance(error, OSError) and error.errno == errno.ENOSPC:
        return "disk_full"
    if isinstance(error, (tarfile.TarError, gzip.BadGzipFile, EOFError)) or "validation" in str(error) or "no database" in str(error):
        return "invalid"
    return "other"


def scrub(message, key):
    """Never let a URL (which carries the key) reach logs or the browser."""
    return message.replace(key, "<key>") if key else message


def fetch_databases(provider, paths, key, update_days, force, report=None):
    """Download, validate and install what is due. Returns (updated kinds, errors); each error is
    {kind, edition, code, message} with the key scrubbed. `report(edition, done, total)` follows
    the downloads."""
    updated = []
    errors = []
    with tempfile.TemporaryDirectory(dir=STATE_DIR) as workdir:
        for kind, probe in (("city", ["location", "latitude"]), ("asn", [])):
            if not needs_update(paths[kind], update_days, force):
                continue
            edition = paths["editions"][kind]
            progress = (lambda done, total, edition=edition: report(edition, done, total)) if report else None
            try:
                if report:
                    report(edition, 0, None)
                if provider.startswith("maxmind"):
                    fetched = fetch_maxmind(edition, key, workdir, progress=progress)
                else:
                    fetched = fetch_dbip(edition, workdir, progress=progress)
                validate(fetched, probe)
                os.chmod(fetched, 0o644)
                os.makedirs(GEOIP_DIR, exist_ok=True)
                shutil.move(fetched, f"{paths[kind]}.new")
                os.replace(f"{paths[kind]}.new", paths[kind])
                updated.append(kind)
            except Exception as exc:
                errors.append({"kind": kind, "edition": edition, "code": error_code(exc),
                               "message": scrub(f"{edition}: {exc}", key)})
    return updated, errors


def fall_back(provider, paths, failures, update_days, previous, report=None):
    """Keep the map working while MaxMind fails. Once its downloads have failed through the short
    retries (the next wait is the long one) and no MaxMind database exists, fetch DB-IP Lite (no
    key needed) and look addresses up there; MaxMind is still tried on schedule. When the MaxMind
    database arrives, the stand-in is deleted. Returns the fallback state for the status file."""
    standin = DATABASES.get("dbip")
    if not provider.startswith("maxmind") or standin is None:
        return None
    if os.path.exists(paths["city"]):
        if previous:
            # the stand-in was ours, fetched only for this: remove it
            for kind in ("city", "asn"):
                try:
                    os.remove(standin[kind])
                except OSError:
                    pass
        return None
    if failures < len(RETRY_STEPS) and not previous:
        return None
    _, errors = fetch_databases("dbip", standin, None, update_days, False, report)
    return {"provider": "dbip", "active": os.path.exists(standin["city"]), "errors": errors}


def update(force=False, retry=False):
    """Download what is due. `force` downloads everything again; `retry` does not wait out an
    earlier failure and starts the retry steps over (a new key, or "Retry now")."""
    values = settings()
    provider = effective_provider(values)
    paths = DATABASES[provider]
    os.makedirs(STATE_DIR, exist_ok=True)
    # one updater at a time: status reads and writes happen under the same lock as the download
    with open(LOCK_FILE, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return {"result": "busy"}
        key = None
        if provider.startswith("maxmind"):
            key, _ = license_key(values)
            if not key:
                write_status({"last_attempt": datetime.now(timezone.utc).isoformat(),
                              "last_error": "maxmind_key_missing", "provider": provider})
                return {"result": "failed", "error": "maxmind_key_missing"}
        last = read_status()
        if not (force or retry) and in_backoff(last):
            return {"result": "backoff", "error": last["last_error"]}
        written = [0.0]

        def report(edition, done, total):
            # the map shows this as a progress bar; written at most every PROGRESS_SECONDS
            now = time.time()
            if done and now - written[0] < PROGRESS_SECONDS and (total is None or done < total):
                return
            written[0] = now
            write_status({**last, "state": "downloading", "provider": provider,
                          "progress": {"edition": edition, "done": done, "total": total, "updated": now}})

        updated, errors = fetch_databases(provider, paths, key, values["update_days"], force, report)
        failures = 0 if not errors else (0 if retry else last.get("failures") or 0) + 1
        fallback = fall_back(provider, paths, failures, values["update_days"], last.get("fallback"), report)
        now = time.time()
        write_status({
            "last_attempt": datetime.now(timezone.utc).isoformat(),
            "last_error": "; ".join(error["message"] for error in errors) or None,
            "errors": errors, "failures": failures, "provider": provider, "state": "idle",
            "next_retry": now + retry_delay(failures) if errors else None,
            "fallback": fallback,
        })
    error = "; ".join(item["message"] for item in errors) or None
    return {"result": "failed" if errors else "ok", "updated": updated, "error": error}


if __name__ == "__main__":
    secure_umask()
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "update":
        mode = sys.argv[2] if len(sys.argv) > 2 else ""
        print(json.dumps(update(force=mode == "force", retry=mode == "retry")))
    else:
        print(json.dumps(status()))
