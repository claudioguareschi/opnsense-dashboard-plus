#!/usr/local/bin/python3

"""Download and update the local geolocation databases used by Firewall Map+.

    firewallmap_geodb.py status          JSON status (never includes the license key)
    firewallmap_geodb.py update [force]  download when missing or older than update_days

MaxMind GeoLite2 needs a license key: the plugin's own key when set, otherwise the key
of a MaxMind GeoIP alias URL (Firewall > Aliases > GeoIP settings). DB-IP Lite needs no
key. Downloads go only to the provider; endpoint addresses are never sent anywhere.
"""

import fcntl
import gzip
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ElementTree
from configparser import ConfigParser
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwmap_common import STATE_DIR, read_json, secure_umask, write_json  # noqa: E402


CONFIG_XML = "/conf/config.xml"
GEOIP_ALIAS_CONF = "/usr/local/etc/filter_geoip.conf"
GEOIP_DIR = "/usr/local/share/GeoIP"
STATUS_FILE = f"{STATE_DIR}/geodb.json"
LOCK_FILE = f"{STATE_DIR}/geodb.lock"
MMDBLOOKUP = "/usr/local/bin/mmdblookup"
MAXMIND_URL = "https://download.maxmind.com/app/geoip_download"
DBIP_URL = "https://download.db-ip.com/free/{edition}-{month}.mmdb.gz"
TIMEOUT = 120
# after a failed download, automatic retries wait this long (a forced update always runs)
RETRY_SECONDS = 900

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
    values = {"provider": "auto", "license_key": "", "update_days": 3, "threat_lists": "", "record_threats": "1"}
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
    }


def validate(path, probe):
    """Make sure a downloaded database answers a lookup before it replaces the current one."""
    result = subprocess.run(
        [MMDBLOOKUP, "--file", path, "--ip", "8.8.8.8", *probe],
        capture_output=True, check=False, text=True, timeout=10,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("downloaded database failed validation")


def download(url, target):
    request = urllib.request.Request(url, headers={"User-Agent": "OPNsense-FirewallMap"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response, open(target, "wb") as handle:
        shutil.copyfileobj(response, handle)


def fetch_maxmind(edition, key, workdir):
    archive = os.path.join(workdir, f"{edition}.tar.gz")
    download(f"{MAXMIND_URL}?{urlencode({'edition_id': edition, 'license_key': key, 'suffix': 'tar.gz'})}", archive)
    with tarfile.open(archive, "r:gz") as tar:
        member = next((item for item in tar.getmembers() if item.name.endswith(f"{edition}.mmdb")), None)
        if member is None:
            raise RuntimeError(f"{edition} archive has no database")
        source = tar.extractfile(member)
        target = os.path.join(workdir, f"{edition}.mmdb")
        with open(target, "wb") as handle:
            shutil.copyfileobj(source, handle)
    return target


def fetch_dbip(edition, workdir):
    # DB-IP publishes the Lite databases monthly; early in a month fall back to the previous one
    now = datetime.now(timezone.utc)
    months = [now.strftime("%Y-%m"), (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")]
    compressed = os.path.join(workdir, f"{edition}.mmdb.gz")
    last_error = None
    for month in months:
        try:
            download(DBIP_URL.format(edition=edition, month=month), compressed)
            break
        except Exception as error:
            last_error = error
    else:
        raise RuntimeError(f"{edition} download failed ({last_error})")
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
    """True while a failed download is recent; a missing key is not a download failure."""
    if last.get("last_error") in (None, "maxmind_key_missing") or not last.get("last_attempt"):
        return False
    try:
        attempted = datetime.fromisoformat(last["last_attempt"]).timestamp()
    except ValueError:
        return False
    return (time.time() if now is None else now) - attempted < RETRY_SECONDS


def scrub(message, key):
    """Never let a URL (which carries the key) reach logs or the browser."""
    return message.replace(key, "<key>") if key else message


def fetch_databases(provider, paths, key, update_days, force):
    """Download, validate and install what is due. Returns (updated kinds, error or None)."""
    updated = []
    error = None
    with tempfile.TemporaryDirectory(dir=STATE_DIR) as workdir:
        for kind, probe in (("city", ["location", "latitude"]), ("asn", [])):
            if not needs_update(paths[kind], update_days, force):
                continue
            edition = paths["editions"][kind]
            try:
                fetched = fetch_maxmind(edition, key, workdir) if provider.startswith("maxmind") else fetch_dbip(edition, workdir)
                validate(fetched, probe)
                os.chmod(fetched, 0o644)
                os.makedirs(GEOIP_DIR, exist_ok=True)
                shutil.move(fetched, f"{paths[kind]}.new")
                os.replace(f"{paths[kind]}.new", paths[kind])
                updated.append(kind)
            except Exception as exc:
                error = scrub(f"{edition}: {exc}", key)
    return updated, error


def update(force=False):
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
                write_status({**read_status(), "last_attempt": datetime.now(timezone.utc).isoformat(),
                              "last_error": "maxmind_key_missing"})
                return {"result": "failed", "error": "maxmind_key_missing"}
        last = read_status()
        if not force and in_backoff(last):
            return {"result": "backoff", "error": last["last_error"]}
        updated, error = fetch_databases(provider, paths, key, values["update_days"], force)
        write_status({"last_attempt": datetime.now(timezone.utc).isoformat(), "last_error": error})
    return {"result": "failed" if error else "ok", "updated": updated, "error": error}


if __name__ == "__main__":
    secure_umask()
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "update":
        print(json.dumps(update(force=len(sys.argv) > 2 and sys.argv[2] == "force")))
    else:
        print(json.dumps(status()))
