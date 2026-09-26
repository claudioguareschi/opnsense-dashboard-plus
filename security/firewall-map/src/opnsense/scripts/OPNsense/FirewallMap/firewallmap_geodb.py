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


CONFIG_XML = "/conf/config.xml"
GEOIP_ALIAS_CONF = "/usr/local/etc/filter_geoip.conf"
GEOIP_DIR = "/usr/local/share/GeoIP"
STATE_DIR = "/var/db/firewallmap"
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
    "dbip": {
        "city": f"{GEOIP_DIR}/dbip-city-lite.mmdb",
        "asn": f"{GEOIP_DIR}/dbip-asn-lite.mmdb",
        "editions": {"city": "dbip-city-lite", "asn": "dbip-asn-lite"},
    },
}


def settings(path=CONFIG_XML):
    """Read the plugin's firewall-wide settings straight from config.xml."""
    values = {"provider": "maxmind", "license_key": "", "update_days": 3}
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
    if values["provider"] not in DATABASES:
        values["provider"] = "maxmind"
    return values


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
    try:
        with open(STATUS_FILE) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def write_status(payload):
    os.makedirs(STATE_DIR, exist_ok=True)
    temporary = f"{STATUS_FILE}.tmp"
    with open(temporary, "w") as handle:
        json.dump(payload, handle)
    os.replace(temporary, STATUS_FILE)


def status():
    values = settings()
    _, key_source = license_key(values)
    paths = DATABASES[values["provider"]]
    last = read_status()
    return {
        "provider": values["provider"],
        "update_days": values["update_days"],
        "key_source": key_source,
        "key_required": values["provider"] == "maxmind",
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


def update(force=False):
    values = settings()
    provider = values["provider"]
    paths = DATABASES[provider]
    key = None
    if provider == "maxmind":
        key, _ = license_key(values)
        if not key:
            write_status({**read_status(), "last_attempt": datetime.now(timezone.utc).isoformat(),
                          "last_error": "maxmind_key_missing"})
            return {"result": "failed", "error": "maxmind_key_missing"}

    last = read_status()
    # a missing key is not a download failure, so it never delays the next attempt
    if not force and last.get("last_error") not in (None, "maxmind_key_missing") and last.get("last_attempt"):
        try:
            attempted = datetime.fromisoformat(last["last_attempt"]).timestamp()
        except ValueError:
            attempted = 0
        if time.time() - attempted < RETRY_SECONDS:
            return {"result": "backoff", "error": last["last_error"]}

    os.makedirs(STATE_DIR, exist_ok=True)
    with open(LOCK_FILE, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return {"result": "busy"}
        updated = []
        error = None
        with tempfile.TemporaryDirectory(dir=STATE_DIR) as workdir:
            for kind, probe in (("city", ["location", "latitude"]), ("asn", [])):
                if not needs_update(paths[kind], values["update_days"], force):
                    continue
                edition = paths["editions"][kind]
                try:
                    fetched = fetch_maxmind(edition, key, workdir) if provider == "maxmind" else fetch_dbip(edition, workdir)
                    validate(fetched, probe)
                    os.chmod(fetched, 0o644)
                    os.makedirs(GEOIP_DIR, exist_ok=True)
                    shutil.move(fetched, f"{paths[kind]}.new")
                    os.replace(f"{paths[kind]}.new", paths[kind])
                    updated.append(kind)
                except Exception as exc:
                    # never let a URL (which carries the key) reach logs or the browser
                    error = f"{edition}: {exc}"
                    if key:
                        error = error.replace(key, "<key>")
        write_status({"last_attempt": datetime.now(timezone.utc).isoformat(), "last_error": error})
    return {"result": "failed" if error else "ok", "updated": updated, "error": error}


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "status"
    if command == "update":
        print(json.dumps(update(force=len(sys.argv) > 2 and sys.argv[2] == "force")))
    else:
        print(json.dumps(status()))
