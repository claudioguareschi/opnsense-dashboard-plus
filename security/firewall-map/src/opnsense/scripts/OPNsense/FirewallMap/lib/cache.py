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

"""Local geolocation lookups and the SQLite cache shared by the Firewall Map+ scripts."""

import json
import os
import sqlite3
import threading
import time

from . import mmdb
from .common import CACHE_DB, log_notice, log_warning


# database paths follow the provider chosen in the firewall-wide settings (see firewallmap_geodb)
GEO_CACHE_SAVE_SECONDS = 60.0
GEO_LOOKUPS_PER_SAMPLE = 25
GEO_CACHE_MAX = 20000
GEO_CACHE_VERSION = 2


# open readers, one per database file, reopened when the file is replaced (an update)
_readers = {}


def database_reader(path):
    stat = os.stat(path)
    key = (stat.st_mtime_ns, stat.st_size)
    cached = _readers.get(path)
    if cached is None or cached[0] != key:
        if cached is not None:
            cached[1].close()
        cached = _readers[path] = (key, mmdb.Reader(path))
    return cached[1]


def mmdb_lookup(database, address):
    """{("location", "latitude"): "37.751", ...} for `address`; {} when the database has no entry
    (a definite miss that is cached). Raises LookupError when the file cannot be read (transient:
    callers must not cache it)."""
    try:
        record = database_reader(database).get(address)
    except (OSError, mmdb.InvalidDatabaseError) as error:
        raise LookupError(str(error)) from error
    except ValueError:
        return {}  # not an address this database covers (IPv6 in an IPv4-only file)
    return mmdb.flatten(record) if record is not None else {}


def lookup_location(address, city_database, asn_database):
    """Resolve one address against the local geolocation databases (never a remote service)."""
    values = mmdb_lookup(city_database, address)
    try:
        latitude = float(values[("location", "latitude")])
        longitude = float(values[("location", "longitude")])
    except (KeyError, ValueError):
        return None
    location = {
        "lat": round(latitude, 4),
        "lon": round(longitude, 4),
        "city": values.get(("city", "names", "en")),
        # GeoLite often knows only the state/province (with a coarse accuracy radius)
        "region": values.get(("subdivisions", "names", "en")),
        "accuracy_km": int(float(values[("location", "accuracy_radius")])) if ("location", "accuracy_radius") in values else None,
        "country": values.get(("country", "iso_code")) or values.get(("registered_country", "iso_code")),
        "country_name": values.get(("country", "names", "en")) or values.get(("registered_country", "names", "en")),
    }
    if os.path.exists(asn_database):
        try:
            asn = mmdb_lookup(asn_database, address)
        except LookupError:
            asn = {}
        if ("autonomous_system_number",) in asn:
            location["asn"] = int(asn[("autonomous_system_number",)])
            location["as_org"] = asn.get(("autonomous_system_organization",))
    return location


def damaged(error):
    """True for a database file that is really corrupt, not for a transient error (a full disk, a
    lock, an I/O hiccup), after which the file is fine to open again later."""
    code = getattr(error, "sqlite_errorcode", None)
    if code is not None:
        return code & 0xFF in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB)
    text = str(error).lower()
    return "malformed" in text or "not a database" in text


def move_aside(path, now=None):
    """Keep a damaged database for inspection under a dated name, its WAL files with it (a stale
    WAL left behind could be replayed into the new file)."""
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time() if now is None else now))
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(f"{path}{suffix}"):
            os.replace(f"{path}{suffix}", f"{path}.corrupt-{stamp}{suffix}")


class CacheStore:
    """Small SQLite key/value store with expiry, shared by the collector's caches.

    One file, no service: GeoIP results, reverse DNS names and investigation lookups survive
    restarts, are written incrementally and are pruned by age and count. A cache must never
    take the collector down: a damaged file is moved aside (with its WAL files, under a dated
    name), any other error at startup (a full disk, a lock) keeps the file and caches in memory
    for this run, and a later database error degrades to "not cached" instead of raising.
    """

    def __init__(self, path=CACHE_DB):
        self.path = path
        self.lock = threading.Lock()
        # a database error is logged once, then again when the cache works
        self.failing = False
        try:
            self.db = self._open(path)
        except sqlite3.Error as error:
            self.db = None
            if damaged(error):
                try:
                    move_aside(path)
                    self.db = self._open(path)
                except (OSError, sqlite3.Error):
                    self.db = None
            if self.db is None:
                log_warning(f"cache unavailable ({error}): caching in memory until the collector restarts")
                self.db = self._open(":memory:")

    @staticmethod
    def _open(path):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("CREATE TABLE IF NOT EXISTS cache (kind TEXT, key TEXT, value TEXT, stored REAL, PRIMARY KEY (kind, key))")
        db.execute("SELECT count(*) FROM cache").fetchone()
        return db

    def _query(self, sql, parameters=()):
        try:
            with self.lock:
                rows = self.db.execute(sql, parameters).fetchall()
        except sqlite3.Error as error:
            self._failed(f"cache query failed: {error}")
            return []
        self._works()
        return rows

    def _failed(self, message):
        if not self.failing:
            log_warning(message)
            self.failing = True

    def _works(self):
        if self.failing:
            log_notice("the cache works again")
            self.failing = False

    def get_all(self, kind, max_age=None, now=None):
        now = time.time() if now is None else now
        rows = self._query("SELECT key, value, stored FROM cache WHERE kind = ?", (kind,))
        result = {}
        for key, value, stored in rows:
            if max_age is None or now - stored < max_age:
                try:
                    result[key] = json.loads(value)
                except ValueError:
                    continue
        return result

    def get(self, kind, key, max_age=None, now=None):
        now = time.time() if now is None else now
        rows = self._query("SELECT value, stored FROM cache WHERE kind = ? AND key = ?", (kind, key))
        if not rows or (max_age is not None and now - rows[0][1] >= max_age):
            return None
        try:
            return json.loads(rows[0][0])
        except ValueError:
            return None

    def put_many(self, kind, items, now=None):
        now = time.time() if now is None else now
        rows = [(kind, key, json.dumps(value), now) for key, value in items]
        with self.lock:
            try:
                self.db.execute("BEGIN")
                self.db.executemany("INSERT OR REPLACE INTO cache (kind, key, value, stored) VALUES (?, ?, ?, ?)", rows)
                self.db.execute("COMMIT")
                self._works()
            except sqlite3.Error as error:
                self._failed(f"cache write failed: {error}")
                try:
                    self.db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass

    def prune(self, kind, max_age=None, keep=None, now=None):
        now = time.time() if now is None else now
        if max_age is not None:
            self._query("DELETE FROM cache WHERE kind = ? AND stored < ?", (kind, now - max_age))
        if keep is not None:
            self._query(
                "DELETE FROM cache WHERE kind = ? AND key NOT IN "
                "(SELECT key FROM cache WHERE kind = ? ORDER BY stored DESC LIMIT ?)", (kind, kind, keep),
            )


class GeoCache:
    """IP -> location cache persisted in SQLite and invalidated when the databases change."""

    def __init__(self, store=None, database=None, asn_database=None, lookup=None, path=None):
        self.store = store if store is not None else CacheStore(path or CACHE_DB)
        self.database = database
        self.asn_database = asn_database
        self.lookup = lookup or (lambda address: lookup_location(address, database, asn_database))
        self.database_mtime = self._database_mtime()
        self.kind = f"geo:{GEO_CACHE_VERSION}:{database}:{self.database_mtime}"
        self.pending = {}
        self.saved_at = time.monotonic()
        self.entries = self.store.get_all(self.kind)

    def _database_mtime(self):
        mtimes = []
        for database in (self.database, self.asn_database):
            try:
                mtimes.append(int(os.stat(database).st_mtime))
            except (OSError, TypeError):
                mtimes.append(None)
        return mtimes

    def save(self, force=False):
        if not self.pending or (not force and time.monotonic() - self.saved_at < GEO_CACHE_SAVE_SECONDS):
            return
        self.store.put_many(self.kind, self.pending.items())
        self.store.prune(self.kind, keep=GEO_CACHE_MAX)
        self.pending = {}
        self.saved_at = time.monotonic()

    def forget_old_databases(self):
        """Drop cached locations from previous database files."""
        self.store._query("DELETE FROM cache WHERE kind LIKE 'geo:%' AND kind != ?", (self.kind,))

    def resolve(self, addresses, budget=GEO_LOOKUPS_PER_SAMPLE):
        """Look up at most `budget` unknown addresses; unresolvable ones are cached as null."""
        for address in addresses:
            if budget <= 0:
                break
            if address not in self.entries:
                budget -= 1
                try:
                    self.entries[address] = self.pending[address] = self.lookup(address)
                except LookupError:
                    continue  # try again on a later sample
        if len(self.entries) > GEO_CACHE_MAX * 2:
            # keep memory bounded: the store keeps the most recent entries
            self.save(force=True)
            self.entries = self.store.get_all(self.kind)

    def get(self, address):
        return self.entries.get(address)
