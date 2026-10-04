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

"""Read MaxMind DB files (.mmdb: MaxMind GeoLite2/GeoIP2 and DB-IP Lite) in process.

The collector looks up every new address it sees; starting mmdblookup twice per address (city and
AS) and parsing its printed output cost a process per lookup. This reads the file directly,
following the published format (https://maxmind.github.io/MaxMind-DB/): a binary search tree over
the address bits, then a data section of typed values. The file is memory-mapped, so only the
pages a lookup touches are read.
"""

import ipaddress
import mmap
import struct

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
METADATA_SEARCH = 128 * 1024
DATA_SEPARATOR = 16


class InvalidDatabaseError(ValueError):
    pass


class Reader:
    """One database file, open until close()."""

    def __init__(self, path):
        with open(path, "rb") as handle:
            try:
                self._map = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError:  # an empty file cannot be mapped
                raise InvalidDatabaseError("empty database file") from None
        try:
            self._setup()
        except Exception:
            self._map.close()
            raise

    def _setup(self):
        end = len(self._map)
        start = self._map.rfind(METADATA_MARKER, max(0, end - METADATA_SEARCH), end)
        if start < 0:
            raise InvalidDatabaseError("not a MaxMind DB file (no metadata)")
        metadata_start = start + len(METADATA_MARKER)
        self.metadata, _ = Decoder(self._map, metadata_start, end).decode(metadata_start)
        try:
            self.node_count = int(self.metadata["node_count"])
            self.record_size = int(self.metadata["record_size"])
            self.ip_version = int(self.metadata["ip_version"])
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidDatabaseError(f"incomplete metadata ({error})") from None
        if self.record_size not in (24, 28, 32):
            raise InvalidDatabaseError(f"unsupported record size {self.record_size}")
        self.node_bytes = self.record_size // 4
        self.tree_size = self.node_count * self.node_bytes
        data_start = self.tree_size + DATA_SEPARATOR
        if data_start > start:
            raise InvalidDatabaseError("search tree larger than the file")
        self._decoder = Decoder(self._map, data_start, start)
        # IPv4 addresses sit under ::/96 in an IPv6 tree: find that node once
        self._ipv4_start = 0
        if self.ip_version == 6:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._record(node, 0)
            self._ipv4_start = node

    def _record(self, node, bit):
        offset = node * self.node_bytes
        data = self._map
        if self.record_size == 24:
            offset += bit * 3
            return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
        if self.record_size == 28:
            middle = data[offset + 3]
            if bit:
                return ((middle & 0x0F) << 24) | (data[offset + 4] << 16) | (data[offset + 5] << 8) | data[offset + 6]
            return ((middle & 0xF0) << 20) | (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
        return struct.unpack_from(">I", data, offset + bit * 4)[0]

    def get(self, address):
        """The record for `address` (a dict), or None when the database has no entry for it."""
        parsed = ipaddress.ip_address(address)
        if parsed.version == 6 and self.ip_version == 4:
            raise ValueError("IPv6 address in an IPv4-only database")
        packed = parsed.packed
        bits = len(packed) * 8
        node = self._ipv4_start if parsed.version == 4 else 0
        for index in range(bits):
            if node >= self.node_count:
                break
            bit = (packed[index >> 3] >> (7 - (index & 7))) & 1
            node = self._record(node, bit)
        if node == self.node_count:
            return None
        if node < self.node_count + DATA_SEPARATOR:
            # a node, or a record pointing into the separator between the tree and the data
            raise InvalidDatabaseError("search tree does not end in data")
        value, _ = self._decoder.decode(self._decoder.base + node - self.node_count - DATA_SEPARATOR)
        return value

    def close(self):
        self._map.close()


class Decoder:
    """Values of the data section (or the metadata), starting at absolute file offsets. A damaged
    file never raises anything but InvalidDatabaseError: every read stays inside the section, a
    pointer may not lead to another pointer, and nesting is bounded."""

    MAX_DEPTH = 32

    def __init__(self, data, base, limit):
        self.data = data
        self.base = base  # pointers are relative to the start of the data section
        self.limit = limit

    def decode(self, offset):
        """(value, offset after it)."""
        try:
            return self._decode(offset, 0)
        except InvalidDatabaseError:
            raise
        except (IndexError, ValueError, struct.error, RecursionError) as error:
            raise InvalidDatabaseError(f"damaged data section ({error})") from None

    def _bytes(self, offset, size):
        if offset < 0 or offset + size > self.limit:
            raise InvalidDatabaseError("data runs past the end of the section")
        return self.data[offset:offset + size]

    def _decode(self, offset, depth, pointer_allowed=True):
        if depth > self.MAX_DEPTH:
            raise InvalidDatabaseError("data nested too deeply")
        control = self._bytes(offset, 1)[0]
        offset += 1
        kind = control >> 5
        if kind == 1:  # pointer: the value lives elsewhere
            if not pointer_allowed:
                raise InvalidDatabaseError("pointer to a pointer")
            size = (control >> 3) & 0x3
            value = control & 0x7
            raw = int.from_bytes(self._bytes(offset, size + 1), "big")
            if size == 0:
                pointer = (value << 8) | raw
            elif size == 1:
                pointer = ((value << 16) | raw) + 2048
            elif size == 2:
                pointer = ((value << 24) | raw) + 526336
            else:
                pointer = raw
            target, _ = self._decode(self.base + pointer, depth + 1, pointer_allowed=False)
            return target, offset + size + 1
        if kind == 0:  # extended type
            kind = 7 + self._bytes(offset, 1)[0]
            offset += 1
        size = control & 0x1F
        if size >= 29:
            extra = size - 28
            number = int.from_bytes(self._bytes(offset, extra), "big")
            offset += extra
            size = (29, 285, 65821)[extra - 1] + number
        if kind == 2:
            return self._bytes(offset, size).decode("utf-8", "replace"), offset + size
        if kind == 7:
            result = {}
            for _ in range(size):
                key, offset = self._decode(offset, depth + 1)
                result[key], offset = self._decode(offset, depth + 1)
            return result, offset
        if kind == 11:
            items = []
            for _ in range(size):
                item, offset = self._decode(offset, depth + 1)
                items.append(item)
            return items, offset
        if kind == 3:
            return struct.unpack(">d", self._bytes(offset, 8))[0], offset + 8
        if kind == 15:
            return struct.unpack(">f", self._bytes(offset, 4))[0], offset + 4
        if kind in (5, 6, 9, 10):
            return int.from_bytes(self._bytes(offset, size), "big"), offset + size
        if kind == 8:
            value = int.from_bytes(self._bytes(offset, size), "big")
            return (value - (1 << 32) if value & 0x80000000 else value) if size == 4 else value, offset + size
        if kind == 14:
            return bool(size), offset
        if kind == 4:
            return bytes(self._bytes(offset, size)), offset + size
        raise InvalidDatabaseError(f"unknown data type {kind}")


def flatten(value, path=()):
    """{("location", "latitude"): "37.751", ...}: every leaf as text, array positions left out (a
    later entry of an array replaces an earlier one), as the collector has always read records."""
    result = {}
    if isinstance(value, dict):
        for key, item in value.items():
            result.update(flatten(item, path + (key,)))
    elif isinstance(value, list):
        for item in value:
            result.update(flatten(item, path))
    elif path and not isinstance(value, (bool, bytes)):
        # strings and numbers: what the map reads (flags like is_in_european_union are not used)
        result[path] = str(value)
    return result
