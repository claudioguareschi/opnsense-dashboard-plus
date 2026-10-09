#!/usr/local/bin/python3

# Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
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



"""Ranking profiles: the collector's operational ranking policy (collector/profile.h).

Exactly one profile is active for the firewall, and every viewer sees the flows it ranks. It is an
administrative setting (general.ranking_profile, a profile UUID), never a viewer's choice, and it
is the complete policy: quality weights, asset importance, security visibility floors and
direction. OPNsense and Python own the configuration: this module resolves the active UUID to a
complete profile, validates it and writes the collector's schema-v1 startup document, which the
collector compiles once and keeps for its lifetime. A change to what the active profile ranks by
(its fingerprint) or another active UUID restarts the collector; edits to inactive profiles change
nothing.

Quality: for each feature, weight x log1p(value / scale), weights totalling exactly 100:

    byte_rate            EMA-smoothed observed byte rate, both directions
    packet_rate          EMA-smoothed observed packet rate
    active_states        PF states of the flow now
    new_state_rate       states new since the previous sample, per second
    flow_volume          bytes of the flow's current activity episode while tracked
    pf_blocked           logged blocked attempts of the remote in the filterlog window
    threat_intelligence  1 when the remote is in a threat-category PF table
    ids_evidence         1 with Suricata alerts, 2 when one has severity 1 or 2

Asset importance multiplies quality by the multiplier of the flow's local anchor (the inside host
when known): the longest matching CIDR rule, else the default. Security visibility floors reserve
a minimum percentage of the ranked flows for the classes S3, S2 and S1 (collector/evidence.h).

Built-in profiles are immutable templates with fixed UUIDs; custom profiles are configuration rows
(copies of a built-in or of another custom profile, with their own UUIDs). The UUID identifies the
object; the fingerprint identifies one definition of it.
"""

import hashlib
import ipaddress
import json
import re

SCHEMA_VERSION = 1
# the collector's closed feature vocabulary, in its order (collector/profile.h)
FEATURES = ("byte_rate", "packet_rate", "active_states", "new_state_rate", "flow_volume", "pf_blocked",
            "threat_intelligence", "ids_evidence")
FLOORS = ("s3_min_percent", "s2_min_percent", "s1_min_percent")
DIRECTIONS = ("equal",)
# the collector's limits (collector/profile.h)
ASSET_RULES_MAX = 4096
MULTIPLIER_MIN = 1.0
MULTIPLIER_MAX = 100.0

BALANCED = "9bded7b2-a028-44ca-b7ab-4e3357694174"
BANDWIDTH = "a5df6449-a682-4029-82c9-ae51b25a87db"
CONNECTIONS = "dcbf98a3-1297-438c-a78b-b21b5bc6bcdd"
SECURITY = "6c02d03d-4087-46a9-b5bc-6378fb5eeada"
DEFAULT = BALANCED


def _builtin(uuid, name, weights, floors, description):
    return {"uuid": uuid, "name": name, "builtin": True, "description": description,
            "weights": dict(zip(FEATURES, weights)), "floors": dict(zip(FLOORS, floors)),
            "default_multiplier": 1, "assets": [], "direction": "equal"}


BUILTINS = [
    _builtin(BALANCED, "Balanced", (25, 5, 15, 15, 15, 8, 8, 9), (4, 2, 1),
             "Traffic, connections and flow volume together, with security evidence counted and a few "
             "places kept for flows that carry it."),
    _builtin(BANDWIDTH, "Bandwidth", (55, 15, 5, 5, 20, 0, 0, 0), (0, 0, 0),
             "The flows moving the most data: byte and packet rates, and the volume of the current "
             "transfer."),
    _builtin(CONNECTIONS, "Connections", (5, 10, 40, 45, 0, 0, 0, 0), (0, 0, 0),
             "The most PF states and the most new connections, whatever their traffic."),
    _builtin(SECURITY, "Security", (5, 5, 10, 15, 0, 20, 15, 30), (30, 20, 15),
             "Flows with security evidence first (high-severity IDS, then other IDS and heavy blocking, "
             "then threat lists and reputation), then connection activity."),
]
BY_UUID = {profile["uuid"]: profile for profile in BUILTINS}


class ProfileError(ValueError):
    """A profile the collector would refuse (the same rules as collector/profile.c)."""


def _number(value, what):
    if isinstance(value, bool):
        raise ProfileError(f"{what} is not a number")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ProfileError(f"{what} is not a number") from None
    if number != number or number in (float("inf"), float("-inf")):
        raise ProfileError(f"{what} is not a finite number")
    return number


def parse_assets(text):
    """Asset rules from their configuration text: one "CIDR multiplier" per line (an address alone
    is a host: /32 or /128). Raises ProfileError on a malformed line."""
    rules = []
    for number, line in enumerate(str(text or "").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ProfileError(f"asset rule {number}: expected \"CIDR multiplier\"")
        rules.append({"cidr": parts[0], "multiplier": parts[1]})
    return rules


def _network(text):
    address, slash, prefix = str(text).partition("/")
    try:
        if slash and not re.fullmatch(r"0|[1-9][0-9]{0,2}", prefix):
            raise ValueError(prefix)
        return ipaddress.ip_network(str(text), strict=True)
    except ValueError:
        raise ProfileError(f"asset rule {text}: not a network address (host bits must be zero)") from None


def validate(profile):
    """The profile in canonical form, or ProfileError: weights of the eight features (no others)
    totalling 100, floors 0-100 totalling at most 100, multipliers within the collector's limits,
    canonical CIDRs (one multiplier per prefix), direction "equal"."""
    weights = profile.get("weights") or {}
    unknown = sorted(set(weights) - set(FEATURES))
    if unknown:
        raise ProfileError(f"unknown feature {unknown[0]}")
    canonical = {}
    for feature in FEATURES:
        if feature not in weights:
            raise ProfileError(f"missing weight {feature}")
        weight = _number(weights[feature], f"weight {feature}")
        if not 0 <= weight <= 100:
            raise ProfileError(f"weight {feature} is outside 0-100")
        canonical[feature] = weight
    if abs(sum(canonical.values()) - 100) > 1e-9:
        raise ProfileError(f"weights total {sum(canonical.values()):g}, not 100")
    floors = profile.get("floors") or {}
    floor_values = {}
    for floor in FLOORS:
        value = _number(floors.get(floor, 0), floor)
        if not 0 <= value <= 100:
            raise ProfileError(f"{floor} is outside 0-100")
        floor_values[floor] = value
    if sum(floor_values.values()) > 100:
        raise ProfileError("security visibility floors total more than 100%")
    default = _number(profile.get("default_multiplier", 1), "default multiplier")
    if not MULTIPLIER_MIN <= default <= MULTIPLIER_MAX:
        raise ProfileError("default multiplier is out of range")
    rules, seen = [], {}
    for rule in profile.get("assets") or []:
        network = _network(rule.get("cidr"))
        multiplier = _number(rule.get("multiplier"), f"asset rule {network} multiplier")
        if not MULTIPLIER_MIN <= multiplier <= MULTIPLIER_MAX:
            raise ProfileError(f"asset rule {network}: multiplier out of range")
        if network in seen:
            if seen[network] != multiplier:
                raise ProfileError(f"asset rule {network}: the same prefix with two multipliers")
            continue
        seen[network] = multiplier
        rules.append({"cidr": str(network), "multiplier": multiplier})
    if len(rules) > ASSET_RULES_MAX:
        raise ProfileError(f"more than {ASSET_RULES_MAX} asset rules")
    direction = profile.get("direction", "equal")
    if direction not in DIRECTIONS:
        raise ProfileError(f"direction {direction} is not supported")
    return dict(profile, weights=canonical, floors=floor_values, default_multiplier=default, assets=rules,
                direction=direction)


def _plain(number):
    return int(number) if float(number).is_integer() and abs(number) < 2 ** 53 else number


def _definition(profile):
    """What the collector ranks by (everything but the identity)."""
    return {"weights": {feature: _plain(profile["weights"][feature]) for feature in FEATURES},
            "asset_importance": {"default_multiplier": _plain(profile["default_multiplier"]),
                                 "rules": [{"cidr": rule["cidr"], "multiplier": _plain(rule["multiplier"])}
                                           for rule in profile["assets"]]},
            "security_visibility": {floor: _plain(profile["floors"][floor]) for floor in FLOORS},
            "direction": profile["direction"]}


def document(profile):
    """The collector's startup document (schema v1, which collector/profile.c compiles) of a
    validated profile."""
    # the name is informational to the collector, whose reader takes printable ASCII only
    name = "".join(c if " " <= c <= "~" else "?" for c in profile["name"])[:128] or "?"
    return {"schema_version": SCHEMA_VERSION,
            "profile": dict({"uuid": profile["uuid"], "name": name}, **_definition(profile))}


def startup_text(profile):
    return json.dumps(document(profile), separators=(",", ":")) + "\n"


def fingerprint(profile):
    """The effective-profile fingerprint: a hash of the complete collector-affecting definition
    (weights, asset rules in prefix order, floors, direction), independent of name and UUID."""
    definition = _definition(profile)
    definition["asset_importance"]["rules"].sort(key=lambda rule: (
        ipaddress.ip_network(rule["cidr"]).version, ipaddress.ip_network(rule["cidr"])))
    text = json.dumps(definition, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def custom(rows):
    """Custom profiles from their configuration rows (the rendered settings' ranking_profiles):
    [(profile, problem)], problem None for a valid one."""
    profiles = []
    for row in rows or []:
        if not isinstance(row, dict) or not row.get("uuid"):
            continue
        profile = {"uuid": str(row["uuid"]), "name": str(row.get("name") or "").strip() or "(unnamed)",
                   "builtin": False, "description": str(row.get("description") or ""),
                   "weights": {feature: row.get(feature) for feature in FEATURES if row.get(feature) is not None},
                   "floors": {floor: row.get(floor) or 0 for floor in FLOORS},
                   "default_multiplier": row.get("default_multiplier") or 1,
                   "direction": row.get("direction") or "equal"}
        try:
            profile["assets"] = parse_assets(row.get("assets"))
            profiles.append((validate(profile), None))
        except ProfileError as error:
            profiles.append((dict(profile, assets=[]), str(error)))
    return profiles


def resolve(values=None, rows=None):
    """The active profile: (profile, problem). The configured UUID among the built-ins and the
    custom profiles; the default, with the reason, when it names no profile or an invalid one."""
    uuid = (values or {}).get("ranking_profile") or DEFAULT
    if uuid in BY_UUID:
        return validate(BY_UUID[uuid]), None
    for profile, problem in custom(rows):
        if profile["uuid"] == uuid:
            if problem:
                return validate(BY_UUID[DEFAULT]), f"ranking profile {profile['name']} is invalid ({problem})"
            return profile, None
    return validate(BY_UUID[DEFAULT]), f"ranking profile {uuid} does not exist"


def descriptor(profile):
    """What status, the map and snapshots say about the active profile."""
    return {"uuid": profile["uuid"], "name": profile["name"], "builtin": bool(profile.get("builtin")),
            "fingerprint": fingerprint(profile)}


def _entry(profile, builtin, problem=None):
    entry = {"uuid": profile["uuid"], "name": profile["name"], "description": profile["description"],
             "builtin": builtin, "weights": {feature: _plain(float(profile["weights"].get(feature, 0)))
                                             for feature in FEATURES},
             "floors": {floor: _plain(float(profile["floors"][floor])) for floor in FLOORS},
             "default_multiplier": _plain(float(profile["default_multiplier"])),
             "assets": "\n".join(f"{rule['cidr']} {_plain(float(rule['multiplier']))}" for rule in profile["assets"]),
             "direction": profile["direction"]}
    if problem is None:
        entry["fingerprint"] = fingerprint(profile)
    else:
        entry["problem"] = problem
    return entry


def catalog(rows=None):
    """The profiles to choose from, with their definitions (the settings page and the field's
    options): built-ins, then custom ones."""
    entries = [_entry(validate(profile), True) for profile in BUILTINS]
    entries.extend(_entry(profile, False, problem) for profile, problem in custom(rows))
    return entries
