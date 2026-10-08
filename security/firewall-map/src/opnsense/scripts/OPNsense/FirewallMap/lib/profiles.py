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



"""Ranking profiles: the collector's ranking policy (collector/CONTRACTS.md, "Ranking profile").

Exactly one profile is active for the firewall and every viewer sees the flows it ranks; it is
an administrative setting (general.ranking_profile, a profile UUID), never a viewer's choice.
OPNsense and Python own the profile configuration: this module resolves the active profile and
generates the collector's startup definition from it (--profile), which the collector compiles once
and keeps for its lifetime: a new or edited active profile restarts the collector.

A profile adds, for each feature, weight x log1p(value / scale):

    byte_rate        EMA-smoothed observed byte rate, both directions (bytes/s)
    packet_rate      EMA-smoothed observed packet rate (packets/s)
    states           PF states of the flow now
    new_state_rate   states new since the previous sample, per second
    blocked          logged blocked attempts of the remote in the filterlog window
    threat_list      1 when the remote is in a threat-category PF table
    ids              1 with Suricata alerts, 2 when one has severity 1 or 2

`activity` multiplies the score by the fade (a flow that stopped moving fades out over 20 s);
`floors` reserve places for the security classes S3, S2 and S1 (collector/evidence.h): minimums,
never caps, and places a class does not use return to the general pool.

Built-in profiles are immutable templates identified by fixed UUIDs (identity is never the
name); custom profiles, copies of a built-in or of another custom profile with their own UUIDs,
are configuration rows (Phase G).
"""

import hashlib

# the collector's closed feature vocabulary (collector/profile.h; CONTRACTS.md "Ranking features")
FEATURES = ("byte_rate", "packet_rate", "states", "new_state_rate", "blocked", "threat_list", "ids")
# one scale per feature, shared by the built-ins: the value at which a feature contributes
# weight x log(2)
SCALES = {"byte_rate": 10000, "packet_rate": 10, "states": 10, "new_state_rate": 1, "blocked": 10,
          "threat_list": 1, "ids": 1}

BALANCED = "9bded7b2-a028-44ca-b7ab-4e3357694174"
BANDWIDTH = "a5df6449-a682-4029-82c9-ae51b25a87db"
CONNECTIONS = "dcbf98a3-1297-438c-a78b-b21b5bc6bcdd"
SECURITY = "6c02d03d-4087-46a9-b5bc-6378fb5eeada"
DEFAULT = BALANCED

# Weights are the ranking contract's starting values (flow volume and direction come in Phase G,
# which also makes them total 100); floors reserve places for security classes S3, S2 and S1.
BUILTINS = [
    {"uuid": BALANCED, "name": "Balanced", "builtin": True, "activity": True, "floors": (5, 3, 2),
     "weights": {"byte_rate": 30, "packet_rate": 10, "states": 15, "new_state_rate": 20, "blocked": 5,
                 "threat_list": 5, "ids": 5},
     "description": "Traffic first, with connection counts and new connections, and a few places kept "
                    "for flows with security evidence."},
    {"uuid": BANDWIDTH, "name": "Bandwidth", "builtin": True, "activity": True, "floors": (0, 0, 0),
     "weights": {"byte_rate": 65, "packet_rate": 15, "states": 5, "new_state_rate": 5},
     "description": "Byte and packet rates, on a logarithmic scale."},
    {"uuid": CONNECTIONS, "name": "Connections", "builtin": True, "activity": False, "floors": (0, 0, 0),
     "weights": {"byte_rate": 10, "packet_rate": 10, "states": 35, "new_state_rate": 45},
     "description": "The most PF states and the most new connections, whatever their traffic."},
    {"uuid": SECURITY, "name": "Security", "builtin": True, "activity": False, "floors": (50, 30, 20),
     "weights": {"byte_rate": 5, "packet_rate": 5, "states": 10, "new_state_rate": 15, "blocked": 20,
                 "threat_list": 15, "ids": 30},
     "description": "Flows with security evidence first, idle or not (high-severity IDS, then other IDS "
                    "and heavy blocking, then threat lists and reputation), then connection activity."},
]
BY_UUID = {profile["uuid"]: profile for profile in BUILTINS}


def active(values=None):
    """The active profile: the configured UUID, or the default when it names no known profile."""
    uuid = (values or {}).get("ranking_profile") or DEFAULT
    return BY_UUID.get(uuid, BY_UUID[DEFAULT])


def definition(profile):
    """The collector's --profile definition (collector/PROTOCOL.md, "Startup")."""
    features = " ".join(f"{name}={float(weight):g}/{float(SCALES[name]):g}"
                        for name, weight in profile.get("weights", {}).items() if weight)
    floors = ",".join(str(int(floor)) for floor in profile.get("floors", (0, 0, 0)))
    return f"activity={int(bool(profile.get('activity')))} floors={floors} {features}".rstrip()


def generation(profile):
    """The definition's identity: changes whenever what the collector ranks by changes, so a
    snapshot or status can tell two versions of one (custom) profile apart."""
    return hashlib.sha256(definition(profile).encode()).hexdigest()[:16]


def descriptor(profile):
    """What status, the map and snapshots say about the active profile."""
    return {"uuid": profile["uuid"], "name": profile["name"], "builtin": bool(profile.get("builtin")),
            "generation": generation(profile)}


def catalog():
    """The selectable profiles (the settings field's options)."""
    return [{"uuid": profile["uuid"], "name": profile["name"], "description": profile["description"],
             "builtin": True} for profile in BUILTINS]
