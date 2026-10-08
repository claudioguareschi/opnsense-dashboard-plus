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



"""Flow Ranking Profiles: what the map's Focus chooses between.

The collector selects the top flows of every enabled profile on every sample, over its shared
tracked set (collector/CONTRACTS.md, "Profiles"); a viewer's Focus only picks one of those
selections, so viewers with different Focuses cost the collector nothing more.

Classic is the ranking Firewall Map has always had: max(byte rate, 1) x activity, with smoothed
rates and a linear fade. The others add, for each feature, weight x log1p(value / scale):

    byte_rate        EMA-smoothed observed byte rate, both directions (bytes/s; Classic's rate)
    packet_rate      EMA-smoothed observed packet rate (packets/s)
    states           PF states of the flow now
    new_state_rate   states new since the previous sample, per second
    blocked          logged blocked attempts of the remote in the filterlog window
    threat_list      1 when the remote is in a threat-category PF table
    ids              1 with Suricata alerts, 2 when one has severity 1 or 2

`activity` multiplies the score by the fade (a flow that stopped moving fades out over 20 s);
`floors` reserve places for the security classes S3, S2 and S1 (collector/evidence.h): minimums,
never caps, and places a class does not use return to the general pool.
"""

# the collector's closed feature vocabulary (collector/profile.h; CONTRACTS.md "Ranking features")
FEATURES = ("byte_rate", "packet_rate", "states", "new_state_rate", "blocked", "threat_list", "ids")
# one scale per feature, shared by the built-ins: the value at which a feature contributes
# weight x log(2)
SCALES = {"byte_rate": 10000, "packet_rate": 10, "states": 10, "new_state_rate": 1, "blocked": 10,
          "threat_list": 1, "ids": 1}
MAX_PROFILES = 8
DEFAULT_FOCUS = "classic"

# Weights are the 0.60 ranking contract's starting values (flow volume and direction come in a
# later phase); floors reserve places for security classes S3, S2 and S1 (collector/evidence.h).
PROFILES = [
    {"key": "classic", "name": "Classic", "classic": True,
     "description": "The busiest flows by byte rate, fading out when they stop (the original ranking)."},
    {"key": "balanced", "name": "Balanced", "activity": True, "floors": (5, 3, 2),
     "weights": {"byte_rate": 30, "packet_rate": 10, "states": 15, "new_state_rate": 20, "blocked": 5,
                 "threat_list": 5, "ids": 5},
     "description": "Traffic first, with connection counts and new connections, and a few places kept "
                    "for flows with security evidence."},
    {"key": "bandwidth", "name": "Bandwidth", "activity": True, "floors": (0, 0, 0),
     "weights": {"byte_rate": 65, "packet_rate": 15, "states": 5, "new_state_rate": 5},
     "description": "Byte and packet rates, on a logarithmic scale."},
    {"key": "security", "name": "Security", "activity": False, "floors": (50, 30, 20),
     "weights": {"byte_rate": 5, "packet_rate": 5, "states": 10, "new_state_rate": 15, "blocked": 20,
                 "threat_list": 15, "ids": 30},
     "description": "Flows with security evidence first, idle or not (high-severity IDS, then other IDS "
                    "and heavy blocking, then threat lists and reputation), then connection activity."},
    {"key": "connections", "name": "Connections", "activity": False, "floors": (0, 0, 0),
     "weights": {"byte_rate": 10, "packet_rate": 10, "states": 35, "new_state_rate": 45},
     "description": "The most PF states and the most new connections, whatever their traffic."},
]
KEYS = [profile["key"] for profile in PROFILES]


def enabled():
    """The enabled profiles, in collector order (Classic first: it is the regression anchor)."""
    return PROFILES[:MAX_PROFILES]


def request_rows(profiles):
    """The collector's PROFILE rows (collector/PROTOCOL.md)."""
    rows = []
    for number, profile in enumerate(profiles):
        if profile.get("classic"):
            rows.append(f"PROFILE {number} classic")
            continue
        features = " ".join(f"{name}={float(weight):g}/{float(SCALES[name]):g}"
                            for name, weight in profile.get("weights", {}).items() if weight)
        floors = ",".join(str(int(floor)) for floor in profile.get("floors", (0, 0, 0)))
        rows.append(f"PROFILE {number} scored activity={int(bool(profile.get('activity')))} floors={floors} "
                    f"{features}".rstrip())
    return rows


def descriptor(profiles):
    """What the map's Focus selector lists."""
    return [{"key": profile["key"], "name": profile["name"], "description": profile["description"]}
            for profile in profiles]
