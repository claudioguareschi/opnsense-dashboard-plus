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
rates and a linear fade. The others add, for each primitive, weight x log1p(value / scale):

    bytes     smoothed byte rate, both directions (bytes/s)
    packets   smoothed packet rate (packets/s)
    states    PF states of the flow now
    created   states created since the previous sample, per second

`activity` multiplies the score by the fade (a flow that stopped moving fades out over 20 s);
`floor` reserves that many of the 150 places for flagged flows (threat-listed or IDS, reputation
or blocked evidence) when there are such flows, and `flagged` adds to their score.
"""

PRIMITIVES = ("bytes", "packets", "states", "created")
MAX_PROFILES = 8
DEFAULT_FOCUS = "classic"

PROFILES = [
    {"key": "classic", "name": "Classic", "classic": True,
     "description": "The busiest flows by byte rate, fading out when they stop (the original ranking)."},
    {"key": "balanced", "name": "Balanced", "activity": True, "floor": 10, "flagged": 1.0,
     "weights": {"bytes": (1.0, 10000), "states": (0.5, 10), "created": (0.5, 1)},
     "description": "Traffic first, with connection counts and new connections, and at least 10 places "
                    "for flagged flows."},
    {"key": "bandwidth", "name": "Bandwidth", "activity": True, "floor": 0, "flagged": 0.0,
     "weights": {"bytes": (1.0, 1000), "packets": (0.25, 10)},
     "description": "Byte and packet rates only, on a logarithmic scale."},
    {"key": "security", "name": "Security", "activity": False, "floor": 100, "flagged": 3.0,
     "weights": {"bytes": (0.25, 10000), "states": (0.5, 10), "created": (1.0, 0.5)},
     "description": "Flagged flows first, idle or not (up to 100 places reserved), then connection "
                    "activity."},
    {"key": "connections", "name": "Connections", "activity": False, "floor": 0, "flagged": 0.0,
     "weights": {"states": (1.0, 1), "created": (1.0, 0.2)},
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
        weights = profile.get("weights", {})
        parts = []
        for primitive in PRIMITIVES:
            weight, scale = weights.get(primitive, (0.0, 1.0))
            parts.append(f"{float(weight):g} {float(scale):g}")
        rows.append(f"PROFILE {number} scored {int(bool(profile.get('activity')))} {int(profile.get('floor', 0))} "
                    f"{float(profile.get('flagged', 0.0)):g} " + " ".join(parts))
    return rows


def descriptor(profiles):
    """What the map's Focus selector lists."""
    return [{"key": profile["key"], "name": profile["name"], "description": profile["description"]}
            for profile in profiles]
