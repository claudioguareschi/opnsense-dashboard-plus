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

"""Test/development-only state attribution oracle."""

from lib.common import is_icmp
from .pf import StateFacts


def observe(records, lists_for, local_addresses, networks=None, sample=None):
    """Group the current states that touch a flagged address: {remote: summary}. sample:
    StateFacts.view() of records, when the caller already has it."""
    seen = {}
    # an address appears in many states: ask the lists once per address and sample
    verdicts = {}
    views, _ = sample if sample is not None else StateFacts().view(records, local_addresses, networks)
    for record, facts in views:
        pair = facts.pair
        if pair is None:
            continue
        remote = pair[1]
        if remote not in verdicts:
            verdicts[remote] = lists_for(remote)
        lists = verdicts[remote]
        if not lists:
            continue
        entry = seen.setdefault(remote, {
            "lists": lists, "inbound": 0, "outbound": 0, "targets": {}, "inside": {}, "services": {}, "bytes": 0,
            "youngest": None, "service_ports": {},
        })
        if record.age is not None:
            entry["youngest"] = record.age if entry["youngest"] is None else min(entry["youngest"], record.age)
        inside, service_port = facts.inside, facts.service_port
        if facts.remote_started:
            entry["inbound"] += 1
            if facts.target not in entry["targets"]:
                entry["targets"][facts.target] = None
        else:
            entry["outbound"] += 1
        if inside and inside.address not in entry["inside"]:
            entry["inside"][inside.address] = None
        service = facts.service
        if service not in entry["services"]:
            entry["services"][service] = None
            if not is_icmp(record.protocol) and service_port:
                entry["service_ports"][service] = f"{service_port}/{record.protocol}"
        entry["bytes"] += record.bytes_in + record.bytes_out
    # Dict membership is constant-time; convert the first-seen ordering back to the
    # existing list-shaped document only once, after the complete sample.
    for entry in seen.values():
        for field in ("targets", "inside", "services"):
            entry[field] = list(entry[field])
    return seen
