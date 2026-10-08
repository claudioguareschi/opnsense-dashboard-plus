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

"""Test/development-only full-PF correlation oracle."""

from collections import deque
from itertools import islice
from lib import ids as production
from lib.ids import CORRELATION_SECONDS, CORRELATION_RETRY_SECONDS, MAX_CORRELATION_KEYS, MAX_IDS_FLOWS, MAX_PENDING_ALERTS, ALERT_WINDOW_SECONDS
from lib.pf import _Record
from .pf import StateFacts


class _StateConnection(_Record):
    """A state-derived connection; recent and IDS evidence share this sample's record."""
    __slots__ = ("key", "protocol", "public", "remote", "inside", "remote_started", "bytes_in", "bytes_out",
                 "age", "rule", "rule_description", "interface", "state", "decision", "source", "seen")

    def __init__(self, key, facts, record, rule, description, now):
        self.key = key
        self.protocol = key[0]
        self.public = facts.public
        self.remote = facts.remote
        self.inside = facts.inside_text
        self.remote_started = facts.remote_started
        self.bytes_in = record.bytes_in
        self.bytes_out = record.bytes_out
        self.age = record.age
        self.rule = rule
        self.rule_description = description
        self.interface = record.origif
        self.state = record.state
        self.decision = "pass"
        self.source = "state"
        self.seen = now


class Correlator(production.Correlator):
    def __init__(self):
        super().__init__()
        self.recent = {}

    def observe_states(self, records, local_addresses, now, descriptions=None, networks=None, sample=None):
        """Index this sample's states by their outside tuple. sample: StateFacts.view() of records,
        when the caller already has it."""
        current = {}
        ambiguous = set()
        views, lan_rules = sample if sample is not None else StateFacts().view(records, local_addresses, networks)
        descriptions = descriptions or {}
        for record, facts in views:
            if facts.pair is None:
                continue
            key = facts.outside
            if key is None:
                continue
            rule = facts.rule_of(record, lan_rules)
            # make_connection()'s shape in one step: this runs for every state of every sample
            connection = _StateConnection(key, facts, record, rule, descriptions.get(rule or "", ""), now)
            previous = current.get(key)
            if previous and previous.inside != connection.inside:
                ambiguous.add(key)
            current[key] = connection
        self.current = current
        self.ambiguous_keys = ambiguous
        if current:
            self._seen(now)
        for key, connection in current.items():
            self.recent.pop(key, None)
            self.recent[key] = connection
        self._expire(now)

    def _expire(self, now):
        self._flagged = None
        for store in (self.recent, self.blocked):
            expired = []
            for key, item in store.items():
                if now - item.get("seen", item.get("time", now)) > CORRELATION_SECONDS:
                    expired.append(key)
                elif self._in_order:
                    break
            for key in expired:
                del store[key]
            # One traversal of the oldest keys: restarting a dict iterator after every
            # deletion repeatedly scans the growing deleted prefix of a large sample.
            excess = max(0, len(store) - MAX_CORRELATION_KEYS)
            for key in list(islice(store, excess)):
                del store[key]
        for key in [key for key, flow in self.flows.items() if now - flow["last"] > ALERT_WINDOW_SECONDS]:
            del self.flows[key]
        while len(self.flows) > MAX_IDS_FLOWS:
            del self.flows[min(self.flows, key=lambda key: self.flows[key]["last"])]

    def resolve(self, local_addresses, now, networks=None):
        """Try pending alerts against what PF and the firewall log have shown; give up after a while."""
        still = []
        for received, alert in self.pending:
            key = self.alert_key(alert, local_addresses, networks)
            if key in self.current:
                kind = "ambiguous" if key in self.ambiguous_keys else "current"
                connection = self.current[key]
            elif key in self.recent:
                kind, connection = "recent", self.recent[key]
            elif key in self.blocked:
                kind, connection = "blocked", self.blocked[key]
            elif now - received < CORRELATION_RETRY_SECONDS:
                still.append((received, alert))
                continue
            else:
                # no firewall state or log entry: Suricata's own record is the connection (an IPS drop
                # never reaches the firewall); a port forward still names the inside target
                self.stats["unmatched"] += 1
                self.unmatched_samples = (self.unmatched_samples + [{
                    "time": alert["time"], "key": list(key), "signature": alert["signature"]}])[-20:]
                kind, connection = "alert", self.alert_connection(key, alert, now)
            if kind != "alert":
                self.stats[kind] += 1
            self._attach(key, kind, connection, alert, now)
        self.pending = deque(still, maxlen=MAX_PENDING_ALERTS)
        self.stats["pending"] = len(still)


def __getattr__(name):
    return getattr(production, name)
