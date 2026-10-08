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

"""Test/development-only state history/ranking oracle."""

import firewallmap_collector as production
from firewallmap_collector import _Flow, _ranked, FADE_SECONDS, MAX_FLOWS, MAX_INSIDE, MAX_SERVICES
from lib.pf import _Record
from .pf import StateFacts


class _FlowTotals(_Record):
    """The retired engine's per-sample totals (its own copy: production now carries only the
    native-era fields). toward/away are bytes from/to the remote."""
    __slots__ = ("toward", "away", "packets", "states", "protocols", "services", "inside", "egress",
                 "remote_started", "local_started", "targets", "ports", "oldest", "bytes_toward", "bytes_away",
                 "rules")

    def __init__(self):
        self.toward = self.away = self.packets = self.states = 0
        self.protocols = set()
        self.services = {}
        self.inside = {}
        self.egress = {}
        self.remote_started = self.local_started = 0
        self.targets = {}
        self.ports = {}
        self.oldest = self.bytes_toward = self.bytes_away = 0
        self.rules = {}


RATE_SMOOTHING = 0.5


class FlowTracker(production.FlowTracker):
    """Turn successive PF state samples into per-flow byte rates with activity fading."""

    def __init__(self, fade_seconds=FADE_SECONDS, smoothing=RATE_SMOOTHING):
        self.fade_seconds = fade_seconds
        self.smoothing = smoothing
        self.counters = {}
        self.flows = {}
        self.sampled_at = None
        self.total_flows = 0
        self.native_visible = None

    def _totals(self, records, local_addresses, elapsed, networks=None, sample=None,
                interface_addresses=None, primary_wan_device=None):
        """{(local, remote): totals} for this sample, and the counters to diff the next one against.

        sample: StateFacts.view() of these records, when the caller already has it. This runs for
        every state of every sample, so each state is folded into its flow's totals in place.
        """
        counters = {}
        totals = {}
        previous_counters = self.counters
        views, lan_rules = sample if sample is not None else StateFacts().view(
            records, local_addresses, networks, interface_addresses, primary_wan_device)
        for record, facts in views:
            pair = facts.pair
            state_id = record.id
            if pair is None or state_id is None:
                continue
            if facts.src_is_remote:
                toward, away = record.bytes_in, record.bytes_out
            else:
                toward, away = record.bytes_out, record.bytes_in
            packets = record.packets_in + record.packets_out
            counters[state_id] = current = (toward, away, packets)
            age = record.age
            # what the state moved since the previous sample
            previous = previous_counters.get(state_id)
            if previous is not None:
                delta = (max(0, toward - previous[0]), max(0, away - previous[1]), max(0, packets - previous[2]))
            elif elapsed is not None and age is not None and age <= 2 * elapsed:
                # a state created since the previous sample: everything it counted is new
                delta = current
            else:
                delta = (0, 0, 0)
            total = totals.get(pair)
            if total is None:
                total = totals[pair] = _FlowTotals()
            # PF counts initiator->responder first; src is the initiator in parse_states()
            weight = delta[0] + delta[1] + 1
            if facts.remote_started:
                total.remote_started += weight
                # what the remote side connected to: a port-forward target or the firewall itself
                counts, key = total.targets, facts.target
                counts[key] = counts.get(key, 0) + weight
            else:
                total.local_started += weight
            if facts.inside:
                counts, key = total.inside, facts.inside.address
                counts[key] = counts.get(key, 0) + weight
            key = record.origif
            if key:
                counts = total.egress
                counts[key] = counts.get(key, 0) + weight
            service = facts.service
            counts = total.services
            counts[service] = counts.get(service, 0) + weight
            total.ports.setdefault(service, facts.port_label)
            if age is not None and age > total.oldest:
                total.oldest = age
            # bytes moved so far by the connections open now, and the rules that let them through
            total.bytes_toward += toward
            total.bytes_away += away
            rule = (lan_rules.get(facts.rule_key) if facts.rule_key is not None and lan_rules else None) \
                or record.rule
            if rule:
                counts = total.rules
                counts[rule] = counts.get(rule, 0) + 1
            total.toward += delta[0]
            total.away += delta[1]
            total.packets += delta[2]
            total.states += 1
            total.protocols.add(record.protocol)
        return totals, counters

    def _update_flow(self, flow, total, elapsed, now):
        if isinstance(flow, dict):
            # Some callers inject dict-shaped flows. Keep their object and mutate it as before;
            # production flows use attributes directly, without a per-field adapter.
            compact = _Flow(flow["first_seen"])
            for key in compact.keys():
                if key in flow:
                    compact[key] = flow[key]
            self._update_flow(compact, total, elapsed, now)
            flow.update(dict(compact))
            return
        flow.rate_in = self.smoothing * (total.toward / elapsed if elapsed else 0.0) + (1 - self.smoothing) * flow.rate_in
        flow.rate_out = self.smoothing * (total.away / elapsed if elapsed else 0.0) + (1 - self.smoothing) * flow.rate_out
        flow.packet_rate = self.smoothing * (total.packets / elapsed if elapsed else 0.0) + (1 - self.smoothing) * flow.packet_rate
        flow.rate = flow.rate_in + flow.rate_out
        flow.states = total.states
        flow.protocols = sorted(total.protocols)
        flow.services = _ranked(total.services, MAX_SERVICES)
        flow.service_ports = {name: total.ports[name] for name in flow.services if total.ports.get(name)}
        # how long the oldest connection behind this flow has been open
        flow.age = total.oldest
        flow.transferred = (total.bytes_toward, total.bytes_away)
        flow.rule = (_ranked(total.rules, 1) or [None])[0]
        flow.inside = _ranked(total.inside, MAX_INSIDE)
        flow.egress = (_ranked(total.egress, 1) or [None])[0]
        started = total.remote_started + total.local_started
        share = total.remote_started / started if started else 0.0
        flow.initiated = "remote" if share >= 0.75 else "local" if share <= 0.25 else "both"
        flow.targets = _ranked(total.targets, MAX_INSIDE)
        if total.toward + total.away > 0:
            flow.last_active = now

    def update(self, records, local_addresses, now, networks=None, sample=None,
               interface_addresses=None, primary_wan_device=None):
        elapsed = (now - self.sampled_at) if self.sampled_at is not None else None
        totals, self.counters = self._totals(records, local_addresses, elapsed, networks, sample,
                                             interface_addresses, primary_wan_device)
        self.sampled_at = now
        self.total_flows = len(totals)
        self.native_visible = None
        # a flow disappears together with its last PF state
        for pair in list(self.flows):
            if pair not in totals:
                del self.flows[pair]
        for pair, total in totals.items():
            flow = self.flows.setdefault(pair, _Flow(now))
            self._update_flow(flow, total, elapsed, now)

    def activity(self, flow, now):
        last_active = flow.last_active if isinstance(flow, _Flow) else flow["last_active"]
        if last_active is None:
            return 0.0
        return max(0.0, 1.0 - (now - last_active) / self.fade_seconds)

    def visible(self, now, limit=MAX_FLOWS):
        """Active or fading flows, strongest first, capped before they reach the browser (None: all)."""
        ranked = []
        for (local, remote), flow in self.flows.items():
            activity = self.activity(flow, now)
            if activity > 0:
                rate = flow.rate if isinstance(flow, _Flow) else flow["rate"]
                ranked.append((max(rate, 1.0) * activity, local, remote, flow, activity))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return ranked if limit is None else ranked[:limit]


def summarize_flows(tracker, geo, local_addresses, role, now, wall_time, hostnames=None, context=None,
                    limit=MAX_FLOWS, anchor=None, visible=None):
    if visible is None:
        visible = tracker.visible(now, limit)
        geo.resolve(address for _, local, remote, _, _ in visible for address in (local, remote))
    return production.summarize_flows(tracker, geo, local_addresses, role, now, wall_time, hostnames,
                                      context, anchor=anchor, visible=visible)


def __getattr__(name):
    return getattr(production, name)
