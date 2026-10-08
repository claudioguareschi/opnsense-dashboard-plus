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

"""Unshipped semantic oracles for state collector PF equivalence and regression tests.

The oracle preserves the retired Python engine's behavior on purpose. Where the specification
deliberately corrects it, the state collector diverges and the difference is declared here (and
covered by a specification test that does not use the oracle).
"""

# (identifier, what the retired engine did, what the specification requires, specification test)
DIVERGENCES = (
    ("event-match-counter-orientation",
     "PF state counters behind an IDS/block tuple were reported in raw PF order "
     "(forward, reverse) as (bytes_in, bytes_out)",
     "bytes_in is traffic from the remote and bytes_out traffic to it, oriented by the PF "
     "initiator, as for Suricata-derived connections",
     "tests/test_collector_engine.py: test_event_matches_are_oriented_by_the_pf_initiator_not_raw_counter_order"),
    ("sample-interval-ownership",
     "the collector supplied the elapsed time between its own step starts",
     "the helper measures the interval between its own PF dump requests and reports a "
     "baseline (no rates) for a helper's first sample",
     "tests/test_collector_engine.py: test_first_sample_of_a_helper_is_a_baseline_then_intervals_are_measured_in_c"),
    ("address-family-translation",
     "a state whose wire and stack keys had different address families failed the whole sample",
     "af-to states are recognized, skipped before any aggregation and counted; the sample is "
     "marked incomplete; anything else unrecognized still fails it",
     "tests/test_collector_specification.py: test_address_family_translation_is_skipped_and_counted"),
    ("snapshot-exemplar-selection",
     "snapshot detail kept states in traversal order and failed when incident evidence exceeded "
     "the ceiling",
     "per-flow quotas (80% reserved for incident flows, 20 each first, water-filled), most "
     "bytes then newest then PF identity, exact totals; truncation is reported, never a failure",
     "tests/test_collector_snapshot.py: test_byte_and_count_backstops_and_incident_truncation"),
    ("address-classification",
     "classification followed the running Python's ipaddress module, where IPv4-mapped shared "
     "address space (::ffff:100.64.0.0/106) was neither public nor private",
     "the plugin's explicit IANA table; IPv4-mapped addresses always follow their IPv4 meaning",
     "tests/test_classification.py: test_matches_the_runtime_ipaddress_module_except_declared"),
)
