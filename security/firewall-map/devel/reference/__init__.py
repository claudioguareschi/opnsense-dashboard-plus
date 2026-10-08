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

"""Unshipped semantic oracles for native PF equivalence and regression tests.

The oracle preserves the retired Python engine's behavior on purpose. Where the specification
deliberately corrects it, the native engine diverges and the difference is declared here (and
covered by a specification test that does not use the oracle).
"""

# (identifier, what the retired engine did, what the specification requires, specification test)
DIVERGENCES = (
    ("event-match-counter-orientation",
     "PF state counters behind an IDS/block tuple were reported in raw PF order "
     "(forward, reverse) as (bytes_in, bytes_out)",
     "bytes_in is traffic from the remote and bytes_out traffic to it, oriented by the PF "
     "initiator, as for Suricata-derived connections",
     "tests/test_native_engine.py: test_event_matches_are_oriented_by_the_pf_initiator_not_raw_counter_order"),
    ("sample-interval-ownership",
     "the collector supplied the elapsed time between its own step starts",
     "the helper measures the interval between its own PF dump requests and reports a "
     "baseline (no rates) for a helper's first sample",
     "tests/test_native_engine.py: test_first_sample_of_a_helper_is_a_baseline_then_intervals_are_measured_in_c"),
)
