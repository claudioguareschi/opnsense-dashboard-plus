/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef FM_HISTORY_H
#define FM_HISTORY_H
#include "state.h"
/* Per-state counter history and the sample interval it implies.
 *
 * Timing: each sample is anchored at the CLOCK_MONOTONIC time its PF dump
 * request was sent. The interval of a sample is its anchor minus the anchor
 * of the last committed sample. A sample with no committed predecessor (a new
 * helper, after history_reset, or after an admission refusal) is a baseline:
 * interval -1 and zero deltas. The anchor commits only with the counters, so a
 * failed or aborted sample leaves both untouched and the next interval spans
 * it, exactly as its counter deltas do. Snapshot traversals never call this. */
struct history;
struct state_delta {
  uint64_t bytes_from_remote, bytes_to_remote, packets;
};
struct history *history_create(struct fm_error *);
void history_destroy(struct history *);
void history_reset(struct history *);
/* Stages a sample anchored at `anchor` (monotonic seconds). */
bool history_begin(struct history *, double anchor, struct fm_error *);
/* The staged sample's interval in seconds, or -1 for a baseline sample. */
double history_interval(const struct history *);
bool history_observe(struct history *, const struct state *, bool remote_initiated,
                     struct state_delta *, struct fm_error *);
void history_commit(struct history *);
void history_abort(struct history *);
size_t history_bytes(const struct history *);
#endif
