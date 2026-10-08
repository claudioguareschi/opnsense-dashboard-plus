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


#ifndef FM_PROFILE_H
#define FM_PROFILE_H
#include "aggregate.h"
#include "ranking.h"

/* Flow Ranking Profiles (CONTRACTS.md, "Profiles"). Every enabled profile
 * selects its top flows each sample over the shared tracked set; a viewer's
 * Focus only chooses among the selections.
 *
 * Classic is the current ranking itself: max(rate, 1) x activity with EMA
 * rates, linear fade and first-seen ties. Every other profile scores
 *   sum_i weight_i * log1p(value_i / scale_i) + flagged weight (flagged flows)
 * over the primitives below, multiplied by the fade activity when the
 * profile says so, plus an incumbency bonus for the flows it selected last
 * sample. A flow scoring 0 is never selected. `floor` reserves that many
 * slots for flagged flows (threat-listed or evidence) when there are such
 * flows; it is a minimum, never a cap: flagged flows also win general
 * slots on their score. Ties go to the earlier first-seen flow. */
#define PROFILE_MAX 8
#define PROFILE_INCUMBENCY 1.1
enum profile_primitive {
  PRIMITIVE_BYTES = 0,   /* smoothed byte rate, both directions (bytes/s) */
  PRIMITIVE_PACKETS = 1, /* smoothed packet rate (packets/s) */
  PRIMITIVE_STATES = 2,  /* PF states of the flow now */
  PRIMITIVE_CREATED = 3, /* states created since the previous sample, per second */
  PRIMITIVE_COUNT = 4
};
struct profile {
  bool classic;
  bool activity;
  unsigned floor;
  double weight[PRIMITIVE_COUNT], scale[PRIMITIVE_COUNT];
  double flagged;
};
struct selected {
  uint32_t flow; /* aggregate flow index */
  double score;
};
struct profiles;
struct profiles *profiles_create(struct fm_error *);
void profiles_destroy(struct profiles *);
/* Sets the enabled profiles; a change of definitions forgets incumbency. */
bool profiles_configure(struct profiles *, const struct profile *, size_t count, struct fm_error *);
size_t profiles_count(const struct profiles *);
const struct profile *profiles_at(const struct profiles *, size_t);
/* Selects up to `limit` flows for every profile. */
bool profiles_select(struct profiles *, const struct aggregate *, const struct ranking *,
                     double interval, size_t limit, struct fm_error *);
size_t profiles_selection(const struct profiles *, size_t profile, const struct selected **);
/* The value of a primitive for an aggregate flow (as profiles_select saw it). */
double profiles_value(const struct aggregate *, const struct ranking *, size_t flow,
                      enum profile_primitive, double interval);
/* Forgets incumbency (a refused sample). */
void profiles_reset(struct profiles *);
size_t profiles_bytes(const struct profiles *);
#endif
