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

/* The active Ranking Profile (CONTRACTS.md, "Ranking profile" and "Ranking
 * features"). Exactly one profile ranks the collector's flows for every
 * viewer: it is operational policy, set by the administrator, and startup
 * configuration (--profile): compiled once, immutable for the process.
 *
 * A profile scores every tracked flow as
 *   sum over features f of weight_f * log1p(value_f / scale_f)
 * over a closed set of features, multiplied by the fade activity when the
 * profile says so, plus an incumbency bonus for the flows it selected last
 * sample. A flow scoring 0 is never selected. Floors reserve places per
 * security class (S3, S2, S1; evidence.h): each flow counts only for its own
 * class, unused places return to the general pool, and a reserved class
 * also wins general places on its score. Ties go to the earlier first-seen
 * flow.
 *
 * Without a profile the selection is the base ranking itself, Classic:
 * max(byte rate, 1) x activity with EMA rates, linear fade and first-seen
 * ties. It is not a product profile: only a collector started without
 * --profile uses it (the regression oracle and its tests); the service
 * always starts one with the active profile. */
#define PROFILE_INCUMBENCY 1.1
/* The ranking features (a closed vocabulary: the request names them, the
 * parser compiles them to these IDs once per request). */
enum profile_feature {
  FEATURE_BYTE_RATE = 0,      /* EMA-smoothed observed byte rate, both directions (bytes/s) */
  FEATURE_PACKET_RATE = 1,    /* EMA-smoothed observed packet rate (packets/s) */
  FEATURE_STATES = 2,         /* PF states of the flow now */
  FEATURE_NEW_STATE_RATE = 3, /* states new since the previous sample, per second */
  FEATURE_BLOCKED = 4,        /* logged blocked attempts of the remote in the window */
  FEATURE_THREAT_LIST = 5,    /* 1 when the remote is in a threat-category PF table */
  FEATURE_IDS = 6,            /* 1 with IDS evidence, 2 when it is high-severity */
  FEATURE_COUNT = 7
};
struct profile {
  bool activity;
  unsigned floor[4]; /* reserved places by security class (index 1-3; 0 unused) */
  double weight[FEATURE_COUNT], scale[FEATURE_COUNT];
};
/* Parses a profile definition ("activity=1 floors=5,3,2
 * byte_rate=30/10000 ..."): every key known, given once, in range; unknown
 * or malformed is an error (message in `why`). Features left out weigh 0. */
bool profile_parse(const char *text, struct profile *, const char **why);
struct selected {
  uint32_t flow; /* aggregate flow index */
  double score;
};
struct ranker;
struct ranker *ranker_create(struct fm_error *);
void ranker_destroy(struct ranker *);
/* Sets the active profile once, at startup (NULL: the base ranking). */
void ranker_configure(struct ranker *, const struct profile *);
/* The active profile, or NULL for the base ranking. */
const struct profile *ranker_profile(const struct ranker *);
/* Selects up to `limit` flows, in rank order. */
bool ranker_select(struct ranker *, const struct aggregate *, const struct ranking *,
                   double interval, size_t limit, struct fm_error *);
size_t ranker_selection(const struct ranker *, const struct selected **);
/* The value of a feature for an aggregate flow. */
double profile_value(const struct aggregate *, const struct ranking *, size_t flow,
                     enum profile_feature, double interval);
/* Forgets incumbency (a refused sample). */
void ranker_reset(struct ranker *);
size_t ranker_bytes(const struct ranker *);
#endif
