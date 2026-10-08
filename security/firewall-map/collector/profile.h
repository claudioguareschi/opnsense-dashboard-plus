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

/* The active Ranking Profile (CONTRACTS.md, "Ranking profile"): the complete
 * operational ranking policy the collector runs under, one for every viewer.
 * It is startup configuration: OPNsense resolves and validates it and passes
 * it as schema-v1 JSON (--profile <file>); profile_load compiles it once into
 * the fixed fields below, and nothing changes it for the life of the process.
 *
 * Effective score of a tracked flow:
 *   (sum over features f of weight_f * log1p(value_f / scale_f)) x asset
 * where the traffic features (byte rate, packet rate, flow volume) fade with
 * the flow's activity, the others (states, new states, evidence) are present
 * facts, `asset` is the multiplier of the flow's local anchor (longest
 * matching CIDR rule, else the default), and an incumbency bonus applies to
 * the flows selected last sample. A flow scoring 0 is never selected.
 * Security visibility floors reserve a minimum share of the selection per
 * class (S3, S2, S1; evidence.h), ceiling-rounded, S3 first: each flow counts
 * only for its own class, unused places return to the general pool, a floor
 * is never a cap, and asset importance never changes a class.
 *
 * Without a profile the selection is the base ranking itself, Classic:
 * max(byte rate, 1) x activity with EMA rates, linear fade and first-seen
 * ties. It is not a product profile: only a collector started without
 * --profile uses it (the regression oracle and its tests). */
#define PROFILE_INCUMBENCY 1.1
#define PROFILE_SCHEMA_VERSION 1
#define PROFILE_FILE_MAX (1u << 20)
#define PROFILE_ASSET_RULES_MAX 4096
/* Asset multipliers: sane numeric limits, rejected outside (never clamped). */
#define PROFILE_MULTIPLIER_MIN 0.000001
#define PROFILE_MULTIPLIER_MAX 1000000.0
/* Discovery weight units of the least important multiplier when a profile
 * has asset rules (profile_unit). */
#define PROFILE_DISCOVERY_UNIT 64
/* The quality features: a closed vocabulary, compiled to these IDs. */
enum profile_feature {
  FEATURE_BYTE_RATE = 0,           /* EMA-smoothed observed byte rate, both directions (bytes/s) */
  FEATURE_PACKET_RATE = 1,         /* EMA-smoothed observed packet rate (packets/s) */
  FEATURE_ACTIVE_STATES = 2,       /* PF states of the flow now */
  FEATURE_NEW_STATE_RATE = 3,      /* states new since the previous sample, per second */
  FEATURE_FLOW_VOLUME = 4,         /* bytes of the current flow episode while tracked */
  FEATURE_PF_BLOCKED = 5,          /* logged blocked attempts of the remote in the window */
  FEATURE_THREAT_INTELLIGENCE = 6, /* 1 when the remote is in a threat-category PF table */
  FEATURE_IDS_EVIDENCE = 7,        /* 1 with IDS evidence, 2 when it is high-severity */
  FEATURE_COUNT = 8
};
struct asset_span;
struct profile {
  char uuid[37];
  double weight[FEATURE_COUNT];     /* the administrator's points, totalling 100 */
  double floor_percent[4];          /* by security class (index 1-3) */
  double default_multiplier;
  /* asset importance: disjoint address spans with their longest-prefix
   * multiplier, sorted, per family (immutable after profile_load) */
  struct asset_span *spans4, *spans6;
  size_t spans4_count, spans6_count;
  size_t asset_rules;
  double min_multiplier; /* the smallest of the default and every rule's */
};
/* Reads and compiles a schema-v1 profile file. On failure `why` says what
 * is wrong (unknown schema version, unknown or missing feature, weights not
 * totalling 100, invalid number or range, malformed CIDR, conflicting
 * duplicate prefix, unsupported direction...). */
bool profile_load(const char *path, struct profile *, char *why, size_t why_size);
/* The same from text (tests and the loader). */
bool profile_compile(const char *text, size_t length, struct profile *, char *why, size_t why_size);
void profile_release(struct profile *);
/* The asset multiplier of an address (the default when no rule matches;
 * 1 without a profile). */
double profile_asset(const struct profile *, struct addr);
/* Discovery weight units of a multiplier: 1 without asset rules (discovery
 * counts raw values), else PROFILE_DISCOVERY_UNIT x multiplier / the
 * profile's smallest multiplier, rounded (saturating). */
uint64_t profile_unit(const struct profile *, double multiplier);
/* The multiplier a discovery unit stands for (inverse of profile_unit). */
double profile_unit_multiplier(const struct profile *, uint64_t unit);
/* The raw-value divisor of discovery counts in the least important units. */
uint64_t profile_unit_floor(const struct profile *);
/* A security class's reserved places in a selection of `limit`: its floor
 * percentage, rounded up (S3 10% of 150 = 15, S2 5% = 8, S1 2% = 3). */
size_t profile_floor_places(const struct profile *, enum security_class, size_t limit);
struct selected {
  uint32_t flow; /* aggregate flow index */
  double score;
};
struct ranker;
struct ranker *ranker_create(struct fm_error *);
void ranker_destroy(struct ranker *);
/* Sets the active profile once, at startup (NULL: the base ranking). The
 * profile is borrowed for the ranker's lifetime. */
void ranker_configure(struct ranker *, const struct profile *);
/* The active profile, or NULL for the base ranking. */
const struct profile *ranker_profile(const struct ranker *);
/* Selects up to `limit` flows, in rank order; every tracked flow's effective
 * score is available afterwards (retention and promotion use it). */
bool ranker_select(struct ranker *, const struct aggregate *, const struct ranking *,
                   double interval, size_t limit, struct fm_error *);
size_t ranker_selection(const struct ranker *, const struct selected **);
/* The last selection's effective score of aggregate flow n (0 if none). */
double ranker_score(const struct ranker *, size_t flow);
/* The effective score a profile would give a flow with these values
 * (promotion estimates for untracked flows; activity 1). */
double profile_estimate(const struct profile *, const double values[FEATURE_COUNT], double asset);
/* The value of a feature for an aggregate flow. */
double profile_value(const struct aggregate *, const struct ranking *, size_t flow,
                     enum profile_feature, double interval);
/* Forgets incumbency (a refused sample). */
void ranker_reset(struct ranker *);
size_t ranker_bytes(const struct ranker *);
#endif
