/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
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

/* Development tools rank with the built-in Balanced profile, exactly as the
 * service passes it at startup: the collector has no ranking of its own. */
#ifndef FM_DEVEL_BALANCED_PROFILE_H
#define FM_DEVEL_BALANCED_PROFILE_H

#include "../collector/profile.h"
#include "../collector/protocol.h"
#include <string.h>

static const char FM_BALANCED_PROFILE[] =
    "{\"schema_version\":1,\"profile\":{\"uuid\":\"9bded7b2-a028-44ca-b7ab-4e3357694174\","
    "\"name\":\"Balanced\",\"weights\":{\"byte_rate\":25,\"packet_rate\":5,\"active_states\":15,"
    "\"new_state_rate\":15,\"flow_volume\":15,\"pf_blocked\":8,\"threat_intelligence\":8,"
    "\"ids_evidence\":9},\"asset_importance\":{\"default_multiplier\":1,\"rules\":[]},"
    "\"security_visibility\":{\"s3_min_percent\":4,\"s2_min_percent\":2,\"s1_min_percent\":1},"
    "\"direction\":\"equal\"}}";

static inline bool fm_balanced_profile(struct profile *profile) {
  char why[128];
  return profile_compile(FM_BALANCED_PROFILE, strlen(FM_BALANCED_PROFILE), profile, why, sizeof(why));
}

/* The ranker's selection as response rows (rank order), as the engine
 * writes them; rows holds BUDGET_RANKED_FLOWS. */
static inline size_t fm_selection_rows(const struct ranker *ranker, const struct ranking *ranking,
                                       const struct aggregate *a, struct ranked_flow *rows) {
  const struct selected *chosen;
  size_t count = ranker_selection(ranker, &chosen);
  for (size_t k = 0; k < count; k++) {
    struct flow_rates rates = {0};
    ranking_rates(ranking, chosen[k].flow, &rates);
    rows[k] = (struct ranked_flow){chosen[k].flow, rates.rate_from_remote, rates.rate_to_remote,
                                   rates.packet_rate, rates.activity, chosen[k].score,
                                   (unsigned char)profile_presence(aggregate_flow(a, chosen[k].flow), &rates),
                                   rates.attempts};
  }
  return count;
}

#endif
