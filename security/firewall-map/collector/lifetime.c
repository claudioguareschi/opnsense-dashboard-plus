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

#include "lifetime.h"
#include <stdlib.h>
#include <time.h>

bool lifetime_index_applies(unsigned index) {
  return index <= 13 || (index >= 20 && index < LIFETIME_TIMEOUTS);
}

uint64_t lifetime_table_max(const uint32_t timeouts[LIFETIME_TIMEOUTS]) {
  uint64_t max = 0;
  for (unsigned i = 0; i < LIFETIME_TIMEOUTS; i++)
    if (lifetime_index_applies(i) && timeouts[i] > max)
      max = timeouts[i];
  return max;
}

/* All in u64: EXPIRE is the kernel's u32 truncation, widened without sign
 * extension; nothing here can wrap. */
bool lifetime_expire_valid(uint64_t timeout_max, uint32_t expire, uint64_t uptime) {
  uint64_t limit = timeout_max > uptime ? timeout_max : uptime;
  return (uint64_t)expire <= limit;
}

bool lifetime_age_known(uint32_t age, uint64_t uptime) { return (uint64_t)age <= uptime; }

uint64_t lifetime_uptime(void) {
#ifdef FM_TEST_HOOKS
  const char *fixed = getenv("FM_TEST_UPTIME");
  if (fixed)
    return strtoull(fixed, NULL, 10);
#endif
  struct timespec now;
#ifdef CLOCK_UPTIME
  if (clock_gettime(CLOCK_UPTIME, &now))
#else
  if (clock_gettime(CLOCK_MONOTONIC, &now))
#endif
    return 0;
  return now.tv_sec < 0 ? 0 : (uint64_t)now.tv_sec;
}

static void reread_uptime(struct lifetime_screen *ls) {
  uint64_t now = lifetime_uptime();
  if (now > ls->uptime)
    ls->uptime = now;
  ls->limit = ls->bound.timeout_max > ls->uptime ? ls->bound.timeout_max : ls->uptime;
}

void lifetime_screen_begin(struct lifetime_screen *ls, struct lifetime_bound bound) {
  *ls = (struct lifetime_screen){.bound = bound};
  reread_uptime(ls);
}

const struct state *lifetime_screen_state(struct lifetime_screen *ls, const struct state *s,
                                          struct state *scratch) {
  ls->observed++;
  if (ls->bound.available && s->expire > ls->limit) {
    reread_uptime(ls); /* the state may have been reported after the last reading */
    if (!lifetime_expire_valid(ls->bound.timeout_max, s->expire, ls->uptime)) {
      ls->invalid++;
      return NULL;
    }
  }
  if (s->age > ls->uptime) {
    reread_uptime(ls);
    if (!lifetime_age_known(s->age, ls->uptime)) {
      *scratch = *s;
      scratch->age = FM_AGE_UNKNOWN;
      ls->age_unknown++;
      return scratch;
    }
  }
  return s;
}
