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

/* Checks of collector/lifetime.c, the PF state lifetime screen: the validity
 * rule at and around its limits, the timeout tables (applying indexes, rule
 * maxima, adaptive values), fail-open without a bound, unknown ages, the
 * observed pfsync-import wrap, family/protocol independence and exact
 * counting. Built with FM_TEST_HOOKS (FM_TEST_UPTIME moves the clock) and run
 * by tests/test_collector_lifetime.py; prints "ok" or every violation. */
#include "../collector/lifetime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failed;
static void expect(const char *what, bool ok) {
  if (!ok) {
    printf("%s\n", what);
    failed = 1;
  }
}
static void set_uptime(unsigned long long seconds) {
  char text[32];
  snprintf(text, sizeof(text), "%llu", seconds);
  setenv("FM_TEST_UPTIME", text, 1);
}
static struct state make(uint32_t expire, uint32_t age, unsigned af, unsigned proto) {
  struct state s;
  memset(&s, 0, sizeof(s));
  s.id = 1;
  s.creator = 7;
  s.expire = expire;
  s.age = age;
  for (unsigned k = 0; k < 2; k++) {
    s.key[k].proto = (unsigned char)proto;
    for (unsigned e = 0; e < 2; e++) {
      s.key[k].e[e].a.af = (unsigned char)af;
      s.key[k].e[e].a.b[af == 4 ? 3 : 15] = (unsigned char)(e + 1);
    }
  }
  return s;
}
static struct lifetime_bound bound(uint64_t max) {
  return (struct lifetime_bound){.available = true, .timeout_max = max};
}

int main(void) {
  /* the rule, as reported values (u32 EXPIRE, u64 uptime and limit) */
  expect("1 normal expiry below the timeout", lifetime_expire_valid(86400, 3600, 600000));
  expect("2 expiry exactly at the timeout bound", lifetime_expire_valid(86400, 86400, 5000));
  expect("2 one second above the timeout (uptime smaller)", !lifetime_expire_valid(86400, 86401, 5000));
  expect("3 expiry exactly at the uptime, uptime larger", lifetime_expire_valid(86400, 600000, 600000));
  expect("4 above max(timeout, uptime): rejected", !lifetime_expire_valid(86400, 600001, 600000));
  expect("4 above max(uptime, timeout): rejected", !lifetime_expire_valid(900000, 900001, 600000));
  expect("5 already expired: absolute expiry below the uptime", lifetime_expire_valid(86400, 599990, 600000));
  expect("5 PFTM_PURGE reports the uptime itself", lifetime_expire_valid(86400, 600000, 600000));
  expect("6 a very large configured timeout admits large expiries",
         lifetime_expire_valid(4000000000ull, 1270699076u, 385008));
  expect("width: largest u32 with the largest u32 timeout", lifetime_expire_valid(0xFFFFFFFFull, 0xFFFFFFFFu, 1));
  expect("width: uptime beyond 32 bits is not truncated", lifetime_expire_valid(86400, 0xFFFFFFFFu, 5000000000ull));
  expect("width: zero timeout and zero uptime still admit 0", lifetime_expire_valid(0, 0, 0));
  expect("age at the uptime is known", lifetime_age_known(385008, 385008));
  expect("age above the uptime is unknown", !lifetime_age_known(385009, 385008));
  expect("an age above 32 bits of uptime stays known", lifetime_age_known(0xFFFFFFFFu, 5000000000ull));

  /* timeout tables: applying indexes only; a rule's larger value raises it */
  uint32_t defaults[LIFETIME_TIMEOUTS] = {120, 30, 86400, 900, 45, 90, 60, 30, 60, 20, 10, 60, 30, 60,
                                          30, 10, 0, 0, 0, 30, 60, 30, 86400, 900, 90};
  expect("default table maximum", lifetime_table_max(defaults) == 86400);
  uint32_t rule[LIFETIME_TIMEOUTS] = {0};
  rule[2] = 604800; /* one rule: tcp.established one week */
  uint64_t rules = lifetime_table_max(rule), defaults_max = lifetime_table_max(defaults);
  uint64_t max = rules > defaults_max ? rules : defaults_max;
  expect("7 a per-rule timeout larger than the defaults raises the maximum", max == 604800);
  expect("7 a state of that rule is accepted", lifetime_expire_valid(max, 600000, 300000));
  uint32_t adaptive[LIFETIME_TIMEOUTS];
  memcpy(adaptive, defaults, sizeof(adaptive));
  adaptive[16] = 1000000000u; /* adaptive.start, a state count */
  adaptive[17] = 2000000000u; /* adaptive.end */
  adaptive[14] = adaptive[15] = adaptive[18] = adaptive[19] = 4000000000u; /* frag, interval, src.track, ts */
  expect("8 adaptive start/end (counts) and non-state timeouts do not enlarge the bound",
         lifetime_table_max(adaptive) == 86400);
  expect("8 adaptive scaling only shortens: a scaled expiry is accepted", lifetime_expire_valid(86400, 43200, 5000));
  expect("8 the unscaled timeout is the bound", !lifetime_expire_valid(86400, 86401, 5000));
  for (unsigned i = 0; i < LIFETIME_TIMEOUTS; i++)
    expect("applying indexes: protocol timeouts only",
           lifetime_index_applies(i) == (i <= 13 || (i >= 20 && i <= 24)));

  /* the screen */
  struct lifetime_screen ls;
  struct state scratch;
  set_uptime(385008);
  /* 11: the observed wrap (fw2, 2026-10-08): EXPIRE about 2^64/1000 mod 2^32 */
  struct state wrapped = make(1270699076u, 3505390807u, 4, 6);
  lifetime_screen_begin(&ls, bound(86400));
  expect("11 the observed pfsync-import wrap is rejected", lifetime_screen_state(&ls, &wrapped, &scratch) == NULL);
  struct state edge = make(0xFFFFFFFFu, 1, 4, 6);
  expect("11 the u32 maximum is rejected", lifetime_screen_state(&ls, &edge, &scratch) == NULL);
  expect("14 counted once each", ls.observed == 2 && ls.invalid == 2 && ls.age_unknown == 0);

  /* 9: no bound: nothing is rejected (fail open), ages are still screened */
  lifetime_screen_begin(&ls, (struct lifetime_bound){.error = 5});
  expect("9 without a bound the state is kept", lifetime_screen_state(&ls, &wrapped, &scratch) != NULL);
  expect("9 counted as observed, not invalid", ls.observed == 1 && ls.invalid == 0);

  /* 10: a live state whose age wrapped: kept, its age unknown (never 0) */
  lifetime_screen_begin(&ls, bound(86400));
  struct state nfs = make(85936, 1444590337u, 4, 6);
  const struct state *kept = lifetime_screen_state(&ls, &nfs, &scratch);
  expect("10 age above the uptime with a valid expiry: kept", kept == &scratch);
  expect("10 its age is unknown", kept && kept->age == FM_AGE_UNKNOWN && kept->expire == 85936 && kept->id == 1);
  expect("10 the original is untouched", nfs.age == 1444590337u);
  struct state normal = make(3600, 120, 4, 6);
  expect("1 a normal state passes unchanged", lifetime_screen_state(&ls, &normal, &scratch) == &normal);
  expect("10/14 counters", ls.observed == 2 && ls.invalid == 0 && ls.age_unknown == 1);

  /* 12: the verdict depends on the lifetime alone */
  unsigned families[2] = {4, 6}, protocols[4] = {6, 17, 1, 58};
  for (unsigned f = 0; f < 2; f++)
    for (unsigned p = 0; p < 4; p++) {
      struct state bad = make(1270699076u, 10, families[f], protocols[p]);
      struct state good = make(60, 10, families[f], protocols[p]);
      lifetime_screen_begin(&ls, bound(86400));
      expect("12 family/protocol: bad rejected", lifetime_screen_state(&ls, &bad, &scratch) == NULL);
      expect("12 family/protocol: good kept", lifetime_screen_state(&ls, &good, &scratch) == &good);
    }

  /* the uptime is read again for a state above the limit: an expired state
   * reported after the first reading is not mistaken for an impossible one */
  set_uptime(1000);
  lifetime_screen_begin(&ls, bound(500));
  set_uptime(1010);
  struct state late = make(1005, 3, 4, 17);
  expect("lazy uptime: an expiry past the first reading is accepted", lifetime_screen_state(&ls, &late, &scratch) == &late);
  struct state later = make(1011, 3, 4, 17);
  expect("lazy uptime: still above max(timeout, uptime now): rejected", lifetime_screen_state(&ls, &later, &scratch) == NULL);
  set_uptime(1000);
  lifetime_screen_begin(&ls, bound(500));
  set_uptime(1020);
  struct state young = make(60, 1015, 4, 6);
  expect("lazy uptime: an age past the first reading is known", lifetime_screen_state(&ls, &young, &scratch) == &young);

  if (!failed)
    printf("ok\n");
  return failed;
}
