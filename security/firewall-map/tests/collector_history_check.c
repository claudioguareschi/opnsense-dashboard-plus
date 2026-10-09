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

/* Property check of collector/history.c, the compact baseline: over many
 * samples with heavy churn, duplicates, counter resets, presizing and growth,
 * every delta and every statistic must equal a naive reference that applies
 * the baseline rules literally (collector/history.h). Built and run by tests/test_collector_history.py;
 * prints "ok" or the first mismatch. */
#include "../collector/history.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POOL 6000

struct ref {
  uint64_t id, from, to, packets;
  uint32_t creator;
  int seen; /* sample number that last saw it, 0 = never */
};
static struct ref committed[POOL * 2], staged[POOL * 2];
static size_t committed_count, staged_count;

static struct ref *find(struct ref *rows, size_t count, uint64_t id, uint32_t creator) {
  for (size_t n = 0; n < count; n++)
    if (rows[n].id == id && rows[n].creator == creator)
      return &rows[n];
  return NULL;
}

static uint64_t rng = 0x9e3779b97f4a7c15u;
static uint64_t next(void) {
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return rng;
}

int main(void) {
  struct fm_error error = {0};
  struct history *h = history_create(&error);
  static uint64_t counters[POOL][3];
  memset(counters, 0, sizeof(counters));
  double anchor = 100.0, interval = -1;
  for (int sample = 1; sample <= 300; sample++) {
    if (sample == 150 && !history_reserve(h, 9000, &error)) {
      printf("reserve failed: %s\n", error.message);
      return 1;
    }
    if (!history_begin(h, anchor, &error)) {
      printf("begin failed: %s\n", error.message);
      return 1;
    }
    staged_count = 0;
    uint64_t want_new = 0, want_surviving = 0, want_duplicates = 0;
    /* a random subset of the pool is present; churn varies by sample */
    unsigned present = 1000 + (unsigned)(next() % 5000), offset = (unsigned)(next() % POOL);
    for (unsigned k = 0; k < present; k++) {
      unsigned slot = (offset + k * 7) % POOL;
      uint32_t creator = 1 + slot % 3;
      uint64_t id = slot / 3 + 1;
      for (int c = 0; c < 3; c++)
        counters[slot][c] += next() % 4 == 0 ? 0 : next() % 5000;
      if (next() % 997 == 0)
        counters[slot][0] = 0; /* a counter that goes backwards */
      struct state s = {.id = id, .creator = creator, .age = (uint32_t)(next() % 10)};
      s.pf_bytes[0] = counters[slot][0];
      s.pf_bytes[1] = counters[slot][1];
      s.pf_packets[0] = counters[slot][2];
      s.pf_packets[1] = 1;
      bool remote = next() % 2;
      int copies = next() % 211 == 0 ? 2 : 1; /* duplicates within the dump */
      for (int copy = 0; copy < copies; copy++) {
        uint64_t from = state_bytes_from_remote(&s, remote), to = state_bytes_to_remote(&s, remote),
                 packets = s.pf_packets[0] + s.pf_packets[1];
        struct state_delta want = {0}, got;
        struct ref *earlier = find(staged, staged_count, id, creator);
        struct ref *previous = earlier ? earlier : find(committed, committed_count, id, creator);
        if (previous) {
          want.bytes_from_remote = from > previous->from ? from - previous->from : 0;
          want.bytes_to_remote = to > previous->to ? to - previous->to : 0;
          want.packets = packets > previous->packets ? packets - previous->packets : 0;
          if (earlier) want_duplicates++; else want_surviving++;
        } else {
          if (interval >= 0 && s.age <= 2 * interval)
            want = (struct state_delta){from, to, packets};
          want_new++;
        }
        if (!history_observe(h, &s, remote, &got, &error)) {
          printf("observe failed: %s\n", error.message);
          return 1;
        }
        if (memcmp(&want, &got, sizeof(want))) {
          printf("sample %d state %llu/%u: delta %llu/%llu/%llu, want %llu/%llu/%llu\n", sample,
                 (unsigned long long)id, creator, (unsigned long long)got.bytes_from_remote,
                 (unsigned long long)got.bytes_to_remote, (unsigned long long)got.packets,
                 (unsigned long long)want.bytes_from_remote, (unsigned long long)want.bytes_to_remote,
                 (unsigned long long)want.packets);
          return 1;
        }
        struct ref *row = earlier ? earlier : &staged[staged_count++];
        *row = (struct ref){id, from, to, packets, creator, sample};
      }
    }
    uint64_t want_departed = 0;
    for (size_t n = 0; n < committed_count; n++)
      if (!find(staged, staged_count, committed[n].id, committed[n].creator))
        want_departed++;
    if (sample % 37 == 0) {
      /* an aborted sample: the next one is a baseline */
      history_abort(h);
      committed_count = 0;
      interval = -1;
      anchor += 2.0;
      continue;
    }
    history_commit(h);
    struct history_stats got = history_stats(h);
    if (got.new_states != want_new || got.surviving != want_surviving ||
        got.duplicates != want_duplicates || got.departed != want_departed ||
        history_entries(h) != staged_count) {
      printf("sample %d stats new %llu/%llu surviving %llu/%llu dup %llu/%llu departed %llu/%llu entries %zu/%zu\n",
             sample, (unsigned long long)got.new_states, (unsigned long long)want_new,
             (unsigned long long)got.surviving, (unsigned long long)want_surviving,
             (unsigned long long)got.duplicates, (unsigned long long)want_duplicates,
             (unsigned long long)got.departed, (unsigned long long)want_departed,
             history_entries(h), staged_count);
      return 1;
    }
    memcpy(committed, staged, staged_count * sizeof(*staged));
    committed_count = staged_count;
    interval = 2.0;
    anchor += 2.0;
    if (history_interval(h) != (sample == 1 || (sample - 1) % 37 == 0 ? -1 : 2.0)) {
      printf("sample %d interval %f\n", sample, history_interval(h));
      return 1;
    }
  }
  /* the table follows the population down: never below a quarter full */
  size_t floor = history_entries(h) * 4 > 64 ? history_entries(h) * 4 : 64;
  if (history_bytes(h) > floor * 40) {
    printf("baseline %zu bytes for %zu entries\n", history_bytes(h), history_entries(h));
    return 1;
  }
  history_destroy(h);
  printf("ok\n");
  return 0;
}
