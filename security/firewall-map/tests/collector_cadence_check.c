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

/* Checks of collector/cadence.c, the recommended sampling interval: the floor
 * for quick samples, the duty cycle, the ramp and decay limits, the
 * hysteresis band, memory pressure, refusals and the ceiling. Built and run
 * by tests/test_collector_cadence.py; prints "ok" or every violation. */
#include "../collector/cadence.h"
#include <stdio.h>

static int failed;
static void expect(const char *what, unsigned long long got, unsigned long long want) {
  if (got != want) {
    printf("%s: %llu, want %llu\n", what, got, want);
    failed = 1;
  }
}

int main(void) {
  struct cadence c = {0};
  /* quick samples (2.5 ms): the 2 s floor, as before adaptive refresh */
  for (int n = 0; n < 5; n++) cadence_update(&c, 0.0025, 1 << 20, 1 << 30, false);
  expect("quick samples", c.interval, CADENCE_FLOOR_MS);
  expect("quick reason", c.reason, CADENCE_REASON_FLOOR);
  /* a first sample of 1 s: 10% duty means 10 s at once */
  struct cadence first = {0};
  expect("first slow sample", cadence_update(&first, 1.0, 0, 0, false), 10000);
  expect("duty reason", first.reason, CADENCE_REASON_DUTY);
  /* from the floor, a very slow sample (30 s: a 300 s interval wanted) at most doubles the
   * interval per sample */
  expect("ramp 1", cadence_update(&c, 30.0, 0, 0, false), 4000);
  expect("ramp 2", cadence_update(&c, 30.0, 0, 0, false), 8000);
  expect("ramp 3", cadence_update(&c, 30.0, 0, 0, false), 16000);
  /* coming down from there to 1 s samples, it stops within the hysteresis band above 10 s */
  uint32_t last = 0;
  for (int n = 0; n < 40; n++) last = cadence_update(&c, 1.0, 0, 0, false);
  if (last < 10000 || last > 13500) {
    printf("settled after the ramp: %u\n", last);
    failed = 1;
  }
  /* steady 1 s samples: 10 s; samples a little quicker (want above 3/4 of it) move nothing */
  struct cadence steady = {0};
  for (int n = 0; n < 10; n++) last = cadence_update(&steady, 1.0, 0, 0, false);
  expect("steady", last, 10000);
  for (int n = 0; n < 20; n++) last = cadence_update(&steady, 0.8, 0, 0, false);
  expect("hysteresis", last, 10000);
  /* quick samples again: the interval shrinks, at most halving per sample, down to the floor */
  struct cadence slow = first;
  /* (the smoothed time falls to 0.7 s: 7 s wanted, rounded up to the half second) */
  expect("decay 1", cadence_update(&slow, 0.001, 0, 0, false), 7500);
  uint32_t previous = 7500;
  for (int n = 0; n < 30; n++) {
    uint32_t now = cadence_update(&slow, 0.001, 0, 0, false);
    if (now < previous / 2 || now > previous) {
      printf("decay step %u -> %u\n", previous, now);
      failed = 1;
    }
    previous = now;
  }
  expect("decayed to the floor", previous, CADENCE_FLOOR_MS);
  /* memory pressure (peak at 95% of the budget): half again */
  struct cadence memory = {0};
  cadence_update(&memory, 0.001, 0, 0, false);
  expect("memory pressure", cadence_update(&memory, 0.001, 95, 100, false), 3000);
  expect("memory reason", memory.reason, CADENCE_REASON_MEMORY);
  /* a refused sample: double; repeated refusals stop at the ceiling */
  struct cadence refused = {0};
  cadence_update(&refused, 0.001, 0, 0, false);
  expect("refused", cadence_update(&refused, 0, 0, 0, true), 4000);
  expect("refused reason", refused.reason, CADENCE_REASON_REFUSED);
  for (int n = 0; n < 40; n++) last = cadence_update(&refused, 0, 0, 0, true);
  expect("ceiling", last, CADENCE_CEILING_MS);
  /* half-second steps, and a nonsense duration counts as 0 */
  struct cadence odd = {0};
  expect("rounded", cadence_update(&odd, 0.3333, 0, 0, false), 3500);
  struct cadence negative = {0};
  expect("negative duration", cadence_update(&negative, -1, 0, 0, false), CADENCE_FLOOR_MS);
  if (!failed) printf("ok\n");
  return failed;
}
