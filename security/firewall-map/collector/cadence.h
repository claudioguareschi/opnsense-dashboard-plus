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

#ifndef FM_CADENCE_H
#define FM_CADENCE_H
#include <stdbool.h>
#include <stdint.h>

/* The collector's recommended sampling interval (adaptive refresh): the
 * collector sees what a sample costs, so it recommends how often to take
 * one; Python schedules within the administrator's bounds and the map shows
 * the resulting freshness. No other component runs its own load control.
 *
 * Provisional policy, until the FW3 scale matrix exists to tune it: keep the
 * collector's duty cycle at CADENCE_DUTY_PERCENT of the interval (the
 * smoothed sample time divided by the share), never below the 2-second
 * floor, so a firewall whose samples are quick samples exactly as before;
 * back off by half again under memory pressure (the heap peak at
 * CADENCE_MEMORY_PERCENT of the budget) and double after a refused sample.
 * Hysteresis: the interval at most doubles per sample, shrinks only below
 * three quarters of the current value and at most halves, and moves in half
 * seconds, so it does not oscillate. */
#define CADENCE_FLOOR_MS 2000
#define CADENCE_CEILING_MS 300000
#define CADENCE_DUTY_PERCENT 10
#define CADENCE_MEMORY_PERCENT 90
#define CADENCE_SMOOTHING 0.3
enum cadence_reason {
  CADENCE_REASON_FLOOR = 0,   /* quick samples: the floor */
  CADENCE_REASON_DUTY = 1,    /* the duty cycle sets it */
  CADENCE_REASON_MEMORY = 2,  /* memory pressure */
  CADENCE_REASON_REFUSED = 3  /* the last sample was refused */
};
struct cadence {
  double smoothed;   /* sample seconds, exponentially smoothed */
  uint32_t interval; /* the current recommendation, ms (0 before the first) */
  enum cadence_reason reason;
};
/* One sample's cost: its wall seconds (dump + processing), its heap peak and
 * budget, and whether it was refused. Updates and returns the recommendation. */
uint32_t cadence_update(struct cadence *, double sample_seconds, uint64_t heap_peak, uint64_t heap_budget,
                        bool refused);
#endif
