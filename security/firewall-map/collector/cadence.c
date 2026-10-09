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

#include "cadence.h"

static uint32_t clamp(double ms) {
  if (ms < CADENCE_FLOOR_MS) return CADENCE_FLOOR_MS;
  if (ms > CADENCE_CEILING_MS) return CADENCE_CEILING_MS;
  return (uint32_t)((uint64_t)(ms + 499) / 500 * 500);
}

uint32_t cadence_update(struct cadence *c, double sample_seconds, uint64_t heap_peak, uint64_t heap_budget,
                        bool refused) {
  if (!(sample_seconds >= 0)) sample_seconds = 0;
  c->smoothed = c->interval ? c->smoothed + CADENCE_SMOOTHING * (sample_seconds - c->smoothed) : sample_seconds;
  double want = c->smoothed * 1000.0 * 100.0 / CADENCE_DUTY_PERCENT;
  enum cadence_reason reason = want > CADENCE_FLOOR_MS ? CADENCE_REASON_DUTY : CADENCE_REASON_FLOOR;
  double current = c->interval ? c->interval : CADENCE_FLOOR_MS;
  if (heap_budget && heap_peak >= heap_budget / 100 * CADENCE_MEMORY_PERCENT && current * 1.5 > want) {
    want = current * 1.5;
    reason = CADENCE_REASON_MEMORY;
  }
  if (refused && current * 2 > want) {
    want = current * 2;
    reason = CADENCE_REASON_REFUSED;
  }
  if (!c->interval) {
    c->interval = clamp(want);
  } else if (want > current) {
    c->interval = clamp(want < current * 2 ? want : current * 2);
  } else if (want < current * 0.75) {
    c->interval = clamp(want > current / 2 ? want : current / 2);
  }
  c->reason = c->interval == CADENCE_FLOOR_MS && reason == CADENCE_REASON_DUTY ? CADENCE_REASON_FLOOR : reason;
  return c->interval;
}
