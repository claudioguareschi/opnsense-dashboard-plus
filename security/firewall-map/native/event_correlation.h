/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef FM_EVENT_CORRELATION_H
#define FM_EVENT_CORRELATION_H
#include "aggregate.h"
#include <stdint.h>

#define FM_MAX_EVENT_QUERIES 2500
struct event_history;
struct event_query { uint16_t id; struct outside_key key; };
struct event_match {
  uint16_t id;
  unsigned char kind; /* 1 current PF state, 2 recently observed PF state */
  struct outside_key key;
  struct correlation_value value;
};

struct event_history *event_history_create(struct fm_error *);
void event_history_destroy(struct event_history *);
bool event_history_update(struct event_history *, const struct aggregate *,
                          double now, struct fm_error *);
size_t event_history_match(const struct event_history *, const struct aggregate *,
                           const struct event_query *, size_t,
                           struct event_match *, size_t, struct fm_error *);

#endif
