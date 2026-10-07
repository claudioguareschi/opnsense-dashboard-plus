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

#ifndef FM_PROTOCOL_H
#define FM_PROTOCOL_H
#include "aggregate.h"
#include "event_correlation.h"
#include "ranking.h"
#include "threat_summary.h"
#include <stdio.h>
#define FM_FRAME_MAX 4096
/* FMAGG3 frames are big-endian u32 length + payload. The stream contains only
 * ranked flow records, optional per-remote threat summaries, requested event
 * matches, and a checksummed completion footer. No C structure is serialized. */
void protocol_put(unsigned char **, uint64_t, unsigned);
uint64_t protocol_get(const unsigned char **, unsigned);
void protocol_address_put(unsigned char **, struct addr);
bool protocol_frame(FILE *, const void *, size_t, uint32_t *,
                    struct fm_error *);
bool protocol_write(FILE *, const struct aggregate *, bool with_deltas,
                    struct fm_error *);
bool protocol_write_ranked(FILE *, const struct aggregate *, const struct ranking *,
                           const struct threat_summary *, const struct event_match *, size_t,
                           struct fm_error *);
bool protocol_write_selected(FILE *, const struct aggregate *,
                             const struct ranked_flow *, size_t, struct fm_error *);
#endif
