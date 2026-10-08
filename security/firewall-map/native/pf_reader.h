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

#ifndef FM_PF_READER_H
#define FM_PF_READER_H
#include "state.h"
#include <stdio.h>
/* Callback state is borrowed and valid only during the call.
 * false aborts the dump. Callers must discard all staged results on any error.
 * No callback side effect may be published until this function succeeds. */
typedef bool (*pf_state_callback)(const struct state *, void *,
                                  struct fm_error *);
/* request_anchor (optional) receives the CLOCK_MONOTONIC time, in seconds,
 * just before the dump request is sent: the sample's timing anchor. */
bool pf_reader_live(pf_state_callback, void *, FILE *raw_fixture,
                    double *request_anchor, struct fm_error *);
/* PF's current state count without traversing (false: unavailable). */
bool pf_reader_state_count(uint64_t *count);
/* PF_STATE_VERSION the reader was compiled against (0 without PF headers). */
unsigned pf_reader_state_version(void);
/* Devel builds only (FM_DEVEL_TOOLS): replay a saved FMNLLE1 capture. */
bool pf_reader_wire(const char *, pf_state_callback, void *, struct fm_error *);
#endif
