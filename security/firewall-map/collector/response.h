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

#ifndef FM_RESPONSE_H
#define FM_RESPONSE_H
#include "error.h"
#include <stdio.h>
/* One response rendered completely in memory, then written to the collector
 * in a single step. A request that fails while rendering leaves nothing on
 * the wire, so the helper can always answer with FMFAIL1 instead of a
 * partial stream. The buffer is accounted heap (fm_realloc, through a
 * funopen stream on FreeBSD), within the sample's memory budget; the
 * protocol's caps bound it at about 88 MiB for the service's request (16
 * candidates per kind, 20,000 threat remotes), 345 MiB at the protocol's 64
 * candidates per kind, and typical responses are a few hundred KB. A
 * response the budget cannot hold is a memory refusal. */
struct response {
  FILE *stream;
  char *data;
  size_t size, capacity;
};
bool response_begin(struct response *, struct fm_error *);
/* Writes and flushes the rendered bytes to `out`, then releases the buffer. */
bool response_commit(struct response *, FILE *out, struct fm_error *);
void response_discard(struct response *);
#endif
