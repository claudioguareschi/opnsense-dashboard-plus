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

#ifndef FM_ERROR_H
#define FM_ERROR_H
#include <stdbool.h>
#include <stddef.h>
/* Why a request failed; sent to Python in FMFAIL1 (PROTOCOL.md). */
enum fm_failure_class {
  FM_FAILURE_STRUCTURAL = 1,   /* malformed or truncated PF/netlink data */
  FM_FAILURE_INTERNAL = 2,     /* an engine invariant did not hold */
  FM_FAILURE_INCOMPATIBLE = 3, /* the kernel's PF ABI differs from the build */
  FM_FAILURE_RESOURCES = 4,    /* allocation failure */
  FM_FAILURE_REQUEST = 5,      /* malformed request from the collector */
};
struct fm_error {
  int code, failure_class;
  char message[160];
};
/* Records the first error only and returns false, so callers can write
 * `return fm_error_set(...)`. ENOMEM is classed as a resource failure, any
 * other code as structural; fm_error_fail names the class explicitly. */
bool fm_error_set(struct fm_error *, int, const char *);
bool fm_error_fail(struct fm_error *, enum fm_failure_class, int, const char *);
#endif
