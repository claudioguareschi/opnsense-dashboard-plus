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

#include "response.h"
#include "alloc.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__FreeBSD__) || defined(__APPLE__)
/* The buffer grows through the accounted heap: it counts against the
 * sample's memory budget like every other allocation, so a response the
 * budget cannot hold fails its allocation (a memory refusal), never an
 * unaccounted one. */
static int response_write(void *cookie, const char *bytes, int count) {
  struct response *r = cookie;
  if (count < 0) {
    errno = EINVAL;
    return -1;
  }
  size_t need = r->size + (size_t)count;
  if (need < r->size) {
    errno = ENOMEM;
    return -1;
  }
  if (need > r->capacity) {
    size_t capacity = r->capacity ? r->capacity : 65536;
    while (capacity < need) {
      if (capacity > SIZE_MAX / 2) {
        errno = ENOMEM;
        return -1;
      }
      capacity *= 2;
    }
    char *grown = fm_realloc(r->data, capacity);
    if (!grown) {
      errno = ENOMEM;
      return -1;
    }
    r->data = grown;
    r->capacity = capacity;
  }
  memcpy(r->data + r->size, bytes, (size_t)count);
  r->size = need;
  return count;
}
bool response_begin(struct response *r, struct fm_error *error) {
  memset(r, 0, sizeof(*r));
  r->stream = funopen(r, NULL, response_write, NULL, NULL);
  return r->stream || fm_error_set(error, errno ? errno : ENOMEM, "response buffer");
}
static void release(struct response *r) { fm_free(r->data); }
#else
/* Elsewhere (development builds only): libc memory, not accounted. */
bool response_begin(struct response *r, struct fm_error *error) {
  memset(r, 0, sizeof(*r));
  r->stream = open_memstream(&r->data, &r->size);
  return r->stream || fm_error_set(error, errno ? errno : ENOMEM, "response buffer");
}
static void release(struct response *r) { free(r->data); }
#endif
bool response_commit(struct response *r, FILE *out, struct fm_error *error) {
  bool ok = r->stream && fclose(r->stream) == 0;
  r->stream = NULL;
  if (!ok)
    fm_error_set(error, errno ? errno : ENOMEM, "response buffer");
  else if (fwrite(r->data, 1, r->size, out) != r->size || fflush(out))
    ok = fm_error_set(error, errno ? errno : EIO, "response write");
  release(r);
  r->data = NULL;
  return ok;
}
void response_discard(struct response *r) {
  if (r->stream)
    fclose(r->stream);
  release(r);
  memset(r, 0, sizeof(*r));
}
