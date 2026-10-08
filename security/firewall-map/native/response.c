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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
bool response_begin(struct response *r, struct fm_error *error) {
  memset(r, 0, sizeof(*r));
  r->stream = open_memstream(&r->data, &r->size);
  return r->stream || fm_error_set(error, errno ? errno : ENOMEM, "response buffer");
}
bool response_commit(struct response *r, FILE *out, struct fm_error *error) {
  bool ok = r->stream && fclose(r->stream) == 0;
  r->stream = NULL;
  if (!ok)
    fm_error_set(error, errno ? errno : ENOMEM, "response buffer");
  else if (fwrite(r->data, 1, r->size, out) != r->size || fflush(out))
    ok = fm_error_set(error, errno ? errno : EIO, "response write");
  free(r->data);
  r->data = NULL;
  return ok;
}
void response_discard(struct response *r) {
  if (r->stream)
    fclose(r->stream);
  free(r->data);
  memset(r, 0, sizeof(*r));
}
