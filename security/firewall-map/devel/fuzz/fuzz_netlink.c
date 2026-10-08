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

/* libFuzzer target for the raw PF netlink decoder (FreeBSD only: it needs the
 * real <netpfil/pf/pf_nl.h> and snl headers). The input is one datagram of
 * netlink messages; the sequence number and generic family are fixed so the
 * fuzzer can reach state decoding. Seed it with datagrams from FMNLLE1
 * captures (devel/native_sample reader ... raw.bin) and mutated copies.
 * Build and run with devel/fuzz/run.sh on the FreeBSD build host. */
#include "../../native/pf_reader.h"
#include <stdlib.h>
#include <string.h>

static bool accept_state(const struct state *state, void *arg, struct fm_error *error) {
  (void)error;
  (*(size_t *)arg) += state->pf_direction;
  return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return 0;
  uint32_t seq;
  memcpy(&seq, data, 4);
  int family = data[4] | data[5] << 8;
  unsigned char *datagram = malloc(size - 8 ? size - 8 : 1);
  if (!datagram) return 0;
  memcpy(datagram, data + 8, size - 8);
  struct fm_error error = {0};
  size_t states = 0;
  bool done = false;
  pf_reader_decode_datagram(datagram, size - 8, seq, family, accept_state, &states, &done, &error);
  free(datagram);
  return 0;
}
