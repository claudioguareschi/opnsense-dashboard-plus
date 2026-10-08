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

#include "../collector/correlation.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct addr address(const char *text) {
  struct addr a = {.af = 4};
  if (inet_pton(AF_INET, text, a.b) != 1) {
    fprintf(stderr, "invalid test address: %s\n", text);
    _Exit(1);
  }
  return a;
}
static int check(bool condition, const char *message) {
  if (!condition) fprintf(stderr, "correlation test failed: %s\n", message);
  return condition;
}
int main(void) {
  struct fm_error error = {0};
  struct correlation *index = correlation_create(&error);
  if (!index) return 1;
  struct outside_key key = {
      .protocol = 6,
      .public = {{.af = 4}, 40000},
      .remote = {{.af = 4}, 443}};
  key.public.a = address("203.0.113.1");
  key.remote.a = address("198.51.100.2");
  struct correlation_value first = {.inside = {{.af = 4}, 50000},
                                    .state_id = 11,
                                    .creator_id = 1,
                                    .has_inside = true};
  first.inside.a = address("192.168.1.10");
  struct correlation_value second = first;
  second.inside.port = 50001;
  second.inside.a = address("192.168.1.11");
  second.state_id = 12;
  bool ok = correlation_add(index, key, &first, &error);
  struct correlation_value found;
  ok = ok && check(correlation_lookup(index, key, &found), "key lookup") &&
       check(!found.ambiguous, "first entry starts unambiguous");
  ok = ok && correlation_add(index, key, &second, &error) &&
       check(correlation_lookup(index, key, &found), "duplicate key lookup") &&
       check(found.state_id == 12 && found.inside.port == 50001,
             "last duplicate wins") &&
       check(found.ambiguous, "different inside endpoints are ambiguous") &&
       check(correlation_count(index) == 1, "duplicate shares one key");
  struct outside_key ordered;
  struct correlation_value ordered_value;
  ok = ok && check(correlation_at(index, 0, &ordered, &ordered_value),
                    "stable first-key iteration") &&
       check(ordered.public.port == key.public.port &&
                 ordered_value.state_id == 12,
             "iteration returns latest value in first insertion slot");
  correlation_destroy(index);
  if (!ok || error.code) {
    if (error.code) fprintf(stderr, "%s\n", error.message);
    return 1;
  }
  puts("correlation lookup, ambiguity, duplicate and order tests passed");
  return 0;
}
