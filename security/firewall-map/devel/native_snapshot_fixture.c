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

/* Synthetic PF reader for production-worker protocol tests. Never linked into
 * the installed helper. Generates one borrowed state at a time. */
#include "../native/snapshot.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef FM_SNAPSHOT_BENCHMARK
#include <sys/resource.h>
#endif

static struct addr address(const char *text) {
  struct addr a = {0};
  a.af = strchr(text, ':') ? 6 : 4;
  inet_pton(a.af == 4 ? AF_INET : AF_INET6, text, a.b);
  return a;
}
static struct state make_state(size_t n, unsigned sample, const char *mode) {
  struct state s = {0};
  s.id = n + 1; s.creator = 7; s.age = 1; s.expire = 120; s.rule = 19;
  s.pf_bytes[0] = 1000 + sample * 100 + n % 50;
  s.pf_bytes[1] = 2000 + sample * 200;
  s.pf_packets[0] = 10 + sample; s.pf_packets[1] = 20 + sample;
  s.peer[0] = s.peer[1] = 4;
  strcpy(s.interface, "igb0"); strcpy(s.original_interface, "igb1");
  strcpy(s.label, "snapshot \"rule\"");
  if (!strcmp(mode, "badlabel"))
    /* "caf\xc3\xa9" cut after the first byte of the two-byte sequence */
    memcpy(s.label, "caf\xc3", 5);
  /* inbound: every state is a remote-initiated port forward (PF direction in) */
  unsigned kind = !strcmp(mode, "mixed") ? n % 6 : !strcmp(mode, "inbound") ? 1 : 0;
  s.pf_direction = kind == 1 || kind == 5 ? FM_IN : FM_OUT;
  unsigned proto = kind == 4 ? 1 : kind == 5 ? 58 : 6;
  struct endpoint local = {address(kind >= 3 && kind != 4 ? "2001:4860::1" : "8.8.8.1"), (uint16_t)(30000 + n % 20000)};
  struct endpoint remote = {address(kind >= 3 && kind != 4 ? "2001:4860::2" : "9.9.9.9"), 443};
  struct endpoint inside = {address(kind >= 3 && kind != 4 ? "fd00::2" : "10.0.0.2"), local.port};
  if (!strcmp(mode, "many") || !strcmp(mode, "sparse")) {
    unsigned index = !strcmp(mode, "many") ? n % 6000 : (n % 100 ? 1 : 0);
    char text[64]; snprintf(text, sizeof(text), "9.1.%u.%u", index / 256, index % 256);
    remote.a = address(text);
  }
  if (proto == 1 || proto == 58) local.port = remote.port = inside.port = 42;
  if (s.pf_direction == FM_OUT) {
    s.key[0].e[0] = remote; s.key[0].e[1] = local;
    s.key[1].e[0] = remote; s.key[1].e[1] = kind == 2 ? local : inside;
  } else {
    remote.port = proto == 58 ? 42 : 55000;
    local.port = proto == 58 ? 42 : 443;
    inside.port = proto == 58 ? 42 : 8443;
    s.key[0].e[0] = remote; s.key[0].e[1] = local;
    s.key[1].e[0] = remote; s.key[1].e[1] = inside;
  }
  s.key[0].proto = s.key[1].proto = proto;
  if (!strcmp(mode, "cross") && sample >= 3)
    s.key[1].e[1].a = address("fd00::2");
  return s;
}

unsigned pf_reader_state_version(void) { return 0; }

/* FM_TEST_INTERVAL (seconds) makes sample anchors deterministic: sample n is
 * anchored at n * interval; otherwise the real monotonic clock is used. */
bool pf_reader_live(pf_state_callback callback, void *arg, FILE *raw,
                    double *request_anchor, struct fm_error *error) {
  (void)raw;
  static unsigned sample = 0;
  sample++;
  if (request_anchor) {
    const char *interval = getenv("FM_TEST_INTERVAL");
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    *request_anchor = interval ? sample * strtod(interval, NULL)
                               : now.tv_sec + now.tv_nsec / 1e9;
  }
  const char *mode = getenv("FM_TEST_MODE");
  if (!mode) mode = "one";
  const char *size = getenv("FM_TEST_COUNT");
  size_t count = size ? strtoull(size, NULL, 10) : 12;
  bool churn = !strcmp(mode, "churn") && sample >= 3;
  for (size_t index = 0; index < count; index++) {
    size_t n = !strcmp(mode, "shuffle") ? count - index - 1 : index;
    if (churn && n == 0) n = count;
    struct state s = make_state(n, sample, mode);
    if (!callback(&s, arg, error)) return false;
  }
  if (!strcmp(mode, "incomplete") && sample >= 3)
    return fm_error_set(error, EPROTO, "synthetic incomplete multipart dump");
  return true;
}

#ifdef FM_SNAPSHOT_BENCHMARK
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  size_t count = strtoull(argv[1], NULL, 10);
  const char *mode = argv[2];
  struct context ctx = {0};
  ctx.ranges[0] = (struct range){address("0.0.0.0"), address("9.255.255.255"), 1};
  ctx.ranges[1] = (struct range){address("10.0.0.0"), address("10.255.255.255"), 2};
  ctx.nr = 2;
  ctx.local[ctx.nl++] = address("8.8.8.1");
  struct snapshot_flow flow = {address("8.8.8.1"), address(!strcmp(mode, "sparse") ? "9.1.0.0" : "9.9.9.9"), false};
  struct fm_error error = {0};
  struct snapshot *s = snapshot_create(&ctx, &flow, 1, FM_SNAPSHOT_BYTES, FM_SNAPSHOT_STATES, 1, time(NULL), &error);
  if (!s) return 1;
  clock_t start = clock();
  for (size_t n = 0; n < count; n++) {
    struct state state = make_state(n, 1, mode);
    if (!snapshot_add(&state, s, &error)) return 1;
  }
  double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
  FILE *out = tmpfile();
  if (!out || !snapshot_write(s, out, &error)) return 1;
  long encoded = ftell(out);
  fclose(out);
  struct rusage usage; getrusage(RUSAGE_SELF, &usage);
#if defined(__APPLE__)
  double rss = usage.ru_maxrss / 1048576.0;
#else
  double rss = usage.ru_maxrss / 1024.0;
#endif
  printf("states=%zu mode=%s traversal=%.6f output=%ld peak_rss_mib=%.3f\n", count, mode, elapsed, encoded, rss);
  snapshot_destroy(s);
  return 0;
}
#endif
