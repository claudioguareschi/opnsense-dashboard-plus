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
#include "../collector/snapshot.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
static struct addr address_text_parse(const char *text) {
  struct addr a = {0};
  a.af = strchr(text, ':') ? 6 : 4;
  if (inet_pton(a.af == 4 ? AF_INET : AF_INET6, text, a.b) != 1) a.af = 0;
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
  /* ports: one remote reaching many inside services (inbound, distinct ports) */
  unsigned kind = !strcmp(mode, "mixed") ? n % 6 : !strcmp(mode, "inbound") || !strcmp(mode, "ports") ? 1 : 0;
  s.pf_direction = kind == 1 || kind == 5 ? FM_IN : FM_OUT;
  unsigned proto = kind == 4 ? 1 : kind == 5 ? 58 : 6;
  struct endpoint local = {address(kind >= 3 && kind != 4 ? "2001:4860::1" : "8.8.8.1"), (uint16_t)(30000 + n % 20000)};
  struct endpoint remote = {address(kind >= 3 && kind != 4 ? "2001:4860::2" : "9.9.9.9"), 443};
  struct endpoint inside = {address(kind >= 3 && kind != 4 ? "fd00::2" : "10.0.0.2"), local.port};
  /* late: like unique, but the flows from index 3000 on carry 100 times the
   * traffic (the heavy flows arrive after a small tracked set filled up);
   * assets and assets_late: unique and late, each flow from its own inside
   * host 10.0.<n / 256>.<n % 256> (asset importance) */
  bool assets = !strcmp(mode, "assets") || !strcmp(mode, "assets_late");
  bool late = !strcmp(mode, "late") || !strcmp(mode, "assets_late");
  if (late && n >= 3000)
    s.pf_bytes[0] = 1000 + sample * 30000 + n % 50;
  if (assets) {
    char text[64];
    snprintf(text, sizeof(text), "10.0.%u.%u", (unsigned)(n >> 8) & 255, (unsigned)n & 255);
    inside.a = address(text);
  }
  if (!strcmp(mode, "unique") || late || assets) {
    /* worst case: every state its own remote, flow, tuple, target and label */
    char text[64];
    snprintf(text, sizeof(text), "9.%u.%u.%u", (unsigned)(n >> 16) & 255, (unsigned)(n >> 8) & 255,
             (unsigned)n & 255);
    remote.a = address(text);
    remote.port = (uint16_t)(1024 + n % 60000);
    snprintf(s.label, sizeof(s.label), "rule %zu", n);
  }
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
    if (!strcmp(mode, "ports"))
      local.port = inside.port = (uint16_t)(1000 + n % 60000);
    s.key[0].e[0] = remote; s.key[0].e[1] = local;
    s.key[1].e[0] = remote; s.key[1].e[1] = inside;
  }
  s.key[0].proto = s.key[1].proto = proto;
  if (!strcmp(mode, "cross") && sample >= 3)
    s.key[1].e[1].a = address("fd00::2");
  return s;
}

unsigned pf_reader_state_version(void) { return 0; }

/* FM_TEST_PREFLIGHT=<count> simulates PF's GET_STATUS state count. */
bool pf_reader_state_count(uint64_t *count) {
  const char *preflight = getenv("FM_TEST_PREFLIGHT");
  if (!preflight)
    return false;
  *count = strtoull(preflight, NULL, 10);
  return true;
}

/* FM_TEST_STATES=<file> replays scenario states written by the specification
 * tests, one traversal per "sample <n>" block (the last block repeats):
 *   state <id> <creator> <in|out> <wire proto> <stack proto>
 *         <wire0> <wire1> <stack0> <stack1>   (a.b.c.d:port or [v6]:port)
 *         <forward bytes> <reverse bytes> <forward packets> <reverse packets>
 *         <age> <interface> <original interface|-> [label]                  */
static bool endpoint_text(const char *text, struct endpoint *e) {
  char address[64];
  unsigned port;
  if (text[0] == '[') {
    if (sscanf(text, "[%63[^]]]:%u", address, &port) != 2) return false;
  } else if (sscanf(text, "%63[^:]:%u", address, &port) != 2)
    return false;
  e->a = address_text_parse(address);
  e->port = (uint16_t)port;
  return e->a.af != 0;
}
static bool scenario(const char *path, unsigned sample, pf_state_callback callback, void *arg,
                     struct fm_error *error) {
  FILE *f = fopen(path, "r");
  if (!f) return fm_error_set(error, errno, "scenario file");
  char line[1024];
  unsigned block = 0, last = 0;
  while (fgets(line, sizeof(line), f)) /* the last block repeats for later samples */
    if (sscanf(line, "sample %u", &block) == 1 && block > last) last = block;
  unsigned wanted = sample < last ? sample : last;
  rewind(f);
  block = 0;
  bool ok = true;
  while (ok && fgets(line, sizeof(line), f)) {
    unsigned number;
    if (sscanf(line, "sample %u", &number) == 1) {
      block = number;
      continue;
    }
    if (block != wanted || strncmp(line, "state ", 6)) continue;
    struct state s = {0};
    char direction[8], keys[4][80], interface[32], original[32], label[96] = "";
    unsigned long long id, forward, reverse, forward_packets, reverse_packets;
    unsigned creator, wire_proto, stack_proto, age;
    int fields = sscanf(line, "state %llu %u %7s %u %u %79s %79s %79s %79s %llu %llu %llu %llu %u %31s %31s %95[^\n]",
                        &id, &creator, direction, &wire_proto, &stack_proto, keys[0], keys[1], keys[2], keys[3],
                        &forward, &reverse, &forward_packets, &reverse_packets, &age, interface, original, label);
    if (fields < 16 || !endpoint_text(keys[0], &s.key[0].e[0]) || !endpoint_text(keys[1], &s.key[0].e[1]) ||
        !endpoint_text(keys[2], &s.key[1].e[0]) || !endpoint_text(keys[3], &s.key[1].e[1])) {
      ok = fm_error_set(error, EINVAL, "scenario state line");
      break;
    }
    s.id = id; s.creator = creator; s.age = age; s.expire = 60; s.rule = 1;
    s.pf_direction = !strcmp(direction, "in") ? FM_IN : FM_OUT;
    s.key[0].proto = (unsigned char)wire_proto; s.key[1].proto = (unsigned char)stack_proto;
    s.pf_bytes[0] = forward; s.pf_bytes[1] = reverse;
    s.pf_packets[0] = forward_packets; s.pf_packets[1] = reverse_packets;
    s.peer[0] = s.peer[1] = 4;
    snprintf(s.interface, sizeof(s.interface), "%s", interface);
    if (strcmp(original, "-")) snprintf(s.original_interface, sizeof(s.original_interface), "%s", original);
    snprintf(s.label, sizeof(s.label), "%s", label);
    ok = callback(&s, arg, error);
  }
  fclose(f);
  return ok && !error->code;
}

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
  const char *states = getenv("FM_TEST_STATES");
  if (states)
    return scenario(states, sample, callback, arg, error);
  const char *mode = getenv("FM_TEST_MODE");
  if (!mode) mode = "one";
  const char *size = getenv("FM_TEST_COUNT");
  size_t count = size ? strtoull(size, NULL, 10) : 12;
  /* FM_TEST_COUNTS=<n1>,<n2>,...: the count of each sample (the last repeats) */
  const char *counts = getenv("FM_TEST_COUNTS");
  for (unsigned k = 1; counts && *counts; k++) {
    char *end;
    count = strtoull(counts, &end, 10);
    if (k == sample || *end != ',') break;
    counts = end + 1;
  }
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
  struct fm_error error = {0};
  struct context *ctx = context_create(&error);
  if (!ctx || !context_add_range(ctx, (struct range){address("0.0.0.0"), address("9.255.255.255"), 1}, &error) ||
      !context_add_range(ctx, (struct range){address("10.0.0.0"), address("10.255.255.255"), 2}, &error) ||
      !context_add_local(ctx, address("8.8.8.1"), &error) || !context_prepare(ctx, &error))
    return 1;
  struct snapshot_flow flow = {address("8.8.8.1"), address(!strcmp(mode, "sparse") ? "9.1.0.0" : "9.9.9.9"), false};
  struct snapshot *s = snapshot_create(ctx, &flow, 1, FM_SNAPSHOT_BYTES, FM_SNAPSHOT_STATES, 1, time(NULL), &error);
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
  context_destroy(ctx);
  return 0;
}
#endif
