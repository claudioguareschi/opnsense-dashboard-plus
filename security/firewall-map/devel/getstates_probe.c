/*
 * Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
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

/* Read-only GETSTATES acquisition probe (0.60 plan, Milestone 1.1b/1.2).
 * Never part of a package. Build on the FreeBSD host:
 *
 *   cd collector && cc -O2 -Wall -Wextra -Werror -DFM_DEVEL_TOOLS -I. \
 *      ../devel/getstates_probe.c aggregate.c alloc.c context.c correlation.c \
 *      error.c event_correlation.c history.c index.c pf_reader.c protocol.c \
 *      ranking.c response.c siphash.c snapshot.c state.c threat_summary.c \
 *      -lm -o /tmp/getstates_probe
 *
 * (every collector source except main.c: protocol.c needs the rest; root's
 * csh on OPNsense cannot expand $(...), hence the explicit list)
 *
 *   getstates_probe [delay_seconds] [per_datagram_ms]
 *
 * Sends one PF GETSTATES dump request, waits delay_seconds before reading
 * anything (a deliberately slow consumer), then drains the multipart reply,
 * optionally sleeping per_datagram_ms after each datagram. Every datagram goes
 * through the production decoder, so the state count is what the collector
 * would see. Prints one JSON line: the socket receive limits, the bytes the
 * socket reported queued after the delay, datagrams, bytes, decoded states,
 * serialized bytes per state, NLMSG_DONE/error status, and the GET_STATUS
 * state count before and after the dump (completeness cross-check). Kernel
 * memory is sampled outside the probe (vmstat -m / -z, netstat -m) while it
 * sleeps; it prints "sent" on stderr when the request is out. */
#include "pf_reader.h"
#include <errno.h>
#include <netlink/netlink.h>
#include <netlink/netlink_generic.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_generic.h>
#include <netpfil/pf/pf_nl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static bool count_state(const struct state *state, void *arg, struct fm_error *error) {
  (void)state;
  (void)error;
  (*(uint64_t *)arg)++;
  return true;
}

static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}

static void pause_ms(double ms) {
  if (ms <= 0)
    return;
  struct timespec t = {(time_t)(ms / 1000), (long)(ms * 1e6) % 1000000000L};
  nanosleep(&t, NULL);
}

static double cpu_seconds(const struct timeval *t) { return t->tv_sec + t->tv_usec / 1e6; }

int main(int argc, char **argv) {
  double delay = argc > 1 ? atof(argv[1]) : 0;
  double per_datagram_ms = argc > 2 ? atof(argv[2]) : 0;
  uint64_t status_before = 0, status_after = 0, states = 0, bytes = 0, datagrams = 0;
  bool have_before = pf_reader_state_count(&status_before);
  struct snl_state ss;
  if (!snl_init(&ss, NETLINK_GENERIC)) {
    fprintf(stderr, "netlink setup: %s\n", strerror(errno));
    return 1;
  }
  struct timeval timeout = {.tv_sec = 10};
  setsockopt(ss.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  int rcvbuf = 0;
  socklen_t length = sizeof(rcvbuf);
  getsockopt(ss.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &length);
  int family = snl_get_genl_family(&ss, PFNL_FAMILY_NAME);
  if (!family) {
    fprintf(stderr, "PF netlink family unavailable\n");
    return 1;
  }
  struct snl_writer nw;
  snl_init_writer(&ss, &nw);
  struct nlmsghdr *request = snl_create_genl_msg_request(&nw, family, PFNL_CMD_GETSTATES);
  if (!request) {
    fprintf(stderr, "netlink request\n");
    return 1;
  }
  request->nlmsg_flags |= NLM_F_DUMP;
  request = snl_finalize_msg(&nw);
  struct rusage before_usage, after_usage;
  getrusage(RUSAGE_SELF, &before_usage);
  double sent = now();
  if (!request || !snl_send_message(&ss, request)) {
    fprintf(stderr, "netlink send: %s\n", strerror(errno));
    return 1;
  }
  uint32_t seq = request->nlmsg_seq;
  fprintf(stderr, "sent\n");
  pause_ms(delay * 1000);
  int queued = -1;
  if (ioctl(ss.fd, FIONREAD, &queued))
    queued = -1;
  unsigned char *buffer = malloc(ss.bufsize);
  if (!buffer) {
    fprintf(stderr, "receive buffer\n");
    return 1;
  }
  struct fm_error error = {0};
  bool done = false, truncated = false;
  double first = 0;
  while (!done && !error.code) {
    ssize_t size = recv(ss.fd, buffer, ss.bufsize, 0);
    if (size < 0 && errno == EINTR)
      continue;
    if (size <= 0) {
      fm_error_set(&error, errno ? errno : EIO, "incomplete netlink dump");
      break;
    }
    if (!datagrams)
      first = now();
    datagrams++;
    bytes += (uint64_t)size;
    if ((size_t)size == ss.bufsize)
      truncated = true; /* a full buffer may mean a cut datagram: report it */
    pf_reader_decode_datagram(buffer, (size_t)size, seq, family, count_state, &states, &done,
                              &error);
    pause_ms(per_datagram_ms);
  }
  double finished = now();
  getrusage(RUSAGE_SELF, &after_usage);
  bool have_after = pf_reader_state_count(&status_after);
  printf("{\"delay_s\":%.3f,\"per_datagram_ms\":%.3f,\"so_rcvbuf\":%d,\"read_buffer\":%zu,"
         "\"queued_after_delay\":%d,\"datagrams\":%llu,\"bytes\":%llu,\"states\":%llu,"
         "\"bytes_per_state\":%.1f,\"done\":%s,\"error\":%d,\"error_class\":%d,"
         "\"error_message\":\"%s\",\"full_buffer_reads\":%s,"
         "\"status_before\":%lld,\"status_after\":%lld,"
         "\"first_datagram_s\":%.3f,\"total_s\":%.3f,\"user_cpu_s\":%.3f,\"system_cpu_s\":%.3f}\n",
         delay, per_datagram_ms, rcvbuf, ss.bufsize, queued, (unsigned long long)datagrams,
         (unsigned long long)bytes, (unsigned long long)states,
         states ? (double)bytes / (double)states : 0.0, done ? "true" : "false", error.code,
         error.failure_class, error.message, truncated ? "true" : "false",
         have_before ? (long long)status_before : -1LL, have_after ? (long long)status_after : -1LL,
         datagrams ? first - sent : 0.0, finished - sent,
         cpu_seconds(&after_usage.ru_utime) - cpu_seconds(&before_usage.ru_utime),
         cpu_seconds(&after_usage.ru_stime) - cpu_seconds(&before_usage.ru_stime));
  free(buffer);
  snl_free(&ss);
  return done && !error.code ? 0 : 1;
}
