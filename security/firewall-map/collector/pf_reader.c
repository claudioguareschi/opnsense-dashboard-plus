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

#include "pf_reader.h"
#include "protocol.h"
#include <errno.h>
#ifdef __FreeBSD__
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netlink/netlink.h>
#include <netlink/netlink_generic.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_generic.h>
#include <netpfil/pf/pf_nl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>
#ifdef FM_DEVEL_TOOLS
#include <sys/filio.h>
#include <sys/ioctl.h>
/* FM_PROBE_BACKLOG (devel builds only): time spent in the state callback and
 * the largest kernel reply backlog seen after a read, printed to stderr when
 * the dump ends. Measures whether collector processing lets PF queue the dump. */
static struct {
  bool enabled;
  double callback_seconds;
  uint64_t states;
  int max_backlog;
} probe;
static double probe_now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}
#endif

_Static_assert(PF_RULE_LABEL_SIZE == FM_LABEL_SIZE, "PF rule label ABI");
_Static_assert(IFNAMSIZ == FM_INTERFACE_SIZE, "PF interface ABI");
_Static_assert(PF_IN == FM_IN && PF_OUT == FM_OUT, "PF direction ABI");
struct reader {
  pf_state_callback callback;
  void *arg;
  struct fm_error *error;
};
static void string_attr(struct reader *r, char *dest, size_t cap,
                        const void *data, size_t n) {
  if (!n || n > cap || ((const char *)data)[n - 1] || memchr(data, 0, n - 1)) {
    fm_error_set(r->error, EPROTO, "string attribute");
    return;
  }
  memcpy(dest, data, n);
}
typedef void (*attribute_fn)(unsigned, const unsigned char *, size_t, void *);
static void attributes(struct reader *r, const unsigned char *p, size_t n,
                       attribute_fn fn, void *arg) {
  while (n && !r->error->code) {
    if (n < sizeof(struct nlattr)) {
      fm_error_set(r->error, EPROTO, "short attribute");
      return;
    }
    struct nlattr a;
    memcpy(&a, p, sizeof(a));
    if (a.nla_len < sizeof(a) || a.nla_len > n || NLA_ALIGN(a.nla_len) > n) {
      fm_error_set(r->error, EPROTO, "attribute length");
      return;
    }
    fn(a.nla_type & NLA_TYPE_MASK, p + sizeof(a), a.nla_len - sizeof(a), arg);
    size_t step = NLA_ALIGN(a.nla_len);
    p += step;
    n -= step;
  }
}
struct key_parse {
  struct key *key;
  unsigned mask;
  size_t lengths[2];
  struct reader *reader;
};
static void key_attr(unsigned type, const unsigned char *p, size_t n,
                     void *arg) {
  struct key_parse *a = arg;
  struct reader *r = a->reader;
  if (type < 1 || type > 6)
    return;
  if (a->mask & (1u << type)) {
    fm_error_set(r->error, EPROTO, "duplicate key attribute");
    return;
  }
  a->mask |= 1u << type;
  if (type <= 2) {
    if (n != 4 && n != 16) {
      fm_error_set(r->error, EPROTO, "address length");
      return;
    }
    memcpy(a->key->e[type - 1].a.b, p, n);
    a->lengths[type - 1] = n;
  } else if (type <= 4) {
    if (n != 2) {
      fm_error_set(r->error, EPROTO, "port length");
      return;
    }
    uint16_t v;
    memcpy(&v, p, 2);
    a->key->e[type - 3].port = ntohs(v);
  } else if (type == 5) {
    if (n != 1 || (*p != AF_INET && *p != AF_INET6)) {
      fm_error_set(r->error, EPROTO, "key family");
      return;
    }
    a->key->e[0].a.af = a->key->e[1].a.af = *p == AF_INET ? 4 : 6;
  } else {
    uint16_t v;
    if (n != 2) {
      fm_error_set(r->error, EPROTO, "protocol length");
      return;
    }
    memcpy(&v, p, 2);
    if (v > 255) {
      fm_error_set(r->error, EPROTO, "protocol");
      return;
    }
    a->key->proto = v;
  }
}
struct state_parse {
  struct state *s;
  uint64_t mask;
  struct reader *reader;
};
struct peer_parse {
  unsigned value;
  struct reader *reader;
};
static void peer_attr(unsigned type, const unsigned char *p, size_t n,
                      void *arg) {
  struct peer_parse *peer = arg;
  struct reader *r = peer->reader;
  unsigned *v = &peer->value;
  if (type == PF_STP_STATE) {
    if (n != 1 || *v != UINT32_MAX) {
      fm_error_set(r->error, EPROTO, "peer state");
      return;
    }
    *v = *p;
  } else if ((type == PF_STP_SEQLO || type == PF_STP_SEQHI ||
              type == PF_STP_SEQDIFF) &&
             n != 4) {
    fm_error_set(r->error, EPROTO, "peer sequence size");
    return;
  } else if (type == PF_STP_WSCALE && n != 1) {
    fm_error_set(r->error, EPROTO, "peer scale size");
    return;
  }
}
static void state_attr(unsigned type, const unsigned char *p, size_t n,
                       void *arg) {
  struct state_parse *a = arg;
  struct reader *r = a->reader;
  struct state *s = a->s;
  if (type >= 64)
    return;
  uint64_t bit = UINT64_C(1) << type;
  if (a->mask & bit) {
    fm_error_set(r->error, EPROTO, "duplicate state attribute");
    return;
  }
  a->mask |= bit;
  switch (type) {
  case PF_ST_ID:
    if (n != 8) {
      fm_error_set(r->error, EPROTO, "ID size");
      return;
    }
    memcpy(&s->id, p, 8);
    break;
  case PF_ST_CREATORID:
    if (n != 4) {
      fm_error_set(r->error, EPROTO, "creator size");
      return;
    }
    memcpy(&s->creator, p, 4);
    break;
  case PF_ST_DIRECTION:
    if (n != 1) {
      fm_error_set(r->error, EPROTO, "direction size");
      return;
    }
    s->pf_direction = *p;
    break;
  case PF_ST_CREATION:
    if (n != 4) {
      fm_error_set(r->error, EPROTO, "age size");
      return;
    }
    memcpy(&s->age, p, 4);
    break;
  case PF_ST_EXPIRE:
    if (n != 4) {
      fm_error_set(r->error, EPROTO, "expire size");
      return;
    }
    memcpy(&s->expire, p, 4);
    break;
  case PF_ST_RULE:
    if (n != 4) {
      fm_error_set(r->error, EPROTO, "rule size");
      return;
    }
    memcpy(&s->rule, p, 4);
    break;
  case PF_ST_ANCHOR:
  case PF_ST_NAT_RULE:
  case PF_ST_RTABLEID:
    if (n != 4) {
      fm_error_set(r->error, EPROTO, "state integer size");
      return;
    }
    break;
  case PF_ST_LOG:
  case PF_ST_SYNC_FLAGS:
  case PF_ST_MIN_TTL:
  case PF_ST_RT:
  case PF_ST_SRC_NODE_FLAGS:
  case PF_ST_RT_AF:
    if (n != 1) {
      fm_error_set(r->error, EPROTO, "state byte size");
      return;
    }
    break;
  case PF_ST_STATE_FLAGS:
  case PF_ST_MAX_MSS:
  case PF_ST_DNPIPE:
  case PF_ST_DNRPIPE:
    if (n != 2) {
      fm_error_set(r->error, EPROTO, "state short size");
      return;
    }
    break;
  case PF_ST_RT_ADDR:
    if (n != 4 && n != 16) {
      fm_error_set(r->error, EPROTO, "route address size");
      return;
    }
    break;
  case PF_ST_RT_IFNAME: {
    char name[IFNAMSIZ] = {0};
    string_attr(r, name, sizeof(name), p, n);
    break;
  }
  case PF_ST_VERSION: {
    uint64_t version;
    if (n != 8) {
      fm_error_set(r->error, EPROTO, "state ABI version size");
      return;
    }
    memcpy(&version, p, 8);
    if (version != PF_STATE_VERSION) {
      char message[96];
      snprintf(message, sizeof(message),
               "PF state ABI version %" PRIu64 ", collector built for %u", version,
               (unsigned)PF_STATE_VERSION);
      fm_error_fail(r->error, FM_FAILURE_INCOMPATIBLE, EPROTO, message);
      return;
    }
    break;
  }
  case PF_ST_IFNAME:
    string_attr(r, s->interface, sizeof(s->interface), p, n);
    break;
  case PF_ST_ORIG_IFNAME:
    string_attr(r, s->original_interface, sizeof(s->original_interface), p, n);
    break;
  case PF_ST_RULE_LABEL:
    string_attr(r, s->label, sizeof(s->label), p, n);
    break;
  case PF_ST_BYTES0:
  case PF_ST_BYTES1:
    if (n != 8) {
      fm_error_set(r->error, EPROTO, "byte counter size");
      return;
    }
    memcpy(&s->pf_bytes[type - PF_ST_BYTES0], p, 8);
    break;
  case PF_ST_PACKETS0:
  case PF_ST_PACKETS1:
    if (n != 8) {
      fm_error_set(r->error, EPROTO, "packet counter size");
      return;
    }
    memcpy(&s->pf_packets[type - PF_ST_PACKETS0], p, 8);
    break;
  case PF_ST_KEY_WIRE:
  case PF_ST_KEY_STACK: {
    struct key_parse k = {.reader = r, .key = &s->key[type - PF_ST_KEY_WIRE]};
    attributes(r, p, n, key_attr, &k);
    if (k.mask != 126 || k.lengths[0] != (k.key->e[0].a.af == 4 ? 4u : 16u) ||
        k.lengths[1] != k.lengths[0]) {
      fm_error_set(r->error, EPROTO, "incomplete key");
      return;
    }
    break;
  }
  case PF_ST_PEER_SRC:
  case PF_ST_PEER_DST: {
    struct peer_parse peer = {.value = UINT32_MAX, .reader = r};
    attributes(r, p, n, peer_attr, &peer);
    if (peer.value == UINT32_MAX) {
      fm_error_set(r->error, EPROTO, "missing peer");
      return;
    }
    s->peer[type - PF_ST_PEER_SRC] = peer.value;
    break;
  }
  default:
    break;
  }
}
static void decode(struct reader *r, const struct nlmsghdr *hdr) {
  if (hdr->nlmsg_len < sizeof(*hdr) + sizeof(struct genlmsghdr)) {
    fm_error_set(r->error, EPROTO, "short generic message");
    return;
  }
  const struct genlmsghdr *g = (const void *)(hdr + 1);
  if (g->cmd != PFNL_CMD_GETSTATES || g->version != 0) {
    fm_error_set(r->error, EPROTO, "state command/version");
    return;
  }
  struct state s = {0};
  struct state_parse a = {.s = &s, .reader = r};
  attributes(r, (const void *)(g + 1),
             hdr->nlmsg_len - sizeof(*hdr) - sizeof(*g), state_attr, &a);
  unsigned required[] = {PF_ST_VERSION,    PF_ST_ID,       PF_ST_CREATORID,
                         PF_ST_DIRECTION,  PF_ST_CREATION, PF_ST_EXPIRE,
                         PF_ST_RULE,       PF_ST_IFNAME,   PF_ST_ORIG_IFNAME,
                         PF_ST_RULE_LABEL, PF_ST_KEY_WIRE, PF_ST_KEY_STACK,
                         PF_ST_BYTES0,     PF_ST_BYTES1,   PF_ST_PACKETS0,
                         PF_ST_PACKETS1,   PF_ST_PEER_SRC, PF_ST_PEER_DST};
  for (size_t n = 0; n < sizeof(required) / sizeof(*required); n++)
    if (!(a.mask & (UINT64_C(1) << required[n]))) {
      fm_error_set(r->error, EPROTO, "missing required state attribute");
      return;
    }
  if (!r->error->code)
#ifdef FM_DEVEL_TOOLS
  {
    double started = probe.enabled ? probe_now() : 0;
#endif
    r->callback(&s, r->arg, r->error);
#ifdef FM_DEVEL_TOOLS
    if (probe.enabled) {
      probe.callback_seconds += probe_now() - started;
      probe.states++;
    }
  }
#endif
}
static void datagram(struct reader *r, unsigned char *buffer, size_t left,
                     uint32_t seq, int family, int *done) {
  unsigned char *p = buffer;
  while (left && !r->error->code) {
    if (left < sizeof(struct nlmsghdr)) {
      fm_error_set(r->error, EPROTO, "short netlink header");
      return;
    }
    struct nlmsghdr *h = (void *)p;
    if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > left ||
        NLMSG_ALIGN(h->nlmsg_len) > left) {
      fm_error_set(r->error, EPROTO, "netlink length");
      return;
    }
    if (h->nlmsg_seq != seq || (h->nlmsg_flags & NLM_F_DUMP_INTR) || *done) {
      fm_error_set(r->error, EPROTO, "netlink sequence/completion");
      return;
    }
    if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) {
      if (h->nlmsg_len < sizeof(*h) + sizeof(int)) {
        fm_error_set(r->error, EPROTO, "short netlink status");
        return;
      }
      int error;
      memcpy(&error, h + 1, sizeof(error));
      if (error) {
        fm_error_set(r->error, error < 0 ? -error : error,
                     "kernel netlink error");
        return;
      }
      if (h->nlmsg_type == NLMSG_ERROR &&
          h->nlmsg_len < sizeof(*h) + sizeof(struct nlmsgerr)) {
        fm_error_set(r->error, EPROTO, "short netlink acknowledgement");
        return;
      }
      if (h->nlmsg_type == NLMSG_DONE)
        *done = 1;
    } else {
      if (h->nlmsg_type != family || !(h->nlmsg_flags & NLM_F_MULTI)) {
        fm_error_set(r->error, EPROTO, "unexpected netlink message");
        return;
      }
      decode(r, h);
    }
    size_t step = NLMSG_ALIGN(h->nlmsg_len);
    left -= step;
    p += step;
  }
}

#ifdef FM_DEVEL_TOOLS
/* Fuzzing entry point (devel/fuzz/fuzz_netlink.c): one received datagram. */
bool pf_reader_decode_datagram(unsigned char *buffer, size_t size, uint32_t seq, int family,
                               pf_state_callback callback, void *arg, bool *done,
                               struct fm_error *error) {
  struct reader r = {.callback = callback, .arg = arg, .error = error};
  int finished = 0;
  datagram(&r, buffer, size, seq, family, &finished);
  *done = finished;
  return !error->code;
}
#endif

bool pf_reader_live(pf_state_callback callback, void *arg, FILE *raw,
                    double *request_anchor, struct fm_error *error) {
  struct reader r = {.callback = callback, .arg = arg, .error = error};
#ifdef FM_DEVEL_TOOLS
  memset(&probe, 0, sizeof(probe));
  probe.enabled = getenv("FM_PROBE_BACKLOG") != NULL;
#endif
  struct snl_state ss;
  if (!snl_init(&ss, NETLINK_GENERIC))
    return fm_error_set(error, errno, "netlink setup");
  unsigned char *buffer = NULL;
  bool ok = false;
  struct timeval timeout = {.tv_sec = 5};
  if (setsockopt(ss.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
    fm_error_set(error, errno, "netlink timeout");
    goto out;
  }
  int family = snl_get_genl_family(&ss, PFNL_FAMILY_NAME);
  if (!family) {
    fm_error_set(error, EPROTO, "PF family unavailable");
    goto out;
  }
  struct snl_writer nw;
  snl_init_writer(&ss, &nw);
  struct nlmsghdr *request =
      snl_create_genl_msg_request(&nw, family, PFNL_CMD_GETSTATES);
  if (!request) {
    fm_error_set(error, ENOMEM, "netlink request");
    goto out;
  }
  request->nlmsg_flags |= NLM_F_DUMP;
  request = snl_finalize_msg(&nw);
  struct timespec sent;
  if (request_anchor) {
    if (clock_gettime(CLOCK_MONOTONIC, &sent)) {
      fm_error_fail(error, FM_FAILURE_INTERNAL, errno, "monotonic clock");
      goto out;
    }
    *request_anchor = sent.tv_sec + sent.tv_nsec / 1e9;
  }
  if (!request || !snl_send_message(&ss, request)) {
    fm_error_set(error, errno ? errno : EIO, "netlink send");
    goto out;
  }
  uint32_t seq = request->nlmsg_seq;
#ifndef FM_DEVEL_TOOLS
  if (raw) {
    fm_error_fail(error, FM_FAILURE_INTERNAL, ENOTSUP, "raw capture requires a devel build");
    goto out;
  }
#else
  if (raw) {
    unsigned char header[16] = "FMNLLE1", *p = header + 8;
    protocol_put(&p, seq, 4);
    protocol_put(&p, family, 4);
    if (fwrite(header, 1, 16, raw) != 16) {
      fm_error_set(error, errno, "raw header");
      goto out;
    }
  }
#endif
  buffer = malloc(ss.bufsize);
  if (!buffer) {
    fm_error_set(error, errno, "receive buffer");
    goto out;
  }
  int done = 0;
  while (!done && !error->code) {
    struct sockaddr_nl sender = {0};
    struct iovec iov = {buffer, ss.bufsize};
    struct msghdr msg = {.msg_name = &sender,
                         .msg_namelen = sizeof(sender),
                         .msg_iov = &iov,
                         .msg_iovlen = 1};
    ssize_t size = recvmsg(ss.fd, &msg, 0);
    if (size < 0 && errno == EINTR)
      continue;
    if (size <= 0) {
      fm_error_set(error, errno ? errno : EIO, "incomplete netlink dump");
      break;
    }
    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
      fm_error_set(error, EPROTO, "truncated netlink datagram");
      break;
    }
    if (sender.nl_pid != 0) {
      fm_error_set(error, EPROTO, "non-kernel netlink sender");
      break;
    }
#ifdef FM_DEVEL_TOOLS
    if (raw && !protocol_frame(raw, buffer, size, NULL, error))
      break;
#endif
#ifdef FM_DEVEL_TOOLS
    int backlog;
    if (probe.enabled && !ioctl(ss.fd, FIONREAD, &backlog) && backlog > probe.max_backlog)
      probe.max_backlog = backlog;
#endif
    datagram(&r, buffer, size, seq, family, &done);
  }
  ok = done && !error->code;
#ifdef FM_DEVEL_TOOLS
  if (probe.enabled)
    fprintf(stderr, "probe: states %ju callback %.6f s (%.3f us/state) max_backlog %d B\n",
            (uintmax_t)probe.states, probe.callback_seconds,
            probe.states ? probe.callback_seconds * 1e6 / probe.states : 0.0, probe.max_backlog);
#endif
out:
  free(buffer);
  snl_free(&ss);
  return ok;
}
unsigned pf_reader_state_version(void) { return PF_STATE_VERSION; }

/* PF's current state count without a dump (netlink GET_STATUS, FreeBSD 14.1
 * and later). Any problem only makes the preflight unavailable: the
 * traversal backstop still bounds the sample. Pending target validation of
 * the command and attribute on each supported OPNsense series. */
#if __FreeBSD_version >= 1401000
struct status_parse {
  uint64_t states;
  bool found;
};
static void status_attr(unsigned type, const unsigned char *p, size_t n, void *arg) {
  struct status_parse *status = arg;
  if (type != PF_GS_STATES)
    return;
  if (n == 4) {
    uint32_t value;
    memcpy(&value, p, 4);
    status->states = value;
    status->found = true;
  } else if (n == 8) {
    memcpy(&status->states, p, 8);
    status->found = true;
  }
}
bool pf_reader_state_count(uint64_t *count) {
  struct snl_state ss;
  if (!snl_init(&ss, NETLINK_GENERIC))
    return false;
  bool found = false;
  struct fm_error ignored = {0};
  struct reader r = {.error = &ignored};
  unsigned char *buffer = NULL;
  struct timeval timeout = {.tv_sec = 2};
  int family = setsockopt(ss.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
                   ? 0 : snl_get_genl_family(&ss, PFNL_FAMILY_NAME);
  struct snl_writer nw;
  if (family) {
    snl_init_writer(&ss, &nw);
    struct nlmsghdr *request = snl_create_genl_msg_request(&nw, family, PFNL_CMD_GET_STATUS);
    request = request ? snl_finalize_msg(&nw) : NULL;
    buffer = request && snl_send_message(&ss, request) ? malloc(ss.bufsize) : NULL;
    ssize_t size = buffer ? recv(ss.fd, buffer, ss.bufsize, 0) : -1;
    for (unsigned char *p = buffer; size >= (ssize_t)sizeof(struct nlmsghdr);) {
      struct nlmsghdr *h = (void *)p;
      if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > (size_t)size)
        break;
      if (h->nlmsg_type == family &&
          h->nlmsg_len >= sizeof(*h) + sizeof(struct genlmsghdr)) {
        struct status_parse status = {0};
        attributes(&r, p + sizeof(*h) + sizeof(struct genlmsghdr),
                   h->nlmsg_len - sizeof(*h) - sizeof(struct genlmsghdr), status_attr, &status);
        if (status.found && !ignored.code) {
          *count = status.states;
          found = true;
        }
        break;
      }
      size_t step = NLMSG_ALIGN(h->nlmsg_len);
      if (step >= (size_t)size)
        break;
      p += step;
      size -= step;
    }
  }
  free(buffer);
  snl_free(&ss);
  return found;
}
#else
bool pf_reader_state_count(uint64_t *count) {
  (void)count;
  return false;
}
#endif
/* The lifetime bound (pf_reader.h). Requests follow libpfctl: GET_TIMEOUT
 * (PF_TO_TIMEOUT -> PF_TO_SECONDS), GETRULES (PF_GR_ANCHOR, PF_GR_ACTION ->
 * PF_GR_NR, PF_GR_TICKET), GETRULE (+ PF_GR_NR, PF_GR_TICKET; PF_GR_CLEAR is
 * never sent: counters are not cleared) and GET_RULESETS / GET_RULESET
 * (PF_RS_PATH, PF_RS_NR -> PF_RS_NR, PF_RS_NAME). */
#if __FreeBSD_version >= 1500000
#define RULESETS_MAX 1024
struct pf_ruleset_entry {
  char path[MAXPATHLEN];
  uint32_t ticket;
  uint64_t max;
};
struct pf_rule_cache {
  struct pf_ruleset_entry *sets;
  size_t count;
  uint64_t rule_max_ever;
};
struct nl_call {
  struct snl_state ss;
  int family;
};
static bool nl_open(struct nl_call *c) {
  if (!snl_init(&c->ss, NETLINK_GENERIC))
    return false;
  struct timeval timeout = {.tv_sec = 2};
  c->family = setsockopt(c->ss.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
                  ? 0 : snl_get_genl_family(&c->ss, PFNL_FAMILY_NAME);
  if (!c->family)
    snl_free(&c->ss);
  return c->family != 0;
}
static struct nlmsghdr *nl_request(struct nl_call *c, struct snl_writer *nw, uint8_t cmd, bool dump) {
  snl_init_writer(&c->ss, nw);
  struct nlmsghdr *hdr = snl_create_genl_msg_request(nw, c->family, cmd);
  if (hdr && dump)
    hdr->nlmsg_flags |= NLM_F_DUMP;
  return hdr;
}
/* Sends the request written to nw and parses the attributes of every reply
 * message with fn: 0, the kernel's error, or EPROTO for a malformed reply. */
static int nl_exchange(struct nl_call *c, struct snl_writer *nw, attribute_fn fn, void *arg) {
  struct nlmsghdr *hdr = snl_finalize_msg(nw);
  int result = hdr ? 0 : ENOMEM;
  if (!result && !snl_send_message(&c->ss, hdr))
    result = EIO;
  if (!result) {
    uint32_t seq = hdr->nlmsg_seq;
    struct snl_errmsg_data e = {0};
    struct fm_error parse = {0};
    struct reader r = {.error = &parse};
    while ((hdr = snl_read_reply_multi(&c->ss, seq, &e)) != NULL)
      if (hdr->nlmsg_len >= sizeof(*hdr) + sizeof(struct genlmsghdr))
        attributes(&r, (const unsigned char *)(hdr + 1) + sizeof(struct genlmsghdr),
                   hdr->nlmsg_len - sizeof(*hdr) - sizeof(struct genlmsghdr), fn, arg);
    result = e.error ? e.error : parse.code ? EPROTO : 0;
  }
  snl_clear_lb(&c->ss);
  return result;
}
struct u32_pair {
  unsigned types[2];
  uint32_t values[2];
  unsigned found;
};
static void u32_attr(unsigned type, const unsigned char *p, size_t n, void *arg) {
  struct u32_pair *u = arg;
  for (unsigned k = 0; k < 2; k++)
    if (u->types[k] && type == u->types[k] && n == 4) {
      memcpy(&u->values[k], p, 4);
      u->found |= 1u << k;
    }
}
static int get_timeout(struct nl_call *c, unsigned index, uint32_t *seconds) {
  struct snl_writer nw;
  if (!nl_request(c, &nw, PFNL_CMD_GET_TIMEOUT, false))
    return ENOMEM;
  snl_add_msg_attr_u32(&nw, PF_TO_TIMEOUT, index);
  struct u32_pair u = {.types = {PF_TO_SECONDS}};
  int error = nl_exchange(c, &nw, u32_attr, &u);
  *seconds = u.values[0];
  return error ? error : u.found == 1 ? 0 : EPROTO;
}
static int get_rules(struct nl_call *c, const char *path, uint32_t *nr, uint32_t *ticket) {
  struct snl_writer nw;
  if (!nl_request(c, &nw, PFNL_CMD_GETRULES, true))
    return ENOMEM;
  snl_add_msg_attr_string(&nw, PF_GR_ANCHOR, path);
  snl_add_msg_attr_u8(&nw, PF_GR_ACTION, PF_PASS);
  struct u32_pair u = {.types = {PF_GR_NR, PF_GR_TICKET}};
  int error = nl_exchange(c, &nw, u32_attr, &u);
  *nr = u.values[0];
  *ticket = u.values[1];
  return error ? error : u.found == 3 ? 0 : EPROTO;
}
/* PF_RT_TIMEOUT: nested PF_TT_TIMEOUT u32 values in index order. */
struct rule_timeouts {
  uint32_t table[LIFETIME_TIMEOUTS];
  unsigned count;
  bool found, malformed;
};
static void timeout_value(unsigned type, const unsigned char *p, size_t n, void *arg) {
  struct rule_timeouts *t = arg;
  if (type != PF_TT_TIMEOUT)
    return;
  if (n != 4 || t->count >= LIFETIME_TIMEOUTS) {
    t->malformed = true;
    return;
  }
  memcpy(&t->table[t->count++], p, 4);
}
static void rule_attr(unsigned type, const unsigned char *p, size_t n, void *arg) {
  struct rule_timeouts *t = arg;
  if (type != PF_RT_TIMEOUT)
    return;
  struct fm_error nested = {0};
  struct reader r = {.error = &nested};
  t->found = true;
  attributes(&r, p, n, timeout_value, t);
  if (nested.code)
    t->malformed = true;
}
static int get_rule_max(struct nl_call *c, const char *path, uint32_t nr, uint32_t ticket,
                        uint64_t *max) {
  struct snl_writer nw;
  if (!nl_request(c, &nw, PFNL_CMD_GETRULE, true))
    return ENOMEM;
  snl_add_msg_attr_string(&nw, PF_GR_ANCHOR, path);
  snl_add_msg_attr_u8(&nw, PF_GR_ACTION, PF_PASS);
  snl_add_msg_attr_u32(&nw, PF_GR_NR, nr);
  snl_add_msg_attr_u32(&nw, PF_GR_TICKET, ticket);
  struct rule_timeouts t = {0};
  int error = nl_exchange(c, &nw, rule_attr, &t);
  if (error)
    return error;
  if (!t.found || t.malformed)
    return EPROTO;
  *max = lifetime_table_max(t.table); /* a rule's 0 means the default */
  return 0;
}
struct name_parse {
  char name[MAXPATHLEN];
  uint32_t nr;
  unsigned found;
};
static void ruleset_attr(unsigned type, const unsigned char *p, size_t n, void *arg) {
  struct name_parse *rs = arg;
  if (type == PF_RS_NR && n == 4) {
    memcpy(&rs->nr, p, 4);
    rs->found |= 1;
  } else if (type == PF_RS_NAME && n && n <= sizeof(rs->name) && !p[n - 1] &&
             !memchr(p, 0, n - 1)) {
    memcpy(rs->name, p, n);
    rs->found |= 2;
  }
}
static int get_children(struct nl_call *c, const char *path, uint32_t *count) {
  struct snl_writer nw;
  if (!nl_request(c, &nw, PFNL_CMD_GET_RULESETS, false))
    return ENOMEM;
  snl_add_msg_attr_string(&nw, PF_RS_PATH, path);
  struct name_parse rs = {0};
  int error = nl_exchange(c, &nw, ruleset_attr, &rs);
  *count = rs.nr;
  return error ? error : rs.found & 1 ? 0 : EPROTO;
}
static int get_child(struct nl_call *c, const char *path, uint32_t nr, char *name) {
  struct snl_writer nw;
  if (!nl_request(c, &nw, PFNL_CMD_GET_RULESET, false))
    return ENOMEM;
  snl_add_msg_attr_string(&nw, PF_RS_PATH, path);
  snl_add_msg_attr_u32(&nw, PF_RS_NR, nr);
  struct name_parse rs = {0};
  int error = nl_exchange(c, &nw, ruleset_attr, &rs);
  if (!error && !(rs.found & 2))
    error = EPROTO;
  if (!error)
    memcpy(name, rs.name, sizeof(rs.name));
  return error;
}
/* One ruleset's rule maximum, from the cache while its ticket is unchanged. */
static int ruleset_max(struct nl_call *c, const struct pf_rule_cache *cache,
                       struct pf_ruleset_entry *fresh, size_t *fresh_count, const char *path,
                       uint64_t *max) {
  uint32_t nr, ticket;
  int error = get_rules(c, path, &nr, &ticket);
  if (error)
    return error;
  for (size_t k = 0; k < cache->count; k++)
    if (cache->sets[k].ticket == ticket && !strcmp(cache->sets[k].path, path)) {
      *max = cache->sets[k].max;
      fresh[(*fresh_count)++] = cache->sets[k];
      return 0;
    }
  uint64_t best = 0;
  for (uint32_t i = 0; i < nr && !error; i++) {
    uint64_t rule;
    error = get_rule_max(c, path, i, ticket, &rule);
    if (!error && rule > best)
      best = rule;
  }
  if (error)
    return error; /* EBUSY: the ruleset changed during the walk */
  struct pf_ruleset_entry *e = &fresh[(*fresh_count)++];
  snprintf(e->path, sizeof(e->path), "%s", path);
  e->ticket = ticket;
  e->max = best;
  *max = best;
  return 0;
}
/* Every filter ruleset, the main one and each anchor (depth first). */
static int rules_bound(struct nl_call *c, struct pf_rule_cache *cache, uint64_t *max) {
  struct pf_ruleset_entry *fresh = calloc(RULESETS_MAX, sizeof(*fresh));
  char(*pending)[MAXPATHLEN] = calloc(RULESETS_MAX, MAXPATHLEN);
  size_t fresh_count = 0, pending_count = 1, walked = 0;
  int error = fresh && pending ? 0 : ENOMEM;
  uint64_t best = 0;
  while (!error && pending_count) {
    char path[MAXPATHLEN];
    memcpy(path, pending[--pending_count], MAXPATHLEN);
    if (++walked > RULESETS_MAX) {
      error = E2BIG;
      break;
    }
    uint64_t set_max = 0;
    uint32_t children = 0;
    error = ruleset_max(c, cache, fresh, &fresh_count, path, &set_max);
    if (!error && set_max > best)
      best = set_max;
    if (!error)
      error = get_children(c, path, &children);
    for (uint32_t k = 0; k < children && !error; k++) {
      char name[MAXPATHLEN];
      if ((error = get_child(c, path, k, name)))
        break;
      if (pending_count >= RULESETS_MAX) {
        error = E2BIG;
        break;
      }
      int length = path[0] ? snprintf(pending[pending_count], MAXPATHLEN, "%s/%s", path, name)
                           : snprintf(pending[pending_count], MAXPATHLEN, "%s", name);
      if (length < 0 || length >= MAXPATHLEN) {
        error = ENAMETOOLONG;
        break;
      }
      pending_count++;
    }
  }
  free(pending);
  if (error) {
    free(fresh);
    return error;
  }
  free(cache->sets);
  cache->sets = fresh;
  cache->count = fresh_count;
  if (best > cache->rule_max_ever)
    cache->rule_max_ever = best;
  *max = cache->rule_max_ever;
  return 0;
}
struct lifetime_bound pf_reader_lifetime_bound(struct pf_rule_cache **cachep) {
  struct lifetime_bound bound = {0};
  if (!*cachep && !(*cachep = calloc(1, sizeof(**cachep)))) {
    bound.error = ENOMEM;
    return bound;
  }
  struct nl_call c;
  errno = 0;
  if (!nl_open(&c)) {
    bound.error = errno ? errno : ENXIO;
    return bound;
  }
  uint32_t table[LIFETIME_TIMEOUTS] = {0};
  int error = 0;
  for (unsigned i = 0; i < LIFETIME_TIMEOUTS && !error; i++)
    if (lifetime_index_applies(i))
      error = get_timeout(&c, i, &table[i]);
  uint64_t rules = 0;
  if (!error)
    error = rules_bound(&c, *cachep, &rules);
  snl_free(&c.ss);
  if (error) {
    bound.error = error;
    return bound;
  }
  uint64_t defaults = lifetime_table_max(table);
  bound.timeout_max = defaults > rules ? defaults : rules;
  bound.available = true;
  return bound;
}
void pf_reader_rule_cache_free(struct pf_rule_cache *cache) {
  if (cache)
    free(cache->sets);
  free(cache);
}
#else
struct pf_rule_cache {
  int unused;
};
struct lifetime_bound pf_reader_lifetime_bound(struct pf_rule_cache **cache) {
  (void)cache;
  return (struct lifetime_bound){.error = ENOTSUP};
}
void pf_reader_rule_cache_free(struct pf_rule_cache *cache) { (void)cache; }
#endif
#ifdef FM_DEVEL_TOOLS
/* Replays a saved FMNLLE1 capture (devel tools only). */
bool pf_reader_wire(const char *path, pf_state_callback callback, void *arg,
                    struct fm_error *error) {
  struct reader r = {.callback = callback, .arg = arg, .error = error};
  FILE *f = fopen(path, "rb");
  if (!f)
    return fm_error_set(error, errno, "wire fixture");
  unsigned char header[16];
  int done = 0;
  bool ok = false;
  if (fread(header, 1, 16, f) != 16 || memcmp(header, "FMNLLE1", 8)) {
    fm_error_set(error, EPROTO, "wire header");
    goto out;
  }
  uint16_t endian = 1;
  if (*(unsigned char *)&endian != 1) {
    fm_error_set(error, ENOTSUP, "wire fixture requires little endian");
    goto out;
  }
  const unsigned char *p = header + 8;
  uint32_t seq = protocol_get(&p, 4);
  int family = protocol_get(&p, 4);
  for (;;) {
    unsigned char size[4];
    size_t got = fread(size, 1, 4, f);
    if (!got && feof(f))
      break;
    if (got != 4) {
      fm_error_set(error, EPROTO, "wire truncated length");
      break;
    }
    p = size;
    size_t n = protocol_get(&p, 4);
    if (!n || n > 4 * 1024 * 1024) {
      fm_error_set(error, EPROTO, "wire frame limit");
      break;
    }
    unsigned char *buffer = malloc(n);
    if (!buffer) {
      fm_error_set(error, errno, "wire allocation");
      break;
    }
    if (fread(buffer, 1, n, f) != n)
      fm_error_set(error, EPROTO, "wire truncated frame");
    else
      datagram(&r, buffer, n, seq, family, &done);
    free(buffer);
    if (error->code)
      break;
  }
  if (ferror(f))
    fm_error_set(error, EIO, "wire read");
  if (!done)
    fm_error_set(error, EPROTO, "wire missing NLMSG_DONE");
  ok = done && !error->code;
out:
  fclose(f);
  return ok;
}
#endif

#else
struct pf_rule_cache {
  int unused;
};
struct lifetime_bound pf_reader_lifetime_bound(struct pf_rule_cache **cache) {
  (void)cache;
  return (struct lifetime_bound){.error = ENOTSUP};
}
void pf_reader_rule_cache_free(struct pf_rule_cache *cache) { (void)cache; }
unsigned pf_reader_state_version(void) { return 0; }
bool pf_reader_state_count(uint64_t *count) {
  (void)count;
  return false;
}
bool pf_reader_live(pf_state_callback callback, void *arg, FILE *raw,
                    double *request_anchor, struct fm_error *error) {
  (void)callback;
  (void)arg;
  (void)raw;
  (void)request_anchor;
  return fm_error_set(error, ENOTSUP,
                      "live PF acquisition requires OPNsense/FreeBSD");
}
#ifdef FM_DEVEL_TOOLS
bool pf_reader_wire(const char *path, pf_state_callback callback, void *arg,
                    struct fm_error *error) {
  (void)path;
  (void)callback;
  (void)arg;
  return fm_error_set(error, ENOTSUP,
                      "saved PF netlink decoding requires OPNsense headers");
}
#endif
#endif
