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
    r->callback(&s, r->arg, r->error);
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
    datagram(&r, buffer, size, seq, family, &done);
  }
  ok = done && !error->code;
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
