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

#include "state.h"
#include <errno.h>
#include <netinet/in.h>
#include <string.h>

void state_flow_key(unsigned char key[FM_FLOW_KEY_SIZE], struct addr local,
                    struct addr remote) {
  key[0] = local.af;
  memcpy(key + 1, local.b, 16);
  key[17] = remote.af;
  memcpy(key + 18, remote.b, 16);
}
bool address_equal(struct addr a, struct addr b) {
  return a.af == b.af && !memcmp(a.b, b.b, 16);
}
unsigned address_flags(const struct context *ctx, struct addr a) {
  for (size_t n = 0; n < ctx->nr; n++)
    if (a.af == ctx->ranges[n].lo.af &&
        memcmp(a.b, ctx->ranges[n].lo.b, 16) >= 0 &&
        memcmp(a.b, ctx->ranges[n].hi.b, 16) <= 0)
      return ctx->ranges[n].flags;
  return 0;
}
static bool is_public(const struct context *ctx, struct addr a) {
  return address_flags(ctx, a) & FM_PUBLIC;
}
static bool is_private(const struct context *ctx, struct addr a) {
  return address_flags(ctx, a) & FM_PRIVATE;
}
static int local(const struct context *ctx, struct addr a) {
  for (size_t n = 0; n < ctx->nl; n++)
    if (address_equal(a, ctx->local[n]))
      return 1;
  return 0;
}
static int prefix(struct addr a, const struct net *n) {
  if (a.af != n->a.af)
    return 0;
  unsigned whole = n->prefix / 8, bits = n->prefix % 8;
  return !memcmp(a.b, n->a.b, whole) &&
         (!bits || ((a.b[whole] ^ n->a.b[whole]) & (0xff << (8 - bits))) == 0);
}
static const char *device(const struct context *ctx, struct addr a,
                          const char *excluded) {
  for (size_t n = 0; n < ctx->nn; n++)
    if ((!excluded || strcmp(ctx->nets[n].device, excluded)) &&
        prefix(a, &ctx->nets[n]))
      return ctx->nets[n].device;
  return NULL;
}
static int inside_address(const struct context *ctx, struct addr a,
                          const char *excluded) {
  return is_private(ctx, a) || (!local(ctx, a) && device(ctx, a, excluded));
}
static int wan_address(const struct context *ctx, struct addr a) {
  for (size_t n = 0; n < ctx->na; n++)
    if (!strcmp(ctx->assigned[n].device, ctx->wan) &&
        address_equal(a, ctx->assigned[n].a))
      return 1;
  return 0;
}
bool endpoint_equal(struct endpoint a, struct endpoint b) {
  return address_equal(a.a, b.a) && a.port == b.port;
}
bool state_is_icmp(unsigned p) {
  return p == IPPROTO_ICMP || p == IPPROTO_ICMPV6;
}
uint64_t state_bytes_from_remote(const struct state *s, bool remote_initiated) {
  return s->pf_bytes[remote_initiated ? FM_PF_FORWARD : FM_PF_REVERSE];
}
uint64_t state_bytes_to_remote(const struct state *s, bool remote_initiated) {
  return s->pf_bytes[remote_initiated ? FM_PF_REVERSE : FM_PF_FORWARD];
}
uint64_t state_packets_from_remote(const struct state *s, bool remote_initiated) {
  return s->pf_packets[remote_initiated ? FM_PF_FORWARD : FM_PF_REVERSE];
}
uint64_t state_packets_to_remote(const struct state *s, bool remote_initiated) {
  return s->pf_packets[remote_initiated ? FM_PF_REVERSE : FM_PF_FORWARD];
}

/* Context local addresses arrive in Python's lexical order, not binary order.
 */
static int origin(const struct context *ctx, struct addr other,
                  const char *egress, int prefer_egress, struct addr *out) {
  int found = 0, preferred = 0;
  for (size_t n = 0; n < ctx->nl; n++)
    if (ctx->local[n].af == other.af) {
      const char *d = device(ctx, ctx->local[n], NULL);
      int pref = prefer_egress && d && !strcmp(d, egress);
      if (!found || pref > preferred) {
        *out = ctx->local[n];
        found = 1;
        preferred = pref;
      }
    }
  return found;
}

size_t state_tuple(unsigned char *b, unsigned proto, struct endpoint inside,
                   struct endpoint far) {
  *b++ = proto;
  *b++ = inside.a.af;
  memcpy(b, inside.a.b, 16);
  b += 16;
  *b++ = inside.port >> 8;
  *b++ = inside.port;
  *b++ = far.a.af;
  memcpy(b, far.a.b, 16);
  b += 16;
  *b++ = far.port >> 8;
  *b = far.port;
  return FM_TUPLE_SIZE;
}

bool state_orient(const struct state *s, struct orientation *o,
                  struct fm_error *error) {
  memset(o, 0, sizeof(*o));
  for (unsigned k = 0; k < 2; k++) {
    if (s->key[k].proto != s->key[FM_WIRE_KEY].proto)
      return fm_error_set(error, EPROTO, "key protocols differ");
    for (unsigned e = 0; e < 2; e++)
      if (s->key[k].e[e].a.af != s->key[k].e[0].a.af ||
          (s->key[k].e[e].a.af != 4 && s->key[k].e[e].a.af != 6))
        return fm_error_set(error, EPROTO, "key address family");
  }
  if (s->key[FM_WIRE_KEY].e[0].a.af != s->key[FM_STACK_KEY].e[0].a.af)
    return fm_error_set(error, EPROTONOSUPPORT,
                        "cross-family translation unsupported");
  const struct key *wire = &s->key[FM_WIRE_KEY], *stack = &s->key[FM_STACK_KEY];
  o->proto = wire->proto;
  if (s->pf_direction == FM_OUT) {
    o->initiator = wire->e[1];
    o->responder = wire->e[0];
    o->untranslated = stack->e[1];
  } else if (s->pf_direction == FM_IN) {
    o->initiator = stack->e[0];
    o->responder = stack->e[1];
    o->untranslated = wire->e[1];
  } else
    return fm_error_set(error, EPROTO, "PF direction");
  /* Inbound pfctl equalizes the left-side ICMP identifier. Outbound it
   * equalizes the right side only: the inside/source identifier must survive.
   */
  if (state_is_icmp(o->proto) && s->pf_direction == FM_IN)
    o->untranslated.port = o->responder.port;
  o->translated = !endpoint_equal(
      o->untranslated, s->pf_direction == FM_OUT ? o->initiator : o->responder);
  return true;
}

bool state_normalize(const struct state *s, const struct context *ctx,
                     struct state_view *v, struct fm_error *error) {
  memset(v, 0, sizeof(*v));
  if (!state_orient(s, &v->pf, error))
    return false;
  struct endpoint src = v->pf.initiator, dst = v->pf.responder,
                  nat = v->pf.untranslated, *inside = NULL;
  bool has_nat = v->pf.translated;
  unsigned proto = v->pf.proto;
  int direction = s->pf_direction;
  /* Exact parser admission: untranslated private/private headers are skipped.
   */
  if (!has_nat && !is_public(ctx, src.a) && !is_public(ctx, dst.a))
    return true;
  v->retained = true;
  struct endpoint *sides[3];
  if (direction == FM_IN) {
    sides[0] = &dst;
    sides[1] = has_nat ? &nat : NULL;
    sides[2] = &src;
  } else {
    sides[0] = has_nat ? &nat : NULL;
    sides[1] = &src;
    sides[2] = &dst;
  }
  for (unsigned n = 0; n < 3 && !inside; n++)
    if (sides[n] && is_private(ctx, sides[n]->a))
      inside = sides[n];
  if (!inside && s->original_interface[0])
    for (unsigned n = 0; n < 2; n++) {
      struct endpoint *e = n ? &dst : &src;
      if (inside_address(ctx, e->a, s->original_interface)) {
        inside = e;
        break;
      }
    }
  struct addr loc, remote;
  int tunnel = 0;
  if (has_nat && is_public(ctx, nat.a))
    loc = nat.a;
  else if (local(ctx, src.a))
    loc = src.a;
  else if (local(ctx, dst.a))
    loc = dst.a;
  else if (has_nat && direction == FM_OUT && is_private(ctx, src.a) &&
           is_public(ctx, dst.a) && !strcmp(s->original_interface, ctx->wan) &&
           wan_address(ctx, src.a))
    loc = src.a;
  else if (has_nat && direction == FM_IN && is_private(ctx, nat.a) &&
           is_public(ctx, src.a) && !strcmp(s->original_interface, ctx->wan) &&
           wan_address(ctx, nat.a))
    loc = nat.a;
  else if (has_nat && is_private(ctx, src.a) && is_public(ctx, dst.a) &&
           ctx->nl) {
    if (!origin(ctx, dst.a, s->original_interface, 0, &loc))
      return true;
    remote = dst.a;
    tunnel = 1;
  } else {
    if (!ctx->nn || !inside || !is_public(ctx, inside->a))
      return true;
    struct endpoint *far = inside == &src ? &dst : &src;
    if (!is_public(ctx, far->a) ||
        !origin(ctx, far->a, s->original_interface, 1, &loc))
      return true;
    remote = far->a;
    tunnel = 1;
  }
  if (!tunnel) {
    remote = address_equal(loc, src.a) ? dst.a : src.a;
    if (!is_public(ctx, remote) || address_equal(remote, loc) ||
        local(ctx, remote))
      return true;
  }
  bool remote_initiated = address_equal(src.a, remote);
  bool apparent = remote_initiated;
  unsigned service_port = dst.port;
  if (!apparent) {
    unsigned source_port = inside ? inside->port : src.port;
    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && source_port &&
        dst.port && source_port < 1024 && dst.port >= 10000) {
      apparent = true;
      service_port = source_port;
    }
  }
  v->has_inside = inside != NULL;
  if (inside)
    v->inside = *inside;
  v->local = loc;
  v->remote = remote;
  v->remote_initiated = remote_initiated;
  v->apparent_remote_initiated = apparent;
  v->service_port = service_port;
  v->remote_endpoint = remote_initiated ? src : dst;
  v->outside_view = !remote_initiated ? src : has_nat ? nat : dst;
  v->mapped = true;
  return true;
}
