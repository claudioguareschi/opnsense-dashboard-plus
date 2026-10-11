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
                    struct addr remote, struct addr owner) {
  key[0] = local.af;
  memcpy(key + 1, local.b, 16);
  key[17] = remote.af;
  memcpy(key + 18, remote.b, 16);
  key[34] = owner.af;
  memcpy(key + 35, owner.b, 16);
}
struct addr state_owner(const struct state_view *v) {
  struct addr none = {0};
  return v->has_inside ? v->inside.a : none;
}
static bool is_public(const struct context *ctx, struct addr a) {
  return address_flags(ctx, a) & FM_PUBLIC;
}
static bool is_private(const struct context *ctx, struct addr a) {
  return address_flags(ctx, a) & FM_PRIVATE;
}
static int inside_address(const struct context *ctx, struct addr a,
                          const char *excluded) {
  return is_private(ctx, a) ||
         (!context_is_local(ctx, a) && context_device(ctx, a, excluded));
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
      const char *d = ctx->local_device[n];
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

static bool icmp_pair(unsigned a, unsigned b) {
  return (a == IPPROTO_ICMP && b == IPPROTO_ICMPV6) || (a == IPPROTO_ICMPV6 && b == IPPROTO_ICMP);
}
bool state_orient(const struct state *s, struct orientation *o,
                  struct fm_error *error) {
  memset(o, 0, sizeof(*o));
  if (s->pf_direction != FM_IN && s->pf_direction != FM_OUT)
    return fm_error_fail(error, FM_FAILURE_STRUCTURAL, EPROTO, "PF direction");
  for (unsigned k = 0; k < 2; k++)
    for (unsigned e = 0; e < 2; e++)
      if (s->key[k].e[e].a.af != s->key[k].e[0].a.af ||
          (s->key[k].e[e].a.af != 4 && s->key[k].e[e].a.af != 6))
        return fm_error_fail(error, FM_FAILURE_INTERNAL, EPROTO, "key address family");
  bool cross_family = s->key[FM_WIRE_KEY].e[0].a.af != s->key[FM_STACK_KEY].e[0].a.af;
  unsigned wire_proto = s->key[FM_WIRE_KEY].proto, stack_proto = s->key[FM_STACK_KEY].proto;
  if (wire_proto != stack_proto && !(cross_family && icmp_pair(wire_proto, stack_proto)))
    return fm_error_fail(error, FM_FAILURE_STRUCTURAL, EPROTO, "key protocols differ");
  if (cross_family) {
    /* af-to translation: complete keys of the two families, protocols equal
     * or the ICMP/ICMPv6 pair af-to rewrites. Not modelled yet: skipped. */
    o->skip = SKIP_AF_TRANSLATION;
    return true;
  }
  const struct key *wire = &s->key[FM_WIRE_KEY], *stack = &s->key[FM_STACK_KEY];
  o->proto = wire->proto;
  if (s->pf_direction == FM_OUT) {
    o->initiator = wire->e[1];
    o->responder = wire->e[0];
    o->untranslated = stack->e[1];
  } else {
    o->initiator = stack->e[0];
    o->responder = stack->e[1];
    o->untranslated = wire->e[1];
  }
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
  if (v->pf.skip)
    return true; /* neither retained nor mapped: counted by the caller */
  struct endpoint src = v->pf.initiator, dst = v->pf.responder,
                  nat = v->pf.untranslated, *inside = NULL;
  bool has_nat = v->pf.translated;
  unsigned proto = v->pf.proto;
  int direction = s->pf_direction;
  /* Each endpoint is classified once (binary search over the ranges). */
  unsigned src_flags = address_flags(ctx, src.a), dst_flags = address_flags(ctx, dst.a),
           nat_flags = has_nat ? address_flags(ctx, nat.a) : dst_flags;
  /* Exact parser admission: untranslated private/private headers are skipped.
   */
  if (!has_nat && !(src_flags & FM_PUBLIC) && !(dst_flags & FM_PUBLIC))
    return true;
  v->retained = true;
  struct endpoint *sides[3];
  unsigned side_flags[3];
  if (direction == FM_IN) {
    sides[0] = &dst, side_flags[0] = dst_flags;
    sides[1] = has_nat ? &nat : NULL, side_flags[1] = nat_flags;
    sides[2] = &src, side_flags[2] = src_flags;
  } else {
    sides[0] = has_nat ? &nat : NULL, side_flags[0] = nat_flags;
    sides[1] = &src, side_flags[1] = src_flags;
    sides[2] = &dst, side_flags[2] = dst_flags;
  }
  unsigned inside_flags = 0;
  for (unsigned n = 0; n < 3 && !inside; n++)
    if (sides[n] && (side_flags[n] & FM_PRIVATE)) {
      inside = sides[n];
      inside_flags = side_flags[n];
    }
  if (!inside && s->original_interface[0])
    for (unsigned n = 0; n < 2; n++) {
      struct endpoint *e = n ? &dst : &src;
      if (inside_address(ctx, e->a, s->original_interface)) {
        inside = e;
        inside_flags = n ? dst_flags : src_flags;
        break;
      }
    }
  struct addr loc, remote;
  int tunnel = 0;
  if (has_nat && (nat_flags & FM_PUBLIC))
    loc = nat.a;
  else if (context_is_local(ctx, src.a))
    loc = src.a;
  else if (context_is_local(ctx, dst.a))
    loc = dst.a;
  else if (has_nat && direction == FM_OUT && (src_flags & FM_PRIVATE) &&
           (dst_flags & FM_PUBLIC) && !strcmp(s->original_interface, ctx->wan) &&
           context_is_wan_address(ctx, src.a))
    loc = src.a;
  else if (has_nat && direction == FM_IN && (nat_flags & FM_PRIVATE) &&
           (src_flags & FM_PUBLIC) && !strcmp(s->original_interface, ctx->wan) &&
           context_is_wan_address(ctx, nat.a))
    loc = nat.a;
  else if (has_nat && (src_flags & FM_PRIVATE) && (dst_flags & FM_PUBLIC) &&
           ctx->nl) {
    if (!origin(ctx, dst.a, s->original_interface, 0, &loc))
      return true;
    remote = dst.a;
    tunnel = 1;
  } else {
    if (!ctx->nn || !inside || !(inside_flags & FM_PUBLIC))
      return true;
    struct endpoint *far = inside == &src ? &dst : &src;
    if (!((far == &src ? src_flags : dst_flags) & FM_PUBLIC) ||
        !origin(ctx, far->a, s->original_interface, 1, &loc))
      return true;
    remote = far->a;
    tunnel = 1;
  }
  if (!tunnel) {
    remote = address_equal(loc, src.a) ? dst.a : src.a;
    if (!is_public(ctx, remote) || address_equal(remote, loc) ||
        context_is_local(ctx, remote))
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
