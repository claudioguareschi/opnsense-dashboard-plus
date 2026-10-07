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

#ifndef FM_STATE_H
#define FM_STATE_H
#include "error.h"
#include <stdint.h>
#define FM_INTERFACE_SIZE 16
#define FM_LABEL_SIZE 64
#define FM_IN 1
#define FM_OUT 2
#define FM_PUBLIC 1
#define FM_PRIVATE 2
struct addr {
  unsigned char af, b[16];
};
struct endpoint {
  struct addr a;
  uint16_t port;
};
struct key {
  struct endpoint e[2];
  unsigned char proto;
};
struct state {
  uint64_t id, bytes[2], packets[2];
  uint32_t creator, age, expire, rule;
  unsigned char direction, peer[2];
  char iface[FM_INTERFACE_SIZE], orig[FM_INTERFACE_SIZE], label[FM_LABEL_SIZE];
  struct key key[2];
};
struct range {
  struct addr lo, hi;
  unsigned flags;
};
struct net {
  struct addr a;
  unsigned prefix;
  char device[FM_INTERFACE_SIZE];
};
struct assigned {
  struct addr a;
  char device[FM_INTERFACE_SIZE];
};
struct service {
  unsigned proto, port, group;
};
/* Python supplies classification ranges, lexical local-address order and
 * specificity-ordered networks; C never parses OPNsense configuration. */
struct context {
  struct range ranges[512];
  size_t nr;
  struct addr local[256];
  size_t nl;
  struct net nets[512];
  size_t nn;
  struct assigned assigned[512];
  size_t na;
  struct service services[256];
  size_t ns;
  char wan[FM_INTERFACE_SIZE];
};
struct state_view {
  struct endpoint src, dst, nat, inside, public, far;
  struct addr local, remote;
  unsigned service_port, proto;
  bool has_nat, has_inside, retained, mapped, src_remote, remote_started;
};
bool state_normalize(const struct state *, const struct context *,
                     struct state_view *, struct fm_error *);
bool address_equal(struct addr, struct addr);
bool endpoint_equal(struct endpoint, struct endpoint);
unsigned address_flags(const struct context *, struct addr);
bool state_is_icmp(unsigned);
size_t state_tuple(unsigned char *, unsigned, struct endpoint, struct endpoint);
/* Shared logical aggregate identity; never includes a discovered map anchor. */
void state_flow_key(unsigned char [34], struct addr, struct addr);
#endif
