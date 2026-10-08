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


#ifndef FM_JSON_H
#define FM_JSON_H
#include "error.h"
#include <stddef.h>

/* A strict, bounded JSON reader for the collector's startup configuration
 * only (never on a sample path): RFC 8259 values, no duplicate object keys,
 * at most JSON_MAX_DEPTH levels and JSON_MAX_NODES values; strings are
 * plain ASCII without escapes other than \" \\ \/ (configuration keys,
 * UUIDs, names, CIDRs). */
#define JSON_MAX_DEPTH 8
#define JSON_MAX_NODES 50000
#define JSON_MAX_STRING 256
enum json_type { JSON_NULL, JSON_BOOL, JSON_NUMBER, JSON_STRING, JSON_ARRAY, JSON_OBJECT };
struct json {
  enum json_type type;
  const char *key;        /* member name inside an object, else NULL */
  const char *string;     /* JSON_STRING */
  double number;          /* JSON_NUMBER */
  int boolean;            /* JSON_BOOL */
  struct json *child;     /* first element or member */
  struct json *next;      /* next sibling */
  size_t count;           /* elements or members */
};
struct json_document;
/* Parses text; NULL with a message in error (FM_FAILURE_REQUEST) when it is
 * not one valid value within the bounds. */
struct json_document *json_parse(const char *text, size_t length, struct fm_error *);
const struct json *json_root(const struct json_document *);
void json_free(struct json_document *);
/* The member named key, or NULL. */
const struct json *json_member(const struct json *object, const char *key);
#endif
