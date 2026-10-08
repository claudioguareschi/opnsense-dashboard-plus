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


#include "json.h"
#include "alloc.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

struct json_document {
  struct json *nodes;
  size_t used;
  char *strings; /* every string and key, NUL-terminated, packed */
  size_t strings_used, strings_capacity;
  struct json *root;
};
struct parser {
  struct json_document *d;
  const char *p, *end;
  struct fm_error *error;
};

static bool fail(struct parser *ps, const char *message) {
  return fm_error_fail(ps->error, FM_FAILURE_REQUEST, EINVAL, message);
}
static void blank(struct parser *ps) {
  while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
    ps->p++;
}
static struct json *node(struct parser *ps) {
  if (ps->d->used >= JSON_MAX_NODES) {
    fail(ps, "JSON too large");
    return NULL;
  }
  struct json *n = &ps->d->nodes[ps->d->used++];
  memset(n, 0, sizeof(*n));
  return n;
}
/* A string token, stored in the document; returns its text or NULL. */
static const char *string(struct parser *ps) {
  if (ps->p >= ps->end || *ps->p != '"') return fail(ps, "JSON string expected"), NULL;
  ps->p++;
  char buffer[JSON_MAX_STRING + 1];
  size_t length = 0;
  for (;;) {
    if (ps->p >= ps->end) return fail(ps, "JSON string not terminated"), NULL;
    unsigned char c = (unsigned char)*ps->p++;
    if (c == '"') break;
    if (c < 0x20 || c > 0x7e) return fail(ps, "JSON string character"), NULL;
    if (c == '\\') {
      if (ps->p >= ps->end) return fail(ps, "JSON string escape"), NULL;
      c = (unsigned char)*ps->p++;
      if (c != '"' && c != '\\' && c != '/') return fail(ps, "JSON string escape"), NULL;
    }
    if (length >= JSON_MAX_STRING) return fail(ps, "JSON string too long"), NULL;
    buffer[length++] = (char)c;
  }
  buffer[length] = 0;
  struct json_document *d = ps->d;
  if (d->strings_used + length + 1 > d->strings_capacity) return fail(ps, "JSON too large"), NULL;
  char *stored = d->strings + d->strings_used;
  memcpy(stored, buffer, length + 1);
  d->strings_used += length + 1;
  return stored;
}
static bool literal(struct parser *ps, const char *word) {
  size_t length = strlen(word);
  if ((size_t)(ps->end - ps->p) < length || memcmp(ps->p, word, length)) return fail(ps, "JSON value");
  ps->p += length;
  return true;
}
/* RFC 8259 number grammar, then strtod on a bounded copy. */
static bool number(struct parser *ps, double *out) {
  const char *start = ps->p;
  if (ps->p < ps->end && *ps->p == '-') ps->p++;
  if (ps->p >= ps->end) return fail(ps, "JSON number");
  if (*ps->p == '0') ps->p++;
  else if (*ps->p >= '1' && *ps->p <= '9')
    while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
  else return fail(ps, "JSON number");
  if (ps->p < ps->end && *ps->p == '.') {
    ps->p++;
    if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') return fail(ps, "JSON number");
    while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
  }
  if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
    ps->p++;
    if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
    if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') return fail(ps, "JSON number");
    while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
  }
  char copy[64];
  size_t length = (size_t)(ps->p - start);
  if (length >= sizeof(copy)) return fail(ps, "JSON number too long");
  memcpy(copy, start, length);
  copy[length] = 0;
  *out = strtod(copy, NULL);
  return isfinite(*out) || fail(ps, "JSON number out of range");
}
static struct json *value(struct parser *ps, unsigned depth);
static bool members(struct parser *ps, struct json *n, unsigned depth, bool object) {
  char close = object ? '}' : ']';
  ps->p++;
  blank(ps);
  struct json *last = NULL;
  if (ps->p < ps->end && *ps->p == close) {
    ps->p++;
    return true;
  }
  for (;;) {
    const char *key = NULL;
    if (object) {
      blank(ps);
      if (!(key = string(ps))) return false;
      for (const struct json *m = n->child; m; m = m->next)
        if (!strcmp(m->key, key)) return fail(ps, "JSON duplicate key");
      blank(ps);
      if (ps->p >= ps->end || *ps->p++ != ':') return fail(ps, "JSON ':' expected");
    }
    struct json *child = value(ps, depth + 1);
    if (!child) return false;
    child->key = key;
    if (last) last->next = child;
    else n->child = child;
    last = child;
    n->count++;
    blank(ps);
    if (ps->p < ps->end && *ps->p == ',') {
      ps->p++;
      continue;
    }
    if (ps->p < ps->end && *ps->p == close) {
      ps->p++;
      return true;
    }
    return fail(ps, object ? "JSON ',' or '}' expected" : "JSON ',' or ']' expected");
  }
}
static struct json *value(struct parser *ps, unsigned depth) {
  if (depth > JSON_MAX_DEPTH) return fail(ps, "JSON nested too deeply"), NULL;
  blank(ps);
  if (ps->p >= ps->end) return fail(ps, "JSON value expected"), NULL;
  struct json *n = node(ps);
  if (!n) return NULL;
  switch (*ps->p) {
  case '{':
    n->type = JSON_OBJECT;
    return members(ps, n, depth, true) ? n : NULL;
  case '[':
    n->type = JSON_ARRAY;
    return members(ps, n, depth, false) ? n : NULL;
  case '"':
    n->type = JSON_STRING;
    return (n->string = string(ps)) ? n : NULL;
  case 't':
    n->type = JSON_BOOL;
    n->boolean = 1;
    return literal(ps, "true") ? n : NULL;
  case 'f':
    n->type = JSON_BOOL;
    return literal(ps, "false") ? n : NULL;
  case 'n':
    n->type = JSON_NULL;
    return literal(ps, "null") ? n : NULL;
  default:
    n->type = JSON_NUMBER;
    return number(ps, &n->number) ? n : NULL;
  }
}

struct json_document *json_parse(const char *text, size_t length, struct fm_error *error) {
  struct json_document *d = fm_calloc(1, sizeof(*d));
  if (d) {
    d->nodes = fm_calloc(JSON_MAX_NODES, sizeof(*d->nodes));
    d->strings_capacity = length + 1;
    d->strings = fm_calloc(d->strings_capacity, 1);
  }
  if (!d || !d->nodes || !d->strings) {
    fm_error_set(error, ENOMEM, "JSON allocation");
    json_free(d);
    return NULL;
  }
  struct parser ps = {d, text, text + length, error};
  d->root = value(&ps, 0);
  if (d->root) {
    blank(&ps);
    if (ps.p != ps.end) {
      fail(&ps, "JSON trailing data");
      d->root = NULL;
    }
  }
  if (!d->root) {
    json_free(d);
    return NULL;
  }
  return d;
}
const struct json *json_root(const struct json_document *d) { return d->root; }
void json_free(struct json_document *d) {
  if (!d) return;
  fm_free(d->nodes);
  fm_free(d->strings);
  fm_free(d);
}
const struct json *json_member(const struct json *object, const char *key) {
  if (!object || object->type != JSON_OBJECT) return NULL;
  for (const struct json *m = object->child; m; m = m->next)
    if (!strcmp(m->key, key)) return m;
  return NULL;
}
