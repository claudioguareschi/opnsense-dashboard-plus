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

/* Replays fuzz inputs through a libFuzzer target without libFuzzer: each
 * argument is a file (one input) or a directory (every regular file in it,
 * in name order). Linked with fuzz_netlink.c or fuzz_state.c and sanitizers,
 * it is the regression run of the inputs kept under devel/fuzz/regressions/
 * (tests/test_collector_fuzz_regressions.py). Prints the count replayed. */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);

static int replay_file(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  unsigned char *data = NULL;
  size_t size = 0, cap = 0;
  for (;;) {
    if (size == cap) {
      unsigned char *grown = realloc(data, cap = cap ? cap * 2 : 4096);
      if (!grown) {
        free(data);
        fclose(f);
        return -1;
      }
      data = grown;
    }
    size_t n = fread(data + size, 1, cap - size, f);
    size += n;
    if (n == 0) break;
  }
  fclose(f);
  LLVMFuzzerTestOneInput(data, size);
  free(data);
  return 0;
}

static int by_name(const struct dirent **a, const struct dirent **b) { return strcmp((*a)->d_name, (*b)->d_name); }

int main(int argc, char **argv) {
  unsigned long replayed = 0;
  for (int i = 1; i < argc; i++) {
    struct stat st;
    if (stat(argv[i], &st)) {
      perror(argv[i]);
      return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
      if (replay_file(argv[i])) return 1;
      replayed++;
      continue;
    }
    struct dirent **names;
    int count = scandir(argv[i], &names, NULL, by_name);
    if (count < 0) {
      perror(argv[i]);
      return 1;
    }
    for (int k = 0; k < count; k++) {
      char path[4096];
      snprintf(path, sizeof(path), "%s/%s", argv[i], names[k]->d_name);
      if (!stat(path, &st) && S_ISREG(st.st_mode)) {
        if (replay_file(path)) return 1;
        replayed++;
      }
      free(names[k]);
    }
    free(names);
  }
  printf("replayed %lu\n", replayed);
  return 0;
}
