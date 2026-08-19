/* SPDX-License-Identifier: MIT
 * Suspect translation unit — Tier-2 should pick up `helper.c` as a
 * sibling source via both same-directory walk and Makefile.am
 * augmentation. */
#include "../include/widget.h"
#include "helper.h"
#include <stdlib.h>

int widget_decode(const uint8_t *data, size_t size,
                  uint8_t **out, size_t *out_size) {
  if (!out || !out_size) return -1;
  *out = NULL; *out_size = 0;
  if (widget_helper(data, size) != 0) return -1;
  uint8_t *buf = (uint8_t *)malloc(size);
  if (!buf) return -2;
  for (size_t i = 0; i < size; i++) buf[i] = data[i];
  *out = buf; *out_size = size;
  return 0;
}
