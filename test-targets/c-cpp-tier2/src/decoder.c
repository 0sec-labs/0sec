/*
 * SPDX-License-Identifier: MIT
 *
 * Decoder — contains the deliberate integer-truncation flaw that the
 * Tier-2 harness aims to demonstrate. Same shape as the Provos /
 * IronCurtain 18-year-old bug: attacker-controlled count and element
 * size multiplied without overflow check, truncated to a narrower
 * allocator field, then memcpy uses the *logical* size against the
 * shorter buffer.
 */

#include "../include/osec_tier2.h"

#include <stdlib.h>
#include <string.h>

int osec_tier2_decoder_run(const uint8_t *payload, size_t payload_size,
                             uint8_t **out, size_t *out_size) {
  if (payload == NULL || out == NULL || out_size == NULL) return -1;
  if (payload_size < 8) return -1;

  uint32_t count = (uint32_t)payload[0]
                 | ((uint32_t)payload[1] << 8)
                 | ((uint32_t)payload[2] << 16)
                 | ((uint32_t)payload[3] << 24);
  uint32_t element_size = (uint32_t)payload[4]
                        | ((uint32_t)payload[5] << 8)
                        | ((uint32_t)payload[6] << 16)
                        | ((uint32_t)payload[7] << 24);

  /* BUG: unchecked multiplication, truncated to 16 bits for the
   * allocator. A short crafted input lets memcpy write past the heap
   * object. Fix would be __builtin_mul_overflow + a length check
   * against the remaining wire size. */
  size_t copy_size = (size_t)count * (size_t)element_size;
  size_t alloc_size = (uint16_t)(count * element_size);
  size_t available = payload_size - 8;

  if (copy_size > available) return -1;

  uint8_t *buf = (uint8_t *)malloc(alloc_size == 0 ? 1 : alloc_size);
  if (buf == NULL) return -2;

  memcpy(buf, payload + 8, copy_size);
  *out = buf;
  *out_size = copy_size;
  return 0;
}
