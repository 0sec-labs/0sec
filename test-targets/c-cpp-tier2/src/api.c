/*
 * SPDX-License-Identifier: MIT
 *
 * Top-level API for the Tier-2 reference library. Drives frame parsing
 * and then invokes the decoder. Public callers should never touch
 * `pwnkit_tier2_decoder_run` directly — Tier-2 proves the bug is
 * reachable from this entry point.
 */

#include "../include/pwnkit_tier2.h"

#include <stdlib.h>

int pwnkit_tier2_decode(const uint8_t *data, size_t size,
                        uint8_t **out, size_t *out_size) {
  if (out == NULL || out_size == NULL) return -1;
  *out = NULL;
  *out_size = 0;

  const uint8_t *payload = NULL;
  size_t payload_size = 0;
  int rc = pwnkit_tier2_frame_parse(data, size, &payload, &payload_size);
  if (rc != 0) return rc;

  return pwnkit_tier2_decoder_run(payload, payload_size, out, out_size);
}
