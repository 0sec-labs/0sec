/*
 * SPDX-License-Identifier: MIT
 *
 * Frame header parser. Trivial — strips a 4-byte magic prefix and
 * hands the rest to the decoder. The point of having this layer is to
 * mediate reachability of the decoder from the public API so Tier-1
 * (single-function) harnessing of `osec_tier2_decoder_run` proves
 * the primitive but Tier-2 has to prove the magic check doesn't filter
 * the trigger out.
 */

#include "../include/osec_tier2.h"

static const uint8_t FRAME_MAGIC[4] = {0x50, 0x57, 0x4e, 0x32}; /* "PWN2" */

int osec_tier2_frame_parse(const uint8_t *data, size_t size,
                             const uint8_t **payload, size_t *payload_size) {
  if (data == NULL || payload == NULL || payload_size == NULL) return -1;
  if (size < 4) return -1;
  for (size_t i = 0; i < 4; i++) {
    if (data[i] != FRAME_MAGIC[i]) return -2;
  }
  *payload = data + 4;
  *payload_size = size - 4;
  return 0;
}
