/*
 * SPDX-License-Identifier: MIT
 *
 * osec Tier-2 reference target — public API.
 *
 * A deliberately vulnerable mini-library shaped like the
 * integer-truncation-on-allocation primitive that Provos / IronCurtain
 * highlighted as the missing-tier-2-harness motivating example. The
 * primitive lives inside `decoder.c`, but `api.c` and `frame.c` mediate
 * reaching it from the public surface, which is exactly why Tier-2
 * (multi-component linking) is the right harness tier for this shape.
 */

#ifndef OSEC_TIER2_H
#define OSEC_TIER2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Public entry point. Wraps the lower-level frame + decoder layers. */
int osec_tier2_decode(const uint8_t *data, size_t size,
                        uint8_t **out, size_t *out_size);

/* Internal layer 1: validates the frame header and strips it. */
int osec_tier2_frame_parse(const uint8_t *data, size_t size,
                             const uint8_t **payload, size_t *payload_size);

/* Internal layer 2: the actual decode + allocation step (the bug
 * lives here). Exposed for Tier-2 single-function harnessing. */
int osec_tier2_decoder_run(const uint8_t *payload, size_t payload_size,
                             uint8_t **out, size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* OSEC_TIER2_H */
