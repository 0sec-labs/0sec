/* Synthetic vulnerable library — pwnkit C/C++ review profile fixture.
 *
 * This is a deliberate, contrived target used by review-profile tests
 * and demos. Do NOT use this code anywhere. The bugs are intentional.
 */

#ifndef PWNKIT_DEMO_DECODER_H
#define PWNKIT_DEMO_DECODER_H

#include <stddef.h>
#include <stdint.h>

/* Decode a length-prefixed payload.
 *
 * Wire format (little-endian):
 *   uint32_t count;
 *   uint32_t element_size;
 *   uint8_t  payload[count * element_size];
 *
 * Returns 0 on success, -1 on malformed input, -2 on allocation failure.
 *
 * The caller owns the returned buffer (via *out) and must free() it.
 */
int decode_payload(const uint8_t *data, size_t size,
                   uint8_t **out, size_t *out_size);

#endif
