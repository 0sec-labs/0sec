/* Synthetic vulnerable library — 0sec C/C++ review profile fixture.
 *
 * Deliberately vulnerable. The bug here is the same shape as the
 * 18-year-old integer-truncation flaw in the Provos / IronCurtain post:
 * arithmetic on attacker-controlled lengths feeds an allocation, and
 * the multiplication is unchecked. A tier-1 libFuzzer harness against
 * `decode_payload` should trip ASan within seconds.
 */

#include "../include/decoder.h"
#include <stdlib.h>
#include <string.h>

int decode_payload(const uint8_t *data, size_t size,
                   uint8_t **out, size_t *out_size) {
  if (data == NULL || out == NULL || out_size == NULL) return -1;
  if (size < 8) return -1;

  uint32_t count = (uint32_t)data[0]
                 | ((uint32_t)data[1] << 8)
                 | ((uint32_t)data[2] << 16)
                 | ((uint32_t)data[3] << 24);
  uint32_t element_size = (uint32_t)data[4]
                        | ((uint32_t)data[5] << 8)
                        | ((uint32_t)data[6] << 16)
                        | ((uint32_t)data[7] << 24);

  /* BUG: unchecked multiplication truncates to the allocator's 16-bit
   * bookkeeping field, returning a tiny allocation that the subsequent
   * memcpy then overflows. The fix would be a checked-mul (e.g.
   * __builtin_mul_overflow) followed by a length validation against the
   * remaining wire size. */
  size_t copy_size = (size_t)count * (size_t)element_size;
  size_t alloc_size = (uint16_t)(count * element_size);
  size_t available = size - 8;

  /* BUG (compounding): the bound check uses the logical copy size, but
   * allocation uses the truncated allocator size. A short crafted input
   * can therefore make memcpy write past the heap object on any host
   * architecture, not only 32-bit targets. */
  if (copy_size > available) return -1;

  uint8_t *buf = (uint8_t *)malloc(alloc_size == 0 ? 1 : alloc_size);
  if (buf == NULL) return -2;

  memcpy(buf, data + 8, copy_size);
  *out = buf;
  *out_size = copy_size;
  return 0;
}
