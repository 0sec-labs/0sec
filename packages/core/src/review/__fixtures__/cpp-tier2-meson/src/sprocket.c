/* SPDX-License-Identifier: MIT */
#include "../include/sprocket.h"
int sprocket_decode(const uint8_t *data, size_t size) {
  if (!data) return -1;
  return sprocket_aux(data, size);
}
