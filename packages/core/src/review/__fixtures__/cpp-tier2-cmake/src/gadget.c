/* SPDX-License-Identifier: MIT */
#include "../include/gadget.h"
int gadget_decode(const uint8_t *data, size_t size) {
  if (!data) return -1;
  return gadget_util(data, size);
}
