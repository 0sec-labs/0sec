/* SPDX-License-Identifier: MIT */
#ifndef GADGET_H
#define GADGET_H
#include <stddef.h>
#include <stdint.h>
int gadget_decode(const uint8_t *data, size_t size);
int gadget_util(const uint8_t *data, size_t size);
#endif
