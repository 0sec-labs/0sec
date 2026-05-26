/* SPDX-License-Identifier: MIT */
#ifndef SPROCKET_H
#define SPROCKET_H
#include <stddef.h>
#include <stdint.h>
int sprocket_decode(const uint8_t *data, size_t size);
int sprocket_aux(const uint8_t *data, size_t size);
#endif
