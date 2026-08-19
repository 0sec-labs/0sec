/* SPDX-License-Identifier: MIT */
#ifndef WIDGET_H
#define WIDGET_H
#include <stddef.h>
#include <stdint.h>
int widget_decode(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);
int widget_helper(const uint8_t *data, size_t size);
#endif
