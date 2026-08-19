## SPDX-License-Identifier: MIT
## Autotools listing for the osec Tier-2 reference target.
## The Tier-2 builder grep-parses this file to discover sibling
## sources for the suspect translation unit.

lib_LTLIBRARIES = libosec_tier2.la

libosec_tier2_la_SOURCES = \
    src/api.c \
    src/frame.c \
    src/decoder.c

libosec_tier2_la_CFLAGS = -Wall -Wextra -I$(top_srcdir)/include
