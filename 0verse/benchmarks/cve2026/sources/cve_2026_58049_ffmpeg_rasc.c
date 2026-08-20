/* Faithful minimal reproducer of CVE-2026-58049 — FFmpeg RASC decoder
 * decode_dlta() heap out-of-bounds write (CWE-787).
 *
 * Upstream bug: decode_dlta() (libavcodec/rasc.c) performs 32-bit reads/writes
 * at the row cursor BEFORE the NEXT_LINE row-boundary check, and validates the
 * DLTA run length in PIXEL units rather than BYTE units. On a PAL8 frame (1
 * byte/pixel) a DLTA run whose pixel count passes the per-row pixel check still
 * writes 4 bytes per step, so 4*count bytes are written past the row buffer — a
 * bitstream-controlled out-of-bounds heap write (+ adjacent OOB read).
 * Fix: validate the DLTA region in byte units and bound the cursor before each
 * 32-bit store.
 *   https://nvd.nist.gov/vuln/detail/CVE-2026-58049  (CVSS 8.6, published 2026-06-27)
 *   https://www.vulncheck.com/advisories/ffmpeg-out-of-bounds-write-in-rasc-decoder-decode-dlta
 *
 * Faithful standalone EXTRACT (real function name, real pixel-vs-byte unit bug,
 * real byte-unit fix), NOT the shipping FFmpeg binary.
 * Source = read(2): [u16 count] DLTA run length, then the run body.
 *
 * Build:  vuln -> gcc -O0 -fno-stack-protector -no-pie ; fixed -> add -DFIXED
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROW_BYTES 256        /* one PAL8 row: 256 pixels = 256 bytes */

/* The real upstream function name. The 32-bit store at `row + cursor` advances
 * the cursor 4 bytes per pixel-step while the run length is checked in pixels. */
int decode_dlta(void)
{
    unsigned char hdr[2] = {0};
    if (read(0, hdr, 2) < 0)
        return 1;
    int count = (int)(hdr[0] | (hdr[1] << 8));   /* DLTA run length (pixels) */
    if (count <= 0)
        count = 1;

    unsigned char *row = (unsigned char *)malloc(ROW_BYTES);
    if (!row)
        return 1;

    static unsigned char body[65536];
    int bn = read(0, body, sizeof body);
    if (bn < 0)
        bn = 0;

#ifdef FIXED
    /* CVE-2026-58049 fix: validate the run in BYTE units (4 bytes per 32-bit
     * store), not pixels, before writing. */
    if ((size_t)count * 4 > ROW_BYTES) {
        free(row);
        return 1;
    }
#else
    /* the bug: run length validated in PIXEL units against the row width */
    if (count > ROW_BYTES)
        count = ROW_BYTES;
#endif
    int cursor = 0;
    for (int i = 0; i < count; i++) {
        /* 32-bit store at the row cursor — happens BEFORE any boundary check */
        memcpy(row + cursor, body + (size_t)i * 4, 4);   /* OOB once cursor >= ROW_BYTES */
        cursor += 4;
    }
    int rv = row[0];
    free(row);
    return rv;
}

int main(void)
{
    return decode_dlta();
}
