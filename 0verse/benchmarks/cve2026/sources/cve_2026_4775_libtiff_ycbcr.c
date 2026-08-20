/* Faithful minimal reproducer of CVE-2026-4775 — libtiff
 * putcontig8bitYCbCr44tile() signed integer overflow (CWE-190 -> OOB write).
 *
 * Upstream bug: in putcontig8bitYCbCr44tile() (libtiff tif_getimage.c) the
 * per-row pointer-progression `incr` is computed in 32-bit *signed* int from an
 * attacker-controlled image width. A very large width overflows `incr` to a
 * negative value, which slips past the upper-bound check and is then used as an
 * (unsigned) store length, so the YCbCr 4:4 tile store writes far past the heap
 * raster — DoS or arbitrary code execution.
 * Fix: compute the progression / length in a width-safe (size_t) type so the
 * multiply cannot wrap and the bound check sees the true value.
 *   https://nvd.nist.gov/vuln/detail/CVE-2026-4775   (CVSS 7.8, published 2026-03-24)
 *   Red Hat: https://access.redhat.com/security/cve/CVE-2026-4775
 *
 * Faithful standalone EXTRACT (real function name, real signed-int progression
 * overflow, real size_t fix), NOT the shipping libtiff binary.
 * Source = read(2): [u32 width] header, then the body.
 *
 * Build:  vuln -> gcc -O0 -fno-stack-protector -no-pie ; fixed -> add -DFIXED
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RASTER_BYTES 4096   /* the heap raster the tile is composited into */

/* The real upstream function name. `incr` (32-bit signed) is the row-store
 * progression; a huge width wraps it negative, the bound check passes, and the
 * 4:4:4 store walks off the raster. */
int putcontig8bitYCbCr44tile(void)
{
    unsigned char hdr[4] = {0};
    if (read(0, hdr, 4) < 0)
        return 1;
    uint32_t w = (uint32_t)(hdr[0] | (hdr[1] << 8) | (hdr[2] << 16) | (hdr[3] << 24));

    unsigned char *raster = (unsigned char *)malloc(RASTER_BYTES);
    if (!raster)
        return 1;

    static unsigned char body[262144];
    int bn = read(0, body, sizeof body);
    if (bn < 0)
        bn = 0;

#ifdef FIXED
    /* CVE-2026-4775 fix: width-safe size_t arithmetic; the bound sees the real
     * value, so a large width is clamped instead of wrapping. */
    size_t incr = (size_t)4 * (size_t)w;     /* 4 components / YCbCr 4:4 group */
    if (incr > RASTER_BYTES)
        incr = RASTER_BYTES;
    size_t n = incr;
#else
    int incr = 4 * (int)w;                    /* signed 32-bit: wraps NEGATIVE */
    if (incr > RASTER_BYTES)                  /* a negative incr slips this guard */
        incr = RASTER_BYTES;
    size_t n = (size_t)incr;                  /* negative -> enormous size_t */
    if (n > sizeof body)
        n = sizeof body;                      /* still far larger than RASTER_BYTES */
#endif
    memcpy(raster, body, n);                  /* heap OOB write when incr wrapped */
    int r = raster[0];
    free(raster);
    return r;
}

int main(void)
{
    return putcontig8bitYCbCr44tile();
}
