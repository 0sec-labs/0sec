/* Faithful minimal reproducer of CVE-2026-32740 — libheif grid-tile compositing
 * heap out-of-bounds write (CWE-787).
 *
 * Upstream bug: HeifPixelImage::copy_image_to() (libheif/pixelimage.cc) computes
 * the destination chroma-plane row offset and the copy height INDEPENDENTLY with
 * integer ceiling division for 4:2:0 subsampling. For a 1xN grid of ODD-height
 * tiles the rounded offset `ys` plus the rounded `copy_height` can exceed the
 * allocated chroma plane by one row, so the per-tile memcpy writes one full
 * chroma row (the disclosed 64 bytes = 32 bytes x 2 chroma planes) past the
 * allocation.
 * Fix (libheif 1.22.0): bound the copy so `ys + copy_height` never exceeds the
 * chroma plane height.
 *   https://nvd.nist.gov/vuln/detail/CVE-2026-32740  (published 2026-05-19, post-cutoff)
 *   https://github.com/strukturag/libheif/security/advisories/GHSA-frfr-f3vg-2g6j
 *   Fixed in https://github.com/strukturag/libheif/releases/tag/v1.22.0
 *
 * Faithful standalone EXTRACT (real function name, real ceil-div chroma offset
 * vs height mismatch, real ys+copy_height bound), NOT the shipping libheif
 * binary (originally C++ pixelimage.cc; extracted as C).
 * Source = read(2): [u16 tile_h] odd tile height, then the tile body.
 *
 * Build:  vuln -> gcc -O0 -fno-stack-protector -no-pie ; fixed -> add -DFIXED
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROW_BYTES 32                 /* one chroma row */
#define CEIL2(x)  (((x) + 1) >> 1)   /* ceil(x/2): 4:2:0 chroma subsampling */

/* The real upstream function name. A 1x4 grid of odd-height tiles makes the
 * ceil-rounded ys + copy_height of the last tile exceed the chroma plane. */
int copy_image_to(void)
{
    unsigned char hdr[2] = {0};
    if (read(0, hdr, 2) < 0)
        return 1;
    int tile_h = (int)(hdr[0] | (hdr[1] << 8));
    if (tile_h <= 0 || tile_h > 200)
        tile_h = 65;                 /* odd height triggers the rounding mismatch */

    const int ntiles  = 4;           /* 1x4 grid */
    int canvas_h      = ntiles * tile_h;
    int plane_h       = CEIL2(canvas_h);          /* chroma plane rows (floor view) */
    unsigned char *plane = (unsigned char *)malloc((size_t)plane_h * ROW_BYTES);
    if (!plane)
        return 1;

    static unsigned char src[256 * ROW_BYTES];
    int sn = read(0, src, sizeof src);
    if (sn < 0)
        sn = 0;

    for (int t = 0; t < ntiles; t++) {
        int y0          = t * tile_h;
        int ys          = CEIL2(y0);              /* dest chroma offset (ceil) */
        int copy_height = CEIL2(tile_h);          /* copy height (ceil, independent) */
#ifdef FIXED
        /* CVE-2026-32740 fix: never copy past the chroma plane. */
        if (ys + copy_height > plane_h)
            copy_height = plane_h - ys;
        if (copy_height < 0)
            copy_height = 0;
#endif
        /* the per-tile chroma store — OOB when ys + copy_height > plane_h */
        for (int r = 0; r < copy_height; r++)
            memcpy(plane + (size_t)(ys + r) * ROW_BYTES, src, ROW_BYTES);
    }
    int rv = plane[0];
    free(plane);
    return rv;
}

int main(void)
{
    return copy_image_to();
}
