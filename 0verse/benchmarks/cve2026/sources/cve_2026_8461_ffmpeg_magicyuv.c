/* Faithful minimal reproducer of CVE-2026-8461 ("PixelSmash") — FFmpeg
 * MagicYUV decoder heap out-of-bounds write (CWE-787).
 *
 * Upstream bug: magy_decode_slice() (libavcodec/magicyuv.c) takes the slice
 * height from the bitstream and converts it to chroma rows with the ceiling
 * right-shift AV_CEIL_RSHIFT(slice_height, vshift). For a 4:2:0 stream an ODD
 * slice_height rounds UP, so the per-slice chroma destination row of the LAST
 * slice lands one row past the chroma plane that was allocated from the floored
 * frame height — a one-row heap out-of-bounds write of attacker pixels.
 * Fix commit (FFmpeg 374b726f / shipped in 8.1.2): reject a slice_height that is
 * misaligned with the chroma vshift, so an odd 4:2:0 slice_height is refused.
 *   https://nvd.nist.gov/vuln/detail/CVE-2026-8461   (published 2026-06-18, post-cutoff)
 *   FFmpeg commit 374b726ffa878ee1cadb987bd1e1e20cc7ed8845
 *     "avcodec/magicyuv: reject slice_height misaligned with chroma vshift"
 *     (Found-by: Ori Hollander, JFrog Vulnerability Research)
 *
 * Faithful standalone EXTRACT (real function name, real AV_CEIL_RSHIFT chroma
 * math, real vshift-alignment fix), NOT the shipping FFmpeg binary.
 * Source = read(2): [u16 slice_height] header, then the slice body.
 *
 * Build:  vuln -> gcc -O0 -fno-stack-protector -no-pie ; fixed -> add -DFIXED
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AV_CEIL_RSHIFT(a, b) (((a) + (1 << (b)) - 1) >> (b))
#define CODED_HEIGHT 32
#define ROW_BYTES    32          /* one chroma row */

/* The real upstream function name. vshift=1 (4:2:0); the chroma plane is sized
 * from the floored coded height, but odd slice heights round up via
 * AV_CEIL_RSHIFT so the last slice's destination row overflows the plane. */
int magy_decode_slice(void)
{
    unsigned char hdr[2] = {0};
    if (read(0, hdr, 2) < 0)
        return 1;
    int slice_height = (int)(hdr[0] | (hdr[1] << 8));
    if (slice_height <= 0 || slice_height > CODED_HEIGHT)
        slice_height = CODED_HEIGHT;

    const int vshift = 1;        /* 4:2:0 vertical chroma subsampling */

#ifdef FIXED
    /* CVE-2026-8461 fix: a slice_height misaligned with the chroma vshift would
     * make AV_CEIL_RSHIFT round up and overflow the plane — reject it. */
    if (slice_height & ((1 << vshift) - 1))
        return 1;
#endif
    /* chroma plane: floor of the coded height (the allocator's view) */
    int plane_rows = AV_CEIL_RSHIFT(CODED_HEIGHT, vshift);  /* 16 rows */
    unsigned char *plane = (unsigned char *)malloc((size_t)plane_rows * ROW_BYTES);
    if (!plane)
        return 1;

    static unsigned char src[ROW_BYTES * 64];
    int sn = read(0, src, sizeof src);
    if (sn < 0)
        sn = 0;

    /* decode each slice into its chroma destination row (the decoder's loop) */
    for (int start = 0; start < CODED_HEIGHT; start += slice_height) {
        int dst_row = AV_CEIL_RSHIFT(start, vshift);                 /* rounds up */
        int rem     = CODED_HEIGHT - start;
        int h       = AV_CEIL_RSHIFT(slice_height < rem ? slice_height : rem, vshift);
        /* the per-row chroma store — OOB when dst_row >= plane_rows */
        for (int r = 0; r < h; r++)
            memcpy(plane + (size_t)(dst_row + r) * ROW_BYTES, src, ROW_BYTES);
    }
    int rv = plane[0];
    free(plane);
    return rv;
}

int main(void)
{
    return magy_decode_slice();
}
