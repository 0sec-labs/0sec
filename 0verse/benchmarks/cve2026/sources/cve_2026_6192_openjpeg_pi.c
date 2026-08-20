/* Faithful minimal reproducer of CVE-2026-6192 — OpenJPEG
 * opj_pi_initialise_encode() integer overflow (CWE-190 / CWE-189).
 *
 * Upstream bug: in opj_pi_initialise_encode() (src/lib/openjp2/pi.c) the
 * include-buffer size is computed as `l_tcp->numlayers * l_step_l` in unsigned
 * 32-bit arithmetic with NO overflow check, so a crafted coding-parameter set
 * wraps the product modulo 2^32 to a small value, opj_calloc() under-allocates,
 * and the subsequent fill writes the REAL (un-wrapped) number of entries past
 * the allocation — a heap out-of-bounds write.
 * Fix commit (uclouvain/openjpeg 839936aa): guard the multiply with
 *   `if (l_step_l <= UINT_MAX / l_tcp->numlayers) { ... allocate ... }`.
 *   https://nvd.nist.gov/vuln/detail/CVE-2026-6192   (published 2026-04-13, post-cutoff)
 *   https://github.com/uclouvain/openjpeg/commit/839936aa33eb8899bbbd80fda02796bb65068951
 *
 * Faithful standalone EXTRACT (real function name, real 32-bit numlayers*step_l
 * size wrap, real UINT_MAX/numlayers fix), NOT the shipping OpenJPEG binary.
 * Source = read(2): [u32 numlayers][u32 step_l] header, then the body.
 *
 * Build:  vuln -> gcc -O0 -fno-stack-protector -no-pie ; fixed -> add -DFIXED
 */
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned int rd_u32(const unsigned char *p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8)
         | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/* The real upstream function name. include_size = numlayers * step_l wraps in
 * 32-bit; the fill (memcpy of the true element count) then overflows calloc. */
int opj_pi_initialise_encode(void)
{
    unsigned char hdr[8] = {0};
    if (read(0, hdr, 8) < 0)
        return 1;
    unsigned int numlayers = rd_u32(hdr);
    unsigned int l_step_l  = rd_u32(hdr + 4);
    if (numlayers == 0)
        numlayers = 1;

#ifdef FIXED
    /* CVE-2026-6192 fix: reject when numlayers*step_l would overflow UINT_MAX. */
    if (!(l_step_l <= UINT_MAX / numlayers))
        return 1;
#endif
    /* the SILENT wrap: unsigned 32-bit product feeds the allocation */
    unsigned int include_size = numlayers * l_step_l;          /* wraps mod 2^32 */
    int16_t *include = (int16_t *)calloc(include_size ? include_size : 1,
                                         sizeof(int16_t));
    if (!include)
        return 1;

    static unsigned char body[262144];
    int bn = read(0, body, sizeof body);
    if (bn < 0)
        bn = 0;
    /* writes the REAL element count (numlayers*step_l int16s) into the wrap */
    size_t real_bytes = (size_t)numlayers * (size_t)l_step_l * sizeof(int16_t);
    if (real_bytes > sizeof body)
        real_bytes = sizeof body;
    memcpy(include, body, real_bytes);     /* heap OOB write past the wrapped alloc */
    int r = include[0];
    free(include);
    return r;
}

int main(void)
{
    return opj_pi_initialise_encode();
}
