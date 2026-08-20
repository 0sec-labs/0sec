/* CLEAN / known-good — looks like intoverflow.c (a `count * elem` multiply feeds
 * malloc + memcpy, so the #22 integer-overflow LENS fires a hypothesis) but is
 * SAFE: the operands are bounded before the multiply and the copy is clamped to
 * the allocation. No PoV exists. A good false-positive probe: the static lens
 * surfaces a lead, the oracle must NOT confirm, and a real model should judge the
 * guarded path is_real=false. Input: [u16 count][u16 elem] header, then body. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    unsigned char hdr[4] = {0};
    if (read(0, hdr, 4) < 0) return 1;
    uint32_t count = (uint32_t)(hdr[0] | (hdr[1] << 8));
    uint32_t elem  = (uint32_t)(hdr[2] | (hdr[3] << 8));
    if (count > 1024 || elem > 64) return 1;       /* bound BEFORE the multiply */
    size_t total = (size_t)count * elem;           /* widened: cannot wrap */
    char *p = malloc(total ? total : 1);
    if (!p) return 1;
    static unsigned char body[70000];
    int bn = read(0, body, sizeof body);
    if (bn < 0) bn = 0;
    size_t cp = total < (size_t)bn ? total : (size_t)bn;  /* clamp to alloc */
    memcpy(p, body, cp);
    int r = p[0];
    free(p);
    return r;
}
