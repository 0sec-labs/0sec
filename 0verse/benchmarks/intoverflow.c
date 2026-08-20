/* CWE-190: integer overflow in a size computation truncates to an undersized
 * allocation, which a full-length copy then overflows. SILENT under the stock
 * allocator; 0verse confirms via the differential-allocator + page-granular
 * quarantine guard (clean under stock, faults under the guard). The size
 * arithmetic `count * elem` feeding malloc/memcpy is the static lens signal.
 * Input: [u16 count][u16 elem] header on stdin, then the body. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    unsigned char hdr[4] = {0};
    if (read(0, hdr, 4) < 0) return 1;
    uint16_t count = (uint16_t)(hdr[0] | (hdr[1] << 8));
    uint16_t elem  = (uint16_t)(hdr[2] | (hdr[3] << 8));
    unsigned short total = (unsigned short)(count * elem);  /* wraps */
    char *p = malloc(total ? total : 1);
    if (!p) return 1;
    static unsigned char body[70000];
    int bn = read(0, body, sizeof body);
    if (bn < 0) bn = 0;
    memcpy(p, body, (size_t)count * elem);   /* writes the REAL size into p */
    return p[0];
}
