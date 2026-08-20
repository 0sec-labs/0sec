/* 0verse M6 benchmark target — single 4-byte magic gate (expected 0verse win).
 *
 * The overflow is reachable only behind a REC0 magic-header check. Plain AFL++
 * with a single 0x00 seed and no dictionary must brute-force 4 bytes of header by
 * coverage alone; the 0verse lane mines the REC0 token from the (decompiled)
 * slice into its dictionary AND runs CMPLOG/redqueen, cracking the gate in ms.
 * The HEAP buffer makes the OOB confirmable by the differential-allocator oracle. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int parse_gated(const unsigned char *data, int len) {
    if (len < 6) return -1;
    if (memcmp(data, "REC0", 4) != 0) return -1;   /* magic-header gate */
    int n = data[4];
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    int i;
    for (i = 0; i < n && (5 + i) < len; i++)
        buf[i] = (char)data[5 + i];                 /* heap OOB write when n >= 16 */
    free(buf);
    return i;
}
