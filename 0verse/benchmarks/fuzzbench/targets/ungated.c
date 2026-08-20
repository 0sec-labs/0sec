/* 0verse M6 benchmark target — UNGATED heap overflow (expected TIE).
 *
 * No magic gate: any input >= 16 bytes overflows a 16-byte HEAP buffer via a
 * hand-rolled copy loop. Both plain AFL++ and the 0verse lane should crash this
 * almost immediately: the honest control where 0verse does NOT win. The heap
 * buffer makes the silent OOB confirmable by the differential-allocator oracle
 * (guard page) just like the rest of the corpus. */
#include <stdint.h>
#include <stdlib.h>

int crash_ungated(const unsigned char *data, int len) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    int i;
    for (i = 0; i < len; i++)
        buf[i] = (char)data[i];   /* heap OOB write once len > 16 */
    int r = buf[0];
    free(buf);
    return r;
}
