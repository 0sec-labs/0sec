/* 0verse M2 benchmark — a bug the STATIC SLICE MISSES but FUZZING CATCHES.
 *
 * `parse_record` copies an attacker-controlled, length-prefixed record into a
 * fixed 32-byte HEAP buffer with a HAND-ROLLED byte-copy loop, behind a 4-byte
 * magic-header gate ("REC0").
 *
 * Why the M1 #2 source->sink slicer finds NOTHING here:
 *   - the only calls in the function are memcmp / malloc / printf / free — none
 *     are taint SINKS (no strcpy/memcpy/sprintf/system),
 *   - there is no recognized taint SOURCE (read/recv/fgets/getenv/argv) inside
 *     the function — input arrives as a plain (buf, len) parameter,
 *   - the overflow is a manual `for` loop, invisible to sink-pattern matching.
 * So slice-then-intersect yields zero candidates: a true negative for the static
 * lane, a true positive for fuzzing.
 *
 * Why fuzzing catches it: the #16-synthesized harness drives `parse_record` from
 * stdin; AFL++ CMPLOG/redqueen cracks the "REC0" gate in milliseconds, then a
 * length byte >= 32 walks the copy loop off the end of the heap buffer. The
 * overflow is SILENT under the stock allocator; the differential-allocator oracle
 * (Electric Fence guard page) turns it into a deterministic, instruction-pinned
 * crash (clean -> crash == real heap OOB write). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_record(const unsigned char *data, int len) {
    if (len < 6) return -1;
    if (memcmp(data, "REC0", 4) != 0) return -1;   /* magic-header gate */
    int n = data[4];                                 /* attacker length 0..255 */
    char *name = (char *)malloc(32);                 /* fixed 32-byte heap buffer */
    if (!name) return -1;
    int i;
    for (i = 0; i <= n && (5 + i) < len; i++)
        name[i] = (char)data[5 + i];                 /* heap OOB write when n >= 32 */
    printf("parsed %d bytes\n", i);
    free(name);
    return n;
}
