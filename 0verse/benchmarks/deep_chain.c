/* 0verse M7 directed-fuzzing benchmark target — a DEEP / GATED bug.
 *
 * The overflow sits behind THREE stacked gates:
 *   gate 1  — a 4-byte string magic   ("DEEP")        cracked by the mined dict
 *   gate 2  — a 32-bit constant        (0xC0FFEE00)    cracked by CMPLOG/redqueen
 *   gate 3  — a COMPUTED 64-bit ARX checksum (xor / ROTATE / add) over 8 bytes
 *             that must equal a fixed 64-bit constant. This is the load-bearing
 *             gate. Two properties put it beyond the coverage lane but inside
 *             angr's reach:
 *               * the bit ROTATION composition is outside AFL++ CMPLOG's
 *                 arithmetic-transform (CMPLOG cracks polynomial multiply/add
 *                 hashes, and even a 32-bit ARX, but not this), and
 *               * the comparison is 64-bit, so blind/heuristic search is ~2^-64.
 *             Measured: the CMPLOG+dictionary lane makes ZERO progress past this
 *             gate (0 crashes, corpus stalls at 4 in 30 s). angr models xor/
 *             rotate/add as ordinary bitvector ops and finds a preimage in ~1 s —
 *             which is exactly what the #41 DistanceDriller drives on a distance
 *             plateau toward the sink.
 *
 * The constant 0x86c070e7fdf9e92b is a reachable ARX-hash value (a satisfying
 * 8-byte preimage exists and was checked offline) — deliberately NOT spelled out
 * here as a quoted literal, so the slice-mined dictionary cannot leak the answer;
 * the only legitimately recoverable string token is the gate-1 magic. Past gate 3
 * a length byte (disjoint from the checksum bytes, so the fuzzer can mutate it
 * freely) walks a hand-rolled copy loop off the end of a 16-byte HEAP buffer — a
 * SILENT overflow the differential-allocator oracle turns into a deterministic,
 * instruction-pinned crash. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DEEP_HASH_K 0x86c070e7fdf9e92bULL

int parse_deep_chain(const unsigned char *data, int len) {
    if (len < 17) return -1;
    if (memcmp(data, "DEEP", 4) != 0) return -1;            /* gate 1: string magic */
    uint32_t key;
    memcpy(&key, data + 4, 4);
    if (key != 0xC0FFEE00u) return -1;                      /* gate 2: 32-bit constant */
    uint64_t c = 0xcbf29ce484222325ULL;                     /* gate 3: 64-bit ARX hash */
    for (int i = 8; i < 16; i++) {
        c ^= data[i];
        c = (c << 27) | (c >> 37);                          /* ROTATE — defeats CMPLOG */
        c += 0x9e3779b97f4a7c15ULL;
    }
    if (c != DEEP_HASH_K) return -1;                        /* CMPLOG-proof checksum */
    int n = data[16];
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    int i;
    for (i = 0; i < n && (17 + i) < len; i++)
        buf[i] = (char)data[17 + i];                        /* heap OOB write when n >= 16 */
    free(buf);
    return i;
}
