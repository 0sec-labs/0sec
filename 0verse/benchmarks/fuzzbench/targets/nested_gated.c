/* 0verse M6 benchmark target — nested gate: 4-byte magic + a 32-bit constant
 * compare (expected larger 0verse win / baseline timeout).
 *
 * Two sequential gates guard the overflow: a FMW1 header, then a 32-bit field
 * that must equal 0xCAFEBABE. The string gate is cracked by the mined dictionary;
 * the integer gate is cracked by CMPLOG/redqueen comparison-unrolling. Plain
 * AFL++ with neither has to luck into ~2^32 for the second gate, typically a
 * timeout inside a short budget. The HEAP buffer makes the OOB oracle-confirmable. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int parse_nested(const unsigned char *data, int len) {
    if (len < 12) return -1;
    if (memcmp(data, "FMW1", 4) != 0) return -1;        /* gate 1: string magic */
    uint32_t key;
    memcpy(&key, data + 4, 4);
    if (key != 0xCAFEBABEu) return -1;                  /* gate 2: 32-bit constant */
    int n = data[8];
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    int i;
    for (i = 0; i < n && (9 + i) < len; i++)
        buf[i] = (char)data[9 + i];                     /* heap OOB write when n >= 16 */
    free(buf);
    return i;
}
