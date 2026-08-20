/* CWE-122: unbounded copy of attacker-controlled input into a small HEAP buffer.
 * The overflow is SILENT under the stock allocator (no free(), modest spill) —
 * the classic "invisible without instrumentation" heap bug. 0verse confirms it
 * via the differential-allocator oracle: clean under stock, faults under the
 * Electric-Fence guard page (clean -> crash = real heap OOB write), pinned to
 * the offending instruction. Expect: read -> strcpy confirmed. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char *buf = malloc(16);
    char in[256] = {0};
    if (!buf) return 1;
    int n = read(0, in, 255);
    if (n >= 0) in[n] = 0;
    strcpy(buf, in);   /* heap overflow when input > 16 bytes */
    return 0;          /* no free(): stock glibc never notices */
}
