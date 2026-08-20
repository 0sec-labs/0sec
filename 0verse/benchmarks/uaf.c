/* CWE-416: use-after-free. A heap buffer is freed, then used again on an
 * attacker-triggered path. SILENT under the stock allocator; 0verse confirms
 * via the quarantine guard allocator (poison-on-free + mprotect) where the
 * dangling read/write faults (SIGSEGV) while a benign control stays clean.
 * Input: first byte 'X' triggers the UAF. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char *p = malloc(64);
    if (!p) return 1;
    strcpy(p, "session");
    free(p);
    char in[8] = {0};
    int n = read(0, in, 7);
    if (n < 0) n = 0;
    in[n] = 0;
    if (in[0] == 'X') {
        p[0] = 'Z';        /* use-after-free WRITE */
        return p[1];       /* and READ */
    }
    return 0;
}
