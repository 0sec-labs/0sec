/* CWE-415: double-free on an attacker-triggered path. 0verse confirms via the
 * quarantine guard allocator, which traps the second free of a quarantined
 * pointer; a benign control stays clean. Input: first byte 'X' triggers it. */
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *p = malloc(32);
    if (!p) return 1;
    free(p);
    char in[8] = {0};
    int n = read(0, in, 7);
    if (n < 0) n = 0;
    in[n] = 0;
    if (in[0] == 'X') free(p);   /* double free */
    return 0;
}
