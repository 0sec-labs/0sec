/* 0verse benchmark — a *guarded* sink, to prove the angr concolic stage (#5).
 *
 * Two callers of the same vulnerable sink `vuln()`:
 *   - reachable_path: vuln fires only behind a magic-value gate  -> SAT, angr
 *     concretizes the witness (x == 0xdeadbeef).
 *   - dead_path:      vuln is behind a contradictory guard        -> UNSAT, angr
 *     proves it unreachable and the hypothesis is PRUNED.
 *
 * This is the static slicer's weakness made concrete: a backward slice reaches
 * `strcpy` from both callers (both look like findings), but only one is real.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the sink: classic stack buffer overflow when strlen(in) >= sizeof(buf) */
void vuln(const char *in) {
    char buf[16];
    strcpy(buf, in);
    printf("%s\n", buf);
}

/* SAT: reachable iff the attacker supplies the magic gate value */
void reachable_path(unsigned int x, const char *in) {
    if (x == 0xdeadbeef) {
        vuln(in);
    }
}

/* UNSAT: the guard is a contradiction — vuln can never run */
void dead_path(unsigned int x, const char *in) {
    if (x > 100 && x < 50) {
        vuln(in);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        return 0;
    }
    unsigned int x = (unsigned int)strtoul(argv[1], NULL, 0);
    reachable_path(x, argv[2]);
    dead_path(x, argv[2]);
    return 0;
}
