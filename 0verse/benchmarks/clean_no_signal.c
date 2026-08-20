/* CLEAN / NO-SIGNAL — the eval's measured-waste case. No attacker-controlled flow
 * into any dangerous sink: the slice, the foxguard pre-pass, and the bug-class
 * lenses all surface NOTHING (zero static signal). The sequential pipeline still
 * burns the full no-signal fuzz complement (~30s, QEMU-mode) confirming nothing.
 *
 * Under a TIGHT scheduler time budget the M7 #44 scheduler skips that lane (no
 * slice signal ⇒ lowest expected value), spending a fraction of the time for the
 * same (empty) finding set. With the default/generous budget the lane still runs,
 * so no capability is lost. Input is parsed as an int and added — no memory op. */
#include <stdio.h>
#include <stdlib.h>

static int add(int a, int b) { return a + b; }

int main(void) {
    char line[256];
    if (fgets(line, sizeof line, stdin)) {
        int n = atoi(line);
        printf("%d\n", add(n, 1));
    }
    return 0;
}
