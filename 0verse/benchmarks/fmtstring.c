/* CWE-134: attacker-controlled data reaches the FORMAT argument of printf.
 * 0verse's lens flags the non-literal format position; the oracle feeds a
 * %s-spray (+ %n) probe -> a wild pointer read/write crash a benign control
 * does not trigger. Input: the format string on stdin. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[256] = {0};
    int n = read(0, buf, 255);
    if (n < 0) n = 0;
    buf[n] = 0;
    printf(buf);          /* tainted format string */
    putchar('\n');
    return 0;
}
