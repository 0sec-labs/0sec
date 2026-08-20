/* CLEAN / known-good — shaped like overflow.c (attacker input flows into a copy
 * into a fixed stack buffer) but SAFE: the copy is length-bounded and the result
 * is always NUL-terminated. The slice/lens may surface read -> copy as a lead;
 * the differential oracle must NOT confirm (no overflow), and a real model should
 * judge it is_real=false. A false-positive probe for the memory-safety lane. */
#include <string.h>
#include <unistd.h>

int main(void) {
    char buf[64];
    char big[512] = {0};
    int n = read(0, big, 511);
    if (n < 0) n = 0;
    big[n] = 0;
    strncpy(buf, big, sizeof(buf) - 1);   /* bounded: at most 63 bytes */
    buf[sizeof(buf) - 1] = 0;             /* always terminated */
    return buf[0];
}
