/* CWE-120: unbounded copy of attacker-controlled input into a small stack buffer.
 * Expect: 0verse confirms  read -> strcpy  via the differential crash oracle. */
#include <string.h>
#include <unistd.h>

int main(void) {
    char buf[16];
    char big[512] = {0};
    int n = read(0, big, 511);
    if (n >= 0) big[n] = 0;
    strcpy(buf, big);   /* overflows buf when input > 16 bytes */
    return 0;
}
