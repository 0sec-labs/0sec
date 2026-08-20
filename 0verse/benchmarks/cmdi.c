/* CWE-78: untrusted environment variable flows into system().
 * Expect: 0verse confirms  getenv -> system  via the canary oracle. */
#include <stdlib.h>

int main(void) {
    char *cmd = getenv("CMD");
    system(cmd);
    return 0;
}
