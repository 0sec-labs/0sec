/* CWE-697 / CWE-287 (hypothesis-only class): a length-less, non-constant-time
 * password compare plus an off-by-one bound. There is NO generic binary oracle
 * for "is this the intended check?", so 0verse surfaces it as a high-value
 * funnel LEAD via the logic lens and NEVER marks it confirmed without a PoV. */
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static int check_password(const char *secret, const char *given) {
    /* off-by-one: copies up to len inclusive into a fixed buffer */
    char scratch[16];
    size_t len = strlen(given);
    for (size_t i = 0; i <= len && i < sizeof scratch; i++) scratch[i] = given[i];
    return strcmp(secret, scratch) == 0;   /* auth compare */
}

int main(void) {
    char given[64] = {0};
    int n = read(0, given, 63);
    if (n < 0) n = 0;
    given[n] = 0;
    if (check_password("s3cr3t-admin-token", given)) {
        printf("ACCESS GRANTED\n");
        return 0;
    }
    printf("denied\n");
    return 1;
}
