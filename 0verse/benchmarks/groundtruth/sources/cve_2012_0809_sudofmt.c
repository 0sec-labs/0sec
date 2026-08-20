/* Faithful minimal reproducer of CVE-2012-0809 — sudo sudo_debug()
 * format-string vulnerability (CWE-134).
 *
 * Upstream bug: sudo_debug() passed the program name (argv[0], attacker
 * controllable) straight through to a printf-family call as the *format*
 * argument, so format directives in the program name were interpreted.
 * Fix commit (sudo 1.8.3p2): use a literal "%s" format.
 *   https://nvd.nist.gov/vuln/detail/CVE-2012-0809
 *
 * Faithful standalone EXTRACT (real function name, real tainted-format sink,
 * real "%s" fix), NOT the shipping sudo binary. Source = read(2). The recognised
 * sink is printf (sudo used fprintf(stderr, ...); the lens keys on the
 * printf family — documented in the manifest note).
 *
 * Build:  vuln -> gcc -O0 -no-pie ; fixed -> add -DFIXED
 */
#include <stdio.h>
#include <unistd.h>

/* The real upstream function name. Sink = printf with a tainted format; the
 * tainted program name is read in-function so the slice sees source->sink. */
int sudo_debug(void)
{
    char progname[256];
    ssize_t n = read(0, progname, sizeof(progname) - 1);
    if (n <= 0)
        return 0;
    progname[n] = '\0';
#ifdef FIXED
    /* CVE-2012-0809 fix: never let attacker text be the format string. */
    printf("%s", progname);
#else
    printf(progname);
#endif
    return 0;
}

int main(void)
{
    return sudo_debug();
}
