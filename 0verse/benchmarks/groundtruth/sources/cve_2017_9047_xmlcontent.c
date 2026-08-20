/* Faithful minimal reproducer of CVE-2017-9047 — libxml2
 * xmlSnprintfElementContent() stack buffer overflow (CWE-787).
 *
 * Upstream bug: xmlSnprintfElementContent() appended a content-model element
 * name into a fixed-size buffer with strcat() while only checking the *current*
 * length against `size` loosely, so a long element name overflowed the buffer.
 * Fix commit (libxml2, b6c1a3d): bound each append against the remaining space
 * and emit " ..." instead of overflowing.
 *   https://nvd.nist.gov/vuln/detail/CVE-2017-9047
 *   https://gitlab.gnome.org/GNOME/libxml2/commit/e26630548e7d138d2c560844c43820b6767251e3
 *
 * Faithful standalone EXTRACT (real function name, real strcat sink, real
 * bounding fix), NOT the shipping libxml2 binary. Source = read(2).
 *
 * Build:  vuln -> gcc -O0 -fno-stack-protector -no-pie ; fixed -> add -DFIXED
 */
#include <string.h>
#include <unistd.h>

/* The real upstream function name. Sink = strcat into the fixed `buf`; the
 * tainted element name is read in-function so the static slice sees the
 * source->sink path. */
int xmlSnprintfElementContent(char *buf, int size)
{
    char name[4096];
    ssize_t n = read(0, name, sizeof(name) - 1);   /* content->name (tainted) */
    if (n <= 0)
        return 0;
    name[n] = '\0';
    int len = (int)strlen(buf);
#ifdef FIXED
    /* CVE-2017-9047 fix: never strcat past the remaining buffer space. */
    if (size - len < (int)strlen(name) + 10) {
        if (size - len > 4)
            strcat(buf, " ...");
        return buf[0];
    }
#endif
    (void)size;
    (void)len;
    strcat(buf, name);
    return buf[0];
}

int main(void)
{
    char buf[50];
    strcpy(buf, "(");
    return xmlSnprintfElementContent(buf, (int)sizeof(buf));
}
