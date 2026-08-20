/* Faithful minimal reproducer of CVE-2004-0597 — libpng png_handle_tRNS()
 * palette buffer overflow (CWE-120/CWE-787).
 *
 * Upstream bug: when reading a tRNS chunk for a PALETTE image, libpng copied
 * `length` bytes (attacker-controlled chunk length) into the fixed-size
 * png_ptr->trans[PNG_MAX_PALETTE_LENGTH] array without bounding `length` to the
 * number of palette entries — an out-of-bounds write.
 * Fix commit (libpng 1.2.6): clamp `length` to num_palette before the copy.
 *   https://nvd.nist.gov/vuln/detail/CVE-2004-0597
 *
 * This is a faithful standalone EXTRACT of the vulnerable function (real name,
 * real unsafe memcpy sink, real fix), NOT the shipping libpng binary. The taint
 * source is read(2) so the static slice has a recognised source->sink path.
 *
 * Build:  vuln  -> gcc -O0 -fno-stack-protector -no-pie
 *         fixed -> add -DFIXED
 */
#include <string.h>
#include <unistd.h>

#define PNG_MAX_PALETTE_LENGTH 256

typedef struct {
    unsigned char trans[PNG_MAX_PALETTE_LENGTH];
    int num_palette;
} png_struct;

/* The real upstream function name. As in libpng, the handler reads the chunk
 * data itself (png_crc_read) and then stores it — source (read) and sink
 * (memcpy) are co-located in the handler. */
int png_handle_tRNS(png_struct *png_ptr)
{
    unsigned char data[4096];
    /* png_crc_read of the tRNS chunk: `length` bytes of attacker data. */
    ssize_t length = read(0, data, sizeof(data));
    if (length <= 0)
        return 0;
#ifdef FIXED
    /* CVE-2004-0597 fix: a tRNS chunk cannot describe more entries than the
     * palette, and never more than PNG_MAX_PALETTE_LENGTH. */
    if (length > png_ptr->num_palette)
        length = png_ptr->num_palette;
    if (length > PNG_MAX_PALETTE_LENGTH)
        length = PNG_MAX_PALETTE_LENGTH;
#endif
    memcpy(png_ptr->trans, data, (size_t)length);
    return png_ptr->trans[0];
}

int main(void)
{
    png_struct png_ptr;
    png_ptr.num_palette = 4;
    return png_handle_tRNS(&png_ptr);
}
