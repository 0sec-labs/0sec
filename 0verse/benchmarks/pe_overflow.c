/* M3 wave-2 (#20) Windows PE x86-64 benchmark — gated stack buffer overflow.

   parse_record copies `len` bytes into a 32-byte stack buffer, but only behind a
   4-byte "PE0!" magic gate. An oversized len overruns the buffer (the classic
   stack smash). Built with mingw-w64 (clang/gcc --target x86_64-w64-mingw32) it
   is a real PE32+; 0verse ingests + slices + triages it on Linux and surfaces the
   bug as a hypothesis, while being honest that the dynamic confirmation needs
   WinAFL on a Windows host (no fabricated crash on Linux). */

#include <windows.h>
#include <string.h>

__declspec(noinline) void parse_record(const char *data, int len) {
    char buf[32];
    if (len >= 4 && data[0] == 0x50 && data[1] == 0x45 &&
        data[2] == 0x30 && data[3] == 0x21) {
        memcpy(buf, data, (size_t)len);   /* overflow when len > 32 */
        if (buf[0]) {
            Sleep(0);
        }
    }
}

int main(void) {
    char in[256];
    DWORD n = 0;
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    ReadFile(h, in, sizeof(in), &n, NULL);
    parse_record(in, (int)n);
    return 0;
}
