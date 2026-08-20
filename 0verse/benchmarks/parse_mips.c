/* M3 wave-2 (#21) MIPS firmware benchmark — freestanding MIPS o32, no libc.

   parse_record copies `len` bytes into a 32-byte stack buffer, but only behind a
   4-byte "MIP!" magic gate. An oversized len overruns the buffer and corrupts the
   saved return address ($ra) — so the function's epilogue `jr $ra` jumps to
   attacker bytes and faults. The Qiling firmware lane drives parse_record
   directly (seeding $a0/$a1 + $ra from the o32 ABI), so no libc/syscalls are
   needed: a control input returns cleanly to the sentinel return address; the
   overflow faults. That differential is the reachability/crash proof. */

void parse_record(char *data, int len) {
    volatile char buf[32];
    if (data[0] == 0x4D && data[1] == 0x49 && data[2] == 0x50 && data[3] == 0x21) {
        for (int i = 0; i < len; i++) {
            buf[i] = data[i];
        }
    }
}

/* The firmware lane never executes _start (it calls parse_record directly); a
   self-loop keeps a valid entry symbol without pulling in a runtime. */
void _start(void) { for (;;) {} }
