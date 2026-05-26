# c-library-demo — pwnkit C/C++ review profile fixture

Synthetic, deliberately vulnerable single-file C library used by the
C/C++ review profile tests and end-to-end demos.

The bug in `src/decoder.c::decode_payload` is the same shape as the
18-year-old integer-truncation flaw described in the Provos /
IronCurtain post (Apr 2026): unchecked arithmetic on attacker-controlled
lengths feeds a `malloc` size, and a 32-bit multiplication wrap returns
a tiny allocation that a subsequent `memcpy` then overflows.

A tier-1 libFuzzer harness against `decode_payload` should trip
AddressSanitizer within seconds.

**Do not use this code anywhere. The bugs are intentional.**
