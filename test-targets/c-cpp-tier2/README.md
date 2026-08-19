# osec Tier-2 reference target

A deliberately vulnerable mini C library used to demonstrate and test
osec's Tier-2 multi-component C/C++ harness workflow.

The library exposes a single public entry point
(`osec_tier2_decode`) layered over a frame parser (`frame.c`) and a
decoder (`decoder.c`). The decoder contains an integer-truncation flaw
on its allocation path — the same shape Provos / IronCurtain
highlighted as the canonical "tier-2 confirms reachability" example.

## Layout

```
test-targets/c-cpp-tier2/
├── include/
│   └── osec_tier2.h     # public API
├── src/
│   ├── api.c              # top-level entry point
│   ├── frame.c            # magic-number frame check
│   └── decoder.c          # the vulnerable allocation path
├── corpus/
│   ├── seed-small         # benign well-framed seed
│   ├── seed-medium        # mid-size seed (does not crash)
│   └── seed-crash-trunc   # 64 KiB seed crafted to crash under ASan via integer truncation
├── Makefile.am            # autotools sources listing
└── configure.ac
```

## Why Tier-2 is the right tier here

Tier-1 (single-function isolation) trivially trips the bug if you
target `osec_tier2_decoder_run` directly with the payload bytes.
That's not enough: it doesn't prove the bug is reachable from the
public API, because the frame parser in `frame.c` rejects anything
without the `PWN2` magic prefix. Tier-2 links the suspect function
against `frame.c` + `api.c`, drives with the magic-prefixed corpus
seeds in `corpus/`, and confirms the primitive is hit through the real
call chain.

## Invocation

```
osec review --harness-tier 2 ./test-targets/c-cpp-tier2/
```

This emits a `harness.c`, a linker shell helper, and a Makefile
fragment under `./test-targets/c-cpp-tier2/.osec-out/tier2/`. osec
intentionally does not compile or run the harness — that step is
either driven by the agent or escalated to Tier-3 (QEMU validation),
which lives outside this module.

## License

Everything in this directory is MIT-licensed. The bug is real but the
code is synthetic; nothing here ships in any product.
