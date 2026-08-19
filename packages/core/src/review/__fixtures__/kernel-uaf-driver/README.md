# kernel-uaf-driver — pwnkit linux-kernel review profile fixture

Synthetic, deliberately vulnerable Linux char-device driver used by the
`linux-kernel` review profile tests.

The bug in `src/uaf_chrdev.c::uaf_dev_release` + `uaf_dev_write` is a
classic UAF: the release path frees `dev->buffer`, but a concurrent
`write` (or a missing `dev->buffer = NULL` after free) lets the next
write touch freed memory. The release path here doesn't NULL the
pointer, and the `write` callback indexes `dev->buffer[i]` without a
re-check after taking the lock — so the freed pointer is dereferenced.

A reproducer shape for this would be a syzkaller program that:

1. opens `/dev/uafdev` from two threads
2. one thread closes (triggering `release`)
3. the other thread writes (triggering the UAF)

Not a real driver. Don't load this. The bug is intentional.
