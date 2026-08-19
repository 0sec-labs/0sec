/*
 * Fake driver with a multi-hop call chain from a syscall entry point down to a
 * vulnerable sink. Used by reachability-rank.test.ts to assert that a sink
 * deep in the call graph ranks the reaching syscall first.
 *
 * Call graph (entry -> sink):
 *   SYSCALL_DEFINE2(vuln_open) -> vuln_dispatch -> vuln_parse_header
 *                                              -> vuln_copy_payload  [SINK]
 *
 * A second, unrelated syscall is included so the ranking has something to
 * deprioritise: SYSCALL_DEFINE1(vuln_stat) -> vuln_readonly_info (never
 * reaches the sink).
 */
#include <linux/fs.h>
#include <linux/uaccess.h>

/* The vulnerable sink: an unchecked copy_from_user into a fixed buffer. */
static int vuln_copy_payload(void __user *src, size_t len)
{
	char buf[64];
	return copy_from_user(buf, src, len);
}

static int vuln_parse_header(void __user *src)
{
	return 0;
}

static int vuln_dispatch(void __user *src, size_t len)
{
	vuln_parse_header(src);
	return vuln_copy_payload(src, len);
}

static int vuln_readonly_info(void)
{
	return 42;
}

SYSCALL_DEFINE2(vuln_open, void __user *, src, size_t, len)
{
	return vuln_dispatch(src, len);
}

SYSCALL_DEFINE1(vuln_stat, int, fd)
{
	return vuln_readonly_info();
}
