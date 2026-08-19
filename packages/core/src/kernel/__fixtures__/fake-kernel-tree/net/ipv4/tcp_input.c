/* Fake TCP input for testing */
#include <linux/tcp.h>

SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags, struct sockaddr __user *, addr, int, addr_len)
{
	return 0;
}

COMPAT_SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags, struct sockaddr __user *, addr, int, addr_len)
{
	return 0;
}

static struct genl_family tcp_metrics_nl_family = {
	.name = "tcp_metrics",
};

static int __init tcp_init(void)
{
	genl_register_family(&tcp_metrics_nl_family);
	return 0;
}
