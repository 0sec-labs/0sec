/* Fake netfilter for testing */
#include <linux/netfilter.h>

static int nf_tables_init(void)
{
	nf_register_net_hook(&init_net, &nft_hook);
	nf_register_net_hooks(&init_net, nft_hooks, ARRAY_SIZE(nft_hooks));
	return 0;
}

static struct netlink_kernel_cfg nfnl_cfg = {
	.groups = NFNLGRP_MAX,
};

static int __init nfnetlink_init(void)
{
	netlink_kernel_create(&init_net, NETLINK_NETFILTER, &nfnl_cfg);
	return 0;
}
