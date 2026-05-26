/* Fake AF_ALG implementation for testing */
#include <linux/crypto.h>
#include <linux/net.h>

static int alg_bind(struct socket *sock, struct sockaddr *sa, int salen)
{
	return 0;
}

static struct alg_type alg_hash_type = {
	.name = "hash",
	.bind = alg_bind,
};

SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	return 0;
}

static long alg_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static const struct file_operations alg_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = alg_ioctl,
};

static int __init af_alg_init(void)
{
	proto_register(&alg_proto, 1);
	sock_register(&alg_family);
	return 0;
}
