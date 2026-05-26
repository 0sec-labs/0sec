/* Fake char device for testing */
#include <linux/fs.h>
#include <linux/miscdevice.h>

static long misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static long misc_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static const struct file_operations misc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = misc_ioctl,
	.compat_ioctl = misc_compat_ioctl,
};
