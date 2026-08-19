/* Fake sysfs/debugfs entries for testing */
#include <linux/sysfs.h>
#include <linux/debugfs.h>

static int security_init(void)
{
	sysfs_create_group(&dev->kobj, &security_attr_group);
	sysfs_create_file(&dev->kobj, &security_attr);
	debugfs_create_file("security_log", 0444, NULL, NULL, &security_fops);
	debugfs_create_dir("security", NULL);
	return 0;
}
