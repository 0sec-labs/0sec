/* Fake procfs for testing */
#include <linux/proc_fs.h>

static int __init proc_init(void)
{
	proc_create("self/status", 0444, NULL, &proc_status_fops);
	proc_create_data("meminfo", 0444, NULL, &meminfo_fops, NULL);
	return 0;
}
