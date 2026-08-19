/* Synthetic vulnerable Linux kernel char-device — 0sec linux-kernel
 * review profile fixture.
 *
 * Deliberately vulnerable. The bug is a use-after-free across the
 * release/write boundary: `release` frees `dev->buffer` but does not
 * NULL it, and `write` later indexes `dev->buffer[i]` after a check
 * that's no longer valid once the buffer has been freed by another
 * fd.
 *
 * Do NOT load this. The bugs are intentional.
 */

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define UAF_BUF_SIZE 4096

struct uaf_dev {
    char *buffer;
    size_t len;
    struct mutex lock;
};

static struct uaf_dev *gdev;

static int uaf_dev_open(struct inode *inode, struct file *filp) {
    filp->private_data = gdev;
    return 0;
}

/* BUG: release frees the shared buffer but does NOT set
 * dev->buffer = NULL. A concurrent fd holding the same dev can later
 * write through the dangling pointer. */
static int uaf_dev_release(struct inode *inode, struct file *filp) {
    struct uaf_dev *dev = filp->private_data;
    mutex_lock(&dev->lock);
    kfree(dev->buffer);
    /* dev->buffer = NULL;   // <-- the missing line */
    mutex_unlock(&dev->lock);
    return 0;
}

static ssize_t uaf_dev_write(struct file *filp, const char __user *buf,
                              size_t count, loff_t *off) {
    struct uaf_dev *dev = filp->private_data;
    size_t i;
    char tmp[UAF_BUF_SIZE];

    if (count > UAF_BUF_SIZE) return -EINVAL;
    if (copy_from_user(tmp, buf, count)) return -EFAULT;

    mutex_lock(&dev->lock);
    /* BUG: no re-check that dev->buffer is non-NULL. If a sibling fd
     * just ran release(), this pointer is freed memory. The
     * dev->buffer[i] = tmp[i] STORE on the next line is a UAF write
     * with attacker-controlled offset and value. */
    for (i = 0; i < count; i++) {
        dev->buffer[i] = tmp[i];
    }
    dev->len = count;
    mutex_unlock(&dev->lock);

    return count;
}

static const struct file_operations uaf_fops = {
    .owner = THIS_MODULE,
    .open = uaf_dev_open,
    .release = uaf_dev_release,
    .write = uaf_dev_write,
};

static int __init uaf_init(void) {
    gdev = kmalloc(sizeof(*gdev), GFP_KERNEL);
    if (!gdev) return -ENOMEM;
    gdev->buffer = kmalloc(UAF_BUF_SIZE, GFP_KERNEL);
    if (!gdev->buffer) { kfree(gdev); return -ENOMEM; }
    gdev->len = 0;
    mutex_init(&gdev->lock);
    return 0;
}

static void __exit uaf_exit(void) {
    kfree(gdev->buffer);
    kfree(gdev);
}

module_init(uaf_init);
module_exit(uaf_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("0sec synthetic UAF char-device fixture");
