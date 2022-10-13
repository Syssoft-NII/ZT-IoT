/*
 * Faked device driver for testing Audit ioctl
 *								2022/10/13
 *						yutaka_ishikawa@nii.ac.jp
 *
 *  In Documentation/admin-guide/devices.txt,
 *  The following major numbers are reserved for local/experimental use:
 *    60-63 char	LOCAL/EXPERIMENTAL USE
 *    60-63 block	LOCAL/EXPERIMENTAL USE
 *    120-127 char	LOCAL/EXPERIMENTAL USE
 *    120-127 block	LOCAL/EXPERIMENTAL USE
 *    240-254 block	LOCAL/EXPERIMENTAL USE
 *  The following major number are reserved for an example:
 *    42 char	Demo/sample use
 *    42 block	Demo/sample use
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#define VERBOSE 1

#define FKDEV_MAJOR	60
#define FKDEV_NAME	"fkdev"
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yutaka Ishikawa yutaka_ishikawa@nii.ac.jp");
MODULE_DESCRIPTION("Faked device for testing Audit ioctl");

extern void audit_ioctl(unsigned long uaddr, ssize_t);

#define HEXVAL_SZ	256
static void
printhexk(char *msg, unsigned char *tbuf, size_t sz)
{
    char	ccbuf[(HEXVAL_SZ)*2+1];
    size_t	di, si, maxlen, len;

    memset(ccbuf, 0, sizeof(ccbuf));
    di = snprintf(ccbuf, HEXVAL_SZ, msg);
    maxlen = (HEXVAL_SZ - di)/2; /* in hexa */
    len = sz > maxlen ? maxlen : sz;
    for (si = 0; si < len; si++) {
	di += snprintf(&ccbuf[di], HEXVAL_SZ - di, "%02x", tbuf[si]);
    }
    snprintf(&ccbuf[di], HEXVAL_SZ - di, "\n");
    printk(ccbuf);
}

static long
ioctl_handle_audit(unsigned int cmd, unsigned long arg)
{
    struct i2c_smbus_ioctl_data data_arg;
    unsigned char	tbuf[sizeof(union i2c_smbus_data)];
    switch (cmd) {
    case I2C_SMBUS:
	if (copy_from_user(&data_arg,
			   (struct i2c_smbus_ioctl_data __user *) arg,
			   sizeof(struct i2c_smbus_ioctl_data)))
	    return -EFAULT;
	break;
    default:
	printk("ioctl: not I2C_SMBUS cmd=0x%x\n", cmd);
	return 0;
    }
    printk("ioctl: I2C_SMBUS(0x%x) &arg(sz=%ld) = 0x%02lx arg.data(sz=%ld) = 0x%02lx\n",
	   cmd, sizeof(struct i2c_smbus_ioctl_data), arg,
	   sizeof(union i2c_smbus_data), (unsigned long) data_arg.data);
    printhexk("ioctl: data1=", (unsigned char*) &data_arg,
	      sizeof(struct i2c_smbus_ioctl_data));
    if (data_arg.data != NULL) {
	if (copy_from_user(tbuf, (const void*) data_arg.data,
			   sizeof(union i2c_smbus_data))) {
	    printk("ioctl: cannot read data from %p\n", (char*) data_arg.data);
	} else {
	    printhexk("ioctl: data2=", tbuf, sizeof(union i2c_smbus_data));
	}
    }
#ifdef ZT_IOT
    audit_ioctl((unsigned long ) data_arg.data, sizeof(union i2c_smbus_data));
#endif
    return 0;
}

static loff_t
fkdev_llseek(struct file *filp, loff_t off, int whence)
{
#ifdef VERBOSE
	printk("%s: off=%lld whence=%d\n", __func__, off, whence);
#endif
    return whence;
}

static ssize_t
fkdev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
#ifdef VERBOSE
    printk("%s: buf=%p size=%ld\n", __func__, buf, count);
#endif
    if (count > 0) {
	buf[0] = 'A';
    }
    return 1;
}

static ssize_t
fkdev_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
#ifdef VERBOSE
    printk("%s: buf=%p size=%ld\n", __func__, buf, count);
#endif
    return count;
}

static ssize_t
fkdev_read_iter(struct kiocb *kio, struct iov_iter *iter)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static ssize_t
fkdev_write_iter(struct kiocb *kio, struct iov_iter *iter)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

#if 0 /* latest kernel version */
static int
fkdev_iopoll(struct kiocb *kiocb, struct io_comp_batch *,
			unsigned int flags)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}
#endif
/* version 5.15 */
static int
fkdev_iopoll(struct kiocb *kiocb, bool spin)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_iterate(struct file *filp, struct dir_context *cntxt)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_iterate_shared(struct file *filp, struct dir_context *cntxt)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static __poll_t
fkdev_poll(struct file *filp,  struct poll_table_struct *tab)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static long
fkdev_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
#ifdef VERBOSE
    printk("%s: cmd=0x%0x arg=0x%02lx\n", __func__, cmd, arg);
#endif
    ioctl_handle_audit(cmd, arg);
    return 0;
}

static long
fkdev_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
#ifdef VERBOSE
    printk("%s: cmd=0x%0x arg=0x%02lx\n", __func__, cmd, arg);
#endif
    ioctl_handle_audit(cmd, arg);
    return 0;
}

static int
fkdev_mmap(struct file *filp, struct vm_area_struct *vm)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_open(struct inode *inode, struct file *file)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_flush(struct file *filp, fl_owner_t id)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

/*
 * .release
 */
static int
fkdev_close(struct inode *inode, struct file *file)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_fsync(struct file *filep, loff_t off1, loff_t off2, int datasync)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_fasync(int i1, struct file *filep, int i2)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_lock(struct file *fp, int a1, struct file_lock *fl)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static ssize_t
fkdev_sendpage(struct file *fp, struct page *pg, int a1,
	       size_t sz, loff_t *off, int a2)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}
    
static unsigned long
fkdev_get_unmapped_area(struct file *fp, unsigned long ul1,
			unsigned long ul2, unsigned long ul3,
			unsigned long ul4)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}
    
static int
fkdev_check_flags(int f)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}
    
static int
fkdev_flock (struct file *fp , int a1, struct file_lock *fl)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static ssize_t
fkdev_splice_write(struct pipe_inode_info *inf, struct file *fp,
		   loff_t *off, size_t sz, unsigned int a1)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}
    
static ssize_t
fkdev_splice_read(struct file *fp, loff_t *off,
		  struct pipe_inode_info *inf, size_t sz, unsigned int a1)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_setlease(struct file *fp, long a1, struct file_lock **fl, void **a2)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static long
fkdev_fallocate(struct file *file, int mode, loff_t offset,
			  loff_t len)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static void
fkdev_show_fdinfo(struct seq_file *m, struct file *f)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return;
}

#ifndef CONFIG_MMU
static unsigned
fkdev_mmap_capabilities(struct file *fp)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}
#endif

static ssize_t
fkdev_copy_file_range(struct file *fp1, loff_t off1, struct file *fp2,
			loff_t off2, size_t sz, unsigned int a1)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static loff_t
fkdev_remap_file_range(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   loff_t len, unsigned int remap_flags)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

static int
fkdev_fadvise(struct file *fp, loff_t off1, loff_t off2, int a1)
{
#ifdef VERBOSE
    printk("%s: called\n", __func__);
#endif
    return 0;
}

/*
 *
 */
struct file_operations fkdev_fops = {
    .llseek = fkdev_llseek,
    .read    = fkdev_read,
    .write   = fkdev_write,
    .read_iter	= fkdev_read_iter,
    .write_iter	= fkdev_write_iter,
    .iopoll	= fkdev_iopoll,
    .iterate	= fkdev_iterate,
    .iterate_shared = fkdev_iterate_shared,
    .poll	= fkdev_poll,
    .unlocked_ioctl = fkdev_unlocked_ioctl,
    .compat_ioctl = fkdev_compat_ioctl,
    .mmap	= fkdev_mmap,
    .open	= fkdev_open,
    .flush	= fkdev_flush,
    .release	= fkdev_close,
    .fsync	= fkdev_fsync,
    .fasync	= fkdev_fasync,
    .lock	= fkdev_lock,
    .sendpage	= fkdev_sendpage,
    .get_unmapped_area = fkdev_get_unmapped_area,
    .check_flags = fkdev_check_flags,
    .flock	= fkdev_flock,
    .splice_write = fkdev_splice_write,
    .splice_read = fkdev_splice_read,
    .setlease = fkdev_setlease,
    .fallocate	= fkdev_fallocate,
    .show_fdinfo = fkdev_show_fdinfo,
#ifndef CONFIG_MMU
    .mmap_capabilities = fkdev_mmap_capabilities,
#endif
    .copy_file_range = fkdev_copy_file_range,
    .remap_file_range = fkdev_remap_file_range,
    .fadvise	= fkdev_fadvise
};

static int
fkdev_init(void)
{
#ifdef ZT_IOT
    printk("%s: ZT_IOT Initializing\n", __func__);
#else
    printk("%s: Initializing\n", __func__);
#endif
    register_chrdev(FKDEV_MAJOR, FKDEV_NAME, &fkdev_fops);
    printk("%s: Done\n", __func__);
    return 0;
}

static void
fkdev_exit(void)
{
    printk("%s: Exiting\n", __func__);
    unregister_chrdev(FKDEV_MAJOR, FKDEV_NAME);
    printk("%s: Done\n", __func__);
}

module_init(fkdev_init);
module_exit(fkdev_exit);
