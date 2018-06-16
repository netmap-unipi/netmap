#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/miscdevice.h>

#include <dev/vale_vlan/vale_vlan_kern.h>



static struct mutex vale_vlan_global_lock;



static ssize_t vale_vlan_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t vale_vlan_write(struct file *, const char __user *,size_t,
	loff_t *);
static int vale_vlan_release(struct inode *, struct file *);
static long vale_vlan_ioctl(struct file *, u_int, u_long);
static int vale_vlan_open(struct inode *, struct file *);



static const struct file_operations vale_vlan_fops = {
	.owner 		= THIS_MODULE,
	.release 	= vale_vlan_release,
	.open 		= vale_vlan_open,
	.write 		= vale_vlan_write,
	.read 		= vale_vlan_read,
	.unlocked_ioctl	= vale_vlan_ioctl,
};



static struct miscdevice vale_vlan_misc = {
	.minor 	= MISC_DYNAMIC_MINOR,
	.name 	= "vale_vlan",
	.fops 	= &vale_vlan_fops,
};



static int
vale_vlan_release(struct inode *inode, struct file *f)
{

	vv_free(f->private_data);
	return 0;
}



static int
vale_vlan_open(struct inode *inode, struct file *f)
{
	struct vale_vlan_dev *dev;
	int ret = 0;

	dev = vv_malloc(sizeof(struct vale_vlan_dev));
	if (dev == NULL) {
		nm_prerr("Error while allocating memory "
			"for a 'struct vale_vlan_dev'");
		return -EFAULT;
	}
	vv_init_dev(dev);
	f->private_data = dev;
	return -ret;
}



static ssize_t
vale_vlan_write(struct file *f, const char __user *ubuf, size_t len,
	loff_t *ppos)
{
	struct vlan_conf_entry *entries;
	ssize_t ret;

	entries = vv_malloc(len);
	if (entries == NULL) {
		nm_prerr("Error while allocating memory for kernel side "
			"'struct vlan_conf_entry' array");
		return -EFAULT;
	}
	if (copy_from_user(entries, ubuf, len) != 0) {
		nm_prerr("Error while copying the 'struct vlan_conf_entry' "
			"to kernel memory");
		return -EFAULT;
	}

	mutex_lock(&vale_vlan_global_lock);
	ret = vv_write(f->private_data, entries, len);
	if (ret == 0) {
		ret = len;
	} else {
		ret = -ret;
	}
	vv_free(entries);
	mutex_unlock(&vale_vlan_global_lock);
	return ret;

}



static ssize_t
vale_vlan_read(struct file *f, char __user *buf, size_t len, loff_t *ppos)
{
	ssize_t ret;
	void *k_buf;

	k_buf = vv_malloc(len);
	if (k_buf == NULL) {
		nm_prerr("Error while allocating memory for kernel side "
			"'struct vlan_conf_entry' array");
		return -EFAULT;
	}

	mutex_lock(&vale_vlan_global_lock);
	ret = vv_read(f->private_data, k_buf, &len);
	if (ret != 0) {
		ret = -ret;
		goto l_free_read;
	}

	ret = len;
	if (copy_to_user(buf, k_buf, len) != 0) {
		ret = -EFAULT;
	}

l_free_read:
	vv_free(k_buf);
	mutex_unlock(&vale_vlan_global_lock);
	return ret;
}



static long
vale_vlan_ioctl(struct file *f, u_int cmd, u_long data)
{
	struct vlanreq_header arg;
	long ret = 0;

	if (_IOC_TYPE(cmd) != VV_IOC_MAGIC) {
		return -ENOTTY;
	}
	if (_IOC_NR(cmd) > VV_IOC_MAXNR) {
		return -ENOTTY;
	}

	switch (cmd) {
	case VV_IOCCTRL:
		if (copy_from_user(&arg, (void *)data,
			sizeof(struct vlanreq_header)) != 0) {
			return -EFAULT;
		}
		mutex_lock(&vale_vlan_global_lock);
		ret = vv_iocctrl(f->private_data, &arg);
		mutex_unlock(&vale_vlan_global_lock);
		break;

	default:
		return -ENOTTY;
	}

	return -ret;
}



static int __init
vale_vlan_init(void)
{
	int ret;

	mutex_init(&vale_vlan_global_lock);
	vv_init_module();
	ret = misc_register(&vale_vlan_misc);
	if (ret != 0) {
		nm_prerr("Failed to register vale_vlan misc device");
		return ret;
	}
	nm_prinf("vale_vlan: misc device successfully registered\n");
	return 0;
}



static void __exit
vale_vlan_fini(void)
{

	misc_deregister(&vale_vlan_misc);
	mutex_destroy(&vale_vlan_global_lock);
	nm_prinf("vale_vlan: misc device deregistered\n");
}



module_init(vale_vlan_init);
module_exit(vale_vlan_fini);
MODULE_AUTHOR("Stefano Duo");
MODULE_DESCRIPTION("IEEE 802.1Q extension to VALE switches");
MODULE_LICENSE("GPL");