#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/sx.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <dev/vale_vlan/vale_vlan_kern.h>

#define DEV_NAME "vale_vlan"

static d_open_t vale_vlan_open;
static d_close_t vale_vlan_close;
static d_read_t vale_vlan_read;
static d_write_t vale_vlan_write;
static d_ioctl_t vale_vlan_ioctl;

static struct cdevsw vale_vlan_cdevsw = {
	.d_version = D_VERSION,
	.d_open    = vale_vlan_open,
	.d_close   = vale_vlan_close,
	.d_read    = vale_vlan_read,
	.d_write   = vale_vlan_write,
	.d_ioctl   = vale_vlan_ioctl,
	.d_name    = DEV_NAME,
};
static struct cdev *vale_vlan_cdev;
extern int vale_vlan_use_count;
static struct sx vale_vlan_global_lock;

static int
vale_vlan_loader(__unused struct module *module, int event, __unused void *arg)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
				   &vale_vlan_cdev, &vale_vlan_cdevsw, 0,
				   UID_ROOT, GID_WHEEL, 0600, DEV_NAME);
		if (error) {
			nm_prerr("Failed to register vale_vlan device\n");
			break;
		}

		vv_init_module();
		sx_init(&vale_vlan_global_lock, "vale_vlan global lock");
		nm_prinf("vale_vlan: device successfully registered\n");
		break;

	case MOD_UNLOAD:
		if (vale_vlan_use_count != 0) {
			nm_prinf("vale_vlan: module can't be unloaded,"
				 "as it is still in use\n");
			error = EBUSY;
			break;
		}
		destroy_dev(vale_vlan_cdev);
		sx_destroy(&vale_vlan_global_lock);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static void
vale_vlan_dtor(void *data)
{

	vv_free(data);
}

static int
vale_vlan_open(struct cdev *dev __unused, int oflags __unused,
	       int devtype __unused, struct thread *td __unused)
{
	struct vale_vlan_dev *vv_dev;
	int ret = 0;

	vv_dev = vv_malloc(sizeof(struct vale_vlan_dev));
	if (vv_dev == NULL) {
		nm_prerr("Error while allocating memory "
			 "for a struct vale_vlan_dev\n");
		return EFAULT;
	}

	sx_xlock(&vale_vlan_global_lock);
	vv_init_dev(vv_dev);
	ret = devfs_set_cdevpriv(vv_dev, vale_vlan_dtor);
	if (ret != 0) {
		vv_free(vv_dev);
	}
	sx_xunlock(&vale_vlan_global_lock);

	return ret;
}

static int
vale_vlan_close(struct cdev *dev __unused, int fflag __unused,
		int devtype __unused, struct thread *td __unused)
{

	return 0;
}

static int
vale_vlan_write(struct cdev *dev __unused, struct uio *uio, int ioflag __unused)
{
	struct vlan_conf_entry *entries;
	struct vale_vlan_dev *vv_dev;
	size_t len;
	int ret = 0;

	len     = uio->uio_resid;
	entries = vv_malloc(len);
	if (entries == NULL) {
		nm_prerr("Error while allocating memory for kernel side"
			 "struct vlan_conf_entry array\n");
		return EFAULT;
	}

	ret = uiomove(entries, len, uio);
	if (ret != 0) {
		nm_prerr("Error %d while copying the struct vlan_conf_entry"
			 "to kernel memory\n",
			 ret);
		goto l_free_write;
	}

	ret = devfs_get_cdevpriv((void **)&vv_dev);
	if (ret != 0) {
		nm_prerr("Error %d while retrieving private"
			 "struct vale_vlan_dev\n",
			 ret);
		goto l_free_write;
	}

	CURVNET_SET(TD_TO_VNET(uio->uio_td));
	sx_xlock(&vale_vlan_global_lock);
	ret = vv_write(vv_dev, entries, len);
	sx_xunlock(&vale_vlan_global_lock);
	CURVNET_RESTORE();

l_free_write:
	vv_free(entries);
	return ret;
}

static int
vale_vlan_read(struct cdev *dev __unused, struct uio *uio, int ioflag __unused)
{
	struct vale_vlan_dev *vv_dev;
	size_t len = uio->uio_resid;
	int ret    = 0;
	void *buf;

	buf = vv_malloc(len);
	if (buf == NULL) {
		nm_prerr("Error while allocating memory for kernel side"
			 "struct vlan_conf_entry array\n");
		return EFAULT;
	}

	ret = devfs_get_cdevpriv((void **)&vv_dev);
	if (ret != 0) {
		nm_prerr("Error %d while retrieving private"
			 "struct vale_vlan_dev\n",
			 ret);
		goto l_free_read;
	}

	sx_xlock(&vale_vlan_global_lock);
	ret = vv_read(vv_dev, buf, &len);
	sx_xunlock(&vale_vlan_global_lock);
	if (ret != 0) {
		goto l_free_read;
	}

	ret = uiomove(buf, len, uio);
	if (ret != 0) {
		nm_prerr("Error while writing results to userspace memory\n");
	}

l_free_read:
	vv_free(buf);
	return ret;
}

static int
vale_vlan_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
		int ffla __unused, struct thread *td)
{
	struct vlanreq_header *hdr = (struct vlanreq_header *)data;
	struct vale_vlan_dev *vv_dev;
	int ret = 0;

	ret = devfs_get_cdevpriv((void **)&vv_dev);
	if (ret != 0) {
		nm_prerr("Error %d while retrieving private"
			 "struct vale_vlan_dev\n",
			 ret);
		return EFAULT;
	}

	switch (cmd) {
	case VALE_VLAN_IOCCTRL:
		sx_xlock(&vale_vlan_global_lock);
		ret = vv_iocctrl(vv_dev, hdr);
		sx_xunlock(&vale_vlan_global_lock);
		break;

	default:
		ret = ENOTTY;
	}

	return ret;
}

DEV_MODULE(vale_vlan, vale_vlan_loader, NULL);
MODULE_DEPEND(vale_vlan, netmap, 1, 1, 1);
MODULE_VERSION(vale_vlan, 1);