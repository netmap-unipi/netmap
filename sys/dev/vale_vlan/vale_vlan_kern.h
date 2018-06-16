#ifndef VALE_VLAN_KERN_H
#define VALE_VLAN_KERN_H



#define WITH_VALE



/* Import declarations needed by netmap */
#if defined(__linux__)
#include <bsd_glue.h>
#elif defined(__FreeBSD__)
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/filio.h>
#include <sys/sockio.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/jail.h>
#include <net/vnet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <sys/time.h>
#include <net/bpf.h>
#include <machine/bus.h>
#include <sys/endian.h>
#include <sys/refcount.h>
#endif /* FreeBSD */
/* End of declarations needed by netmap */

#include <dev/vale_vlan/vv_os_interface.h>
#include <net/vale_vlan_user.h>

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>



struct vale_vlan_dev {
	int selected_conf;
	int32_t error_entry;
};



int vv_write(struct vale_vlan_dev *, struct vlan_conf_entry *, size_t);
int vv_read(struct vale_vlan_dev *, uint8_t *, size_t *);
long vv_iocctrl(struct vale_vlan_dev *, struct vlanreq_header *);
void vv_init_dev(struct vale_vlan_dev *);
void vv_init_module(void);



#endif /* VALE_VLAN_KERN_H */