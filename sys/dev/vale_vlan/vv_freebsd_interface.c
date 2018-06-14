#include <sys/malloc.h>
#include <sys/kernel.h>

#include <dev/vale_vlan/vv_os_interface.h>

MALLOC_DECLARE(M_VALE_VLAN);
MALLOC_DEFINE(M_VALE_VLAN, "vale_vlan",
    "IEEE 802.1Q extension to VALE switches");

int vale_vlan_use_count = 0;



void *vv_malloc(size_t size)
{

	return malloc(size, M_VALE_VLAN, M_NOWAIT | M_ZERO);
}



void vv_free(void *addr)
{

	free(addr, M_VALE_VLAN);
}


/* At the moment the refcount functions are only called inside functions defined
 * inside vale_vlan.c. They are all called under the global lock, if we ever
 * remove the global lock, or change locking related stuff, we need to pay
 * attention to data races on vale_vlan_use_count
 */
void vv_try_module_get(void)
{

	++vale_vlan_use_count;
}



void vv_module_put(void)
{

	--vale_vlan_use_count;
}