#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/module.h>

#include <dev/vale_vlan/vale_vlan_kern.h>



void *vv_malloc(size_t size)
{
	void *rv;

	rv = kmalloc(size, GFP_ATOMIC | __GFP_ZERO);
	if (IS_ERR(rv)) {
		return NULL;
	}

	return rv;
}



void vv_free(void *addr)
{

	kfree(addr);
}



void vv_try_module_get()
{

	try_module_get(THIS_MODULE);
}



void vv_module_put()
{

	module_put(THIS_MODULE);
}