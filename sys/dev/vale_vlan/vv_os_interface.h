#ifndef VV_OS_INTERFACE_H
#define VV_OS_INTERFACE_H

/* OS headers needed for lists */
#if defined(__linux__)
#include <linux/if.h>
#include <linux/list.h>
#elif defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/queue.h>
#endif

void *vv_malloc(size_t);
void vv_free(void *);

void vv_try_module_get(void);
void vv_module_put(void);

/* DOUBLY LINKED LIST TEMPLATE
 * #define vv_list_declare(head_struct_t, elem_struct_t)
 * #define vv_list_head_init(head_p)
 * #define vv_list_elem_init(elem_p)
 * #define vv_list_entry(elem_struct_t)
 * #define vv_list_insert_head(head_p, elem_p, entry_name)
 * #define vv_list_remove(elem_p, entry_name)
 * #define vv_list_foreach(cursor_p, head_p, entry_name)
 * #define vv_list_foreach_safe(cursor_p, head_p, entry_name, temp_p)
 */

#if defined(__linux__)
#define vv_list_declare(head_struct_t, elem_struct_t) struct list_head

#define vv_list_head_init(head_p) INIT_LIST_HEAD(head_p)

#define vv_list_elem_init(elem_p, entry_name)                                  \
	INIT_LIST_HEAD(&(elem_p)->entry_name)

#define vv_list_entry(elem_struct_t) struct list_head

#define vv_list_insert_head(head_p, elem_p, entry_name)                        \
	list_add(&(elem_p)->entry_name, head_p)

#define vv_list_remove(elem_p, entry_name) list_del(&((elem_p)->entry_name))

#define vv_list_foreach(cursor_p, head_p, entry_name)                          \
	list_for_each_entry(cursor_p, head_p, entry_name)

#define vv_list_foreach_safe(cursor_p, head_p, entry_name, temp_p)             \
	list_for_each_entry_safe(cursor_p, temp_p, head_p, entry_name)

#elif defined(__FreeBSD__)
#define vv_list_declare(head_struct_t, elem_struct_t)                          \
	LIST_HEAD(head_struct_t, elem_struct_t)

#define vv_list_head_init(head_p) LIST_INIT(head_p)

#define vv_list_elem_init(elem_p, entry_name) (void)(elem_p)

#define vv_list_entry(elem_struct_t) LIST_ENTRY(elem_struct_t)

#define vv_list_insert_head(head_p, elem_p, entry_name)                        \
	LIST_INSERT_HEAD(head_p, elem_p, entry_name)

#define vv_list_remove(elem_p, entry_name) LIST_REMOVE(elem_p, entry_name)

#define vv_list_foreach(cursor_p, head_p, entry_name)                          \
	LIST_FOREACH(cursor_p, head_p, entry_name)

#define vv_list_foreach_safe(cursor_p, head_p, entry_name, temp_p)             \
	LIST_FOREACH_SAFE(cursor_p, head_p, entry_name, temp_p)

#endif

#endif /* VV_OS_INTERFACE_H */