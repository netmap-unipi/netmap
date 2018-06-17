#include <dev/vale_vlan/vale_vlan_kern.h>



#define TAG_LENGTH	4
#define TAG_START	12
#define TAG_END		(TAG_START + TAG_LENGTH)
#define TAG_PID		12
#define TAG_CI		14
#define TAG_PID_OFFSET	0 /* from start of tag */
#define TAG_CI_OFFSET	2 /* from start of tag */



static int
tag_frame(struct nm_bdg_fwd *ft, struct netmap_vp_adapter *vpna,
	uint16_t vlan_id)
{
	struct nm_bdg_fwd *ft_end = ft + ft->ft_frags - 1;
	struct nm_bdg_fwd *ft_cur = NULL;
	uint8_t *buf = NULL;
	uint32_t buf_size;
	uint16_t be_tpid;
	uint16_t be_tci; /* at the moment PCP and DEI are always set to 0 */
	int n_bytes = 0;

	buf_size = NETMAP_BUF_SIZE((struct netmap_adapter *)vpna);
	if (ft_end->ft_len + TAG_LENGTH > buf_size) {
		nm_prinf("Not enough space for the tag in the last fragment\n");
		return EINVAL;
	}
	if (ft->ft_offset + TAG_END > ft->ft_len) {
		nm_prinf("Header split between two nm_bdg_fwd,"
			"at the moment not supported\n");
		return EINVAL;
	}

	ft_end->ft_len += TAG_LENGTH;
	for (ft_cur = ft_end; ft_cur != ft-1; --ft_cur) {
		uint8_t *start_addr = NULL;
		uint8_t *dest_addr = NULL;
		uint16_t buf_len = ft_cur->ft_len;
		buf = ft_cur->ft_buf;

		if (ft_cur->ft_flags & NS_INDIRECT) {
			return EINVAL;
		}
		if (ft_cur != ft_end) {
			/* copy 4 bytes from the end of the current buffer
			 * to the beginning of the next buffer
			 */
			uint8_t *next_buf = (ft_cur+1)->ft_buf;
			start_addr = buf + buf_len - TAG_LENGTH;
			dest_addr = next_buf;
			*(uint32_t *)dest_addr = *(uint32_t *)start_addr;
		}

		start_addr = buf + ft_cur->ft_offset;
		dest_addr = start_addr + TAG_LENGTH;
		/* we already added TAG_LENGTH to ft_end->ft_len, therefore the
		 * last fragment case is covered without any additional check
		 */
		n_bytes = buf_len - TAG_LENGTH - ft_cur->ft_offset;
		memmove(dest_addr, start_addr, n_bytes);
	}

	/* now we need to write the tag */
	be_tpid = htobe16(0x8100);
	be_tci = htobe16(vlan_id);
	buf = ft->ft_buf;
	*(uint16_t *)(buf + ft->ft_offset + TAG_PID) = be_tpid;
	*(uint16_t *)(buf + ft->ft_offset + TAG_CI) = be_tci;

	return 0;
}



static int
untag_frame(struct nm_bdg_fwd *ft, struct netmap_vp_adapter *vpna,
	uint16_t *vlan_id)
{
	struct nm_bdg_fwd *ft_end = ft + ft->ft_frags - 1;
	struct nm_bdg_fwd *ft_cur = NULL;
	uint8_t *buf = NULL;
	uint16_t be_tpid;
	uint16_t be_tci;
	int n_bytes = 0;

	if (ft->ft_offset + TAG_END > ft->ft_len) {
		/* VLAN header not contained in the first fragment */
		return EINVAL;
	}
	if (ft_end->ft_len < TAG_LENGTH) {
		/* During the untagging we strip TAG_LENGTH bytes from the
		 * frame, therefore in this case last fragment would become
		 * empty and we would need to update fragmentation flags etc.
		 * At the moment we don't handle this case.
		 */
		return EINVAL;
	}

	/* first we retrieve the informations we need */
	buf = ft->ft_buf + ft->ft_offset;
	be_tpid = *(uint16_t *)(buf + TAG_PID);
	if (be_tpid != htobe16(0x8100)) {
		nm_prinf("Not an IEEE802.Q frame\n");
		return EINVAL;
	}
	be_tci = *(uint16_t *)(buf + TAG_CI);
	*vlan_id = be16toh(be_tci) & 0x0FFF;

	/* then we remove the tag */
	for (ft_cur = ft; ft_cur != ft_end+1; ++ft_cur) {
		uint8_t *start_addr = NULL;
		uint8_t *dest_addr = NULL;
		uint16_t buf_len = ft_cur->ft_len;
		buf = ft_cur->ft_buf;

		if (ft_cur->ft_flags & NS_INDIRECT) {
			/* we do not support indirect userspace buffers */
			return EINVAL;
		}
		if (ft_cur != ft) {
			/* copy 4 bytes from the start of the current buffer
			 * to the end of the previous buffer
			 */
			struct nm_bdg_fwd *prev_ft = ft_cur - 1;
			uint8_t *prev_buf = prev_ft->ft_buf;
			uint16_t prev_buf_len = prev_ft->ft_len;

			start_addr = buf;
			dest_addr = prev_buf + prev_buf_len - TAG_LENGTH;
			*(uint32_t *)dest_addr = *(uint32_t *)start_addr;
		}

		dest_addr = buf + ft->ft_offset;
		start_addr = dest_addr + TAG_LENGTH;
		n_bytes = buf_len - TAG_LENGTH - ft->ft_offset;
		memmove(dest_addr, start_addr, n_bytes);
	}

	ft_end->ft_len -= TAG_LENGTH;
	return 0;
}


/* Core data structure used by tagging bridges to forward frames.
 *
 * trunk port: index of the trunk port inside the tagging VALE bridge
 * port_to_vlan_id: translates a port index to its corresponding vlan id
 * vlan_id_to_port: translates a vlan id to its corresponding port index
 */
struct vlan_lookup_data {
	uint32_t trunk_port;
	uint16_t port_to_vlan_id[NM_BDG_MAXPORTS];
	uint32_t vlan_id_to_port[VV_MAX_VLAN_ID];
};



/* must be called with vv_global_lock */
static void
initialize_lookup_data(struct vlan_lookup_data *l_data)
{
	int i;

	l_data->trunk_port = NM_BDG_NOPORT;
	for (i = 0; i < NM_BDG_MAXPORTS; ++i) {
		l_data->port_to_vlan_id[i] = 0x000;
	}
	for (i = 0; i < VV_MAX_VLAN_ID; ++i) {
		l_data->vlan_id_to_port[i] = NM_BDG_NOPORT;
	}
}



struct port_elem {
	struct port port_desc;
	vv_list_entry(port_elem) list;
};



/* for each vlan conf there is only one tagging bridge,
 * therefore we can store a lookup data structure directly inside
 * the struct which describes the configuration
 */
struct vale_vlan_conf {
	struct vlan_lookup_data l_data;
	char conf_name[NETMAP_REQ_IFNAMSIZ];
	void *vlan_bdg_auth_tokens[VV_MAX_VLAN_ID];
	void *mod_bdg_auth_token;
	uint32_t number_of_ports[VV_MAX_VLAN_ID];
	vv_list_declare(list_head, port_elem) port_list;
};



/* there is one 'vlan_id bridge' with a specific vlan_id per configuration,
 * therefore we only need the configuration name and vlan_id to create
 * a unique bridge name
 */
static inline void
get_vlan_bdg_name(char *bridge_name, size_t len, const char *conf_name,
	uint16_t vlan_id)
{

	snprintf(bridge_name, len, "valeV%d%s:", vlan_id, conf_name);
}



static inline void
get_ap_name(char *port_name, size_t len, const char *conf_name,
	uint16_t vlan_id)
{

	snprintf(port_name, len, "%sAP%d", conf_name, vlan_id);
}



/* there is one tagging bridge per configuration, therefore we
 * only need the configuration name to create a unique bridge name
 */
static inline void
get_tagging_bdg_name(char *bridge_name, size_t len, const char *conf_name)
{

	snprintf(bridge_name, len, "valeV%sTP:", conf_name);
}



static void
initialize_conf(struct vale_vlan_conf *conf)
{

	initialize_lookup_data(&(conf->l_data));
	conf->conf_name[0] = '\0';
	bzero(conf->vlan_bdg_auth_tokens, sizeof(conf->vlan_bdg_auth_tokens));
	conf->mod_bdg_auth_token = NULL;
	bzero(conf->number_of_ports, sizeof(conf->number_of_ports));
	vv_list_head_init(&conf->port_list);
}



static uint32_t
vlan_lookup(struct nm_bdg_fwd *ft, uint8_t *dst_ring,
	struct netmap_vp_adapter *vpna, void *lookup_data)
{
	struct vlan_lookup_data *l_data = lookup_data;
	uint32_t bdg_port = vpna->bdg_port;
	uint32_t dest_port = NM_BDG_NOPORT;
	uint16_t vlan_id = 0x000;
	const char *bdg_name;
	int ret = 0;

	bdg_name = netmap_bdg_name(vpna);

	if (unlikely(ft->ft_flags & NS_INDIRECT)) {
		/* we do not handle userspace indirect buffers */
		return NM_BDG_NOPORT;
	}

	if (bdg_port == l_data->trunk_port) {
		ret = untag_frame(ft, vpna, &vlan_id);
		if (ret) {
			return NM_BDG_NOPORT;
		}

		dest_port = l_data->vlan_id_to_port[vlan_id];
	} else {
		vlan_id = l_data->port_to_vlan_id[bdg_port];
		ret = tag_frame(ft, vpna, vlan_id);
		if (ret) {
			return NM_BDG_NOPORT;
		}

		dest_port = l_data->trunk_port;
	}

	return dest_port;
}



static struct netmap_bdg_ops vlan_ops = {vlan_lookup, NULL, NULL};



static inline int
modify_bdg(struct vale_vlan_conf *conf, const char *bdg_name)
{

	nm_prinf("Trying to modify bdg %s for conf %s\n",
		bdg_name, conf->conf_name);
	return netmap_bdg_regops(bdg_name, &vlan_ops, &conf->l_data,
		conf->mod_bdg_auth_token);
}



static inline int
reset_bdg(struct vale_vlan_conf *conf, const char *bdg_name)
{

	nm_prinf("Trying to reset bdg %s for conf %s\n",
		bdg_name, conf->conf_name);
	return netmap_bdg_regops(bdg_name, NULL, NULL,
		conf->mod_bdg_auth_token);
}



#define MAX_VLAN_CONFS 4
/* used to access currently active vlan confs */
static uint16_t vlan_conf_index[MAX_VLAN_CONFS];
static struct vale_vlan_conf vlan_confs[MAX_VLAN_CONFS];
static uint16_t num_active_vlan_confs = 0;



/* Fails if conf alredy exists or we're out of space */
static int
vale_vlan_create_conf(const char *conf_name, uint16_t *conf_index)
{
	uint16_t free_conf = MAX_VLAN_CONFS;
	char tagging_bdg_name[NETMAP_REQ_IFNAMSIZ];
	struct vale_vlan_conf *conf = NULL;
	void *auth_token = NULL;
	int ret = 0;
	int i;

	if (num_active_vlan_confs == MAX_VLAN_CONFS) {
		nm_prinf("vale_vlan: maximum number of"
			"configurations reached\n");
		return ENOMEM;
	}

	for (i = 0; i < MAX_VLAN_CONFS; ++i) {
		if (strncmp(vlan_confs[i].conf_name,
			    conf_name,
			    sizeof(vlan_confs[i].conf_name)) == 0) {
			nm_prinf("vale_vlan: a configuration named"
				"%s alredy exists\n", conf_name);
			return EEXIST;
		} else if (vlan_confs[i].conf_name[0] == '\0') {
			/* a free slot is represented by an empty conf_name */
			free_conf = i;
		}
	}

	/* create bridge in exclusive mode */
	get_tagging_bdg_name(tagging_bdg_name, sizeof(tagging_bdg_name),
		conf_name);
	auth_token = netmap_bdg_create(tagging_bdg_name, &ret);
	if (auth_token == NULL || ret != 0) {
		nm_prerr("Error %d during bridge %s creation\n",
			ret, tagging_bdg_name);
		return ret;
	}

	vlan_conf_index[num_active_vlan_confs++] = free_conf;
	conf = &vlan_confs[free_conf];
	initialize_conf(conf);
	strncpy(conf->conf_name, conf_name, sizeof(conf->conf_name));
	/* makes sure the string is null-byte ended */
	conf->conf_name[sizeof(conf->conf_name)-1] = '\0';
	conf->mod_bdg_auth_token = auth_token;
	*conf_index = free_conf;

	ret = modify_bdg(conf, tagging_bdg_name);
	if (ret) {
		int ret2;
		nm_prerr("Error %d during bridge %s regops()\n",
			ret, tagging_bdg_name);
		ret2 = netmap_bdg_destroy(tagging_bdg_name,
			conf->mod_bdg_auth_token);
		if (ret2) {
			/* cannot happen */
			nm_prerr("Error %d during bridge %s destroy(), "
				 "this should never happen\n",
				ret2, tagging_bdg_name);
		}
		initialize_conf(conf);
		--num_active_vlan_confs;
		return ret;
	}
	vv_try_module_get();

	nm_prinf("vale_vlan: successfully created "
		 "configuration %s\n", conf_name);
	return 0;
}



/* Fails if the conf doesn't exist
 *
 * must be called with vv_global_lock
 */
static int
vale_vlan_select_conf(const char *conf_name, uint16_t *conf_index)
{
	int i;

	for (i = 0; i < num_active_vlan_confs; ++i) {
		int index = vlan_conf_index[i];
		if (strncmp(vlan_confs[index].conf_name,
			    conf_name,
			    sizeof(vlan_confs[index].conf_name)) == 0) {
			*conf_index = index;
			nm_prinf("vale_vlan: successfully selected "
				"configuration %s\n", conf_name);
			return 0;
		}
	}

	nm_prinf("vale_vlan: a configuration named %s doesn't exist\n",
		conf_name);
	return ENXIO;
}



/* Fails if the conf doesn't exist or the tagging bridge isn't empty
 *
 * must be called with vv_global_lock
 */
static int
vale_vlan_delete_conf(const char *conf_name)
{
	uint16_t conf_index = MAX_VLAN_CONFS;
	char tagging_bdg_name[NETMAP_REQ_IFNAMSIZ];
	struct vale_vlan_conf *conf = NULL;
	uint16_t i;
	int ret;

	for (i = 0; i < num_active_vlan_confs; ++i) {
		int index = vlan_conf_index[i];
		if (strncmp(vlan_confs[index].conf_name,
			    conf_name,
			    sizeof(vlan_confs[index].conf_name)) == 0) {
			conf = &vlan_confs[index];
			conf_index = i;
			break;
		}
	}

	if (!conf || i == num_active_vlan_confs) {
		/* conf doesn't exist */
		return ENXIO;
	}

	/* redundant check */
	for (i = 0; i < VV_MAX_VLAN_ID; ++i) {
		if (conf->number_of_ports[i] != 0) {
			return EBUSY;
		}
	}

	get_tagging_bdg_name(tagging_bdg_name, sizeof(tagging_bdg_name),
		conf_name);
	ret = netmap_bdg_destroy(tagging_bdg_name,
		conf->mod_bdg_auth_token);
	if (ret) {
		/* cannot happen (?) */
		nm_prerr("Error %d during bridge %s destroy(), "
			 "this should not happend\n", ret, tagging_bdg_name);
		return ret;
	}

	conf->conf_name[0] = '\0';	/* marks conf slot as free */
	vlan_conf_index[conf_index] = vlan_conf_index[--num_active_vlan_confs];
	vv_module_put();
	return 0;
}


/* returns 0 if conf_index isn't a possible index or if
 * the conf entry isn't in use
 *
 * must be called with vv_global_lock
 */
static int
conf_exists(int conf_index)
{

	if (conf_index < 0 || conf_index >= MAX_VLAN_CONFS) {
		return 0;
	}
	return vlan_confs[conf_index].conf_name[0] != '\0';
}



#define NM_API_VERSION 12



static void *
modify_trunk_port(void *private_data, void *callback_data, int *error)
{
	struct vlan_lookup_data *l_data = private_data;
	uint32_t *new_trunk_port = callback_data;

	l_data->trunk_port = *new_trunk_port;
	*error = 0;
	return l_data;
}



struct mod_access_port {
	uint32_t old_port_index;
	uint32_t new_port_index;
	uint16_t old_vlan_id;
	uint16_t new_vlan_id;
};



static void *
modify_access_port(void *private_data, void *callback_data, int *error)
{
	struct vlan_lookup_data *l_data = private_data;
	struct mod_access_port *mod = callback_data;

	l_data->port_to_vlan_id[mod->old_port_index] = mod->new_vlan_id;
	l_data->vlan_id_to_port[mod->old_vlan_id] = mod->new_port_index;
	*error = 0;
	return l_data;
}



static int
create_vale_port(const char* name)
{
	struct nmreq_vale_newif newif;
	struct nmreq_header hdr;
	int ret = 0;

	nm_prinf("Trying to create port %s\n", name);

	bzero(&hdr, sizeof(hdr));
	hdr.nr_version = NM_API_VERSION;
	hdr.nr_reqtype = NETMAP_REQ_VALE_NEWIF;
	strncpy(hdr.nr_name, name, sizeof(hdr.nr_name));
	hdr.nr_name[sizeof(hdr.nr_name)-1] = '\0';

	bzero(&newif, sizeof(newif));
	hdr.nr_body = (uintptr_t)&newif;

	ret = nm_vi_create(&hdr);
	if (ret == 0) {
		vv_try_module_get();
	} else {
		nm_prerr("Error %d during port %s nm_vi_create()\n", ret, name);
	}

	return ret;
}



static int
destroy_vale_port(const char* name)
{
	int ret;

	nm_prinf("Trying to destroy port %s\n", name);
	ret = nm_vi_destroy(name);
	if (ret == 0) {
		vv_module_put();
	} else {
		nm_prerr("Error %d during port %s nm_vi_destroy()\n",
			ret, name);
	}
	return ret;
}



static int
attach_port_list(struct vale_vlan_conf *conf, const char *bdg_name,
    const char *port_name, uint8_t port_type, uint16_t vlan_id)
{
	struct port_elem *p_elem = NULL;

	p_elem = vv_malloc(sizeof(struct port_elem));
	if (!p_elem) {
		return EFAULT;
	}

	vv_list_elem_init(p_elem, list);
	p_elem->port_desc.vlan_id = vlan_id;
	p_elem->port_desc.port_type = port_type;
	snprintf(p_elem->port_desc.bdg_name,
		sizeof(p_elem->port_desc.bdg_name), "%s", bdg_name);
	snprintf(p_elem->port_desc.port_name,
		sizeof(p_elem->port_desc.port_name), "%s", port_name);
	vv_list_insert_head(&conf->port_list, p_elem, list);
	return 0;
}



static int
detach_port_list(struct vale_vlan_conf *conf, const char *port_name)
{
	struct port_elem *cursor = NULL;
	struct port_elem *next = NULL;

	vv_list_foreach_safe(cursor, &conf->port_list, list, next) {
		if (strncmp(cursor->port_desc.port_name,
			    port_name,
			    sizeof(cursor->port_desc.port_name)) == 0) {
			vv_list_remove(cursor, list);
			vv_free(cursor);
			return 0;
		}
	}

	return ENXIO;
}



static int detach_trunk_port(struct vale_vlan_conf *, const char *, uint16_t);
static int detach_access_port(struct vale_vlan_conf *, const char *, uint16_t);



static int
attach_port(const char *bdg_name, const char *port_name, void *auth_token,
	uint32_t *port_index)
{
	struct nmreq_vale_attach nmr_att;
	struct nmreq_header hdr;
	int ret = 0;

	nm_prinf("Trying to attach port %s%s\n", bdg_name, port_name);
	bzero(&nmr_att, sizeof(nmr_att));
	nmr_att.reg.nr_mode = NR_REG_ALL_NIC;

	bzero(&hdr, sizeof(hdr));
	hdr.nr_version = NM_API_VERSION;
	hdr.nr_reqtype = NETMAP_REQ_VALE_ATTACH;
	hdr.nr_body = (uintptr_t)&nmr_att;
	snprintf(hdr.nr_name, sizeof(hdr.nr_name), "%s%s", bdg_name, port_name);

	ret = nm_bdg_ctl_attach(&hdr, auth_token);
	if (ret == 0) {
		vv_try_module_get();

	}
	*port_index = nmr_att.port_index;
	return ret;
}



static int
detach_port(const char *bdg_name, const char *port_name, void *auth_token,
	uint32_t *port_index)
{
	struct nmreq_vale_detach nmr_det;
	struct nmreq_header hdr;
	int ret = 0;

	nm_prinf("Trying to detach port %s%s\n", bdg_name, port_name);
	bzero(&nmr_det, sizeof(nmr_det));

	bzero(&hdr, sizeof(hdr));
	hdr.nr_version = NM_API_VERSION;
	hdr.nr_reqtype = NETMAP_REQ_VALE_DETACH;
	hdr.nr_body = (uintptr_t)&nmr_det;
	snprintf(hdr.nr_name, sizeof(hdr.nr_name), "%s%s", bdg_name, port_name);

	ret = nm_bdg_ctl_detach(&hdr, auth_token);
	if (ret == 0) {
		vv_module_put();
	}
	*port_index = nmr_det.port_index;
	return ret;
}



static int
attach_access_port(struct vale_vlan_conf *conf, const char *port_name,
	uint16_t vlan_id)
{
	void *vlan_bdg_auth_token = conf->vlan_bdg_auth_tokens[vlan_id];
	uint32_t port_index = NM_BDG_NOPORT;
	char tagging_bdg_name[NETMAP_REQ_IFNAMSIZ];
	char vlan_bdg_name[NETMAP_REQ_IFNAMSIZ];
	struct mod_access_port mod_ap;
	char ap_name[NETMAP_REQ_IFNAMSIZ];
	int ret = 0;

	nm_prinf("Trying to attach port %s with vlan id: %d to conf %s\n",
		port_name, vlan_id, conf->conf_name);
	if (vlan_id == 0x000 || vlan_id == 0xFFF) {
		return EINVAL;
	}
	get_tagging_bdg_name(tagging_bdg_name, sizeof(tagging_bdg_name),
		conf->conf_name);
	get_vlan_bdg_name(vlan_bdg_name, sizeof(vlan_bdg_name), conf->conf_name,
		vlan_id);

	if (conf->number_of_ports[vlan_id] == 0) {
		/* we need to create a bridge in exclusive mode */
		vlan_bdg_auth_token = netmap_bdg_create(vlan_bdg_name, &ret);
		if (vlan_bdg_auth_token == NULL || ret != 0) {
			return ret;
		}

		conf->vlan_bdg_auth_tokens[vlan_id] = vlan_bdg_auth_token;
	}

	ret = attach_port(vlan_bdg_name, port_name, vlan_bdg_auth_token,
		&port_index);
	if (ret) {
		goto l_destroy_vlan_bdg;
	}

	if (++conf->number_of_ports[vlan_id] != 1) {
		/* an access port has alredy been created and attached to the
		 * tagging bridge
		 */
		return ret;
	}

	/* we need to create an access port and attach it
	 * to the tagging bridge
	 */
	get_ap_name(ap_name, sizeof(ap_name), conf->conf_name, vlan_id);
	ret = create_vale_port(ap_name);
	if (ret) {
		goto l_detach_access_port;
	}

	ret = attach_port(vlan_bdg_name, ap_name, vlan_bdg_auth_token,
		&port_index);
	if (ret) {
		goto l_destroy_access_port;
	}

	ret = attach_port(tagging_bdg_name, ap_name,
		conf->mod_bdg_auth_token, &port_index);
	if (ret) {
		goto l_detach_access_port_vlan_bdg;
	}

	/* this can fail only if bdg_name doesn't exist or hasn't been tagging
	 * by us, and in either case we would have alredy failed one of our
	 * previous call
	 */
	mod_ap.old_port_index = mod_ap.new_port_index = port_index;
	mod_ap.old_vlan_id = mod_ap.new_vlan_id = vlan_id;
	nm_bdg_update_private_data(tagging_bdg_name, modify_access_port,
		&mod_ap, conf->mod_bdg_auth_token);

	return ret;

l_detach_access_port_vlan_bdg:
	/* cannot fail */
	detach_port(vlan_bdg_name, ap_name, vlan_bdg_auth_token, &port_index);

l_destroy_access_port:
	/* cannot fail */
	destroy_vale_port(ap_name);

l_detach_access_port:
	/* cannot fail */
	detach_port(vlan_bdg_name, port_name, vlan_bdg_auth_token, &port_index);
	--conf->number_of_ports[vlan_id];

l_destroy_vlan_bdg:
	if (conf->number_of_ports[vlan_id] == 0) {
		/* we need to destroy the vlan bridge only when we fail
		 * something after creating it
		 */
		conf->vlan_bdg_auth_tokens[vlan_id] = NULL;
		/* cannot fail */
		netmap_bdg_destroy(vlan_bdg_name, vlan_bdg_auth_token);
	}

	return ret;
}



static int
attach_trunk_port(struct vale_vlan_conf *conf, const char *port_name,
	uint16_t vlan_id)
{
	uint32_t port_index = NM_BDG_NOPORT;
	char mod_bdg_name[NETMAP_REQ_IFNAMSIZ];
	int ret = 0;

	if (vlan_id != 0xFFF || conf->l_data.trunk_port != NM_BDG_NOPORT) {
		return EINVAL;
	}

	get_tagging_bdg_name(mod_bdg_name, sizeof(mod_bdg_name),
		conf->conf_name);
	ret = attach_port(mod_bdg_name, port_name, conf->mod_bdg_auth_token,
		&port_index);
	if (ret) {
		return ret;
	}

	/* this can't fail because we have the bridge in exclusive mode */
	nm_bdg_update_private_data(mod_bdg_name, modify_trunk_port,
		&port_index, conf->mod_bdg_auth_token);
	return ret;
}




static int
action_attach(struct vale_vlan_conf *conf, const char *port_name,
	uint8_t port_type, uint16_t vlan_id)
{
	char bdg_name[NETMAP_REQ_IFNAMSIZ];
	int ret = 0;

	switch (port_type){
	case TRUNK_PORT:
		ret = attach_trunk_port(conf, port_name, vlan_id);
		if (ret) {
			return ret;
		}
		get_tagging_bdg_name(bdg_name, sizeof(bdg_name),
			conf->conf_name);
		break;

	case ACCESS_PORT:
		ret = attach_access_port(conf, port_name, vlan_id);
		if (ret) {
			return ret;
		}
		get_vlan_bdg_name(bdg_name, sizeof(bdg_name), conf->conf_name,
			vlan_id);
		break;

	default:
		return EINVAL;
	}


	ret = attach_port_list(conf, bdg_name, port_name, port_type, vlan_id);
	if (ret) {
		switch (port_type){
		case TRUNK_PORT:
			/* cannot fail */
			detach_trunk_port(conf, port_name, vlan_id);
			break;

		case ACCESS_PORT:
			/* cannot fail */
			detach_access_port(conf, port_name, vlan_id);
			break;
		}
	}

	return ret;
}



static int
action_create_and_attach(struct vale_vlan_conf *conf, const char *port_name,
	uint8_t port_type, uint16_t vlan_id)
{
	int ret = 0;

	ret = create_vale_port(port_name);
	if (ret) {
		return ret;
	}

	ret = action_attach(conf, port_name, port_type, vlan_id);
	if (ret) {
		/* cannot fail */
		destroy_vale_port(port_name);
	}

	return ret;
}



static int
detach_trunk_port(struct vale_vlan_conf *conf, const char *port_name,
	uint16_t vlan_id)
{
	uint32_t port_index = NM_BDG_NOPORT;
	char bdg_name[NETMAP_REQ_IFNAMSIZ];
	int ret = 0;

	if (vlan_id != 0xFFF) {
		return EINVAL;
	}

	get_tagging_bdg_name(bdg_name, sizeof(bdg_name), conf->conf_name);
	ret = detach_port(bdg_name, port_name, conf->mod_bdg_auth_token,
		&port_index);
	if (ret) {
		return ret;
	}

	port_index = NM_BDG_NOPORT;
	/* this can't fail because we have the bridge in exlusive mode */
	nm_bdg_update_private_data(bdg_name, modify_trunk_port,
		&port_index, conf->mod_bdg_auth_token);
	return ret;
}



static int
detach_access_port(struct vale_vlan_conf *conf, const char *port_name,
	uint16_t vlan_id)
{
	struct mod_access_port mod_access_port;
	uint32_t port_index = NM_BDG_NOPORT;
	void *vlan_bdg_auth_token = NULL;
	char tagging_bdg_name[NETMAP_REQ_IFNAMSIZ];
	char vlan_bdg_name[NETMAP_REQ_IFNAMSIZ];
	char ap_name[NETMAP_REQ_IFNAMSIZ];
	int ret = 0;

	if (vlan_id == 0x000 || vlan_id == 0xFFF) {
		return EINVAL;
	}
	get_vlan_bdg_name(vlan_bdg_name, sizeof(vlan_bdg_name), conf->conf_name,
		vlan_id);
	get_tagging_bdg_name(tagging_bdg_name, sizeof(tagging_bdg_name),
		conf->conf_name);
	get_ap_name(ap_name, sizeof(ap_name), conf->conf_name, vlan_id);
	vlan_bdg_auth_token = conf->vlan_bdg_auth_tokens[vlan_id];

	ret = detach_port(vlan_bdg_name, port_name, vlan_bdg_auth_token,
		&port_index);
	if (ret) {
		return ret;
	}

	if (--conf->number_of_ports[vlan_id] > 0) {
		/* there are still other vlan ports on this vlan bridge */
		return ret;
	}

	/* we have just detached the last vlan port on this bridge, we need
	 * to remove (and destroy) the access port and the bridge as well
	 */
	ret = detach_port(tagging_bdg_name, ap_name,
		conf->mod_bdg_auth_token, &port_index);
	if (ret) {
		goto l_attach_access_port;
	}

	ret = detach_port(vlan_bdg_name, ap_name, vlan_bdg_auth_token,
		&port_index);
	if (ret) {
		goto l_attach_access_port_mod_bdg;
	}

	ret = destroy_vale_port(ap_name);
	if (ret) {
		goto l_attach_access_port_vlan_bdg;
	}

	ret = netmap_bdg_destroy(vlan_bdg_name, vlan_bdg_auth_token);
	if (ret) {
		/* cannot happen (?) */
		goto l_create_access_port;
	}

	mod_access_port.old_port_index = port_index;
	mod_access_port.new_port_index = NM_BDG_NOPORT;
	mod_access_port.old_vlan_id = vlan_id;
	mod_access_port.new_vlan_id = 0x000;
	/* this can't fail because we have the bridge in exlusive mode */
	nm_bdg_update_private_data(tagging_bdg_name, modify_access_port,
		&mod_access_port, conf->mod_bdg_auth_token);


	return ret;

l_create_access_port:
	create_vale_port(ap_name); /* cannot fail */

l_attach_access_port_vlan_bdg:
	/* cannot fail */
	attach_port(vlan_bdg_name, ap_name, vlan_bdg_auth_token, &port_index);

l_attach_access_port_mod_bdg:
	/* cannot fail */
	attach_port(tagging_bdg_name, ap_name, conf->mod_bdg_auth_token,
		&port_index);

l_attach_access_port:
	/* cannot fail */
	attach_port(vlan_bdg_name, port_name, vlan_bdg_auth_token, &port_index);
	++conf->number_of_ports[vlan_id];

	return ret;

}



static int
lookup_vlan_id(struct vale_vlan_conf *conf, const char *port_name,
	uint16_t *vlan_id)
{
	struct port_elem *p_elem = NULL;

	vv_list_foreach(p_elem, &conf->port_list, list) {
		if (strcmp(p_elem->port_desc.port_name, port_name) == 0) {
			*vlan_id = p_elem->port_desc.vlan_id;
			return 0;
		}
	}
	return ENXIO;
}



static int
lookup_trunk_port(struct vale_vlan_conf *conf, char *trunk_port_name)
{
	struct port_elem *p_elem = NULL;

	vv_list_foreach(p_elem, &conf->port_list, list) {
		if (p_elem->port_desc.port_type == TRUNK_PORT) {
			snprintf(trunk_port_name, NETMAP_REQ_IFNAMSIZ, "%s",
				p_elem->port_desc.port_name);
			return 0;
		}
	}
	return ENXIO;
}



static int
action_detach(struct vale_vlan_conf *conf, char *port_name, uint8_t port_type,
	uint16_t vlan_id)
{
	int ret = 0;

	switch (port_type) {
	case TRUNK_PORT:
		if (port_name[0] == '\0') {
			ret = lookup_trunk_port(conf, port_name);
			if (ret) {
				return ret;
			}
		}
		ret = detach_trunk_port(conf, port_name, vlan_id);
		if (ret) {
			return ret;
		}
		break;

	case ACCESS_PORT:
		if (vlan_id == 0xFFF) {
			ret = lookup_vlan_id(conf, port_name, &vlan_id);
			if (ret) {
				return ret;
			}
		}

		ret = detach_access_port(conf, port_name, vlan_id);
		if (ret) {
			return ret;
		}
		break;

	default:
		return EINVAL;
	}

	ret = detach_port_list(conf, port_name);
	if (ret) {
		switch (port_type){
		case TRUNK_PORT:
			ret = attach_trunk_port(conf, port_name, vlan_id);
			break;

		case ACCESS_PORT:
			ret = attach_access_port(conf, port_name, vlan_id);
			break;
		}
	}

	return ret;
}



static int
action_detach_and_destroy(struct vale_vlan_conf *conf, char *port_name,
	uint8_t port_type, uint16_t vlan_id)
{
	int ret = 0;

	ret = action_detach(conf, port_name, port_type, vlan_id);
	if (ret) {
		return ret;
	}

	ret = destroy_vale_port(port_name);
	if (ret) {
		/* cannot fail */
		action_attach(conf, port_name, port_type, vlan_id);
	}
	return ret;
}



int
vv_write(struct vale_vlan_dev *dev, struct vlan_conf_entry *entries, size_t len)
{
	struct vale_vlan_conf *conf = &vlan_confs[dev->selected_conf];
	struct vlan_conf_entry *cur;
	int rollback_ret;
	int n_entries;
	int ret;
	int i;

	if (len % sizeof(struct vlan_conf_entry) != 0) {
		nm_prerr("write() must receive an array of "
			 "'struct vlan_conf_entry', len of entries %d\n",
			 (int)len);
		return EINVAL;
	}
	if (!conf_exists(dev->selected_conf)) {
		nm_prerr("vale_vlan: you must first select or create a "
			"vlan conf through an ioctl()\n");
		return EINVAL;
	}

	n_entries = len / sizeof(struct vlan_conf_entry);
	dev->error_entry = -1;
	for(i = 0, cur = entries; i < n_entries; ++i, ++cur) {
		/* parameter checks */
		if ((cur->port_type != TRUNK_PORT
			&& cur->port_type != ACCESS_PORT)
			|| cur->vlan_id >= 4095) {
			nm_prinf("vale_vlan: invalid parameter for "
				"entry number %d\n", i);
			ret = EINVAL;
			goto l_rollback_write;
		}

		switch (cur->action) {
		case CREATE_AND_ATTACH_PORT:
			ret = action_create_and_attach(conf, cur->port_name,
				cur->port_type, cur->vlan_id);
			if (ret) {
				nm_prerr("vale_vlan: error %d during action "
					"CREATE_AND_ATTACH_PORT, entry n. %d\n",
					ret, i);
				goto l_rollback_write;
			}
			break;

		case ATTACH_PORT:
			ret = action_attach(conf, cur->port_name,
				cur->port_type, cur->vlan_id);
			if (ret) {
				nm_prerr("vale_vlan: error %d during action "
					"ATTACH_PORT, entry n. %d\n", ret, i);
				goto l_rollback_write;
			}
			break;

		case DETACH_AND_DESTROY_PORT:
			ret = action_detach_and_destroy(conf, cur->port_name,
				cur->port_type, cur->vlan_id);
			if (ret) {
				nm_prerr("vale_vlan: error %d during "
					"DETACH_AND_DESTROY_PORT, entry n. %d\n",
					ret, i);
				goto l_rollback_write;
			}
			break;

		case DETACH_PORT:
			ret = action_detach(conf, cur->port_name,
				cur->port_type, cur->vlan_id);
			if (ret) {
				nm_prerr("vale_vlan: error %d during "
					"DETACH_PORT, entry n. %d\n", ret, i);
				goto l_rollback_write;
			}
			break;

		default:
			nm_prinf("vale_vlan: unknown action for "
				"entry number %d\n", i);
			ret = EINVAL;
			goto l_rollback_write;
		}
	}
	return ret;

l_rollback_write:
	dev->error_entry = i;
	rollback_ret = ret;
	for (--i, --cur; i >= 0; --i, --cur) {
		switch (cur->action) {
		case CREATE_AND_ATTACH_PORT:
			ret = action_detach_and_destroy(conf, cur->port_name,
				cur->port_type, cur->vlan_id);
			if (ret) {
				nm_prerr("Failed while rollbacking, "
					"entry n. %d\n", i);
			}
			break;

		case ATTACH_PORT:
			ret = action_detach(conf, cur->port_name,
				cur->port_type, cur->vlan_id);
			if (ret) {
				nm_prerr("Failed while rollbacking, "
					"entry n. %d\n", i);
			}
			break;

		case DETACH_AND_DESTROY_PORT:
			ret = action_create_and_attach(conf, cur->port_name,
				cur->port_type, cur->vlan_id);
			if (ret) {
				nm_prerr("Failed while rollbacking, "
					"entry n. %d\n", i);
			}
			break;

		case DETACH_PORT:
			ret = action_attach(conf, cur->port_name,
				cur->port_type, cur->vlan_id);
			if (ret) {
				nm_prerr("Failed while rollbacking, "
					"entry n. %d\n", i);
			}
			break;
		}
	}

	return rollback_ret;
}


int
vv_read(struct vale_vlan_dev *dev, uint8_t *buf, size_t *len)
{

	if (dev->selected_conf == -1) {
		return EINVAL;
	}

	if (dev->error_entry != -1) {
		/* error read() */
		if (*len != sizeof(dev->error_entry)) {
			nm_prerr("After receiving an error from a write() call,"
				" read() must receive a int32_t pointer\n");
			return EINVAL;
		}

		memcpy(buf, &dev->error_entry, sizeof(dev->error_entry));
		*len = sizeof(dev->error_entry);
		dev->error_entry = -1;
	} else {
		/* conf read() */
		struct vale_vlan_conf *conf;
		struct port_elem *p_elem;
		size_t ret = 0;

		if (*len % sizeof(struct port) != 0) {
			nm_prerr("read() must receive an array of "
				"'struct vlan_conf_entry'\n");
			return EINVAL;
		}

		conf = &vlan_confs[dev->selected_conf];
		vv_list_foreach(p_elem, &conf->port_list, list) {
			if (*len < ret + sizeof(struct port) ) {
				*len = ret;
				return 0;
			}
			memcpy(buf, &p_elem->port_desc,
				sizeof(p_elem->port_desc));
			ret += sizeof(struct port);
			buf += sizeof(struct port);
		}

		*len = ret;
	}

	return 0;
}



void
vv_init_dev(struct vale_vlan_dev *dev)
{
	dev->selected_conf = -1;
	dev->error_entry = -1;
}



long
vv_iocctrl(struct vale_vlan_dev *dev, struct vlanreq_header *req)
{
	uint16_t req_type = req->vr_req_type;
	uint16_t conf_index = MAX_VLAN_CONFS;
	int ret;

	switch (req_type) {
	case VV_REQ_CREATE_CONF:
		ret = vale_vlan_create_conf(req->vr_conf_name, &conf_index);
		if (ret) {
			nm_prerr("Error %d while creating configuration %s\n",
				ret, req->vr_conf_name);
			return ret;
		}

		dev->selected_conf = conf_index;
		break;

	case VV_REQ_SELECT_CONF:
		ret = vale_vlan_select_conf(req->vr_conf_name, &conf_index);
		if (ret) {
			nm_prerr("Error %d while selecting configuration %s\n",
				ret, req->vr_conf_name);
			return ret;
		}

		dev->selected_conf = conf_index;
		break;

	case VV_REQ_DELETE_CONF:
		ret = vale_vlan_delete_conf(req->vr_conf_name);
		if (ret) {
			nm_prerr("Configuration %s %s\n", req->vr_conf_name,
				ret == ENXIO ? "doesn't exist"
				: "still has ports attached");
			return ret;
		}

		dev->selected_conf = -1;
		break;

	default:
		return EINVAL;
	}
	return 0;
}


void
vv_init_module(void)
{
	int i;

	for (i = 0; i < MAX_VLAN_CONFS; ++i) {
		initialize_conf(&vlan_confs[i]);
	}
	nm_prinf("vale_vlan: module loaded\n");
}