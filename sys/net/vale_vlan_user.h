#ifndef _VALE_VLAN_MODULE_H_
#define _VALE_VLAN_MODULE_H_



#ifndef IF_NAMESIZE
#define IF_NAMESIZE	16
#endif



#define MAX_VLAN_ID		4096
#define VALE_VLAN_API		1
#define CONF_NAME_LENGTH	6



#define VALE_VLAN_IOC_MAGIC 'v'
#define VALE_VLAN_IOC_MAXNR 0
#define VALE_VLAN_IOCCTRL _IOWR(VALE_VLAN_IOC_MAGIC, 0, struct vlanreq_header)



/* ioctl data parameter */
struct vlanreq_header {
	uint16_t 		vr_version;	/* API version */
#define VLAN_REQ_CREATE_CONF	0x0001
#define VLAN_REQ_SELECT_CONF	0x0002
#define VLAN_REQ_DELETE_CONF	0x0003
	uint16_t 		vr_req_type;
	/* vlan configuration name */
	char			vr_conf_name[CONF_NAME_LENGTH];
	/* ptr to vlanreq_xyz struct, at the moment none exist */
	uint64_t		vr_body;
};



/* struct passed between user and kernel during write operations */
struct vlan_conf_entry {
	char 				port_name[IF_NAMESIZE];
#define TRUNK_PORT			0x01
#define VLAN_PORT 			0x02
	uint8_t 			port_type;
#define CREATE_AND_ATTACH_PORT 		0x11
#define ATTACH_PORT 			0x12
#define DETACH_AND_DESTROY_PORT		0x13
#define DETACH_PORT			0x14
	uint8_t 			action;

	/* 0x000 and 0xFFF are reserved
	 * 0x000 means that the frame doensn't carry a vlan id
	 * 0xFFF is reserved for implementation use
	 */
	uint16_t 			vlan_id;
};



/* struct passed between user and kernel during read operations */
struct port {
	char bdg_name[IF_NAMESIZE];
	char port_name[IF_NAMESIZE];
	uint16_t vlan_id;
	/* port_type defines inside struct vlan_conf_entry */
	uint8_t port_type;
};



#endif /* _VALE_VLAN_MODULE_H_ */