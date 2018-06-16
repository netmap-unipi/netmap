#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

#include <net/vale_vlan_user.h>



#define DEVICE_NAME "/dev/vale_vlan"



static int
str_to_uint16(const char *str, uint16_t *res)
{
	intmax_t val;
	char *end;
	errno = 0;

	val = strtoimax(str, &end, 10);
	if (errno == ERANGE || val < 0 || val > UINT16_MAX || end == str || *end != '\0') {
		return -1;
	}
	*res = (uint16_t) val;
	return 0;
}



static int
vlan_ioctl(int fd, const char *conf_name, uint16_t req_type)
{
	struct vlanreq_header hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.vr_req_type = req_type;
	snprintf(hdr.vr_conf_name, sizeof(hdr.vr_conf_name), "%s", conf_name);

	return ioctl(fd, VALE_VLAN_IOCCTRL, &hdr);
}


static ssize_t
vlan_write(int fd, const char *port_name, uint8_t port_type, uint8_t action,
	uint16_t vlan_id)
{
	struct vlan_conf_entry entry;

	memset(&entry, 0, sizeof(entry));
	if (port_name) {
		snprintf(entry.port_name, sizeof(entry.port_name),
			"%s",
			port_name);
	}
	entry.port_type = port_type;
	entry.vlan_id = vlan_id;
	entry.action = action;

	return write(fd, &entry, sizeof(entry));
}


#define MAX_LIST_ENTRIES 256

static void
list_conf(int fd)
{
	struct port *port_entries = NULL;
	int ret;
	int i;

	port_entries = malloc(sizeof(struct port) * MAX_LIST_ENTRIES);
	if (!port_entries) {
		exit(EXIT_FAILURE);
	}

	ret = read(fd, port_entries, sizeof(struct port) * MAX_LIST_ENTRIES);
	if (ret < 0) {
		perror("read()");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < ret / (int)sizeof(struct port); ++i) {
		printf("%s%s, type:",
			port_entries[i].bdg_name,
			port_entries[i].port_name);
		if (port_entries[i].port_type == TRUNK_PORT) {
			printf("trunk port\n");
		} else {
			printf("access port, vlan id:%d\n",
				port_entries[i].vlan_id);
		}
	}

	free(port_entries);
}



static int
valid_port_name(const char *conf_name)
{

	return (strlen(conf_name) + 1) <= IF_NAMESIZE;
}



static void
attach_vlan_port(int fd, char *port_and_vlan, int create)
{
	char port_name[IF_NAMESIZE];
	uint16_t vlan_id = 0;
	uint8_t action;
	ssize_t ret;
	char *token;

	token = strtok(port_and_vlan, "=");
	if (!token) {
		/* cannot happen (?) */
		fprintf(stderr, "You must specify a vlan id\n");
		exit(EXIT_FAILURE);
	}
	if (!valid_port_name(token)) {
		fprintf(stderr, "Max port name length = %d\n", IF_NAMESIZE);
		exit(EXIT_FAILURE);
	}
	snprintf(port_name, sizeof(port_name), "%s", token);

	token = strtok(NULL, "=");
	if (!token) {
		fprintf(stderr, "You must specify a vlan id\n");
		exit(EXIT_FAILURE);
	}
	if (str_to_uint16(token, &vlan_id) == -1 || vlan_id > 4095) {
		fprintf(stderr, "Invalid vlan id: %u\n", vlan_id);
		exit(EXIT_FAILURE);
	}

	action = create ? CREATE_AND_ATTACH_PORT : ATTACH_PORT;
	ret = vlan_write(fd, port_name, VLAN_PORT, action, vlan_id);
	if (ret < 0) {
		perror(port_name);
		exit(EXIT_FAILURE);
	}
}



static void
detach_vlan_port(int fd, const char *port_name, int destroy)
{
	uint8_t action;
	ssize_t ret;

	action = destroy ? DETACH_AND_DESTROY_PORT : DETACH_PORT;
	ret = vlan_write(fd, port_name, VLAN_PORT, action, 0xFFF);
	if (ret < 0) {
		perror(port_name);
		exit(EXIT_FAILURE);
	}
}



static void
attach_trunk_port(int fd, const char *port_name, int create)
{
	uint8_t action;
	ssize_t ret;

	if (!valid_port_name(port_name)) {
		fprintf(stderr, "Max port name length = %d\n", IF_NAMESIZE);
		exit(EXIT_FAILURE);
	}

	action = create ? CREATE_AND_ATTACH_PORT : ATTACH_PORT;
	ret = vlan_write(fd, port_name, TRUNK_PORT, action, 0xFFF);
	if (ret < 0) {
		perror(port_name);
		exit(EXIT_FAILURE);
	}
}



static void
detach_trunk_port(int fd, int destroy)
{
	uint8_t action;
	ssize_t ret;

	action = destroy ? DETACH_AND_DESTROY_PORT : DETACH_PORT;
	ret = vlan_write(fd, NULL, TRUNK_PORT, action, 0xFFF);
	if (ret < 0) {
		exit(EXIT_FAILURE);
	}
}



static int
valid_conf_name(const char *conf_name)
{

	return (strlen(conf_name) + 1) <= CONF_NAME_LENGTH;
}



static void
create_conf(int fd, const char *conf_name)
{
	int ret;

	if (!valid_conf_name(conf_name)) {
		fprintf(stderr, "Max conf name length = %d\n",
			CONF_NAME_LENGTH - 1);
		exit(EXIT_FAILURE);
	}

	ret = vlan_ioctl(fd, conf_name, VLAN_REQ_CREATE_CONF);
	if (ret < 0) {
		perror(conf_name);
		exit(EXIT_FAILURE);
	}
}



static void
delete_conf(int fd, const char *conf_name)
{
	int ret;

	if (!valid_conf_name(conf_name)) {
		fprintf(stderr, "Max conf name length = %d\n",
			CONF_NAME_LENGTH - 1);
		exit(EXIT_FAILURE);
	}

	ret = vlan_ioctl(fd, conf_name, VLAN_REQ_DELETE_CONF);
	if (ret < 0) {
		perror(conf_name);
		exit(EXIT_FAILURE);
	}
}



static void
select_conf(int fd, const char *conf_name)
{
	int ret;

	if (!valid_conf_name(conf_name)) {
		fprintf(stderr, "Max conf name length = %d\n",
			CONF_NAME_LENGTH - 1);
		exit(EXIT_FAILURE);
	}

	ret = vlan_ioctl(fd, conf_name, VLAN_REQ_SELECT_CONF);
	if (ret < 0) {
		perror(conf_name);
		exit(EXIT_FAILURE);
	}
}



static void
usage(const char *file_name, FILE *std_stream)
{

	fprintf(std_stream,
		"Usage:\n"
		"%s arguments\n"
		"\t-n conf_name		create (and select) configuration "
			"conf_name\n"
		"\t-r conf_name		delete configuration conf_name\n"
		"\t-s conf_name		select configuration conf_name\n"
		"\t-t interface		attach interface as trunk port\n"
		"\t-T			detach trunk port\n"
		"\t-p interfaces		create persistent VALE port "
			"and attach it as trunk port\n"
		"\t-P 			detach trunk port and destroy it (must "
			"have been created through -p)\n"
		"\t-a interface=vlan_id	attach interface as vlan port with id "
			"vlan_id\n"
		"\t-A interface		detach vlan port interface\n"
		"\t-c interface=vlan_id	create persistent VALE port and attach "
			"it as vlan port with id vlan_id\n"
		"\t-C interface		detach vlan port interface and destroy "
			"it (must have been created through -c)\n"
		"\t-l 			list attached interfaces\n",
		file_name);
}



int
main(int argc, char **argv)
{
	int fd;
	char c;

	if (argc == 1) {
		usage(argv[0], stderr);
		exit(EXIT_FAILURE);
	}

	fd = open(DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		perror(DEVICE_NAME);
		exit(EXIT_FAILURE);
	}

	while ((c = getopt(argc, argv, "n:s:r:t:Tp:Pc:C:a:A:hl")) != -1) {
		switch (c) {
		case 't':	/* attach trunk port */
			attach_trunk_port(fd, optarg, 0 /* don't create */);
			break;
		case 'T':	/* detach trunk port */
			detach_trunk_port(fd, 0 /* don't destroy */);
			break;
		case 'p':	/* create and attach trunk port */
			attach_trunk_port(fd, optarg, 1 /* create */);
			break;
		case 'P':	/* detach and destroy trunk port */
			detach_trunk_port(fd, 1 /* destroy */);
			break;
		case 'a':	/* attach vlan port */
			attach_vlan_port(fd, optarg, 0 /* don't create */);
			break;
		case 'A':	/* detach vlan port */
			detach_vlan_port(fd, optarg, 0 /* don't destroy */);
			break;
		case 'c':	/* create and attach vlan port */
			attach_vlan_port(fd, optarg, 1 /* create */);
			break;
		case 'C':	/* detach and destroy vlan port */
			detach_vlan_port(fd, optarg, 1 /* destroy */);
			break;
		case 'n':	/* create new configuration */
			create_conf(fd, optarg);
			break;
		case 'r':	/* destroy existing configuration */
			delete_conf(fd, optarg);
			break;
		case 's':	/* select existing configuration */
			select_conf(fd, optarg);
			break;
		case 'l':	/* list existing configuration */
			list_conf(fd);
			break;
		case 'h':	/* help */
			usage(argv[0], stdout);
			exit(0);
		default:	/* error, unknown option or missing parameter */
			usage(argv[0], stdout);
			exit(EXIT_FAILURE);
		}
	}
	return 0;
}