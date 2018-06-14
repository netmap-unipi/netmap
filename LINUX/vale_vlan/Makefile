obj-m := vale_vlan.o
vale_vlan-y := ../../sys/dev/vale_vlan/vale_vlan.o vv_linux_interface.o vale_vlan_linux.o

N_SRC?= $(PWD)/../..
K_SRC?= /lib/modules/$(shell uname -r)/build
SRCDIR= $(PWD)

EXTRA_CFLAGS := -I$(N_SRC) -I$(N_SRC)/LINUX -I$(N_SRC)/sys -DCONFIG_NETMAP -I$(SRCDIR)/../sys
EXTRA_CFLAGS += -Wno-unused-but-set-variable -g

all:	build

build:
	make -C $(K_SRC) M=$(PWD) \
		CONFIG_NETMAP=m CONFIG_NETMAP_VALE=y CONFIG_MYMODULE=m \
		EXTRA_CFLAGS='$(EXTRA_CFLAGS)' KBUILD_EXTRA_SYMBOLS=$(N_SRC)/Module.symvers

clean:
	(rm -rf *.o *.ko modules.order mymodule_lin.mod.c Module.symvers)
