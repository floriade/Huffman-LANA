#
# Lightweight Autonomic Network Architecture
#
# Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
# Swiss federal institute of technology (ETH Zurich)
# Subject to the GPL.
#

# LANA core backend
lana-y   := core.o      \
	   xt_vlink.o   \
	   xt_engine.o  \
	   xt_fblock.o  \
	   xt_builder.o \
	   xt_critbit.o \
	   xt_user.o
obj-m    += lana.o

# Some of the optional modules are packed, so that we have two or more
# packages: lana.ko and each loadable functional block

# Test modules
obj-m    += fb_dummy.o
obj-m    += fb_huff.o
# Real modules
obj-m    += fb_eth.o
obj-m    += fb_ethvlink.o
obj-m    += fb_pflana.o
obj-m    += fb_bpf.o
obj-m    += fb_counter.o
obj-m    += fb_tee.o

MDIR     := /lib/modules/$(shell uname -r)
KDIR     := $(MDIR)/build
DEST     := $(MDIR)/kernel/drivers/net/lana/

all: build

build:
	make -C $(KDIR) M=$(PWD) modules

install:
	@install -d $(DEST)
	@cp -r *.ko $(DEST)
	@echo "modules installed"
	@depmod
	@echo "modules.dep regenerated"

uninstall:
	@rm -rf $(DEST)
	@echo "modules uninstalled"
	@depmod
	@echo "modules.dep regenerated"

load_core:
	# modprobes here
	@echo "not now"

unload_core:
	# rmmods here
	@echo "not now"

clean:
	make -C $(KDIR) M=$(PWD) clean

help:
	@echo "make <targets>"
	@echo "available targets:"
	@echo "  build         - Builds source"
	@echo "  clean         - Removes generated files"
	@echo "  install       - Installs .ko files into system"
	@echo "  uninstall     - Removes .ko files from system"
	@echo "  load_core     - Loads core modules into the kernel"
	@echo "  unload_core   - Unloads core modules from the kernel"
	@echo "  help          - Shows this help"

