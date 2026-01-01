TOP_DIR := $(shell pwd)
BOARD_ARCH?=arm

obj-m:=fci.o

all: modules

modules clean modules_install:
	$(MAKE) -C $(KERNEL_SOURCE) ARCH=$(BOARD_ARCH) M=`pwd` $@
