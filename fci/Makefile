TOP_DIR := $(shell pwd)

# Support both KERNEL_SOURCE (original) and KERNEL_SRC (Yocto)
KERNEL_SOURCE ?= $(KERNEL_SRC)

# The module object list lives in Kbuild, which the kernel sub-make reads
# instead of this file. This Makefile is only the out-of-tree kernel-descend
# wrapper; ARCH is passed by the caller (root Makefile / Yocto recipe).
all: modules

modules clean modules_install:
	$(MAKE) -C $(KERNEL_SOURCE) ARCH=$(ARCH) KBUILD_EXTRA_SYMBOLS="$(KBUILD_EXTRA_SYMBOLS)" M=`pwd` $@
