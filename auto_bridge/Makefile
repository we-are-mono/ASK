#
#
#  Copyright (C) 2007 Mindspeed Technologies, Inc.
#  Copyright 2015-2016 Freescale Semiconductor, Inc.
#  Copyright 2017,2021 NXP
#
# SPDX-License-Identifier:    GPL-2.0+
# The GPL-2.0+ license for this file can be found in the COPYING.GPL file
# included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
#

TOP_DIR := $(shell pwd)

# Support both KERNEL_SOURCE (original) and KERNEL_SRC (Yocto)
KERNEL_SOURCE ?= $(KERNEL_SRC)

# The module object list and build flags (-DLS104X -DVLAN_FILTER, the bridge
# include path) live in Kbuild, which the kernel sub-make reads instead of this
# file. This Makefile is only the out-of-tree kernel-descend wrapper; ARCH is
# passed by the caller (root Makefile / Yocto recipe).
all:
	$(MAKE) -C $(KERNEL_SOURCE) ARCH=$(ARCH) M=`pwd` modules

clean:
	$(MAKE) -C $(KERNEL_SOURCE) ARCH=$(ARCH) M=`pwd` clean
