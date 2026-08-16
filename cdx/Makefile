#
 #  Copyright 2014-2016 Freescale Semiconductor, Inc.
 #  Copyright 2017-2018,2021 NXP
 #
 # SPDX-License-Identifier:    GPL-2.0+
 # The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 # included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 #
#

# Kernel-module build wrapper only. The object list and compile flags live in
# Kbuild, which kbuild reads in preference to this file when the kernel build
# descends here (make -C $(KERNELDIR) M=`pwd`), so the flag/obj logic must not
# be duplicated below.

all: modules

modules clean:
	make CROSS_COMPILE=$(CROSS_COMPILE) V=1 ARCH=$(ARCH) CFG_FLAGS="$(CFG_FLAGS)" -C $(KERNELDIR) M=`pwd` $@
