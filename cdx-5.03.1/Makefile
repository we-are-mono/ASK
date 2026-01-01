#
 #  Copyright 2014-2016 Freescale Semiconductor, Inc.
 #  Copyright 2017-2018,2021 NXP
 #
 # SPDX-License-Identifier:    GPL-2.0+
 # The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 # included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 #
#
PLATFORM?=LS1043A

# Include netcomm SW specific definitions
KERNELVERSION?=3.19.3
ifeq ($(KERNELVERSION),3.19.3)
include $(KERNELDIR)/drivers/net/ethernet/freescale/fman/ncsw_config.mk
else
#### This KERNELDIR is for kernel version 4.1.8 and 4.1.30
include $(KERNELDIR)/drivers/net/ethernet/freescale/sdk_fman/ncsw_config.mk
endif



CDX_VERSION_FILE:=./version.h


all: version modules

modules clean:
	make CROSS_COMPILE=$(CROSS_COMPILE) V=1 ARCH=$(ARCH) CFG_FLAGS="$(CFG_FLAGS)" -C $(KERNELDIR) M=`pwd` $@

####included for dpa offload

ifeq ($(KERNELVERSION),3.19.3)
FMAN_DRIVER_PATH = $(KERNELDIR)/drivers/net/ethernet/freescale/fman
DPAA_DRIVER_PATH = $(KERNELDIR)/drivers/net/ethernet/freescale/dpa
else
#### This driver path is for kernel version 4.1.8 and 4.1.30
FMAN_DRIVER_PATH = $(KERNELDIR)/drivers/net/ethernet/freescale/sdk_fman
DPAA_DRIVER_PATH = $(KERNELDIR)/drivers/net/ethernet/freescale/sdk_dpaa
endif

EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/inc
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/inc/etc
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/inc/cores
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/inc/Peripherals
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/inc/flib
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/inc/integrations/T4240
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/src/inc
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/src/inc/wrapper
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/src/inc/system
EXTRA_CFLAGS += -I$(FMAN_DRIVER_PATH)/src/wrapper
EXTRA_CFLAGS += -I$(KERNELDIR)/drivers/crypto/caam
EXTRA_CFLAGS += -I$(DPAA_DRIVER_PATH)
EXTRA_CFLAGS += $(CFG_FLAGS)

#EXTRA_CFLAGS += -DDPAA_DEBUG_ENABLE
EXTRA_CFLAGS +=  -DDPA_IPSEC_OFFLOAD

dpa_if_objs = devman.o\
                 cdx_debug.o\
                 dpa_cfg.o\
                 cdx_dev.o\
                 dpa_test.o\
		 cdx_dpa.o\
		 cdx_ehash.o\
		 devoh.o\
                 cdx_ceetm_app.o \
		 dpa_control_mc.o\
                 cdx_mc_query.o\
		 dpa_ipsec.o\
		 cdx_dpa_ipsec.o\
		 query_ipsec.o\
		cdx_ifstats.o\
		control_rtp_relay.o\
		cdx_reassm.o\
		dpa_wifi.o\
		voip.o\
		cdx_qos.o\
		vsp_cfg.o\
		procfs.o

####end of includes

EXTRA_CFLAGS += -Werror -I$(src) -DENDIAN_LITTLE -DGCC_TOOLCHAIN

EXTRA_LDFLAGS += 

obj-m += cdx.o

cdx_cmd_objs = control_tx.o \
	control_rx.o \
	control_ipv4.o \
	control_ipv6.o \
	control_vlan.o \
	control_pppoe.o \
	control_socket.o \
        control_natpt.o \
	control_bridge.o \
	control_stat.o \
	control_ipsec.o \
	query_Rx.o \
	control_tunnel.o \
	control_qm.o\
	control_wifi.o

cdx-y += cdx_main.o \
	cdx_hal.o \
	cdx_timer.o \
	cdx_cmdhandler.o \
	layer2.o \
	$(cdx_cmd_objs) \
	$(dpa_if_objs)


version:
	if [ -d .git ]; then  \
		CDX_GIT_VERSION=$$(git describe --always --tags --dirty) ; \
		printf "/*Auto-generated file. Do not edit !*/\n#ifndef CDX_VERSION_H\n\n#define CDX_VERSION_H\n\n#define CDX_VERSION \"$${CDX_GIT_VERSION}\"\n\n#endif /* CDX_VERSION_H */\n" > $(CDX_VERSION_FILE) ; \
	fi

