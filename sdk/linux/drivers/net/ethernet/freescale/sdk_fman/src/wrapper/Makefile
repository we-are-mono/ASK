KASAN_SANITIZE := n

#
# Makefile for the Freescale Ethernet controllers
#
ccflags-y           += -DVERSION=\"\"
#
#Include netcomm SW specific definitions
include $(srctree)/drivers/net/ethernet/freescale/sdk_fman/ncsw_config.mk

NCSW_FM_INC = $(srctree)/drivers/net/ethernet/freescale/sdk_fman/Peripherals/FM/inc

ccflags-y += -I$(NCSW_FM_INC)
ccflags-y += -I$(NET_DPA)

obj-y		+= fsl-ncsw-PFM.o

fsl-ncsw-PFM-objs	:=	lnxwrp_fm.o lnxwrp_fm_port.o \
				lnxwrp_sysfs.o lnxwrp_sysfs_fm.o lnxwrp_sysfs_fm_port.o
