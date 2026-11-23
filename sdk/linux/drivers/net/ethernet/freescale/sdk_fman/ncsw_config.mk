#
# Makefile config for the Freescale NetcommSW
#
NET_DPA     = $(srctree)/drivers/net
DRV_DPA     = $(srctree)/drivers/net/ethernet/freescale/sdk_dpaa
FMAN        = $(srctree)/drivers/net/ethernet/freescale/sdk_fman

ccflags-y +=-include $(FMAN)/ls1043_dflags.h
ccflags-y += -I$(DRV_DPA)/
ccflags-y += -I$(FMAN)/inc
ccflags-y += -I$(FMAN)/inc/cores
ccflags-y += -I$(FMAN)/inc/etc
ccflags-y += -I$(FMAN)/inc/Peripherals
ccflags-y += -I$(FMAN)/inc/flib
ccflags-y += -I$(FMAN)/inc/integrations/LS1043

ccflags-y += -I$(FMAN)/src/inc
ccflags-y += -I$(FMAN)/src/inc/system
ccflags-y += -I$(FMAN)/src/inc/wrapper
ccflags-y += -I$(FMAN)/src/inc/xx
