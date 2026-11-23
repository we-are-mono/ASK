subdir-ccflags-y := -Werror
KASAN_SANITIZE := n

# Include netcomm SW specific definitions
include $(srctree)/drivers/net/ethernet/freescale/sdk_fman/ncsw_config.mk
ccflags-y += -I$(NET_DPA)

# Common
obj-$(CONFIG_FSL_SDK_DPA)		+= dpa_alloc.o
obj-$(CONFIG_FSL_SDK_DPA)	+= qbman_driver.o

# Bman
obj-$(CONFIG_FSL_SDK_BMAN)		+= bman_high.o
obj-$(CONFIG_FSL_BMAN_CONFIG)	+= bman_config.o bman_driver.o
obj-$(CONFIG_FSL_BMAN_DEBUGFS)  += bman_debugfs_interface.o
bman_debugfs_interface-y	 = bman_debugfs.o

# Qman
obj-$(CONFIG_FSL_SDK_QMAN)		+= qman_high.o qman_utility.o
obj-$(CONFIG_FSL_QMAN_CONFIG)	+= qman_config.o qman_driver.o
obj-$(CONFIG_FSL_QMAN_DEBUGFS)	+= qman_debugfs_interface.o
qman_debugfs_interface-y	 = qman_debugfs.o
