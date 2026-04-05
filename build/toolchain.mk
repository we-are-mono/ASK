# Cross-compilation toolchain for LS1046A (Debian crossbuild-essential-arm64)

CROSS_COMPILE  := aarch64-linux-gnu-
ARCH           := arm64
PLATFORM       := LS1043A

CC             := $(CROSS_COMPILE)gcc
CXX            := $(CROSS_COMPILE)g++
AR             := $(CROSS_COMPILE)ar
STRIP          := $(CROSS_COMPILE)strip

KDIR           ?= $(HOME)/Mono/linux
