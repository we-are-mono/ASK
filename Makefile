include build/toolchain.mk
include build/sources.mk

DEFCONFIG  := $(CURDIR)/config/kernel/defconfig
DIST       := $(CURDIR)/dist
SRCDIR     := $(CURDIR)/sources
PATCHES    := $(CURDIR)/patches
HOST       := aarch64-linux-gnu

# Built dependency paths
FMLIB_DIR  := $(SRCDIR)/fmlib
FMC_DIR    := $(SRCDIR)/fmc/source
LIBFCI_DIR := $(CURDIR)/fci/lib
SYSROOT    := $(SRCDIR)/sysroot
ABM_DIR    := $(CURDIR)/auto_bridge

# Kernel module args
KBUILD_ARGS := CROSS_COMPILE=$(CROSS_COMPILE) ARCH=$(ARCH)
CDX_ARGS    := $(KBUILD_ARGS) KERNELDIR=$(KDIR) PLATFORM=$(PLATFORM)
FCI_ARGS    := $(KBUILD_ARGS) KERNEL_SOURCE=$(KDIR) BOARD_ARCH=$(ARCH) \
               KBUILD_EXTRA_SYMBOLS=$(CURDIR)/cdx/Module.symvers
ABM_ARGS    := $(KBUILD_ARGS) KERNEL_SOURCE=$(KDIR) PLATFORM=$(PLATFORM)

# Stamps to track what's been fetched/patched/built
S := $(SRCDIR)/.stamps
$(shell mkdir -p $(S))

# ============================================================================
#  Top-level targets
# ============================================================================

.PHONY: all setup sources modules userspace kernel dist serve clean clean-all help \
        cdx fci auto_bridge fmc cmm dpa_app

all: modules userspace

setup:
	./build/setup.sh

# ============================================================================
#  Source dependencies — fetch, patch, build into $(SRCDIR)
# ============================================================================

sources: $(S)/fmlib $(S)/fmc $(S)/libfci $(S)/libnfnetlink $(S)/libnfct

# -- fmlib -----------------------------------------------------------------

$(S)/fmlib:
	@echo "==> fmlib: clone + patch + build"
	rm -rf $(FMLIB_DIR)
	git clone -q --depth 1 -b $(NXP_TAG) $(FMLIB_REPO) $(FMLIB_DIR)
	cd $(FMLIB_DIR) && git apply $(PATCHES)/fmlib/01-mono-ask-extensions.patch
	$(MAKE) -C $(FMLIB_DIR) CROSS_COMPILE=$(CROSS_COMPILE) KERNEL_SRC=$(KDIR) libfm-arm.a
	ln -sf libfm-arm.a $(FMLIB_DIR)/libfm.a
	@touch $@

# -- fmc -------------------------------------------------------------------

$(S)/fmc: $(S)/fmlib
	@echo "==> fmc: clone + patch + build"
	rm -rf $(SRCDIR)/fmc
	git clone -q --depth 1 -b $(NXP_TAG) $(FMC_REPO) $(SRCDIR)/fmc
	cd $(SRCDIR)/fmc && git apply $(PATCHES)/fmc/01-mono-ask-extensions.patch
	$(MAKE) -C $(FMC_DIR) \
		CC=$(CC) CXX=$(CXX) AR=$(AR) \
		MACHINE=ls1046 \
		FMD_USPACE_HEADER_PATH=$(FMLIB_DIR)/include/fmd \
		FMD_USPACE_LIB_PATH=$(FMLIB_DIR) \
		LIBXML2_HEADER_PATH=/usr/include/libxml2 \
		TCLAP_HEADER_PATH=/usr/include
	@touch $@

# -- libfci ----------------------------------------------------------------

$(S)/libfci:
	@echo "==> libfci: build"
	$(MAKE) -C $(LIBFCI_DIR) CC=$(CC) AR=$(AR)
	@touch $@

# -- libnfnetlink (patched) ------------------------------------------------

$(S)/libnfnetlink:
	@echo "==> libnfnetlink: fetch + patch + build"
	mkdir -p $(SRCDIR)/tarballs
	[ -f $(SRCDIR)/tarballs/libnfnetlink-$(LIBNFNETLINK_VER).tar.bz2 ] || \
		wget -q -P $(SRCDIR)/tarballs $(LIBNFNETLINK_URL)
	rm -rf $(SRCDIR)/libnfnetlink-$(LIBNFNETLINK_VER)
	tar xf $(SRCDIR)/tarballs/libnfnetlink-$(LIBNFNETLINK_VER).tar.bz2 -C $(SRCDIR)
	cd $(SRCDIR)/libnfnetlink-$(LIBNFNETLINK_VER) && \
		git init -q && git add -A && git commit -q -m "upstream" && \
		git apply $(PATCHES)/libnfnetlink/01-nxp-ask-nonblocking-heap-buffer.patch && \
		./configure --host=$(HOST) --prefix=$(SYSROOT) --enable-static --disable-shared -q && \
		$(MAKE) -j$$(nproc) -s && $(MAKE) install -s
	@touch $@

# -- libnetfilter_conntrack (patched) --------------------------------------

$(S)/libnfct: $(S)/libnfnetlink
	@echo "==> libnetfilter_conntrack: fetch + patch + build"
	mkdir -p $(SRCDIR)/tarballs
	[ -f $(SRCDIR)/tarballs/libnetfilter_conntrack-$(LIBNFCT_VER).tar.xz ] || \
		wget -q -P $(SRCDIR)/tarballs $(LIBNFCT_URL)
	rm -rf $(SRCDIR)/libnetfilter_conntrack-$(LIBNFCT_VER)
	tar xf $(SRCDIR)/tarballs/libnetfilter_conntrack-$(LIBNFCT_VER).tar.xz -C $(SRCDIR)
	cd $(SRCDIR)/libnetfilter_conntrack-$(LIBNFCT_VER) && \
		git init -q && git add -A && git commit -q -m "upstream" && \
		git apply $(PATCHES)/libnetfilter-conntrack/01-nxp-ask-comcerto-fp-extensions.patch && \
		PKG_CONFIG_PATH=$(SYSROOT)/lib/pkgconfig \
		./configure --host=$(HOST) --prefix=$(SYSROOT) --enable-static --disable-shared -q \
			CFLAGS="-I$(SYSROOT)/include" LDFLAGS="-L$(SYSROOT)/lib" && \
		$(MAKE) -j$$(nproc) -s && $(MAKE) install -s
	@touch $@

# ============================================================================
#  Kernel modules (out-of-tree)
# ============================================================================

modules: cdx fci auto_bridge

cdx:
	$(MAKE) -C cdx $(CDX_ARGS) modules

fci: cdx
	$(MAKE) -C fci $(FCI_ARGS) modules

auto_bridge:
	$(MAKE) -C auto_bridge $(ABM_ARGS)

# ============================================================================
#  Userspace binaries
# ============================================================================

userspace: fmc cmm dpa_app

fmc: $(S)/fmc
	@true

cmm: $(S)/libfci $(S)/libnfct
	$(MAKE) -C cmm CC=$(CC) \
		LIBFCI_DIR=$(LIBFCI_DIR) \
		ABM_DIR=$(ABM_DIR) \
		SYSROOT=$(SYSROOT)

dpa_app: $(S)/fmc
	$(MAKE) -C dpa_app CC=$(CC) \
		CFLAGS="-DDPAA_DEBUG_ENABLE -DNCSW_LINUX \
		-I$(FMC_DIR) -I$(CURDIR)/cdx \
		-I$(FMLIB_DIR)/include/fmd \
		-I$(FMLIB_DIR)/include/fmd/Peripherals \
		-I$(FMLIB_DIR)/include/fmd/integrations" \
		LDFLAGS="-lpthread -lcli -L$(FMC_DIR) -lfmc -L$(FMLIB_DIR) -lfm -lstdc++ -lxml2 -lm"

# ============================================================================
#  Kernel image
# ============================================================================

kernel:
	cp $(DEFCONFIG) $(KDIR)/.config
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) olddefconfig
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) -j$$(nproc) Image modules

# ============================================================================
#  Distribution / deploy
# ============================================================================

dist: all
	mkdir -p $(DIST)
	cp cdx/cdx.ko $(DIST)/
	cp fci/fci.ko $(DIST)/
	cp auto_bridge/auto_bridge.ko $(DIST)/
	cp $(FMC_DIR)/fmc $(DIST)/
	cp cmm/src/cmm $(DIST)/
	cp dpa_app/dpa_app $(DIST)/
	@echo "Artifacts staged in $(DIST)/"

serve: dist
	cd $(DIST) && python3 -m http.server 8000

# ============================================================================
#  Clean
# ============================================================================

clean:
	$(MAKE) -C cdx $(CDX_ARGS) clean
	$(MAKE) -C fci $(FCI_ARGS) clean
	$(MAKE) -C auto_bridge $(ABM_ARGS) clean
	$(MAKE) -C $(LIBFCI_DIR) clean
	$(MAKE) -C cmm clean
	-$(MAKE) -C dpa_app clean 2>/dev/null
	rm -f $(S)/*
	rm -rf $(DIST)

clean-all: clean
	rm -rf $(SRCDIR)

# ============================================================================
#  Help
# ============================================================================

help:
	@echo "make setup      - install host cross-compilation deps (needs sudo)"
	@echo "make            - build everything (fetches sources, patches, builds)"
	@echo "make sources    - fetch + patch + build all source dependencies"
	@echo "make modules    - build kernel modules (cdx, fci, auto_bridge)"
	@echo "make userspace  - build userspace binaries (fmc, cmm, dpa_app)"
	@echo "make kernel     - build kernel Image + in-tree modules"
	@echo "make dist       - stage all artifacts into dist/"
	@echo "make serve      - HTTP server on dist/ (port 8000)"
	@echo "make clean      - clean local build artifacts (keeps sources)"
	@echo "make clean-all  - clean everything including fetched sources"
