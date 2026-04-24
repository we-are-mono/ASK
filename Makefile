include build/toolchain.mk
include build/sources.mk
include build/deploy.mk

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
        cdx fci auto_bridge fmc cmm dpa_app \
        ask-image stage-image \
        deploy-agent-wan deploy-agent-lan deploy-agents ask-test

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
#  Test harness
#
#  Three-node topology:
#    wan    — WAN-side host (runs orchestrator + pytest + the iperf3
#             server). Usually localhost.
#    target — the DUT (ls1046a-class gateway) under test.
#    lan    — LAN-side traffic generator (typically a libvirt VM) behind
#             the DUT's NAT, reachable from wan via a control-plane NIC.
#
#  Workflow (per-run):
#    1. make ask-image     — build the Yocto test image (kas).
#    2. make stage-image   — copy the bundled Image.gz into TFTP_ROOT
#                            (default /srv/tftp) as $(TFTP_IMAGE_NAME).
#    3. <U-Boot>           — at the DUT's U-Boot prompt:
#                              tftpboot ${loadaddr} <wan_ip>:$(TFTP_IMAGE_NAME)
#                              booti ${loadaddr} - ${fdtaddr}
#                            Board boots into the test image in ~15s;
#                            askd-agent starts automatically via S70askd-agent.
#    4. make deploy-agents — rsync askd-agent + orchestrator to wan + lan,
#                            enable systemd units. Requires agent up on DUT.
#    5. make ask-test      — run the test suite. Assumes agents are up;
#                            exits non-zero on failure.
# ============================================================================

# Build the Yocto test image via kas. Produces Image.gz with the ASK stack,
# python3, askd-agent, and the KASAN/lockdep/kmemleak-enabled kernel.
ask-image:
	cd meta-ask && kas build .config.yaml

# Drop the bundled kernel+initramfs into the WAN host's TFTP root so
# U-Boot on the DUT can pull it. Copies rather than symlinks because
# tftpd (running as user `tftp`) cannot traverse into /home/<user>
# (mode 0700). Re-run after each ask-image rebuild.
IMAGE_DEPLOY_DIR := $(CURDIR)/meta-ask/build/tmp/deploy/images/ask-ls1046a
IMAGE_ARTIFACT   := $(IMAGE_DEPLOY_DIR)/Image.gz-initramfs-ask-ls1046a.bin
IMAGE_BASENAME   := $(notdir $(IMAGE_ARTIFACT))
stage-image:
	@test -f $(IMAGE_ARTIFACT) || { echo "no image — run 'make ask-image' first" >&2; exit 1; }
	sudo install -d $(TFTP_ROOT)
	sudo install -m 0644 $(IMAGE_ARTIFACT) $(TFTP_ROOT)/$(TFTP_IMAGE_NAME)
	# Also stage under the Yocto artifact name so a U-Boot env set to fetch
	# the raw filename keeps working. Hard link avoids the double-copy cost.
	sudo ln -f $(TFTP_ROOT)/$(TFTP_IMAGE_NAME) $(TFTP_ROOT)/$(IMAGE_BASENAME)
	@echo "==> staged $(TFTP_IMAGE_NAME) and $(IMAGE_BASENAME) ($$(stat -Lc%s $(TFTP_ROOT)/$(TFTP_IMAGE_NAME)) B)"
	@echo "    at U-Boot: tftpboot \$${loadaddr} <name>; booti ..."

# Install askd-agent onto the WAN host (local) and the LAN host (SSH over
# the control-plane bridge). Does not touch the DUT — its copy ships
# inside the Yocto image. Split into per-node targets so each can be
# tested in isolation.

deploy-agent-wan:
	@echo "==> deploy-agent: wan (local)"
	sudo install -d $(WAN_PREFIX)
	sudo rsync -a --delete $(ASKD_AGENT_SRC)/ $(WAN_PREFIX)/askd_agent/
	sudo rsync -a --delete $(ASK_ORCH_SRC)/   $(WAN_PREFIX)/ask_orch/  2>/dev/null || true
	sudo install -m0644 $(ASKD_SERVICE) /etc/systemd/system/askd-agent.service
	@if [ ! -x $(WAN_PREFIX)/venv/bin/python ]; then \
	    echo "==> wan: bootstrapping venv"; \
	    sudo python3 -m venv $(WAN_PREFIX)/venv; \
	fi
	sudo $(WAN_PREFIX)/venv/bin/pip install --quiet --upgrade $(ASKD_REQUIREMENTS)
	sudo systemctl daemon-reload
	sudo systemctl enable --now askd-agent.service
	@echo "==> deploy-agent-wan: done. curl http://127.0.0.1:9110/health to verify."

# The LAN host needs a control-plane NIC reachable from the WAN host at
# $(LAN_SSH) (default root@172.30.0.10 — override via env/override file
# if your setup differs). Until that's provisioned, this target will
# fail — use deploy-agent-wan alone for smoke-testing the WAN half.
deploy-agent-lan:
	@echo "==> deploy-agent: lan ($(LAN_SSH))"
	rsync -a --delete -e ssh $(ASKD_AGENT_SRC)/ $(LAN_SSH):$(LAN_PREFIX)/askd_agent/
	scp $(ASKD_SERVICE) $(LAN_SSH):/tmp/askd-agent.service
	ssh $(LAN_SSH) 'set -e; \
	    sudo mv /tmp/askd-agent.service /etc/systemd/system/; \
	    [ -x $(LAN_PREFIX)/venv/bin/python ] || sudo python3 -m venv $(LAN_PREFIX)/venv; \
	    sudo $(LAN_PREFIX)/venv/bin/pip install --quiet --upgrade $(ASKD_REQUIREMENTS); \
	    sudo apt-get install -y --no-install-recommends python3-scapy; \
	    sudo systemctl daemon-reload; \
	    sudo systemctl enable --now askd-agent.service'
	@echo "==> deploy-agent-lan: done."

deploy-agents: deploy-agent-wan deploy-agent-lan

# Run the end-to-end test suite. Does NOT auto-deploy — assumes the DUT
# is already on the test image; the conftest's autouse reachability
# fixture fail-fasts the whole run if the agent doesn't respond.
#
# sudo is needed because tests drive the LAN VM over the libvirt PTY
# (/dev/pts/N, owned by libvirt-qemu:tty 0600) and can drive the DUT
# over /dev/ttyUSB0 (root:plugdev 0660). Running pytest against the
# source tree (PYTHONPATH=tools) rather than the installed venv means
# test edits pick up without a redeploy.
#
# Pass extra pytest args via ASK_TEST_ARGS, e.g.:
#   make ask-test ASK_TEST_ARGS='-k iperf --junit-xml=/tmp/out.xml'
ask-test:
	sudo PYTHONPATH=$(CURDIR)/tools $(WAN_PREFIX)/venv/bin/pytest \
	    -c $(CURDIR)/tools/pyproject.toml \
	    $(CURDIR)/tools/tests $(ASK_TEST_ARGS)

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
