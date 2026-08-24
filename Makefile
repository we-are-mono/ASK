include build/deploy.mk

# ============================================================================
#  ASK build + test entry points
#
#  The ASK image is built with Yocto/kas — see README.md for the full build
#  guide. This Makefile does NOT cross-compile the ASK components standalone;
#  the kas recipes under meta-ask/ (and the Armbian / OpenWrt package feeds)
#  are the authoritative builders. What remains here is host setup, the kas
#  image wrapper, and the test-harness orchestration.
#
#  Three-node test topology:
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

.PHONY: setup ask-image stage-image deploy-agent-wan deploy-agents ask-test help

# Install the host tools the kas build needs: kas itself, BitBake's host
# dependencies, and the en_US.UTF-8 locale BitBake requires. Debian 13
# (trixie) amd64; needs sudo. One-time per machine.
setup:
	sudo apt-get update
	sudo apt-get install -y git kas build-essential chrpath diffstat gawk \
	    bzip2 lz4 rpcsvc-proto locales
	sudo sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
	sudo locale-gen
	sudo update-locale LANG=en_US.UTF-8
	[ -f meta-ask/site.conf ] || cp meta-ask/site.conf.example meta-ask/site.conf
	@echo "==> host ready. Now EDIT meta-ask/site.conf: point DL_DIR and SSTATE_DIR at"
	@echo "    writable directories you create first, then run 'make ask-image'."

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
	sudo install -m0644 $(ASKD_SERVICE) /etc/systemd/system/askd-agent.service
	@if [ ! -x $(WAN_PREFIX)/venv/bin/python ]; then \
	    echo "==> wan: bootstrapping venv"; \
	    sudo python3 -m venv $(WAN_PREFIX)/venv; \
	fi
	sudo $(WAN_PREFIX)/venv/bin/pip install --quiet --upgrade $(ASKD_REQUIREMENTS)
	sudo systemctl daemon-reload
	sudo systemctl enable --now askd-agent.service
	@echo "==> deploy-agent-wan: done. curl http://127.0.0.1:9110/health to verify."

deploy-agents: deploy-agent-wan

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
#
# sudo resets the environment, so ASK_* configuration variables
# (ASK_WAN_IP, ASK_REGEN_GOLDEN, ...) are re-stated explicitly on the
# sudo command line — without this they silently fall back to their
# in-tree defaults.
# Space-free values only (they're IPs/ifnames/flags) — a value with
# spaces would word-split on the sudo command line. ASK_TEST_ARGS is
# pytest arguments, not test configuration, and is passed separately.
ASK_ENV := $(shell env | grep -E '^ASK_[A-Za-z0-9_]+=[^ ]*$$' | grep -v '^ASK_TEST_ARGS=' | tr '\n' ' ')
ask-test:
	sudo $(ASK_ENV) PYTHONPATH=$(CURDIR)/tools $(WAN_PREFIX)/venv/bin/pytest \
	    -c $(CURDIR)/tools/pyproject.toml \
	    $(CURDIR)/tools/tests $(ASK_TEST_ARGS)

# ============================================================================
#  Help
# ============================================================================

help:
	@echo "make setup         - install host build deps + locale (one-time, sudo)"
	@echo "make ask-image     - build the Yocto test image via kas"
	@echo "make stage-image   - copy the built image into the TFTP root"
	@echo "make deploy-agents - install askd-agent on the WAN (+ LAN) host"
	@echo "make ask-test      - run the end-to-end pytest suite"
