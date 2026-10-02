-include .ask-test.mk
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
#             the DUT's NAT, reached through its serial console.
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
#    4. make deploy-agents — install the WAN agent and runner dependencies.
#    5. make test          — run the test suite. Assumes agents are up;
#                            exits non-zero on failure.
# ============================================================================

.PHONY: setup ask-image stage-image deploy-agent-wan deploy-agents ask-test test test-host test-dut test-startup test-env help

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
IMAGE_DTB        := $(IMAGE_DEPLOY_DIR)/mono-gateway-dk.dtb
stage-image:
	@test -f $(IMAGE_ARTIFACT) || { echo "no image — run 'make ask-image' first" >&2; exit 1; }
	@test -f $(IMAGE_DTB) || { echo "no device tree — run 'make ask-image' first" >&2; exit 1; }
	sudo install -d $(TFTP_ROOT)
	sudo install -m 0644 $(IMAGE_ARTIFACT) $(TFTP_ROOT)/$(TFTP_IMAGE_NAME)
	sudo install -m 0644 $(IMAGE_DTB) $(TFTP_ROOT)/mono-gateway-dk.dtb
	# Also stage under the Yocto artifact name so a U-Boot env set to fetch
	# the raw filename keeps working. Hard link avoids the double-copy cost.
	sudo ln -f $(TFTP_ROOT)/$(TFTP_IMAGE_NAME) $(TFTP_ROOT)/$(IMAGE_BASENAME)
	@echo "==> staged $(TFTP_IMAGE_NAME) and $(IMAGE_BASENAME) ($$(stat -Lc%s $(TFTP_ROOT)/$(TFTP_IMAGE_NAME)) B)"
	@echo "    matching device tree: mono-gateway-dk.dtb"
	@echo "    at U-Boot: tftpboot \$${loadaddr} <name>; booti ..."

# Install askd-agent onto the local WAN host. The DUT copy ships in the
# Yocto image; the LAN client is driven over UART.

deploy-agent-wan:
	@echo "==> deploy-agent: wan (local)"
	sudo install -d $(WAN_PREFIX)
	sudo rsync -a --delete $(ASKD_AGENT_SRC)/ $(WAN_PREFIX)/askd_agent/
	sudo install -m0644 $(ASKD_SERVICE) /etc/systemd/system/askd-agent.service
	@if [ ! -x $(WAN_PREFIX)/venv/bin/python ]; then \
	    echo "==> wan: bootstrapping venv"; \
	    sudo python3 -m venv $(WAN_PREFIX)/venv; \
	fi
	sudo $(WAN_PREFIX)/venv/bin/pip install --quiet $(ASKD_REQUIREMENTS)
	sudo systemctl daemon-reload
	sudo systemctl enable --now askd-agent.service
	@echo "==> deploy-agent-wan: done. curl http://127.0.0.1:9110/health to verify."

deploy-agents: deploy-agent-wan

# Keep environment and make-command-line settings identical. The Python
# adapter forwards arguments through sudo without shell interpolation.
export $(filter ASK_%,$(.VARIABLES))
export DUT_IP WAN_IP WAN_AGENT_IP K ARGS

test:
	@"$(WAN_PREFIX)/venv/bin/python" "$(CURDIR)/tools/run_tests.py" all

ask-test: test

test-host:
	@"$(WAN_PREFIX)/venv/bin/python" "$(CURDIR)/tools/run_tests.py" host

test-dut:
	@"$(WAN_PREFIX)/venv/bin/python" "$(CURDIR)/tools/run_tests.py" dut

test-startup:
	@"$(WAN_PREFIX)/venv/bin/python" "$(CURDIR)/tools/run_tests.py" startup

test-env:
	sudo python3 -m venv "$(WAN_PREFIX)/venv"
	sudo "$(WAN_PREFIX)/venv/bin/pip" install -r "$(CURDIR)/tools/requirements.txt"

# ============================================================================
#  Help
# ============================================================================

help:
	@echo "make setup         - install host build deps + locale (one-time, sudo)"
	@echo "make ask-image     - build the Yocto test image via kas"
	@echo "make stage-image   - copy the built image into the TFTP root"
	@echo "make deploy-agents - install askd-agent on the WAN host"
	@echo "make test          - host + DUT suite; DUT_IP=... WAN_IP=... K='ipsec or mcast'"
	@echo "make test-host     - host suite without sudo or hardware; ARGS='-vv'"
	@echo "make test-dut      - DUT suite; WAN_AGENT_IP overrides the WAN control address"
	@echo "make test-startup  - dedicated rdinit=/bin/sh startup suite"
	@echo "make test-env      - install pinned runner dependencies without deploying agents"
	@echo "make ask-test      - alias for make test; ASK_* settings remain supported"
