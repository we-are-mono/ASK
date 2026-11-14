# Deploy config for the ASK test harness.
# Installs the WAN agent and runner dependencies. The DUT agent ships
# in the Yocto image, and the LAN client uses QEMU guest-agent control.

# WAN host — the machine physically reachable from the DUT's WAN
# interface. Runs the orchestrator + pytest. Usually localhost (the
# machine driving this build); override if deploying from elsewhere.
WAN_PREFIX  ?= /opt/askd-agent

# Canonical agent source tree (same one the Yocto recipe ships).
ASKD_AGENT_SRC := $(CURDIR)/tools/askd_agent
ASKD_SERVICE   := $(CURDIR)/meta-ask/recipes-support/ask-test-agent/files/askd-agent.service

# Agent and orchestrator share the pinned dependency set.
ASKD_REQUIREMENTS := -r $(CURDIR)/tools/requirements.txt

# TFTP root on the WAN host, from which U-Boot on the DUT pulls the test
# image and its device tree (docs/testing.md, "Booting the image"). Override
# if your tftpd serves from elsewhere. Each kernel line is staged under its
# own names (Image-ask-<line>.gz, mono-gateway-dk-<line>.dtb); these two
# name whichever line was staged last, the pair the board's `run ask` fetches.
TFTP_ROOT       ?= /srv/tftp
TFTP_IMAGE_NAME ?= Image-ask-test.gz
TFTP_DTB_NAME   ?= mono-gateway-dk.dtb
