# Deploy config for the ASK test harness.
# Installs the WAN agent and runner dependencies. The DUT agent ships
# in the Yocto image, and the LAN client is driven over UART.

# WAN host — the machine physically reachable from the DUT's WAN
# interface. Runs the orchestrator + pytest. Usually localhost (the
# machine driving this build); override if deploying from elsewhere.
WAN_PREFIX  ?= /opt/askd-agent

# Canonical agent source tree (same one the Yocto recipe ships).
ASKD_AGENT_SRC := $(CURDIR)/meta-ask/recipes-support/ask-test-agent/files/askd_agent
ASKD_SERVICE   := $(CURDIR)/meta-ask/recipes-support/ask-test-agent/files/askd-agent.service

# Agent and orchestrator share the pinned dependency set.
ASKD_REQUIREMENTS := -r $(CURDIR)/tools/requirements.txt

# TFTP root on the WAN host — U-Boot on the DUT does
#   tftpboot ${loadaddr} ${tftp_root}/Image; booti ...
# to pull the test image. Override if your tftpd serves from elsewhere.
TFTP_ROOT       ?= /srv/tftp
TFTP_IMAGE_NAME ?= Image-ask-test.gz
