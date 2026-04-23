# Deploy config for the ASK test harness.
# Installs askd-agent (and, on the WAN host, the ask_orch orchestrator)
# to the three harness nodes. The DUT itself is handled via the Yocto
# image, not here.

# WAN host — the machine physically reachable from the DUT's WAN
# interface. Runs the orchestrator + pytest. Usually localhost (the
# machine driving this build); override if deploying from elsewhere.
WAN_SSH     ?=
WAN_PREFIX  ?= /opt/askd-agent

# LAN host — the traffic-generator endpoint behind the DUT's LAN port.
# Reachable via a host-only control-plane NIC (so the harness can
# orchestrate it without going through the DUT's NAT). For the primary
# dev site this is a libvirt VM named "loki" at 172.30.0.10; override
# as needed.
LAN_SSH     ?= root@172.30.0.10
LAN_PREFIX  ?= /opt/askd-agent

# Canonical agent source tree (same one the Yocto recipe ships).
ASKD_AGENT_SRC := $(CURDIR)/meta-ask/recipes-support/ask-test-agent/files/askd_agent
ASKD_SERVICE   := $(CURDIR)/meta-ask/recipes-support/ask-test-agent/files/askd-agent.service

# ask_orch — orchestrator library. Lives in tools/, not meta-ask/,
# because it runs on the WAN host only (never ships inside the Yocto
# image).
ASK_ORCH_SRC   := $(CURDIR)/tools/ask_orch

# Python deps pinned on the WAN + LAN venvs. pyserial is for the uart
# helper used by tests from the WAN host (not the agent itself).
ASKD_REQUIREMENTS := aiohttp scapy pyroute2 pytest pytest-asyncio cffi pyserial

# TFTP root on the WAN host — U-Boot on the DUT does
#   tftpboot ${loadaddr} ${tftp_root}/Image; booti ...
# to pull the test image. Override if your tftpd serves from elsewhere.
TFTP_ROOT       ?= /srv/tftp
TFTP_IMAGE_NAME ?= Image-ask-test.gz
