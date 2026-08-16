# Plain Makefile for CMM (replaces autotools)
# Invoked from top-level: make -C cmm CC=... LIBFCI_DIR=... SYSROOT=...

SRCDIR   := src
BUILDDIR := src

# Patched libs sysroot (built by build/build-patched-libs.sh)
SYSROOT  ?= ../sources/sysroot

# Cross pkg-config against patched sysroot
PKG_CONFIG      ?= pkg-config
PKG_CONFIG_PATH ?= $(SYSROOT)/lib/pkgconfig

NFCT_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags libnetfilter_conntrack 2>/dev/null)
NFCT_LIBS   := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs libnetfilter_conntrack 2>/dev/null)

CFLAGS  += -O2 -g -Wall -Werror -fPIE
CFLAGS  += $(NFCT_CFLAGS)
CFLAGS  += -I$(SRCDIR)
CFLAGS  += -I$(LIBFCI_DIR)/include
CFLAGS  += -I$(ABM_DIR)/include
CFLAGS  += -DAUTO_BRIDGE -DLS1043 -DWIFI_ENABLE -DENABLE_EGRESS_QOS

LDFLAGS += -L$(LIBFCI_DIR) -L$(SYSROOT)/lib
LDLIBS  := -lpthread -lfci -lcli -lpcap $(NFCT_LIBS) -lmnl

SRCS := \
	rtnl_parse.c \
	neighbor_resolution.c \
	module_expt.c \
	cmm.c \
	conntrack.c \
	ffcontrol.c \
	forward_engine.c \
	route_cache.c \
	pppoe.c \
	ffbridge.c \
	client_daemon.c \
	rtnl.c \
	module_rx.c \
	module_tx.c \
	module_qm.c \
	module_prf.c \
	module_vlan.c \
	module_macvlan.c \
	module_mcast.c \
	module_mc6.c \
	module_mc4.c \
	keytrack.c \
	timeout.c \
	module_tunnel.c \
	module_relay.c \
	itf.c \
	module_stat.c \
	module_route.c \
	module_socket.c \
	module_rtp.c \
	module_wifi.c \
	alt_conf.c \
	voicebuf.c \
	module_pktcap.c \
	module_icc.c \
	cmm_asym_ff.c \
	module_ipsec.c \
	module_ipr.c \
	libcmm.c

OBJS := $(SRCS:%.c=$(BUILDDIR)/%.o)

all: version $(BUILDDIR)/cmm

$(BUILDDIR)/cmm: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Fuzz harness for cmm's RTNL attribute parser. ASAN/UBSAN-instrumented;
# OOB detection is the oracle. Built separately — `make -C cmm fuzzer` —
# so the default image isn't sanitizer-instrumented. The Yocto recipe
# (meta-ask/recipes-ask/cmm/cmm_1.0.bb) DEPENDS on gcc-sanitizers to
# stage libasan/libubsan into the cross sysroot.
FUZZER_SRC    := test/cmm_rtnl_fuzzer.c
FUZZER_BIN    := $(BUILDDIR)/cmm_rtnl_fuzzer
FUZZER_CFLAGS := -O1 -g -Wall -Werror \
                 -fsanitize=address,undefined -fno-omit-frame-pointer

fuzzer: $(FUZZER_BIN)

# Builds together with the production rtnl_parse.c so the fuzzer
# exercises the same cmm_parse_rtattr the daemon ships. LDFLAGS picks
# up Yocto's --hash-style=gnu / reproducible-build flags when invoked
# from the recipe; harmless additions on a host build.
$(FUZZER_BIN): $(FUZZER_SRC) $(SRCDIR)/rtnl_parse.c
	$(CC) $(FUZZER_CFLAGS) $(LDFLAGS) -o $@ $(FUZZER_SRC) $(SRCDIR)/rtnl_parse.c

version:
	@if [ -d .git ]; then \
		V=$$(git describe --always --tags --dirty 2>/dev/null || echo "unknown"); \
		printf '/* Auto-generated */\n#ifndef VERSION_H\n#define VERSION_H\n#define CMM_VERSION "%s"\n#endif\n' "$$V" > $(SRCDIR)/version.h; \
	fi

clean:
	rm -f $(BUILDDIR)/*.o $(BUILDDIR)/cmm $(FUZZER_BIN)

.PHONY: all version clean fuzzer
