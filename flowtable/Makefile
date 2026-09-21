# Plain Makefile for ask-flowtable (the default-on flow-offload service).
# Invoked from the meta-ask recipe as: make -C flowtable CC=...
# Depends only on libc; it shells out to the runtime `nft` and reads sysfs
# and a raw NETLINK_ROUTE socket, so there is nothing to link against.

SRCDIR   := src
BUILDDIR := src

CFLAGS  += -O2 -g -std=gnu11 -Wall -Wextra -Werror -fPIE
CFLAGS  += -I$(SRCDIR)
LDFLAGS += -pie

SRCS := \
	policy.c \
	sha256.c \
	marker.c \
	conf.c \
	render.c \
	backend.c \
	nft.c \
	nft_process.c \
	supervisor.c \
	log.c \
	enumerate.c \
	netlink.c \
	main.c

OBJS := $(SRCS:%.c=$(BUILDDIR)/%.o)

all: $(BUILDDIR)/ask-flowtable

$(BUILDDIR)/ask-flowtable: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BUILDDIR)/ask-flowtable

.PHONY: all clean
