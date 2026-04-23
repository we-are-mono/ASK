SUMMARY = "Minimal initramfs for testing ASK on LS1046A target"
LICENSE = "MIT"

IMAGE_INSTALL = " \
    busybox \
    base-files \
    shadow \
    kmod \
    bash \
    \
    \
    ethtool \
    iproute2 \
    iputils \
    iptables \
    nftables \
    bridge-utils \
    conntrack-tools \
    tcpdump \
    iperf3 \
    netcat \
    socat \
    traceroute \
    dropbear \
    strongswan \
    \
    \
    vim \
    htop \
    less \
    strace \
    ltrace \
    gdb \
    file \
    \
    \
    cdx \
    fci \
    auto-bridge \
    config \
    kernel-module-nf-conntrack-netlink \
    kernel-module-xt-conntrack \
    kernel-module-xt-masquerade \
    cmm \
    dpa-app \
    dnsmasq \
    fmc \
    \
    \
    lmsensors-fancontrol \
    lmsensors-config-fancontrol \
"

# Test harness (agent + python fuzzing/orchestration tooling + stress tools).
# Kept separate so it's obvious what the test image adds on top of the base.
IMAGE_INSTALL:append = " \
    ask-test-agent \
    python3-core \
    python3-aiohttp \
    python3-pyroute2 \
    python3-scapy \
    python3-pytest \
    python3-cffi \
    nmap \
    stress-ng \
    trace-cmd \
    perf \
"

IMAGE_FSTYPES = "cpio.gz"

IMAGE_FEATURES += "empty-root-password"
IMAGE_FEATURES:remove = "package-management"

# Bundle the initramfs into the kernel Image so U-Boot only needs to
# tftpboot a single file.
INITRAMFS_IMAGE_BUNDLE = "1"

# Skip a root filesystem for this boot — everything lives in the initramfs.
USE_DEVFS = "0"

# We ship conntrack-tools for the 'conntrack' CLI (to inspect ASK-offloaded
# flows) but don't need the HA state-sync daemon. Its init script would
# fail at boot because it has no /etc/conntrackd/conntrackd.conf — strip it.
ROOTFS_POSTPROCESS_COMMAND += "disable_conntrackd_init;"

# Our gateway-setup init script (from the 'config' recipe) launches
# dnsmasq with /etc/dnsmasq-gateway.conf, so the upstream package's init
# and empty /etc/dnsmasq.conf would just race and fail. Strip them.
ROOTFS_POSTPROCESS_COMMAND += "disable_dnsmasq_default_init;"

disable_conntrackd_init() {
    rm -f ${IMAGE_ROOTFS}/etc/init.d/conntrackd
    rm -f ${IMAGE_ROOTFS}/etc/rcS.d/*conntrackd*
    rm -f ${IMAGE_ROOTFS}/etc/rc*.d/*conntrackd*
}

disable_dnsmasq_default_init() {
    rm -f ${IMAGE_ROOTFS}/etc/rcS.d/*dnsmasq*
    rm -f ${IMAGE_ROOTFS}/etc/rc*.d/*dnsmasq*
}

inherit image
