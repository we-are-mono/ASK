SUMMARY = "Minimal initramfs for testing ASK on LS1046A target"
LICENSE = "MIT"

IMAGE_INSTALL = " \
    busybox \
    coreutils \
    base-files \
    shadow \
    kmod \
    bash \
    \
    \
    ethtool \
    iproute2 \
    iproute2-bridge \
    iproute2-tc \
    iproute2-devlink \
    iputils \
    iptables \
    nftables \
    bridge-utils \
    conntrack-tools \
    smcroute \
    ppp \
    ppp-oe \
    kernel-module-ppp-generic \
    kernel-module-pppoe \
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
    sysstat \
    \
    \
    cdx \
    fci \
    auto-bridge \
    sfp-led \
    lp5812-driver \
    config \
    kernel-module-nf-conntrack-netlink \
    kernel-module-ask-flowtable \
    kernel-module-nft-flow-offload \
    kernel-module-nf-flow-table-inet \
    kernel-module-nft-ct \
    kernel-module-nft-nat \
    kernel-module-nft-masq \
    kernel-module-nft-chain-nat \
    kernel-module-xt-tcpudp \
    kernel-module-xt-conntrack \
    kernel-module-xt-masquerade \
    kernel-module-ip6-tables \
    kernel-module-ip6table-filter \
    kernel-module-ip6table-mangle \
    cmm \
    dpa-app \
    dnsmasq \
    fmc \
    \
    \
    lmsensors-sensors \
    \
    \
    nxp-mwifiex \
    nxp-wifi-firmware \
    kernel-module-cfg80211 \
    hostapd \
    wpa-supplicant \
    iw \
    wireless-regdb-static \
"

# Test harness (agent + python fuzzing/orchestration tooling + stress tools).
# Kept separate so it's obvious what the test image adds on top of the base.
IMAGE_INSTALL:append = " \
    ask-test-agent \
    kernel-module-dummy \
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

# smcroute is here so the routed-multicast tests have a real consumer writing
# ipmr's MFC. They own the daemon's lifecycle: each case starts it with `-N`
# and a generated config, so the VIF set is exactly the interfaces that case
# names. A daemon started at boot would enable every multicast-capable
# interface it could find and shift every VIF index out from under them. The
# recipe registers no init script today; this is the guard against one
# arriving with a version bump.
ROOTFS_POSTPROCESS_COMMAND += "disable_smcroute_init;"

disable_conntrackd_init() {
    rm -f ${IMAGE_ROOTFS}/etc/init.d/conntrackd
    rm -f ${IMAGE_ROOTFS}/etc/rcS.d/*conntrackd*
    rm -f ${IMAGE_ROOTFS}/etc/rc*.d/*conntrackd*
}

disable_dnsmasq_default_init() {
    rm -f ${IMAGE_ROOTFS}/etc/rcS.d/*dnsmasq*
    rm -f ${IMAGE_ROOTFS}/etc/rc*.d/*dnsmasq*
}

disable_smcroute_init() {
    rm -f ${IMAGE_ROOTFS}/etc/init.d/smcroute
    rm -f ${IMAGE_ROOTFS}/etc/rc*.d/*smcroute*
}

inherit image
