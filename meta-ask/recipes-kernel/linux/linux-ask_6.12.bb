# The 6.12 kernel line: Linux 6.12.118 with NXP's lf-6.12.49-2.2.0 SDK, the
# line OpenWrt ships. What every line shares is in linux-ask.inc.
ASK_KERNEL_LINE = "6.12"

LINUX_VERSION = "6.12.118"
KERNEL_BRANCH = "linux-6.12.y"
# v6.12.118, peeled (the annotated tag object is c246b196...).
KERNEL_SRCREV = "b869a5313cbfe7102873d3de318ddb68675146d0"

require linux-ask.inc

# The series, in order: one entry per patch in patches/kernel/6.12 (a glob
# once dropped every patch numbered 100 or above).
SRC_URI += "\
           file://010-ask-fast-path-core.patch \
           file://040-ask-xfrm-ipsec-offload.patch \
           file://070-ask-ppp-hooks.patch \
           file://080-wext-core-restore-ndo_do_ioctl.patch \
           file://093-netlink-name-every-cb-mutex-class.patch \
           file://094-qbman-kasan-sanitize-off.patch \
           file://108-xfrm-validate-xmit-einprogress.patch \
           file://110-sdk-mainline-build-compat.patch \
           file://120-emc2305-dt-fan-control.patch \
           file://125-usb-typec-hd3ss3220-port-configuration.patch \
           file://130-thermal-linear-governor.patch \
           file://139-netfilter-nftables-commit-in-progress.patch \
           file://140-ask-flowtable-context.patch \
           file://141-ask-flowtable-teardown-attribution.patch \
           file://142-ask-flowtable-teardown-handback.patch \
           file://143-ask-flowtable-tunnel-path.patch \
           file://144-ask-flowtable-extend-ct-timeout.patch \
           file://146-xfrm-packet-offload-mixed-family-child-route.patch \
           file://147-netfilter-flowtable-attach-conntrack.patch \
           file://148-netfilter-port-probe.patch \
           file://149-netfilter-ipv6-prefix-translation.patch \
           file://151-netfilter-flowtable-pppoe-peer.patch \
           file://152-netfilter-nftables-device-hook-transactions.patch \
           file://160-bridge-switchdev-mdb-group.patch \
           file://161-bridge-multicast-egress-snapshot.patch \
           file://162-bridge-forward-path-forwarding-state.patch \
           file://163-bridge-fdb-forward-port-refresh.patch \
           file://170-ipv6-hop-limit-checksum-complete.patch \
           file://172-br_netfilter-label-hooks-and-count-changes.patch \
           file://173-netfilter-nft_flow_offload-skip-br_netfilter-frames.patch \
           file://174-netfilter-flowtable-carry-transit-esp-and-ip-in-ip.patch \
           file://175-netfilter-flowtable-conntrack-sees-carried-replies.patch \
           file://180-wireguard-fastpath.patch \
           file://186-netfilter-flowtable-walk-latency.patch \
           file://189-sdk_dpaa-rx-pool-recovery.patch \
          "
