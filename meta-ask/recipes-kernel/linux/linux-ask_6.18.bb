# The 6.18 kernel line: Linux 6.18.63 with NXP's lf-6.18.37-2.1.0 SDK. What
# every line shares is in linux-ask.inc.
ASK_KERNEL_LINE = "6.18"

LINUX_VERSION = "6.18.63"
KERNEL_BRANCH = "linux-6.18.y"
# v6.18.63, peeled.
KERNEL_SRCREV = "1cdda838e8475edf89b73ff0cc952005dd0b1fa7"
NXP_SDK_BRANCH = "lf-6.18.y"

require linux-ask.inc

# NXP's 6.18 qoriq-dpaa-eth.dtsi includes the RCPM binding header.
NXP_SDK_PATHS += "include/dt-bindings/soc/fsl,qoriq-rcpm.h"

# The series, in order: one entry per patch in patches/kernel/6.18 (a glob
# once dropped every patch numbered 100 or above).
SRC_URI += "\
           file://010-ask-fman-dpaa-ehash.patch \
           file://040-ask-xfrm-ipsec-offload.patch \
           file://070-ask-ppp-hooks.patch \
           file://080-wext-core-restore-ndo_do_ioctl.patch \
           file://090-qbman-dpa_alloc-preallocate-nodes.patch \
           file://091-sdk_dpaa-dpa_get_channel-use-mutex.patch \
           file://092-sdk_fman-FmPcdLockTryLockAll-nest-annotation.patch \
           file://093-netlink-name-every-cb-mutex-class.patch \
           file://094-sdk-fman-dpaa-qbman-kasan-sanitize-off.patch \
           file://096-sdk_fman-mac-hash-alloc-null-check.patch \
           file://098-sdk_dpaa-bp-alloc-slab-build-skb.patch \
           file://099-sdk_fman-ehash-flex-arrays.patch \
           file://100-sdk_dpaa-ethtool-quiet-phyless-ports.patch \
           file://101-sdk_fman-sysfs-restore-irqs-on-early-return.patch \
           file://102-sdk_dpaa-extend-stop-drain-delays.patch \
           file://103-qbman-ceetm-lfq-unwind.patch \
           file://104-sdk_dpaa-rx-stats-before-stack-verdict.patch \
           file://105-sdk_dpaa-buffer-seed-failure.patch \
           file://106-sdk_fman-keep-firmware-port-icids.patch \
           file://107-sdk_dpaa-offload-hooks-under-rcu.patch \
           file://109-sdk_dpaa-rx-max-frame-follows-mtu.patch \
           file://110-sdk-mainline-build-compat.patch \
           file://111-sdk_dpaa-cpu-queues-bounded-by-pool-share.patch \
           file://112-sdk_dpaa-jumbo-rx-buffers.patch \
           file://120-emc2305-dt-fan-control.patch \
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
           file://150-sdk_dpaa-hardware-qdisc.patch \
           file://151-netfilter-flowtable-pppoe-peer.patch \
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
           file://184-sdk_dpaa-rx-checksum-feature.patch \
           file://185-netfilter-flowtable-neigh-resolution.patch \
           file://186-netfilter-flowtable-walk-latency.patch \
           file://187-netfilter-flowtable-closing-handback.patch \
          "
