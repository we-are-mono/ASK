SUMMARY = "ASK runtime configuration files"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI = "file://S03debugfs \
           file://S05ask-modules \
           file://S20status-leds \
           file://S40gateway-setup \
           file://S50cmm \
           file://dnsmasq-gateway.conf \
          "

# No source tree — just config files, referenced via UNPACKDIR below.
# Point S at UNPACKDIR so bitbake doesn't warn about a missing ${BP}.
S = "${UNPACKDIR}"

RDEPENDS:${PN} += "dnsmasq iptables iproute2 cmm"

# These files are installed from ${ASK_SRCROOT} (outside SRC_URI's reach).
# Without listing them as task input checksums, bitbake's sstate signature for
# do_install doesn't change when their *content* does — meaning a fresh kas
# build silently restores the previous (stale) version from sstate. Each
# entry is "<path>:True" so bitbake hashes the file and the task re-runs on
# any content change.
do_install[file-checksums] += " \
    ${ASK_SRCROOT}/config/gateway-dk/cdx_cfg.xml:True \
    ${ASK_SRCROOT}/dpa_app/files/etc/cdx_pcd.xml:True \
    ${ASK_SRCROOT}/dpa_app/files/etc/cdx_sp.xml:True \
    ${ASK_SRCROOT}/sources/fmc/etc/fmc/config/hxs_pdl_v3.xml:True \
    ${ASK_SRCROOT}/sources/fmc/etc/fmc/config/cfgdata.xsd:True \
    ${ASK_SRCROOT}/sources/fmc/etc/fmc/config/netpcd.xsd:True \
    ${ASK_SRCROOT}/config/ask-modules.conf:True \
    ${ASK_SRCROOT}/config/fastforward:True \
"

do_install:prepend() {
    # sources/fmc/ is gitignored and fetched out-of-band by `make sources`
    # (the Debian build flow). On a fresh clone that step is easy to miss,
    # and do_install would otherwise fail deep in an install line with no
    # hint. Fail early, naming the fix.
    for f in hxs_pdl_v3.xml cfgdata.xsd netpcd.xsd; do
        if [ ! -e "${ASK_SRCROOT}/sources/fmc/etc/fmc/config/$f" ]; then
            bbfatal "config: ${ASK_SRCROOT}/sources/fmc/etc/fmc/config/$f missing — run 'make sources' in the ASK repo first (sources/ is gitignored)."
        fi
    done
}

fakeroot do_install() {
    # Board-specific FMAN port config (consumed by dpa_app / fmc).
    install -d ${D}${sysconfdir}
    install -m 0644 ${ASK_SRCROOT}/config/gateway-dk/cdx_cfg.xml ${D}${sysconfdir}/cdx_cfg.xml

    # PCD + soft-parser XML that dpa_app hands to fmc.
    install -m 0644 ${ASK_SRCROOT}/dpa_app/files/etc/cdx_pcd.xml ${D}${sysconfdir}/cdx_pcd.xml
    install -m 0644 ${ASK_SRCROOT}/dpa_app/files/etc/cdx_sp.xml  ${D}${sysconfdir}/cdx_sp.xml

    # fmc's header-parser PDL and XSD schemas — fmc opens these relative to
    # /etc/fmc/config/ by default.
    install -d ${D}${sysconfdir}/fmc/config
    install -m 0644 ${ASK_SRCROOT}/sources/fmc/etc/fmc/config/hxs_pdl_v3.xml \
        ${D}${sysconfdir}/fmc/config/hxs_pdl_v3.xml
    install -m 0644 ${ASK_SRCROOT}/sources/fmc/etc/fmc/config/cfgdata.xsd \
        ${D}${sysconfdir}/fmc/config/cfgdata.xsd
    install -m 0644 ${ASK_SRCROOT}/sources/fmc/etc/fmc/config/netpcd.xsd \
        ${D}${sysconfdir}/fmc/config/netpcd.xsd

    install -d ${D}${sysconfdir}/modules-load.d
    install -m 0644 ${ASK_SRCROOT}/config/ask-modules.conf \
        ${D}${sysconfdir}/modules-load.d/ask.conf

    install -d ${D}${sysconfdir}/config
    install -m 0644 ${ASK_SRCROOT}/config/fastforward ${D}${sysconfdir}/config/fastforward

    install -d ${D}${sysconfdir}/init.d
    install -d ${D}${sysconfdir}/rcS.d

    # Mount debugfs early (needed by kmemleak + failslab in the test harness;
    # sysvinit's mountvirtfs doesn't do this). Runs before module loading so
    # modules that register debugfs entries see the mount point ready.
    install -m 0755 ${UNPACKDIR}/S03debugfs ${D}${sysconfdir}/init.d/debugfs
    ln -sf ../init.d/debugfs ${D}${sysconfdir}/rcS.d/S03debugfs

    # sysvinit hook that reads modules-load.d/ask.conf and modprobes each
    # line — busybox has no systemd-modules-load.service equivalent.
    install -m 0755 ${UNPACKDIR}/S05ask-modules ${D}${sysconfdir}/init.d/ask-modules
    ln -sf ../init.d/ask-modules ${D}${sysconfdir}/rcS.d/S05ask-modules

    # Gateway networking (WAN=eth4 static 10.0.0.62/24, LAN=eth3 static 192.168.1.1/24,
    # iptables MASQUERADE, dnsmasq DHCP server). Runs in rcS so the board
    # is gateway-ready by the time multi-user services (dropbear) come up.
    install -m 0755 ${UNPACKDIR}/S40gateway-setup ${D}${sysconfdir}/init.d/gateway-setup
    ln -sf ../init.d/gateway-setup ${D}${sysconfdir}/rcS.d/S40gateway-setup
    install -m 0644 ${UNPACKDIR}/dnsmasq-gateway.conf ${D}${sysconfdir}/dnsmasq-gateway.conf

    # CMM (ASK connection manager) — depends on cdx/fci being loaded first.
    install -m 0755 ${UNPACKDIR}/S50cmm ${D}${sysconfdir}/init.d/cmm
    ln -sf ../init.d/cmm ${D}${sysconfdir}/rcS.d/S50cmm

    # Status LED config — runs after modules-load.d brings up leds-lp5812
    # (S05ask-modules), but before the gateway/CMM bring-up so the cue is
    # visible from early boot.
    install -m 0755 ${UNPACKDIR}/S20status-leds ${D}${sysconfdir}/init.d/status-leds
    ln -sf ../init.d/status-leds ${D}${sysconfdir}/rcS.d/S20status-leds
}

FILES:${PN} = " \
    ${sysconfdir}/cdx_cfg.xml \
    ${sysconfdir}/cdx_pcd.xml \
    ${sysconfdir}/cdx_sp.xml \
    ${sysconfdir}/fmc/config/* \
    ${sysconfdir}/modules-load.d/ask.conf \
    ${sysconfdir}/config/fastforward \
    ${sysconfdir}/init.d/debugfs \
    ${sysconfdir}/rcS.d/S03debugfs \
    ${sysconfdir}/init.d/ask-modules \
    ${sysconfdir}/rcS.d/S05ask-modules \
    ${sysconfdir}/init.d/gateway-setup \
    ${sysconfdir}/rcS.d/S40gateway-setup \
    ${sysconfdir}/dnsmasq-gateway.conf \
    ${sysconfdir}/init.d/cmm \
    ${sysconfdir}/rcS.d/S50cmm \
    ${sysconfdir}/init.d/status-leds \
    ${sysconfdir}/rcS.d/S20status-leds \
"
