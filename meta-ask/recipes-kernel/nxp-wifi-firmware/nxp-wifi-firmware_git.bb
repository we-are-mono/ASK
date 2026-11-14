SUMMARY = "NXP 88W9098 PCIe Wi-Fi firmware (u-blox JODY-W3)"
DESCRIPTION = "Firmware and regulatory/TX-power configuration for the 88W9098 \
PCIe radio on the Mono Gateway DK, loaded by the nxp-mwifiex (moal) driver \
from /lib/firmware/nxp/. Pinned per kernel line to the imx-firmware release \
that pairs with the driver's: on 6.12 the commit the OpenWrt production build \
uses, so the test image and the shipping image run the same firmware; on \
6.18 lf-6.18.37_2.1.0."

LICENSE = "Proprietary"

inherit ask-provenance

SRC_URI = "git://github.com/nxp-imx/imx-firmware.git;protocol=https;branch=${FIRMWARE_BRANCH}"

FIRMWARE_BRANCH:ask612 = "lf-6.12.49_2.2.0"
SRCREV:ask612 = "8c9b278016c97527b285f2fcbe53c2d428eb171d"
LIC_FILES_CHKSUM:ask612 = "file://LICENSE.txt;md5=bc649096ad3928ec06a8713b8d787eac"

FIRMWARE_BRANCH:ask618 = "lf-6.18.37_2.1.0"
SRCREV:ask618 = "07dd4579523496db967107397695958ff80b6c51"
# LA_OPT_NXP_Software_License v64.2 (May 2026).
LIC_FILES_CHKSUM:ask618 = "file://LICENSE.txt;md5=ef4f968b9dae8ba406390cd617c2301d"

S = "${WORKDIR}/git"

# Firmware only; nothing to compile or strip.
do_compile[noexec] = "1"
do_configure[noexec] = "1"
INHIBIT_PACKAGE_STRIP = "1"
INHIBIT_SYSROOT_STRIP = "1"

# Only the 9098 PCIe set. The repository carries every NXP part; installing
# the lot would put tens of megabytes of firmware for radios this board does
# not have into an initramfs that is already loaded over TFTP.
FW_DIR = "FwImage_9098_PCIE"

do_install() {
    install -d ${D}${nonarch_base_libdir}/firmware/nxp
    install -m 0644 ${S}/${FW_DIR}/pcieuart9098_combo_v1.bin ${D}${nonarch_base_libdir}/firmware/nxp/
    install -m 0644 ${S}/${FW_DIR}/pcie9098_wlan_v1.bin      ${D}${nonarch_base_libdir}/firmware/nxp/
    install -m 0644 ${S}/${FW_DIR}/uart9098_bt_v1.bin        ${D}${nonarch_base_libdir}/firmware/nxp/
    install -m 0644 ${S}/${FW_DIR}/ed_mac_ctrl_V3_909x.conf  ${D}${nonarch_base_libdir}/firmware/nxp/
    install -m 0644 ${S}/${FW_DIR}/txpwrlimit_cfg_9098.conf  ${D}${nonarch_base_libdir}/firmware/nxp/
}

FILES:${PN} = "${nonarch_base_libdir}/firmware"
