SUMMARY = "NXP 88W9098 PCIe Wi-Fi firmware (u-blox JODY-W3)"
DESCRIPTION = "Firmware and regulatory/TX-power configuration for the 88W9098 \
PCIe radio on the Mono Gateway DK, loaded by the nxp-mwifiex (moal) driver \
from /lib/firmware/nxp/. Pinned to the same imx-firmware commit the OpenWrt \
production build uses, so the test image and the shipping image run the same \
firmware."

LICENSE = "Proprietary"
LIC_FILES_CHKSUM = "file://LICENSE.txt;md5=bc649096ad3928ec06a8713b8d787eac"

SRC_URI = "git://github.com/nxp-imx/imx-firmware.git;protocol=https;branch=lf-6.12.49_2.2.0"
SRCREV = "8c9b278016c97527b285f2fcbe53c2d428eb171d"

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
