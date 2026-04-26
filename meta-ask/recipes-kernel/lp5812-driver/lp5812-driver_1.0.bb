SUMMARY = "Texas Instruments LP5812 LED Matrix Driver"
DESCRIPTION = "Linux kernel driver for TI LP5812 LED controller that supports 4x3 LED matrix via I2C"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/GPL-2.0-only;md5=801f80980d171dd6425610833a22dbe6"

inherit module

SRC_URI = " \
    file://leds-lp5812.c \
    file://leds-lp5812.h \
    file://Makefile \
"

S = "${WORKDIR}/sources"
UNPACKDIR = "${S}"

do_install:append() {
    # Install module configuration if needed
    install -d ${D}${sysconfdir}/modules-load.d
    echo "leds-lp5812" > ${D}${sysconfdir}/modules-load.d/leds-lp5812.conf
}

FILES:${PN} += "${sysconfdir}/modules-load.d/leds-lp5812.conf"
