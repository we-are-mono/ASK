SUMMARY = "ASK test-harness on-node HTTP/JSON agent"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI = " \
    file://askd_agent \
    file://S70askd-agent \
"

# No upstream source — everything is in files/.
S = "${UNPACKDIR}"

RDEPENDS:${PN} += " \
    python3-core \
    python3-aiohttp \
"

do_install() {
    # Install the Python package into the system site-packages. On the
    # target there's no venv — we use the distro python3 directly.
    install -d ${D}${PYTHON_SITEPACKAGES_DIR}/askd_agent
    install -m 0644 ${UNPACKDIR}/askd_agent/*.py \
        ${D}${PYTHON_SITEPACKAGES_DIR}/askd_agent/

    # Thin launcher wrapping `python3 -m askd_agent`.
    install -d ${D}${bindir}
    cat > ${D}${bindir}/askd-agent <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -m askd_agent "$@"
EOF
    chmod 0755 ${D}${bindir}/askd-agent

    # sysvinit: S70askd-agent → /etc/init.d/askd-agent + rcS.d symlink.
    install -d ${D}${sysconfdir}/init.d
    install -d ${D}${sysconfdir}/rcS.d
    install -m 0755 ${UNPACKDIR}/S70askd-agent ${D}${sysconfdir}/init.d/askd-agent
    ln -sf ../init.d/askd-agent ${D}${sysconfdir}/rcS.d/S70askd-agent
}

FILES:${PN} = " \
    ${PYTHON_SITEPACKAGES_DIR}/askd_agent \
    ${bindir}/askd-agent \
    ${sysconfdir}/init.d/askd-agent \
    ${sysconfdir}/rcS.d/S70askd-agent \
"

inherit python3-dir
