# Apply the ASK Comcerto fast-path extension patch on top of the stock
# libnetfilter-conntrack recipe. The patch adds ASK-specific CTA
# attributes and flags consumed by cmm. Backward-compatible with stock
# users (conntrack-tools).

FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/patches/libnetfilter-conntrack/${PV}:"

SRC_URI += "file://01-nxp-ask-comcerto-fp-extensions.patch"

ERROR_QA:remove = "patch-status"
WARN_QA:remove  = "patch-status"

EXTRA_OECONF:append = " --enable-static"
