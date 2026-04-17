# Apply the ASK extension patch on top of the stock libnfnetlink recipe.
# The patch adds nfnl_set_nonblocking_mode() / heap-buffer APIs consumed
# by the cmm daemon. Since the patch only ADDS symbols, all other
# libnfnetlink users (conntrack-tools, libnetfilter_conntrack) keep working.

FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/patches/libnfnetlink/${PV}:"

SRC_URI += "file://01-nxp-ask-nonblocking-heap-buffer.patch"

ERROR_QA:remove = "patch-status"
WARN_QA:remove  = "patch-status"

# cmm needs the static archive.
EXTRA_OECONF:append = " --enable-static"
