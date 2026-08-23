# Canonical NXP DPAA/FMan/QBMan SDK pin (NXP tag lf-6.12.49-2.2.0).
#
# Format-neutral single source of truth for the SDK SRCREV, shared by every
# consumer of the ASK release so none has to parse another's build format:
#   - meta-ask (bitbake):  require ${ASK_SRCROOT}/pins/nxp-sdk-srcrev.inc
#   - OpenWrt sync (sh):   sed -n 's/^NXP_SDK_SRCREV = "\(.*\)"/\1/p' <this file>
#   - Armbian (bash):      same sed
#
# One line, `KEY = "VALUE"`: valid bitbake AND trivially greppable. Bump this on
# an SDK update — every consumer picks it up from the pinned ASK tree, so
# ASK_VERSION stays the single pin.
NXP_SDK_SRCREV = "df24f9428e38740256a410b983003a478e72a7c0"
