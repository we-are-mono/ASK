# Canonical NXP DPAA/FMan/QBMan SDK pin for the 6.18 kernel line (NXP tag
# lf-6.18.37-2.1.0). Each kernel line has its own, at pins/<line>/.
#
# Format-neutral single source of truth for the SDK SRCREV, shared by every
# consumer of the ASK release so none has to parse another's build format:
#   - meta-ask (bitbake):  linux-ask.inc requires pins/<line>/nxp-sdk-srcrev.inc
#   - OpenWrt sync (sh):   sed -n 's/^NXP_SDK_SRCREV = "\(.*\)"/\1/p' <this file>
#   - Armbian (bash):      same sed
#
# One line, `KEY = "VALUE"`: valid bitbake AND trivially greppable. Bump this on
# an SDK update — every consumer picks it up from the pinned ASK tree, so
# ASK_VERSION stays the single pin.
NXP_SDK_SRCREV = "6e694eda40aabd6671fca82b5416dbd76beeebb9"
