# NXP DPAA SDK drivers

ASK's copy of NXP's QorIQ SDK drivers for DPAA1: FMan (`sdk_fman`), the DPAA
Ethernet driver (`sdk_dpaa`), QMan and BMan (`fsl_qbman`), their headers and
the LS1046A device tree they bind to. Mainline carries its own FMan, DPAA and
QBMan drivers, but not the classifier (PCD) ASK offloads through, and their
device tree bindings are not the SDK's.

One copy, `sdk/linux/`, laid out as in a kernel tree, is what every kernel line
builds. It is NXP's code, with ASK's changes made in place, from:

| NXP branch  | NXP release        | NXP commit                                 |
|-------------|--------------------|--------------------------------------------|
| `lf-6.18.y` | `lf-6.18.37-2.1.0` | `6e694eda40aabd6671fca82b5416dbd76beeebb9` |

NXP's repository is <https://github.com/nxp-qoriq/linux>. The files keep
NXP's license headers. The code is written in the newest kernel line's terms;
where an older line's kernel API differs, a `LINUX_VERSION_CODE` guard keyed on
the release that changed it says so.

## How it reaches the kernel

The kernel recipe's `do_overlay_sdk` (`meta-ask/recipes-kernel/linux/linux-ask.inc`)
copies the copy onto stock mainline before the line's patch series applies:
each directory `NXP_SDK_PATHS` names replaces mainline's wholesale, each file
it names overwrites mainline's. The copy holds exactly those paths.
`make kernel-series-prepare` lays the same base.

## Changing it

Edit the files here. ASK's changes to the SDK are commits on these files, not
patches in `patches/kernel/<line>/`: `make kernel-series-check` refuses a
patch that touches them. A fix is made once and reaches every line.

## Taking NXP's changes

The branch `vendor/nxp-sdk` holds NXP's code unmodified, at the same paths:
each of its commits replaces the copy with NXP's files at one NXP commit, and
updates the table above. `git diff vendor/nxp-sdk master -- sdk/linux` is ASK's
change to NXP's code. To take a newer NXP release:

1. Check out `vendor/nxp-sdk` (in a worktree of its own).
2. Replace `sdk/linux/` with the `NXP_SDK_PATHS` files at the new NXP commit,
   update the table, and commit, naming the NXP release and commit.
3. Merge `vendor/nxp-sdk` into a topic branch off `master`: git merges NXP's
   changes into ASK's copy three-way, against the previous import. Code ASK
   removed as dead stays removed: resolve such a conflict by keeping the
   removal, unless NXP's change makes the code live.
4. Build and test every line, as for any other SDK change.

A new kernel line builds the same copy: where its kernel API differs, add the
guards, keyed on the release that changed it.
