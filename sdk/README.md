# NXP DPAA SDK drivers

ASK's copy of NXP's QorIQ SDK drivers for DPAA1: FMan (`sdk_fman`), the DPAA
Ethernet driver (`sdk_dpaa`), QMan and BMan (`fsl_qbman`), their headers and
the LS1046A device tree they bind to. Mainline carries its own FMan, DPAA and
QBMan drivers, but not the classifier (PCD) ASK offloads through, and their
device tree bindings are not the SDK's.

Each kernel line has its own copy, laid out as in a kernel tree:

| Line | Copy        | NXP branch  | NXP release        | Imported from NXP commit                   |
|------|-------------|-------------|--------------------|--------------------------------------------|
| 6.12 | `sdk/6.12/` | `lf-6.12.y` | `lf-6.12.49-2.2.0` | `df24f9428e38740256a410b983003a478e72a7c0` |
| 6.18 | `sdk/6.18/` | `lf-6.18.y` | `lf-6.18.37-2.1.0` | `6e694eda40aabd6671fca82b5416dbd76beeebb9` |

NXP's repository is <https://github.com/nxp-qoriq/linux>. The files keep
NXP's license headers.

## How it reaches the kernel

The kernel recipe's `do_overlay_sdk` (`meta-ask/recipes-kernel/linux/linux-ask.inc`)
copies a line's copy onto stock mainline before the line's patch series
applies: each directory `NXP_SDK_PATHS` names replaces mainline's wholesale,
each file it names overwrites mainline's. A copy holds exactly those paths.
`make kernel-series-prepare` lays the same base.

## Changing it

Edit the files here. ASK's changes to the SDK are commits on these files, not
patches in `patches/kernel/<line>/`: `make kernel-series-check` refuses a
patch that touches them. A fix that applies to both lines lands in both
copies, the newest line first.

## Taking NXP's changes

The branch `vendor/nxp-sdk` holds NXP's code unmodified: each of its commits
replaces a line's copy with NXP's files at one NXP commit, and updates the
table above. `git diff vendor/nxp-sdk master -- sdk/<line>` is ASK's change to
NXP's code for that line. To take a newer NXP release:

1. Check out `vendor/nxp-sdk` (in a worktree of its own).
2. Replace `sdk/<line>/` with the `NXP_SDK_PATHS` files at the new NXP
   commit, update the table, and commit, naming the NXP release and commit.
3. Merge `vendor/nxp-sdk` into a topic branch off `master`: git merges NXP's
   changes into ASK's copy three-way, against the previous import.
4. Build and test the line as for any other SDK change.

A new kernel line starts the same way: its NXP copy is imported on
`vendor/nxp-sdk` as `sdk/<line>/` and merged, then ASK's changes are carried
over from the newest line's copy.
