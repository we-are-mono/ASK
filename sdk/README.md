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

## Removing dead code

NXP's drivers serve every QorIQ part, every NCSW integration and options ASK
never builds. Code no shipped build reaches is removed, so what is left is
what runs. Dead means dead in every consumer's build, on every line: the test
image's config, the SDK options as ASK's `config/kernel/defconfig` sets them
(what consumers build from), and OpenWrt's `target/linux/layerscape` configs.
Removing it is never a judgement about the code; it is a proof, made by
tools, before anything is deleted.

`tools/sdk_prune.py` is the tooling. It reads both lines' image builds and
series branches, so first run `make ask-image LINE=<line>` and
`make kernel-series-prepare LINE=<line>` for each line; it also needs
`unifdef` (`make setup`). It compiles the SDK directories outside bitbake
(`build`), with each line's image toolchain and `.config`, in two config
variants (`image`, `consumer`), onto the line's patched kernel, so a proof
covers four builds in minutes. Its work directory is
`meta-ask/build/sdk-prune`.

There are four kinds of dead code, each with its own proof:

| Kind | Found by | Proof |
|---|---|---|
| A file no build compiles or includes | `unused-files` | every object identical |
| A branch for an option off everywhere, another target, or another FMan integration | `macros`, then `unifdef` | every object identical |
| A function nothing calls | `remove` | symbol comparison, then the rig |
| State only removed code set | reading the code | the reasoning, in the commit |

**Files and branches** must not change one byte of compiled code:

1. `sdk_prune.py build before` snapshots the objects as they are.
2. For files: `unused-files` lists the `.c`/`.h` files no object or device
   tree of either image build, and no cdx object, reads. Delete them (`git rm`) and the Kconfig and
   Makefile lines that name them. It sees only kernel objects: a uapi header
   stays while anything in userspace still builds against it.
3. For branches: `macros` records what every SDK and cdx unit's compiler
   sees, then `unifdef` resolves, file by file, each condition on a macro the
   policy lists name (in the tool: options off in every consumer config,
   targets ASK never is, NCSW's `FM_*` integration switches) to the one value
   every unit reading the file sees. A macro the units disagree on, or that
   the file defines itself, is left alone. Add a name to the list only after
   checking every consumer config.
4. Prove it on a copy of `sdk/linux` with
   `sdk_prune.py --sdk <copy> unifdef --blank`, which blanks removed lines
   instead of deleting them: NCSW's error macros carry `__LINE__` into the
   objects, so only a copy whose surviving lines keep their numbers can
   compile identical. `sdk_prune.py --sdk <copy> build after`, then
   `compare before after`, must report every object identical, on every line
   and variant.
5. Run `unifdef` on `sdk/linux` without `--blank`. `diff -rqB` against the
   proven copy must show no difference but blank lines.

**Functions nothing calls** cannot keep the objects identical; their proof is
what the compiler and linker see:

1. `sdk_prune.py remove` takes the global functions no relocation names, in
   any compilation unit of either image build, of the SDK in both variants,
   or of cdx -- the sections that only export a symbol aside (`__ksymtab*`,
   and the `.export_symbol` that `EXPORT_SYMBOL` writes on these lines) -- and
   no out-of-tree module of the image needs, and that the source does not
   use: the SDK copy and cdx read as C, the kernel patches' added lines
   counted as uses wherever they name one. The source scan is what keeps a
   function whose every call was inlined in its own file, which leaves no
   relocation.
2. It plans each deletion (the definition, the comment right above it, its
   `EXPORT_SYMBOL`, every declaration with its comment, an `#if` block left
   empty), applies it to a scratch copy and builds all four. A static
   function or variable the compiler then reports unused joins the list; so
   does a global whose last caller went. It repeats until the builds are
   clean and nothing new is uncalled.
3. `remove --apply` writes the result to `sdk/linux` (as `sed -i 'A,Bd'`);
   `compare before after --removed meta-ask/build/sdk-prune/remove.json`
   must show only the planned functions gone, statics now inlined into their
   last caller (clones such as `.isra` among them), functions resized by that
   inlining or by the layout of their file's strings, and nothing new; it
   fails on a global function gone that was not planned.
4. Fix by hand the comments that still name a removed function, and remove
   the host tests' cases for it. Then build and test both lines, and run
   the rig on both before merging: this kind is proven by analysis, not by
   identical code.

**State only removed code set** (a flag nothing left sets, the branch that
tests it, the field) is found by reading what step 4 leaves, and removed by
hand, with the reasoning in the commit: for example, a port struct zeroed at
creation keeps a flag false that only a removed function set.

What every removal keeps to:
- Code any consumer config compiles stays, however unlikely its use.
- Only the tools delete, or the Edit tool by hand; never a hand-written
  `sed`/script over the copy.
- One commit per kind, saying what went and how it was proven.
- `-D__LINE__=0` instead of `--blank` does not work: the build warns about
  redefining a builtin, and warnings are errors.
- A definition or declaration counts only at file scope: a call written as
  `return f(x);` or `else f(x);` looks like a declaration to a scan that
  ignores scope, and deleting it would change live code.
- Only compilation units count as references, never a link of them:
  `vmlinux.o` holds the SDK's code as the image build compiled it, and its
  calls between dead functions keep each other alive.
