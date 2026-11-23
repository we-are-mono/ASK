# ASK Versioning and Branching

How ASK is versioned, released and maintained across Linux kernel lines.

## One trunk, every line

ASK is coupled to its kernel: the patch series, the NXP SDK drivers it overlays
and the interface between cdx and the kernel hooks all follow the kernel line.
Rather than a branch per line, one trunk carries every supported line side by
side, the way OpenWrt carries its targets' kernels:

```text
patches/kernel/6.12/   patches/kernel/6.18/      the series, one per line
sdk/6.12/              sdk/6.18/                 ASK's copy of the NXP SDK drivers
meta-ask/recipes-kernel/linux/
    linux-ask_6.12.bb  linux-ask_6.18.bb         kernel pin and series order
    linux-ask.inc                                what the lines share
```

Each SDK copy is NXP's code for that line with ASK's changes made in place;
the `vendor/nxp-sdk` branch keeps NXP's code unmodified, so a newer NXP release
merges in three-way (`sdk/README.md`).

Everything else -- cdx, ask_flowtable, the flowtable daemon, the tests -- is one
copy that builds for every line. What differs between kernel or SDK releases is
kept in `cdx/compat.h`, keyed on the release that changed it, so the sources are
written once, in the newest line's terms.

A build picks its line: `make ask-image LINE=6.12` (the default is the newest).
Each line builds in its own `meta-ask/build/tmp-<line>`, and the test targets
take the same `LINE`.

`master` is the trunk and stays releasable. Work happens on short-lived branches
off `master`, is tested, and merges back.

## Versions and tags

There is one ASK version across lines, and one tag per release: the release
commit is tagged once, annotated, `mono-<version>` (`mono-1.4.0`). Every line
is built from that same commit, so the line is not part of the name; a
consumer's own kernel picks the series it applies (OpenWrt reads its
`KERNEL_PATCHVER`).

What the tag does carry is which lines the release is released for -- tested
with the full rig suite and supported. The release commit declares them in
`RELEASED_LINES`, one per line, and the tag message repeats them:

```text
$ cat RELEASED_LINES
6.12
6.18
$ git tag -a mono-1.4.0 -m "ASK 1.4.0 (lines: 6.12, 6.18)"
```

Consumers refuse a release whose `RELEASED_LINES` lacks their kernel's line:
the OpenWrt sync and the `ask-version` pin both check it. `make release-status
LINE=<line>` reports whether the line's release matrix qualifies and whether
the line is listed.

The version follows ASK's own changes, not the kernel's: porting to a new line
changes no functionality, so it is no major bump. A pushed tag never moves.

Tags from before the trunk (`mono-1.0.0` to `mono-1.3.1`) are 6.12 releases
and stay as they are. The `mt-6.12.y` branch stays where it is; no new `mt-*`
branches are made.

## How many lines

At most two lines are released at once.

- **A new line** (7.x, once NXP publishes an SDK for it and the fleet's OpenWrt
  targets that kernel) is ported on a topic branch: copy the newest line's series
  and recipe, port them, and adapt `cdx/compat.h`. It merges into `master` once
  it builds warning-free and its host suite is green, and joins
  `RELEASED_LINES` at parity -- its full rig suite green; releases cover it
  from then on.
- **The older line** takes critical fixes only once the fleet's OpenWrt has left
  its kernel, and is removed after: it leaves `RELEASED_LINES`, then its
  series, pin and recipe go, with the `compat.h` branches only it needed.

## Fixes and backports

A fix lands on the newest line first, then on the other line where it applies.
A backport keeps its link to the original change: it is cherry-picked, and
adapted by hand only where the pick does not apply -- toward the same intent,
never a different fix on one line.

- **Shared code** (cdx, ask_flowtable, the daemon, the tests) has nothing to
  backport: it is one commit for every line. A kernel interface that differs
  goes behind `cdx/compat.h`, keyed on the release that changed it.
- **A kernel patch** is a file in each line's series, so it is changed in a git
  history generated from that series. The work repository
  (`meta-ask/build/kernel-series`) holds every line's branches side by side:

  ```sh
  make kernel-series-prepare LINE=6.18   # base-6.18, and series-6.18 on top of it
  make kernel-series-prepare LINE=6.12
  # In meta-ask/build/kernel-series: commit the fix on series-6.18 as a
  # fixup of the patch that owns its concern (git commit --fixup=<commit>),
  # then carry the same commit to the other line:
  git checkout series-6.12 && git cherry-pick -x <fixup commit>
  # Resolve conflicts where the kernels differ, then on each branch:
  git rebase -i --autosquash base-<line>
  make kernel-series-regen LINE=<line>   # writes back only the patches that changed
  make kernel-series-check LINE=<line>   # the files reproduce the branch on a fresh base
  ```

  The two copies of a patch may differ only where the kernels do.
- **An upstream fix** a line lacks comes, by preference, with a stable bump
  that carries it (below). If none does, it is cherry-picked with `-x` onto
  the line's series as a patch of its own -- its upstream subject, a
  `[ Upstream commit <sha> ]` line, a note of anything adapted, a new number
  and `SRC_URI` entry -- and it goes again with the bump that brings it.

The regression test travels with the fix: the host suite runs against each
line's tree (`make test-host LINE=<line>`), so one test proves every copy.

A release covers the lines its `RELEASED_LINES` lists. A fix for one line
only is a release like any other; the other line's consumers can stay on the
version they have.

## Testing

| When | What |
|---|---|
| Every change | host suite on every line; scoped rig tests on the newest line and on the line the change targets |
| Every stable bump | the upstream commits between the old and the new stable tag that touch files the line's patches touch, reviewed |
| Every release | the full suite on each line released |

## Stable bumps

A line follows its kernel's stable releases. A bump moves the line's
`KERNEL_SRCREV`, regenerates its series against the new base, and is reviewed
against the upstream changes to the files the series touches
(`make kernel-stable-review LINE=<line> TO=<tag>` lists them): stable
backports have changed behaviour the patches rely on before (the 6.18
flowtable's transmit path, its TCP close, nft's reading of PPPoE frames).
