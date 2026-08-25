# ASK Versioning and Branching

This document describes how ASK is versioned, branched, released, and maintained across different Linux kernel versions.

## Branches

ASK uses the following branch model:

* `master` — active development for the newest kernel version we support.
* `mono-6.12` — maintenance branch for the Linux 6.12 compatibility line.
* `mono-6.18` — maintenance branch for the Linux 6.18 compatibility line.

The `mono-*` branches are created when a kernel compatibility line becomes a released/stable version of ASK.

`master` always represents the next version of ASK under active development.

### Example

While ASK 1.0 is the current release:

```text
master       -> development for Linux 6.18
mono-6.12    -> ASK 1.0 maintenance for Linux 6.12
```

After the first stable 6.18 release:

```text
master       -> development for the next kernel version
mono-6.18    -> 6.18 maintenance
mono-6.12    -> 6.12 maintenance
```

## Initial 6.12 Release

ASK initially targets Linux 6.12.

Until ASK 1.0 is released, all development remains on `master`, including fixes and improvements to the 6.12 implementation.

Once the 6.12 implementation is considered stable and ASK 1.0 is released:

```bash
git tag -a v1.0.0 -m "ASK 1.0.0"
git branch mono-6.12
```

The `mono-6.12` branch represents the 6.12 maintenance line from that point onward.

`master` then becomes the development branch for the next kernel compatibility target, initially Linux 6.18.

## Developing a New Kernel Compatibility Version

A new kernel compatibility version is developed on `master`.

For example, after ASK 1.0:

```text
mono-6.12  -> maintenance
master     -> 6.18 development
```

There is no need to create `mono-6.18` when 6.18 development starts.

`mono-6.18` is created only when the 6.18 implementation is stable and becomes a released version of ASK.

For example:

```bash
git tag -a v2.0.0 -m "ASK 2.0.0"
git branch mono-6.18
```

After this point:

```text
master     -> development for the next kernel version
mono-6.18  -> 6.18 maintenance
mono-6.12  -> 6.12 maintenance
```

## Fixes and Backports

New fixes should normally be developed on `master` first.

Once a fix is committed to `master`, determine which maintained branches are affected.

If a fix is also required on an older compatibility branch, cherry-pick the fix onto that branch:

```bash
git switch mono-6.12
git cherry-pick -x <commit>
```

The `-x` option records the original commit in the backport commit, making the relationship between the two changes explicit.

Do not routinely merge maintenance branches into `master`, or `master` into maintenance branches.

The normal direction is:

```text
                    master
                      │
                  fix/feature
                      │
          ┌───────────┼───────────┐
          │           │           │
          ▼           ▼           ▼
      6.18 branch  6.12 branch  other
       (if needed)  (if needed)
```

A fix should only be backported when it is applicable to the older branch.

## API and Kernel-Version Differences

A backport does not have to be identical to the original commit.

Different kernel versions may provide different APIs or require different implementations.

For example:

```text
master / 6.18:
    use new_kernel_api()

mono-6.12:
    use old_kernel_api()
```

If the same logical bug exists in both versions, fix it on `master` first and adapt the implementation when backporting it to `mono-6.12`.

The important requirement is that the branches receive the appropriate equivalent fix, not that their source code or Git history remain identical.

## Features

New features should normally be developed on `master`.

Features should only be backported to an older maintenance branch when there is an explicit reason to support them there.

Maintenance branches should not automatically receive every change from `master`.

In particular, kernel-version-specific functionality that depends on a newer kernel API should not be backported merely to keep the branches similar.

## Commit Structure

Keep commits focused and logically independent whenever practical.

For example:

```text
module: fix race in foo
module: improve error handling
module: add support for new kernel API
module: fix memory leak
```

Avoid combining unrelated fixes into large commits.

This makes it possible to selectively cherry-pick individual fixes into maintained branches.

A commit on `master` should therefore be considered the canonical version of a change whenever possible.

## Release Tags

Tags identify the exact ASK version that was released.

For example:

```text
v1.0.0
v1.0.1
v1.1.0
v2.0.0
```

Branches identify maintenance lines, while tags identify exact releases.

For example:

```text
mono-6.12
    ├── v1.0.0
    ├── v1.0.1
    └── v1.0.2

mono-6.18
    ├── v2.0.0
    └── v2.0.1
```

## Support Policy

Each `mono-*` branch represents a specific kernel compatibility line.

For example:

```text
mono-6.12 -> Linux 6.12.y
mono-6.18 -> Linux 6.18.y
```

The branch name refers to the kernel series, not to one particular kernel patch release.

ASK should be tested against appropriate current releases from each supported kernel series.

A maintenance branch may be retired when support for its corresponding kernel series is discontinued.

## Summary

The rules are:

1. `master` is the active development branch.
2. The current kernel compatibility implementation is developed on `master` until it is released.
3. A `mono-X.Y` branch is created when the corresponding kernel compatibility line becomes a stable/released ASK version.
4. Release branches are maintained independently after they are created.
5. Fixes are developed on `master` first whenever practical.
6. Applicable fixes are selectively backported to maintained branches using `git cherry-pick -x`.
7. Do not routinely merge maintenance branches into `master` or `master` into maintenance branches.
8. Backported fixes may require different implementations because of kernel API differences.
9. New features are developed on `master` and only selectively backported.
10. Tags identify exact ASK releases; branches identify maintained kernel compatibility lines.

The intended long-term structure is:

```text
                         master
                           │
                    next development
                           │
                           ▼
                         ...
                           │
                       v2.0.0
                           │
                           └── mono-6.18
                                  │
                                  │ maintenance
                                  ▼

v1.0.0 ─────────────────────── mono-6.12
                                  │
                                  │ maintenance
                                  ▼
```

The key principle is:

> `master` moves forward; `mono-*` branches stay behind and receive only the fixes and changes that are applicable to their supported kernel series.

