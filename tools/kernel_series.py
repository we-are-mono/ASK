"""A kernel line's patch series, as a git branch to work on and back.

patches/kernel/<line>/*.patch is the series' one source of truth; this builds
the git history it is edited in, and writes it back. The NXP SDK drivers are
not patched: their code is ASK's copy, sdk/linux, edited in place.

  prepare        base-<line>: the line's stable commit with sdk/linux
                 overlaid, as the recipe's do_overlay_sdk lays it, in one
                 commit; series-<line>: the series applied onto it, strictly
                 (git am, no three-way), in the recipe's SRC_URI order.
  regen          series-<line>'s commits written back over their patch files
                 (matched by subject); a file whose change did not change --
                 bar its commit id, blob abbreviations and hunk offsets -- is
                 left as it is. A commit that changes the SDK copy's files is
                 refused: that change belongs in sdk/linux.
  check          the patch files applied onto a fresh base-<line>, strictly,
                 must reproduce series-<line>; the directory and SRC_URI must
                 name the same patches, and no patch may touch the SDK copy.
  stable-review  the upstream commits between the line's stable commit and
                 --to that touch a file the series touches: what a stable bump
                 must be read against.

The work repository defaults to meta-ask/build/kernel-series (ignored by git);
the kas download cache's git mirrors are used when site.conf names one.
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ask_orch import kernel_line  # noqa: E402

ROOT = kernel_line.ROOT
RECIPES = ROOT / kernel_line.RECIPES
STABLE_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
STABLE_MIRROR = "git.kernel.org.pub.scm.linux.kernel.git.stable.linux.git"
IDENT = ["-c", "user.name=Tomaz Zaman", "-c", "user.email=tomaz@mono.si"]


def git(repo, *args, check=True, capture=True):
    result = subprocess.run(["git", "-C", str(repo), *args], text=True, check=False,
                            capture_output=capture)
    if check and result.returncode:
        raise SystemExit(f"git {' '.join(args)}: {(result.stderr or '').strip()}")
    return result.stdout if capture else ""


def assignment(text, name):
    match = re.search(r'^' + re.escape(name) + r'\s*=\s*"([^"]*)"', text, re.M)
    if not match:
        raise SystemExit(f"{name} not set")
    return match.group(1)


class Line:
    """What a line's recipe says, and where its SDK copy is."""

    def __init__(self, line):
        self.line = line
        recipe = (RECIPES / f"linux-ask_{line}.bb").read_text()
        shared = (RECIPES / "linux-ask.inc").read_text()
        self.kernel = assignment(recipe, "KERNEL_SRCREV")
        self.sdk = kernel_line.sdk(ROOT)
        block = re.search(r'^NXP_SDK_PATHS = "\\\n(.*?)^"', shared, re.M | re.S)
        if not block:
            raise SystemExit("NXP_SDK_PATHS not found in linux-ask.inc")
        self.overlay = block.group(1).replace("\\", " ").split()
        for extra in re.findall(r'^NXP_SDK_PATHS\s*\+=\s*"([^"]*)"', recipe, re.M):
            self.overlay += extra.split()
        self.order = re.findall(r"^\s*file://(\d{3}-[^\s]+\.patch)", recipe, re.M)
        self.dir = ROOT / "patches" / "kernel" / line
        self.base = f"base-{line}"
        self.series = f"series-{line}"

    def in_sdk(self, path):
        """Whether a kernel-tree path is one the SDK copy overlays."""
        return any(path == entry or path.startswith(entry + "/") for entry in self.overlay)


def download_dir():
    site = ROOT / "meta-ask" / "site.conf"
    if site.exists():
        match = re.search(r'^DL_DIR\s*=\s*"([^"]+)"', site.read_text(), re.M)
        if match:
            return Path(match.group(1)) / "git2"
    return None


def source():
    mirror = download_dir()
    if mirror and (mirror / STABLE_MIRROR).is_dir():
        return str(mirror / STABLE_MIRROR)
    return STABLE_URL


def repository(work):
    repo = Path(work)
    if not (repo / ".git").exists():
        repo.mkdir(parents=True, exist_ok=True)
        git(repo, "init", "-q")
    return repo


def has(repo, rev):
    return subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{rev}^{{commit}}"],
                          capture_output=True).returncode == 0


def fetch(repo, rev):
    """A stable commit by its hash, or a tag by its name (kept as a local tag)."""
    if has(repo, rev):
        return
    spec = rev if re.fullmatch(r"[0-9a-f]{40}", rev) else f"refs/tags/{rev}:refs/tags/{rev}"
    print(f"fetching {rev} from {source()}")
    git(repo, "fetch", "-q", "--no-tags", source(), spec, capture=False)
    if not has(repo, rev):
        raise SystemExit(f"{rev}: not found in {source()}")


def subject(text):
    match = re.search(r"^Subject: \[PATCH\] (.*(?:\n [^\n]*)*)", text, re.M)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else None


def normalized(text):
    """A patch without what regeneration renews by itself: its commit id, the
    blob abbreviations, and where each hunk starts -- git am finds a hunk at an
    offset, so a file written against an earlier state of the series applies
    the same, and rewriting it would only add noise to the change that moved it."""
    text = re.sub(r"^(From [0-9a-f]{40} .*|index [0-9a-f]+\.\.[0-9a-f]+.*)$", "", text, flags=re.M)
    return re.sub(r"^@@ -\d+((?:,\d+)?) \+\d+((?:,\d+)?) @@", r"@@ -\1 +\2 @@", text, flags=re.M)


def apply_series(repo, line, files_dir):
    for name in line.order:
        patch = Path(files_dir) / name
        if not patch.exists():
            raise SystemExit(f"{name}: in the recipe's SRC_URI, not in {files_dir}")
        result = subprocess.run(["git", "-C", str(repo), *IDENT, "am", "-q", str(patch)],
                                capture_output=True, text=True)
        if result.returncode:
            subprocess.run(["git", "-C", str(repo), "am", "--abort"], capture_output=True)
            raise SystemExit(f"{name} does not apply:\n{result.stdout}{result.stderr}")


def sdk_patches(line):
    """The patch files that touch the SDK copy's paths, each with its count."""
    touching = {}
    for path in sorted(line.dir.glob("*.patch")):
        pairs = re.findall(r"^diff --git a/(\S+) b/(\S+)$", path.read_text(), re.M)
        hits = {name for pair in pairs for name in pair if line.in_sdk(name)}
        if hits:
            touching[path.name] = len(hits)
    return touching


def overlay(repo, line):
    """sdk/linux laid over the checked-out tree, as do_overlay_sdk lays it:
    a listed directory replaces mainline's wholesale, a listed file overwrites
    mainline's, and the copy may hold nothing else."""
    if not line.sdk.is_dir():
        raise SystemExit(f"{line.sdk}: no SDK copy")
    stray = sorted(str(path.relative_to(line.sdk)) for path in line.sdk.rglob("*")
                   if (path.is_file() or path.is_symlink())
                   and not line.in_sdk(str(path.relative_to(line.sdk))))
    if stray:
        raise SystemExit(f"{line.sdk} holds files outside NXP_SDK_PATHS: {', '.join(stray)}")
    for path in line.overlay:
        src, dst = line.sdk / path, Path(repo) / path
        if not src.exists():
            raise SystemExit(f"{path}: in NXP_SDK_PATHS, not in {line.sdk}")
        git(repo, "rm", "-rq", "--ignore-unmatch", "--", path)
        if src.is_dir():
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst, symlinks=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst, follow_symlinks=False)


def prepare(args, line):
    repo = repository(args.work)
    fetch(repo, line.kernel)
    git(repo, "checkout", "-q", "-f", "-B", line.base, line.kernel)
    git(repo, "clean", "-qfdx")
    overlay(repo, line)
    git(repo, "add", "-A")
    git(repo, *IDENT, "commit", "-qm", f"base: {line.kernel[:12]} + sdk/linux")
    git(repo, "checkout", "-q", "-B", line.series, line.base)
    apply_series(repo, line, line.dir)
    print(f"{line.series}: {len(line.order)} patches on {line.base} in {repo}")


def regen(args, line):
    repo = repository(args.work)
    files = {subject(path.read_text()): path for path in line.dir.glob("*.patch")}
    commits = git(repo, "rev-list", "--reverse", f"{line.base}..{line.series}").split()
    for commit in commits:
        changed = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", commit).split()
        if hits := sorted(path for path in changed if line.in_sdk(path)):
            title = git(repo, "show", "-s", "--format=%s", commit).strip()
            raise SystemExit(f"commit {commit[:12]} ({title}) changes the SDK copy's files "
                             f"({', '.join(hits)}): make that change in sdk/linux/, then "
                             "prepare again; nothing was written")
    written = kept = 0
    for commit in commits:
        title = re.sub(r"\s+", " ", git(repo, "show", "-s", "--format=%s", commit)).strip()
        path = files.pop(title, None)
        if path is None:
            raise SystemExit(f"no patch file for commit {commit[:12]} ({title}): add it to "
                             f"linux-ask_{line.line}.bb's SRC_URI and create {line.dir}/<NNN-concern>.patch")
        text = git(repo, "format-patch", "--no-numbered", "--zero-commit", "-1", commit, "--stdout")
        if normalized(text) == normalized(path.read_text()):
            kept += 1
            continue
        path.write_text(text)
        written += 1
    print(f"{line.dir}: {written} rewritten, {kept} unchanged")
    if files:
        print("patch files no commit produced: " + ", ".join(sorted(p.name for p in files.values())))
        raise SystemExit(1)


def check(args, line):
    names = sorted(path.name for path in line.dir.glob("*.patch"))
    if sorted(line.order) != names:
        missing = sorted(set(names) - set(line.order))
        absent = sorted(set(line.order) - set(names))
        raise SystemExit(f"SRC_URI and {line.dir} differ: not in SRC_URI {missing}, no file {absent}")
    if touching := sdk_patches(line):
        raise SystemExit(f"patches changing sdk/linux files (count each), which are edited "
                         f"in place instead: {touching}")
    repo = repository(args.work)
    with tempfile.TemporaryDirectory(prefix=f"check-{line.line}-") as scratch:
        tree = Path(scratch) / "tree"
        git(repo, "worktree", "add", "-q", "--detach", str(tree), line.base)
        try:
            apply_series(tree, line, line.dir)
            diff = git(tree, "diff", "--stat", line.series, "HEAD")
        finally:
            git(repo, "worktree", "remove", "--force", str(tree), check=False)
    if diff.strip():
        raise SystemExit(f"{line.dir} does not reproduce {line.series}:\n{diff}")
    print(f"{line.dir}: {len(line.order)} patches apply strictly and reproduce {line.series}")


def stable_review(args, line):
    repo = repository(args.work)
    fetch(repo, line.kernel)
    fetch(repo, args.to)
    touched = set()
    for path in line.dir.glob("*.patch"):
        touched.update(re.findall(r"^diff --git a/(\S+) b/", path.read_text(), re.M))
    # The overlay replaces these wholesale; upstream changes to them never reach the build.
    touched = sorted(p for p in touched if not line.in_sdk(p))
    log = git(repo, "log", "--no-merges", "--format=%h %s", f"{line.kernel}..{args.to}", "--", *touched)
    commits = log.splitlines()
    print(f"{len(commits)} upstream commits in {line.kernel[:12]}..{args.to} touch the {len(touched)} "
          f"files the {line.line} series patches:")
    for entry in commits:
        files = git(repo, "show", "--format=", "--name-only", entry.split()[0]).split()
        print(f"  {entry}\n      {' '.join(f for f in files if f in touched)}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("action", choices=["prepare", "regen", "check", "stable-review"])
    parser.add_argument("--line", default=None, help="kernel line (default: ASK_LINE, else the newest)")
    parser.add_argument("--work", default=str(ROOT / "meta-ask" / "build" / "kernel-series"))
    parser.add_argument("--to", help="stable-review: the stable tag or commit to review a bump to")
    args = parser.parse_args(argv)
    line = Line(args.line or kernel_line.current())
    if args.action == "stable-review" and not args.to:
        parser.error("stable-review needs --to")
    {"prepare": prepare, "regen": regen, "check": check, "stable-review": stable_review}[args.action](args, line)


if __name__ == "__main__":
    main()
