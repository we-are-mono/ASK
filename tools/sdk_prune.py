"""Prove code in the SDK copy dead, and remove it.

sdk/README.md ("Removing dead code") describes the method and its rules; this
is its tooling. Every subcommand reads both lines' image builds (make
ask-image LINE=<line>: toolchain, .config and objects); build also reads each
line's series branch (make kernel-series-prepare LINE=<line>).

  build         compile the SDK copy's directories for every line and config
                variant outside bitbake, with the line's image toolchain and
                .config, onto its patched kernel; snapshot the objects without
                debug info as <work>/snap/<name>-<line>-<variant>.
  compare       two snapshots: every object identical (the proof for a change
                that must not change code), or with --removed, the function
                symbols that went, appeared or changed size.
  macros        what the compiler sees: each SDK and cdx object's compile,
                from the image build's .cmd files, rerun as -E -dM, with the
                files it read.
  unused-files  SDK .c/.h files no object of either image build, or of cdx,
                compiles or includes.
  unifdef       resolve, file by file, the conditions on the macros the policy
                lists name to what every unit reading the file sees; --blank
                keeps each surviving line where it was, for the identity proof.
  uncalled      global SDK functions no object references and no source calls.
  remove        delete the uncalled functions (definition, declarations,
                export, the comments right above them) and whatever that
                leaves unused, to a fixed point; --apply writes the result.

The work directory defaults to meta-ask/build/sdk-prune (ignored by git).
"""

import argparse
import bisect
import glob
import itertools
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ask_orch import kernel_line  # noqa: E402
import kernel_series  # noqa: E402

ROOT = kernel_line.ROOT
SERIES_REPO = ROOT / "meta-ask" / "build" / "kernel-series"
SDK_DIRS = ("drivers/net/ethernet/freescale/sdk_dpaa", "drivers/net/ethernet/freescale/sdk_fman",
            "drivers/staging/fsl_qbman")
# The image's own .config, and the same with the SDK options the test image
# turns on and ASK's config/kernel/defconfig (what consumers build from)
# leaves off. Add an option here when the two configs come to differ on it.
VARIANTS = {
    "image": {},
    "consumer": {"CONFIG_FSL_DPAA_TS": None, "CONFIG_FSL_QMAN_FQ_LOOKUP": None,
                 "CONFIG_FSL_SDK_FMAN_EHASH_SYNC_FAULT": None},
}

# unifdef policy. Resolved as undefined: options off in every consumer
# config (meta-ask's, OpenWrt's config-6.12 files, config/kernel/defconfig),
# symbols no build defines, and targets ASK never is. Add a name only after
# checking every consumer config.
UNDEF = set("""
CONFIG_FMAN_PFC CONFIG_FSL_BMAN_TEST_HIGH CONFIG_FSL_BMAN_TEST_THRESH CONFIG_FSL_DPAA_CEETM
CONFIG_FSL_DPAA_DBG_LOOP CONFIG_FSL_DPAA_ETH_DEBUG CONFIG_FSL_DPAA_HOOKS CONFIG_FSL_DPA_CHECKING
CONFIG_FSL_QMAN_TEST_HIGH CONFIG_FSL_QMAN_TEST_STASH_POTATO CONFIG_FSL_SDK_FMAN_RTC_API
CONFIG_FSL_USDPAA CONFIG_ARM CONFIG_GUEST_PARTITION CONFIG_MULTI_PARTITION_SUPPORT
CONFIG_PREEMPT_RT_FULL CONFIG_PTP_1588_CLOCK_DPAA CONFIG_FMAN_DISABLE_OH_AND_DISTRIBUTE_RESOURCES
CONFIG_FMAN_DISABLE_OH_TO_REUSE_RESOURCES __MWERKS__ NCSW_VXWORKS BIGPHYSAREA_ENABLE
FMAN_RESOURCES_UNIT_TEST FM_IOCTL_DBG FM_CC_DEBUG FM_CC_MURAM_DEBUG FM_COMPAT DPA_ALLOC_DEBUG
VERBOSE_WRITE DISABLE_SANITY_CHECKS DISABLE_INIT_PARAMETERS_CHECK DISABLE_ASSERTIONS
""".split())
# NCSW's integration and errata switches: the value the units see, per file.
INTEGRATION = re.compile(r"^FM_[A-Z0-9_]+$")
# Fixed for this SoC and toolchain: the value the units see.
FIXED = set("""
CONFIG_ARM64 DPAA_VERSION DEBUG_ERRORS LS1043 CONFIG_FMAN_ARM
__BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__ __ORDER_BIG_ENDIAN__
""".split())
INCLUDE_GUARDS = {"FM_EHASH_H", "FM_EH_TYPES_H", "FM_RESS_TEST_H_"}

TOKEN = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)
# A directive and its continuation lines: a backslash before a newline is
# taken before anything else, or the line's own run would swallow it.
PP_LINE = re.compile(r"^[ \t]*#(?:\\\n|[^\n])*", re.M)
TYPEISH = re.compile(r"^[\s*\w]*$")


# ---------------------------------------------------------------- C source

class Source:
    """A C file, with comments and literals blanked (positions kept), and the
    brace depth outside preprocessor lines."""

    def __init__(self, text):
        self.text = text
        self.lines = text.split("\n")
        self.newlines = [i for i, c in enumerate(text) if c == "\n"]
        self.comments = []
        chars = list(text)
        for m in TOKEN.finditer(text):
            if m.group().startswith("/"):
                self.comments.append((self.line_of(m.start()), self.line_of(m.end() - 1)))
            for i in range(m.start(), m.end()):
                if chars[i] != "\n":
                    chars[i] = " "
        self.code = "".join(chars)
        self.code_lines = self.code.split("\n")
        # Directives blanked too: a ; { or } in a macro is no statement's end.
        self.bare = PP_LINE.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), self.code)
        plain = list(self.bare)
        # extern "C" { ... } opens no scope.
        for m in re.finditer(r'\bextern\s+"C"\s*\{', text):
            close = self.match(m.end() - 1, "{", "}")
            plain[m.end() - 1] = " "
            if close is not None:
                plain[close] = " "
        steps = ((c == "{") - (c == "}") for c in plain)
        self.depth = list(itertools.accumulate(steps, initial=0))  # before each char
        self.body = {}

    def line_of(self, pos):
        return bisect.bisect_left(self.newlines, pos) + 1

    def match(self, pos, opening, closing):
        """Position of the bracket closing the one at pos."""
        depth = 0
        for i in range(pos, len(self.code)):
            depth += (self.code[i] == opening) - (self.code[i] == closing)
            if not depth:
                return i
        return None

    def classify(self, name, pos):
        """A mention's kind: ("def"|"decl"|"export", first line, last line),
        or ("use", line, line). A definition or declaration is one at file
        scope: type words, the name, its parameters, then { or ;. For a
        definition, self.body[pos] is then its braces' positions."""
        line = self.line_of(pos)
        export = r"^\s*EXPORT_SYMBOL(?:_GPL)?\(\s*" + re.escape(name) + r"\s*\)\s*;\s*$"
        if re.match(export, self.code_lines[line - 1]):
            return "export", line, line
        if self.depth[pos]:
            return "use", line, line
        bound = max(self.bare.rfind(c, 0, pos) for c in ";{}") + 1
        directives = list(PP_LINE.finditer(self.code, bound, pos))
        if directives and self.code.find("\n", directives[-1].end() - 1, pos) >= 0:
            bound = directives[-1].end()
        prefix = self.code[bound:pos]
        rest = self.code[pos + len(name):]
        if not prefix.strip() or not TYPEISH.match(prefix) or not rest.lstrip().startswith("("):
            return "use", line, line
        paren = pos + len(name) + (len(rest) - len(rest.lstrip()))
        close = self.match(paren, "(", ")")
        if close is None:
            return "use", line, line
        # Attributes and annotations between the parameters and { or ;.
        i = close + 1
        while i < len(self.code):
            c = self.code[i]
            if c.isspace() or c.isalnum() or c == "_":
                i += 1
            elif c == "(":
                end = self.match(i, "(", ")")
                if end is None:
                    break
                i = end + 1
            else:
                break
        first = self.line_of(bound + len(prefix) - len(prefix.lstrip()))
        if i < len(self.code) and self.code[i] == "{":
            end = self.match(i, "{", "}")
            if end is None:
                return "use", line, line
            self.body[pos] = (i, end)
            return "def", first, self.line_of(end)
        if i < len(self.code) and self.code[i] == ";":
            return "decl", first, self.line_of(i)
        return "use", line, line

    def statement(self, pos):
        """The file-scope statement around pos (a variable's definition:
        static DEFINE_SPINLOCK(x); or static const int x[] = {...};) as its
        first and last line, or None inside a body."""
        if self.depth[pos]:
            return None
        bound = max(self.bare.rfind(c, 0, pos) for c in ";{}") + 1
        directives = list(PP_LINE.finditer(self.code, bound, pos))
        if directives and self.code.find("\n", directives[-1].end() - 1, pos) >= 0:
            bound = directives[-1].end()
        i = pos
        while i < len(self.code) and self.code[i] != ";":
            if self.code[i] in "({":
                end = self.match(i, self.code[i], ")" if self.code[i] == "(" else "}")
                if end is None:
                    return None
                i = end
            i += 1
        if i >= len(self.code):
            return None
        lead = self.code[bound:pos]
        return self.line_of(bound + len(lead) - len(lead.lstrip())), self.line_of(i)

    def comment_above(self, first):
        """The first line of the comments directly above line first (no blank
        line between, no code beside them), and those comments."""
        ends = defaultdict(list)
        for a, b in self.comments:
            ends[b].append(a)
        taken = []
        while first - 1 in ends and not self.code_lines[first - 2].strip():
            start = min(ends[first - 1])
            if self.code_lines[start - 1].strip():
                break
            taken.append((start, first - 1))
            first = start
        return first, taken


def c_files(root):
    return sorted(p for p in Path(root).rglob("*") if p.suffix in (".c", ".h") and p.is_file())


def names_regex(names):
    return re.compile(r"\b(" + "|".join(map(re.escape, sorted(names, key=len, reverse=True))) + r")\b")


def plan_removal(root, names, variables=None):
    """Line ranges deleting each function in names: {name: None (global) |
    [files] (static, those files only)}, and each static variable in
    variables: {name: [files]}. Returns (plan {file: [[first, last], ...]},
    uses {name: [where]} of the names that cannot go, review [notes]). A name
    used only inside the body of a function that goes, goes too; one used
    anywhere else stays, and so then may what its body uses: to a fixed
    point."""
    names, variables = dict(names), dict(variables or {})
    uses_all = {}
    while True:
        plan, uses, review = plan_pass(root, names, variables)
        if not uses:
            return plan, uses_all, review
        uses_all.update(uses)
        for name in uses:
            names.pop(name, None)
            variables.pop(name, None)


def plan_pass(root, names, variables=None):
    root = Path(root)
    variables = variables or {}
    found, uses, review = {}, defaultdict(list), []
    for path in c_files(root):
        rel = str(path.relative_to(root))
        active = {n for n, files in names.items() if files is None or rel in files}
        local = {n for n, files in variables.items() if rel in files}
        if not active and not local:
            continue
        text = path.read_text(errors="replace")
        regex = names_regex(active | local)
        if not regex.search(text):
            continue
        src = Source(text)
        mentions = [(m.group(1), m.start()) for m in regex.finditer(src.code)]
        kinds = []
        for name, pos in mentions:
            if name in local:
                span = src.statement(pos)
                kinds.append((name, pos, "var", *span) if span else (name, pos, "use", 0, 0))
            else:
                kinds.append((name, pos, *src.classify(name, pos)))
        bodies = list(src.body.values())
        ranges = []
        for name, pos, kind, a, b in kinds:
            line = src.line_of(pos)
            if any(x < pos < y for x, y in bodies):
                continue  # inside a body that goes too
            if kind == "use":
                uses[name].append(f"{rel}:{line}")
                continue
            if kind != "export":
                a, taken = src.comment_above(a)
                for x, y in taken:
                    body = "\n".join(src.lines[x - 1:y])
                    if re.search(r"@Group|@\{|@\}", body) or y - x > 80:
                        review.append(f"{rel}:{x}-{y} taken with {name}: {src.lines[x - 1].strip()[:60]!r}")
            ranges.append((name, a, b))
        found[rel] = (src, ranges)
    plan = {}
    for rel, (src, ranges) in found.items():
        lines = [(a, b) for name, a, b in ranges if name not in uses]
        if lines:
            plan[rel] = tidy(src, lines)
    return plan, dict(uses), review


def tidy(src, ranges):
    """Merged ranges, plus one of two blank lines a deletion leaves side by
    side, plus any #if block the deletions leave empty."""
    gone = set()
    for a, b in ranges:
        gone.update(range(a, b + 1))
    total = len(src.lines) - (src.lines[-1] == "")

    def blank(i):
        return 1 <= i <= total and not src.lines[i - 1].strip()

    while True:
        live = [i for i in range(1, total + 1) if i not in gone]
        for k, i in enumerate(live):
            if re.match(r"^\s*#\s*if", src.code_lines[i - 1]):
                j = k + 1
                while j < len(live) and not src.code_lines[live[j] - 1].strip():
                    j += 1
                if j < len(live) and re.match(r"^\s*#\s*endif", src.code_lines[live[j] - 1]):
                    gone.update(live[k:j + 1])
                    break
        else:
            break
    runs = []
    for i in sorted(gone):
        if runs and i == runs[-1][1] + 1:
            runs[-1][1] = i
        else:
            runs.append([i, i])
    for a, b in runs:
        if blank(a - 1) and blank(b + 1):
            gone.add(b + 1)
    out = []
    for i in sorted(gone):
        if out and i == out[-1][1] + 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return out


def apply_plan(root, plan):
    """Delete the planned lines with sed (one pass per file, line numbers of
    the file as it was)."""
    for rel, ranges in sorted(plan.items()):
        subprocess.run(["sed", "-i", ";".join(f"{a},{b}d" for a, b in ranges), str(Path(root) / rel)],
                       check=True)


# ------------------------------------------------------------- the builds

def image_work(line):
    dirs = sorted(glob.glob(str(kernel_line.tmpdir(line, ROOT) / "work/*/linux-ask/*")))
    if not dirs:
        raise SystemExit(f"no image build for {line}: make ask-image LINE={line}")
    return Path(dirs[-1])


def toolchain(line):
    bindir = [p for p in (image_work(line) / "recipe-sysroot-native/usr/bin").glob("aarch64-*") if p.is_dir()]
    if not bindir:
        raise SystemExit(f"no cross toolchain in {line}'s image build")
    return bindir[0], bindir[0].name + "-"


def tool(line, name):
    bindir, cross = toolchain(line)
    return str(bindir / (cross + name))


def sdk_objects(tree):
    return sorted(o for d in SDK_DIRS for o in (Path(tree) / d).rglob("*.o")
                  if not o.name.endswith(".mod.o") and ".tmp" not in o.name)


def with_variant(config, settings):
    for name, value in settings.items():
        line = f"# {name} is not set" if value is None else f"{name}={value}"
        config, n = re.subn(rf"^(?:{name}=.*|# {name} is not set)$", line, config, flags=re.M)
        if not n:
            config += line + "\n"
    return config


def build(work, line, variant, sdk, name):
    """Compile the SDK directories from sdk for one line and variant; returns
    (ok, diagnostics) and leaves a snapshot when it compiled."""
    bindir, cross = toolchain(line)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    src, out = work / f"src-{line}", work / f"out-{line}-{variant}"
    series = subprocess.run(["git", "-C", str(SERIES_REPO), "rev-parse", f"series-{line}"],
                            capture_output=True, text=True)
    if series.returncode:
        raise SystemExit(f"no series-{line} branch: make kernel-series-prepare LINE={line}")
    stamp = src / ".sdk-prune-series"
    if not stamp.exists() or stamp.read_text() != series.stdout:
        shutil.rmtree(src, ignore_errors=True)
        src.mkdir(parents=True)
        archive = subprocess.Popen(["git", "-C", str(SERIES_REPO), "archive", f"series-{line}"],
                                   stdout=subprocess.PIPE)
        subprocess.run(["tar", "-x", "-C", str(src)], stdin=archive.stdout, check=True)
        if archive.wait():
            raise SystemExit(f"git archive series-{line} failed")
        stamp.write_text(series.stdout)
        for v in VARIANTS:
            shutil.rmtree(work / f"out-{line}-{v}", ignore_errors=True)
    for entry in kernel_series.Line(line).overlay:
        target, source = src / entry, Path(sdk) / entry
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        elif target.exists() or target.is_symlink():
            target.unlink()
        if source.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target, symlinks=True)
            else:
                shutil.copy2(source, target)
    make = ["make", "-s", "-C", str(src), f"O={out}", "ARCH=arm64", f"CROSS_COMPILE={cross}",
            f"-j{os.cpu_count()}"]
    image_config = kernel_line.tmpdir(line, ROOT) / "work-shared/ask-ls1046a/kernel-build-artifacts/.config"
    config = with_variant(image_config.read_text(), VARIANTS[variant])
    marker = out / ".sdk-prune-config"
    if not marker.exists() or marker.read_text() != config:
        out.mkdir(parents=True, exist_ok=True)
        (out / ".config").write_text(config)
        for target in ("olddefconfig", "prepare"):
            r = subprocess.run(make + [target], env=env, capture_output=True, text=True)
            if r.returncode:
                raise SystemExit(f"make {target} failed for {line} {variant}:\n{r.stderr[-3000:]}")
        marker.write_text(config)
    for d in SDK_DIRS:
        shutil.rmtree(out / d, ignore_errors=True)
    r = subprocess.run(make + [d + "/" for d in SDK_DIRS], env=env, capture_output=True, text=True)
    log = r.stdout + r.stderr
    (work / f"build-{name}-{line}-{variant}.log").write_text(log)
    diagnostics = [x for x in log.splitlines() if "warning:" in x or "error:" in x]
    if r.returncode and not diagnostics:
        diagnostics = log.splitlines()[-20:]
    snap = work / "snap" / f"{name}-{line}-{variant}"
    shutil.rmtree(snap, ignore_errors=True)
    if not r.returncode:
        for o in sdk_objects(out):
            dest = snap / o.relative_to(out)
            dest.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run([str(bindir / (cross + "objcopy")), "--strip-debug", str(o), str(dest)], check=True)
    return not r.returncode, diagnostics


def build_all(work, sdk, name, quiet=False):
    """Every line and variant; returns {(line, variant): diagnostics}, empty
    lists when all compiled cleanly."""
    results = {}
    for line in kernel_line.lines(ROOT):
        for variant in VARIANTS:
            ok, diagnostics = build(work, line, variant, sdk, name)
            results[(line, variant)] = diagnostics
            if not quiet:
                state = "clean" if ok and not diagnostics else f"{len(diagnostics)} diagnostics"
                print(f"  {name} {line} {variant}: {state}")
    return results


# --------------------------------------------------------------- analyses

def function_symbols(line, snap):
    """{(object, function): size} for a snapshot, and the set of those that
    are global."""
    out, global_ = {}, set()
    for o in sorted(Path(snap).rglob("*.o")):
        listing = subprocess.run([tool(line, "nm"), "-S", "--defined-only", str(o)],
                                 capture_output=True, text=True, check=True).stdout
        for entry in listing.splitlines():
            p = entry.split()
            if len(p) == 4 and p[2] in "Tt":
                key = (str(o.relative_to(snap)), p[3])
                out[key] = int(p[1], 16)
                if p[2] == "T":
                    global_.add(key)
    return out, global_


def compare(work, before, after, removed=None):
    """Prints the comparison; returns whether it holds: identical, or with
    removed, no function gone but the planned ones and statics -- a static
    left with one caller is inlined into it, as a clone (.isra) is -- and
    none new. A global function gone that was not planned is live code lost.
    What changed size is printed for reading: inlining and the layout of a
    file's strings move every function they touch."""
    holds = True
    for line in kernel_line.lines(ROOT):
        for variant in VARIANTS:
            a, b = (work / "snap" / f"{s}-{line}-{variant}" for s in (before, after))
            if not a.is_dir() or not b.is_dir():
                print(f"{line} {variant}: no snapshot pair")
                holds = False
                continue
            if removed is None:
                objs_a = {str(o.relative_to(a)) for o in a.rglob("*.o")}
                objs_b = {str(o.relative_to(b)) for o in b.rglob("*.o")}
                differ = sorted(o for o in objs_a & objs_b
                                if (a / o).read_bytes() != (b / o).read_bytes())
                print(f"{line} {variant}: {len(objs_a & objs_b) - len(differ)} objects identical")
                for o in sorted(objs_a ^ objs_b):
                    print(f"  only {'before' if o in objs_a else 'after'}: {o}")
                for o in differ:
                    print(f"  differs: {o}")
                holds &= not differ and objs_a == objs_b
                continue
            (fa, global_a), (fb, _) = function_symbols(line, a), function_symbols(line, b)
            gone = [k for k in fa if k not in fb]
            planned = [k for k in gone if k[1] in removed]
            inlined = [k for k in gone if k[1] not in removed and k not in global_a]
            lost = [k for k in gone if k[1] not in removed and k in global_a]
            new = sorted(k for k in fb if k not in fa)
            resized = sorted(k for k in fa.keys() & fb.keys() if fa[k] != fb[k])
            print(f"{line} {variant}: {len(planned)} planned functions gone "
                  f"({sum(fa[k] for k in planned)} bytes), {len(inlined)} statics inlined, "
                  f"{len(lost)} global functions lost, {len(new)} new, {len(resized)} resized")
            for k in sorted(inlined):
                print(f"  inlined: {k[1]} ({k[0]}, {fa[k]} bytes)")
            for k in sorted(lost):
                print(f"  LOST: {k[1]} ({k[0]}, {fa[k]} bytes)")
            for k in new:
                print(f"  new: {k[1]} ({k[0]})")
            for k in resized:
                print(f"  resized: {k[1]} ({k[0]}): {fa[k]} -> {fb[k]}")
            holds &= not new and not lost
    return holds


def compiled(o):
    """Whether an object is a compilation unit, not a link of others:
    vmlinux.o, for one, holds the SDK's code as the image build compiled it,
    and its calls between dead functions would keep them alive."""
    cmd = o.parent / f".{o.name}.cmd"
    return cmd.exists() and " -c " in (parse_cmd(cmd)[1] or "")


def exported_only(section):
    """Whether a relocation section only publishes symbols: the export tables
    of older kernels (__ksymtab*), and the .export_symbol section EXPORT_SYMBOL
    writes on these lines, which modpost reads. A function named only there
    is exported, not called."""
    return "__ksymtab" in section or "export_symbol" in section


def references(work, line):
    """Symbols any relocation names, outside the export tables, in the SDK
    objects of the work builds, the compilation units of the line's image
    build outside the SDK, and cdx's; and what the image's out-of-tree
    modules need of the kernel."""
    image = image_work(line) / "build"
    objs = [o for v in VARIANTS for o in sdk_objects(work / f"out-{line}-{v}")]
    objs += [o for o in image.rglob("*.o") if not any(str(o.relative_to(image)).startswith(d) for d in SDK_DIRS)
             and compiled(o)]
    objs += [o for o in (ROOT / "cdx").glob("*.o") if compiled(o)]
    named = set()
    # The image's modules built outside the kernel tree (Wi-Fi, LED drivers):
    # what each needs of the kernel is an undefined symbol in its .ko.
    work = kernel_line.tmpdir(line, ROOT) / "work"
    for depth in range(3, 7):
        for ko in work.glob("/".join(["*"] * depth) + "/*.ko"):
            if any(part in ("linux-ask", "image", "package", "packages-split", "sysroot-destdir")
                   or part.startswith("recipe-sysroot") for part in ko.relative_to(work).parts):
                continue
            listing = subprocess.run([tool(line, "nm"), "-u", str(ko)], capture_output=True, text=True).stdout
            named.update(entry.split()[-1] for entry in listing.splitlines() if entry.strip())
    for o in objs:
        listing = subprocess.run([tool(line, "readelf"), "-rW", str(o)], capture_output=True, text=True).stdout
        section = ""
        for entry in listing.splitlines():
            if entry.startswith("Relocation section"):
                section = entry.split("'")[1]
            elif not exported_only(section):
                p = entry.split()
                if len(p) >= 5 and p[2].startswith("R_AARCH64"):
                    named.add(p[4].split("+")[0])
    return named


def global_functions(work, line):
    out = {}
    for v in VARIANTS:
        tree = work / f"out-{line}-{v}"
        for o in sdk_objects(tree):
            listing = subprocess.run([tool(line, "nm"), "--defined-only", str(o)],
                                     capture_output=True, text=True, check=True).stdout
            for entry in listing.splitlines():
                p = entry.split()
                if len(p) == 3 and p[1] == "T":
                    out.setdefault(p[2], str(o.relative_to(tree)))
    return out


def source_uses(sdk, names):
    """Where the source calls or otherwise uses each name, to a fixed point
    (a name that stays makes what its body uses stay): the SDK copy and cdx
    read as C (declarations and exports are not uses), the kernel patches'
    added lines taken as uses wherever they name it."""
    names, uses_all = set(names), {}
    while names:
        uses = source_pass(sdk, names)
        if not uses:
            break
        uses_all.update(uses)
        names -= set(uses)
    return uses_all


def source_pass(sdk, names):
    _, uses, _ = plan_pass(sdk, {n: None for n in names})
    uses = defaultdict(list, uses)
    regex = names_regex(names)
    for path in c_files(ROOT / "cdx"):
        src = Source(path.read_text(errors="replace"))
        for m in regex.finditer(src.code):
            kind, line, _ = src.classify(m.group(1), m.start())
            if kind == "use":
                uses[m.group(1)].append(f"cdx/{path.name}:{line}")
    for patch in sorted((ROOT / "patches" / "kernel").glob("*/*.patch")):
        for n, text in enumerate(patch.read_text(errors="replace").splitlines(), 1):
            if text.startswith("+") and not text.startswith("+++"):
                for m in regex.finditer(TOKEN.sub(" ", text[1:])):
                    uses[m.group(1)].append(f"{patch.relative_to(ROOT)}:{n}")
    return dict(uses)


def uncalled(work, sdk):
    """Global SDK functions no relocation names in any build of any line and
    the source does not use, from the work builds as they stand. Returns
    (dead [names], kept {name: uses})."""
    candidates = None
    for line in kernel_line.lines(ROOT):
        defined = global_functions(work, line)
        unreferenced = set(defined) - references(work, line)
        candidates = unreferenced if candidates is None else candidates & unreferenced
    uses = source_uses(sdk, candidates)
    return sorted(n for n in candidates if n not in uses), {n: uses[n] for n in sorted(uses)}


UNUSED_STATIC = re.compile(r"(drivers/\S+?):\d+:\d+: (?:error|warning): '(\w+)' defined but not used "
                           r"\[-W(?:error=)?unused-(function|variable|const-variable)\]")


def remove(work, sdk, extra, apply):
    sdk = Path(sdk)
    print("building the copy as it is")
    if any(build_all(work, sdk, "before").values()):
        raise SystemExit("the copy does not build cleanly as it is; see the build logs in " + str(work))
    dead, kept = uncalled(work, sdk)
    names = {n: None for n in dead + list(extra)}
    variables = {}
    print(f"{len(dead)} uncalled functions; {len(kept)} kept for a use in the source")
    scratch = work / "scratch" / "linux"
    for rnd in itertools.count(1):
        plan, uses, review = plan_removal(sdk, names, variables)
        for n, where in uses.items():
            print(f"  {n} is used ({', '.join(where[:3])}): kept")
            names.pop(n, None)
            variables.pop(n, None)
        print(f"round {rnd}: {len(names)} functions, {len(variables)} variables, "
              f"{sum(b - a + 1 for r in plan.values() for a, b in r)} lines in {len(plan)} files")
        for note in review:
            print("  review:", note)
        shutil.rmtree(scratch.parent, ignore_errors=True)
        shutil.copytree(sdk, scratch, symlinks=True)
        apply_plan(scratch, plan)
        results = build_all(work, scratch, "after")
        unused, unused_vars, other = defaultdict(set), defaultdict(set), []
        for (line, variant), diagnostics in results.items():
            for d in diagnostics:
                m = UNUSED_STATIC.search(d)
                if m:
                    f = m.group(1)
                    f = f[f.index("drivers/"):] if "drivers/" in f else f
                    (unused if m.group(3) == "function" else unused_vars)[m.group(2)].add(f)
                else:
                    other.append(f"{line} {variant}: {d}")
        if other:
            print("\n".join(sorted(set(other))[:40]))
            raise SystemExit("the removal does not build; the scratch copy is " + str(scratch))
        if unused or unused_vars:
            print("  unused now:", ", ".join(sorted(unused) + sorted(unused_vars)))
            for n, files in unused.items():
                names[n] = sorted(set(names.get(n) or []) | files)
            for n, files in unused_vars.items():
                variables[n] = sorted(set(variables.get(n, [])) | files)
            continue
        orphans = [n for n in uncalled(work, scratch)[0] if n not in names]
        if orphans:
            print("  uncalled now:", ", ".join(orphans))
            names.update({n: None for n in orphans})
            continue
        break
    (work / "remove.json").write_text(json.dumps({"names": names, "variables": variables, "plan": plan},
                                                 indent=1, sort_keys=True))
    with open(work / "remove.sh", "w") as f:
        f.write("#!/bin/sh\nset -eu\ncd \"${1:-.}\"\n")
        for rel, ranges in sorted(plan.items()):
            f.write(f"sed -i '{';'.join(f'{a},{b}d' for a, b in ranges)}' {rel}\n")
    print(f"fixed point: {len(names)} functions; plan in {work}/remove.json, script in {work}/remove.sh")
    print(f"prove it: {sys.argv[0]} compare before after --removed {work}/remove.json")
    if apply:
        apply_plan(sdk, plan)
        print(f"applied to {sdk}")


def cmd_files(build_dir, kind="o"):
    return sorted(glob.glob(f"{build_dir}/**/.*.{kind}.cmd", recursive=True))


def parse_cmd(path):
    text = Path(path).read_text(errors="replace")
    compile_ = re.search(r"^savedcmd_(\S+) := (.*)$", text, re.M)
    source = re.search(r"^source_\S+ := (\S+)$", text, re.M)
    deps = re.search(r"^deps_\S+ := \\\n(.*?)\n\n", text, re.M | re.S)
    files = []
    for item in (deps.group(1).split("\\\n") if deps else []):
        item = item.strip().rstrip("\\").strip()
        if item and not item.startswith("$(wildcard"):
            files.append(item)
    return (compile_.group(1) if compile_ else None, compile_.group(2) if compile_ else "",
            source.group(1) if source else None, files)


def tree_path(path):
    """A dependency's kernel-tree path, through symlinks (the device tree
    includes dt-bindings by scripts/dtc/include-prefixes)."""
    m = re.search(r"/kernel-source/(.*)$", os.path.realpath(path))
    return m.group(1) if m else None


def macros(line):
    """Each SDK and cdx object of the line's image build: its source, the
    kernel-tree files it read, and every macro it saw."""
    bindir, _ = toolchain(line)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    build_dir = image_work(line) / "build"
    cmds = [(c, build_dir) for d in SDK_DIRS for c in cmd_files(build_dir / d)]
    # cdx builds as an external module, from the kernel's build tree.
    artifacts = kernel_line.tmpdir(line, ROOT) / "work-shared/ask-ls1046a/kernel-build-artifacts"
    cdx = [(c, artifacts) for c in glob.glob(str(ROOT / "cdx" / ".*.o.cmd"))
           if f"/tmp-{line}/" in Path(c).read_text(errors="replace")]
    objects = {}
    for path, cwd in cmds + cdx:
        obj, command, source, files = parse_cmd(path)
        if not obj or " -c " not in command or obj.endswith(".mod.o"):
            continue
        args, out, skip = shlex.split(command), [], False
        for a in args:
            if skip:
                skip = False
            elif a == "-o":
                skip = True
            elif a != "-c" and not a.startswith(("-Wp,-MMD", "-Wp,-MD")):
                out.append(a)
        r = subprocess.run(out + ["-E", "-dM", "-o", "-"], cwd=cwd, env=env, capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f"{obj}: {r.stderr[:500]}")
        seen = {}
        for entry in r.stdout.splitlines():
            m = re.match(r"#define (\w+)(\([^)]*\))? ?(.*)$", entry)
            if m:
                seen[m.group(1)] = (m.group(2) or "") + "=" + m.group(3)
        read = {tree_path(f) for f in files + ([source] if source else [])} - {None}
        objects[obj if cwd == build_dir else f"cdx:{obj}"] = {"files": sorted(read), "macros": seen}
    return objects


def unifdef_plan(sdk, macro_sets):
    """{file: [unifdef flags]}: per file, each policy macro its conditions
    test, resolved to the one value every unit reading the file sees."""
    units = [(o["macros"], set(o["files"])) for m in macro_sets for o in m.values()]
    numeric = re.compile(r"^=(-?\d+|0x[0-9a-fA-F]+|)$")
    plan = {}
    for path in c_files(sdk):
        rel = str(path.relative_to(sdk))
        seeing = [m for m, files in units if rel in files]
        if not seeing:
            continue
        text = path.read_text(errors="replace")
        tested = set()
        for expr in re.findall(r"^\s*#\s*(?:if|ifdef|ifndef|elif)\b(.*)$", text, re.M):
            tested |= set(re.findall(r"\b[A-Za-z_]\w*\b", expr))
        local = set(re.findall(r"^\s*#\s*(?:define|undef)\s+(\w+)", text, re.M))
        flags = []
        for name in sorted(tested - local - INCLUDE_GUARDS):
            if not (name in UNDEF or name in FIXED or INTEGRATION.match(name)):
                continue
            values = {m.get(name) for m in seeing}
            if len(values) != 1:
                continue
            v = values.pop()
            if v is None:
                flags.append(f"-U{name}")
            elif numeric.match(v):
                flags.append(f"-D{name}{v}" if v != "=" else f"-D{name}")
            elif name == "__BYTE_ORDER__" and v == "=__ORDER_LITTLE_ENDIAN__":
                flags.append("-D__BYTE_ORDER__=1234")
        if flags:
            plan[rel] = flags
    return plan


# -------------------------------------------------------------------- main

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--work", default=str(ROOT / "meta-ask" / "build" / "sdk-prune"))
    parser.add_argument("--sdk", default=str(kernel_line.sdk(ROOT)), help="the copy to work on")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("build")
    p.add_argument("name", help="snapshot name")
    p = sub.add_parser("compare")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--removed", help="remove.json, or a JSON list or object of function names")
    sub.add_parser("macros")
    sub.add_parser("unused-files")
    p = sub.add_parser("unifdef")
    p.add_argument("--blank", action="store_true", help="blank removed lines instead of deleting them")
    sub.add_parser("uncalled")
    p = sub.add_parser("remove")
    p.add_argument("--also", nargs="*", default=[], help="further functions to remove")
    p.add_argument("--apply", action="store_true", help="write the result to the copy")
    args = parser.parse_args(argv)
    work, sdk = Path(args.work), Path(args.sdk)
    work.mkdir(parents=True, exist_ok=True)

    if args.command == "build":
        results = build_all(work, sdk, args.name)
        for (line, variant), diagnostics in results.items():
            for d in diagnostics[:20]:
                print(f"{line} {variant}: {d}")
        return 1 if any(results.values()) else 0
    if args.command == "compare":
        removed = None
        if args.removed:
            data = json.loads(Path(args.removed).read_text())
            removed = set(data.get("names", data)) if isinstance(data, dict) else set(data)
        return 0 if compare(work, args.before, args.after, removed) else 1
    if args.command == "macros":
        for line in kernel_line.lines(ROOT):
            out = work / f"macros-{line}.json"
            objects = macros(line)
            out.write_text(json.dumps(objects))
            print(f"{line}: {len(objects)} objects in {out}")
        return 0
    if args.command == "unused-files":
        read = set()
        for line in kernel_line.lines(ROOT):
            build_dir = image_work(line) / "build"
            for c in (cmd_files(build_dir) + cmd_files(build_dir, "dtb")
                      + glob.glob(str(ROOT / "cdx" / ".*.o.cmd"))):
                _, _, source, files = parse_cmd(c)
                read |= {tree_path(f) for f in files + ([source] if source else [])} - {None}
        unused = [str(p.relative_to(sdk)) for p in c_files(sdk) if str(p.relative_to(sdk)) not in read]
        print("\n".join(unused) or "none")
        print(f"{len(unused)} files no build compiles or includes", file=sys.stderr)
        return 0
    if args.command == "unifdef":
        sets = [json.loads((work / f"macros-{line}.json").read_text()) for line in kernel_line.lines(ROOT)]
        plan = unifdef_plan(sdk, sets)
        changed = 0
        for rel, flags in sorted(plan.items()):
            r = subprocess.run(["unifdef", "-m", *(["-b"] if args.blank else []), *flags, str(sdk / rel)],
                               capture_output=True, text=True)
            if r.returncode == 2 or r.stderr.strip():
                print(f"{rel}: {r.stderr.strip()}")
                if r.returncode == 2:
                    return 1
            changed += r.returncode == 1
        print(f"{changed} of {len(plan)} files changed in {sdk}")
        return 0
    if args.command == "uncalled":
        if any(build_all(work, sdk, "uncalled").values()):
            raise SystemExit("the copy does not build cleanly; see the build logs in " + str(work))
        dead, kept = uncalled(work, sdk)
        for n, where in kept.items():
            print(f"kept {n}: {', '.join(where[:3])}")
        print("\n".join(dead))
        print(f"{len(dead)} uncalled, {len(kept)} kept for a use in the source", file=sys.stderr)
        return 0
    if args.command == "remove":
        remove(work, sdk, args.also, args.apply)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
