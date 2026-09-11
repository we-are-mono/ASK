"""Exercise DPA, FMC and FMLIB startup against fault-injected device ioctls."""

from pathlib import Path
import io
import os
import re
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]


def vendor_tree(name, tmp_path):
    """Apply the shipped patch to the pinned vendor revision, even before a build."""
    revision = re.search(r'SRCREV = "([0-9a-f]+)"', (
        ROOT / f"meta-ask/recipes-ask/{name}/{name}_git.bb"
    ).read_text()).group(1)
    candidates = [ROOT / "sources" / name,
                  ROOT / f"meta-ask/build/tmp/work/cortexa72-oe-linux/{name}/git/git"]
    source = next((p for p in candidates if (p / ".git").exists()), None)
    if source is None:
        pytest.skip(f"build the ASK image to fetch the pinned {name} source")
    archive = subprocess.check_output(["git", "-C", str(source), "archive", revision])
    target = tmp_path / name
    target.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tf:
        tf.extractall(target, filter="data")
    subprocess.run(["git", "apply", "--whitespace=nowarn",
                    str(ROOT / f"patches/{name}/01-mono-ask-extensions.patch")],
                   cwd=target, check=True)
    return target


def test_dpa_lifecycle(tmp_path):
    fmc = vendor_tree("fmc", tmp_path)
    fmlib = vendor_tree("fmlib", tmp_path)
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    uapi = kernel / "include/uapi/linux/fmd"
    if not uapi.exists():
        pytest.skip("build the ASK kernel or set ASK_KERNEL_SOURCE for its FMD headers")
    includes = [ROOT / "cdx", fmc / "source", fmlib / "include/fmd",
                fmlib / "include/fmd/Peripherals", fmlib / "include/fmd/integrations",
                uapi, uapi / "Peripherals", uapi / "integrations"]
    # Compile the actual persistence helpers without the XML compiler's C++
    # dependencies. The XML compiler itself is outside this device-lifecycle test.
    source = (fmc / "source/libfmc.cpp").read_text()
    parts = []
    for name in ("createDevices", "fmc_release", "fmc_load"):
        match = re.search(r"^(?:int|void|bool) " + name + r"\([^;]*?\)\s*\{", source, re.M)
        end, depth = match.end(), 1
        while depth:
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        parts.append(source[match.start():end])
    persistence = tmp_path / "fmc_persistence.cpp"
    persistence.write_text('#include <fstream>\n#include "fmc.h"\n'
                           'extern "C" {\nextern const char *TMPFILENAME;\n'
                           + "\n".join(parts) + "\n}\n")
    binary = tmp_path / "dpa_lifecycle"
    command = [os.environ.get("HOSTCC", "cc"), "-O1", "-g",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-fno-pie", "-no-pie", "-ffunction-sections", "-fdata-sections",
               "-Wl,--gc-sections", "-DLS1043", "-DENDIAN_LITTLE", "-DNCSW_LINUX",
               "-DSEC_PROFILE_SUPPORT", "-DVLAN_FILTER", "-DNO_FMC_LOG"]
    for path in includes:
        command.extend(["-I", str(path)])
    for function in ("malloc", "calloc", "free", "open", "close", "ioctl"):
        command.append(f"-Wl,--wrap={function}")
    command.extend([str(Path(__file__).with_name("dpa_lifecycle.c")),
                    str(fmc / "source/fmc_exec.c"), str(fmlib / "src/fm_lib.c"),
                    str(persistence), "-lstdc++",
                    "-o", str(binary)])
    subprocess.run(command, check=True)
    result = subprocess.run([str(binary)], cwd=tmp_path, capture_output=True, text=True, timeout=180,
                            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DPA lifecycle fault points passed" in result.stdout
    print(result.stdout.strip().splitlines()[-1])


def test_ehash_teardown(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not sdk.exists():
        pytest.skip("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")

    def function(source, name):
        match = re.search(r"^(?:static )?(?:void|t_Error|uint32_t) " + name
                          + r"\([^;]*?\)\s*\{", source, re.M)
        assert match, name
        end, depth = match.end(), 1
        while depth:
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        return source[match.start():end] + "\n"

    ehash = (sdk / "Peripherals/FM/Pcd/fm_ehash.c").read_text()
    cc = (sdk / "Peripherals/FM/Pcd/fm_cc.c").read_text()
    wrapper = (sdk / "src/wrapper/lnxwrp_ioctls_fm.c").read_text()
    (tmp_path / "ehash_production.inc").write_text(
        function(ehash, "FreeEnEhashInfo") + function(ehash, "FM_PCD_HashTableDelete")
        + function(cc, "copy_td_to_ccbase") + function(cc, "FM_PCD_CcRootDelete")
        + wrapper[wrapper.index("#define FM_PCD_COOKIE_SLOTS"):
                  wrapper.index("static t_Error fm_pcd_cookie_to_handle")]
    )
    binary = tmp_path / "ehash_lifecycle"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("ehash_lifecycle.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
