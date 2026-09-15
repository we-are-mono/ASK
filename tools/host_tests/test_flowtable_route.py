"""Exercise the kernel's forced-interface route lookup after FIB failure."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def test_flowtable_strict_reverse_route(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "net/ipv4/route.c").read_text()
    start = source.index("struct rtable *ip_route_output_key_hash_rcu(")
    end = source.index("\n}\n", start) + 3
    flags = "\n".join(line for line in (kernel / "include/net/flow.h").read_text().splitlines()
                      if line.startswith("#define FLOWI_FLAG_"))
    (tmp_path / "route_production.inc").write_text(flags + "\n" + source[start:end])
    binary = tmp_path / "flowtable_route"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_route.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
