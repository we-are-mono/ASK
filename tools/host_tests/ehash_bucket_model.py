"""The rig's classifier bucket model agrees with the SDK's own hash."""

from ask_orch.process import run_process
import os
from pathlib import Path
import random
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/tests"))
import _ehash_bucket as model  # noqa: E402


def kernel_hash(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    pcd = kernel / "drivers/net/ethernet/freescale/sdk_fman/Peripherals/FM/Pcd"
    if not pcd.exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    source = (pcd / "fm_cc.c").read_text()
    match = re.search(r"^void get_indexed_hash_bucket\([^;]*?\)\s*\{", source, re.M)
    assert match, "get_indexed_hash_bucket"
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    (tmp_path / "std_ext.h").write_text("#include <stdint.h>\n")
    (tmp_path / "bucket.c").write_text(
        '#include <stdio.h>\n#include "crc64.h"\n' + source[match.start():end] + r'''
int main(void)
{
    unsigned char key[64];
    unsigned int size, shift, mask, i;
    uint16_t index;

    while (scanf("%u %u %u", &shift, &mask, &size) == 3 && size <= sizeof(key)) {
        for (i = 0; i < size; i++)
            scanf("%2hhx", &key[i]);
        get_indexed_hash_bucket(size, key, shift, mask, &index);
        printf("%u\n", index);
    }
    return 0;
}
''')
    binary = tmp_path / "bucket"
    run_process([os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-O1", "-I", str(tmp_path),
                    "-I", str(pcd), str(tmp_path / "bucket.c"), "-o", str(binary)], check=True)

    def run(cases):
        lines = "".join(f"{shift} {mask} {len(key)} {key.hex()}\n" for key, mask, shift in cases)
        out = run_process([str(binary)], input=lines, capture_output=True, text=True, check=True)
        return [int(x) for x in out.stdout.split()]
    return run


def test_bucket_model_matches_the_sdk(tmp_path):
    run = kernel_hash(tmp_path)
    rng = random.Random(295)
    cases = [(bytes(rng.randrange(256) for _ in range(size)), mask, shift)
             for size in (10, 14, 22, 38, 56) for mask in (0x7FFF, 0xFF, 0xF) for shift in (0, 1, 2)
             for _ in range(20)]
    assert run(cases) == [model.bucket(key, mask, shift) for key, mask, shift in cases]


def test_crowded_ipv4_ports_share_a_bucket_whatever_surrounds_them(tmp_path):
    run = kernel_hash(tmp_path)
    pairs = model.crowded_ipv4([48271, 48274, 48275, 48277])
    assert len({s for s, _ in pairs}) == 4 and all(1024 <= s < 32768 for s, _ in pairs)
    rng = random.Random(1)
    for _ in range(16):
        portid, source, destination = rng.randrange(256), rng.randbytes(4), rng.randbytes(4)
        keys = [model.ipv4_key(portid, source, destination, 17, s, d) for s, d in pairs]
        assert len(set(run([(key, model.IPV4_MASK, 0) for key in keys]))) == 1
