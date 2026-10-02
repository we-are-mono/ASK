"""Exercise the patched receive epilogue with descriptor/skb shared storage."""

from ask_orch.process import run_process
import os
from pathlib import Path
import re
import subprocess

from _host_flowtable import (function)

ROOT = Path(__file__).resolve().parents[2]


def test_mwifiex_rx_cleanup(tmp_path):
    recipe = ROOT / "meta-ask/recipes-kernel/nxp-mwifiex/nxp-mwifiex_git.bb"
    source = ROOT / "meta-ask/build/tmp/work/ask_ls1046a-oe-linux/nxp-mwifiex/git/git"
    revision = re.search(r'SRCREV = "([0-9a-f]+)"', recipe.read_text())[1]
    path = tmp_path / "mlinux/moal_shim.c"
    path.parent.mkdir()
    path.write_bytes(subprocess.check_output(["git", "show", revision + ":mlinux/moal_shim.c"], cwd=source))
    run_process(["git", "apply", "--whitespace=error", str(recipe.parent / "files" /
        "0002-moal-do-not-free-an-skb-already-handed-to-the-stack.patch")], cwd=tmp_path, check=True)
    epilogue = function(path.read_text(), "moal_recv_packet").split("\ndone:\n")[1]
    harness = '''
#include <assert.h>
#include <stdlib.h>
enum { MLAN_STATUS_SUCCESS, MLAN_STATUS_FAILURE, MLAN_STATUS_PENDING };
struct buffer { void *pdesc, *pbuf; };
#define LEAVE() ((void)0)
#define dev_kfree_skb(skb) free(skb)
static int cleanup(int status, struct buffer *pmbuf, void *skb) {
''' + epilogue + '''
int main(void) {
    struct buffer *embedded = calloc(1, sizeof(*embedded));
    assert(cleanup(MLAN_STATUS_FAILURE, embedded, embedded) == MLAN_STATUS_PENDING);
    struct buffer separate = { .pbuf = &separate };
    assert(cleanup(MLAN_STATUS_FAILURE, &separate, malloc(32)) == MLAN_STATUS_FAILURE);
    struct buffer attached = { .pdesc = &attached, .pbuf = &attached };
    assert(cleanup(MLAN_STATUS_FAILURE, &attached, &attached) == MLAN_STATUS_FAILURE);
    struct buffer *consumed = malloc(sizeof(*consumed));
    free(consumed);
    assert(cleanup(MLAN_STATUS_PENDING, consumed, consumed) == MLAN_STATUS_PENDING);
    assert(cleanup(MLAN_STATUS_SUCCESS, NULL, NULL) == MLAN_STATUS_SUCCESS);
}
'''
    (tmp_path / "test.c").write_text(harness)
    binary = tmp_path / "test"
    run_process(["cc", "-g", "-O1", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
                    str(tmp_path / "test.c"), "-o", str(binary)], check=True)
    run_process([str(binary)], check=True, env={**os.environ,
        "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS": "halt_on_error=1"})
