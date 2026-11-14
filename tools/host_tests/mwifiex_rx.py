"""Exercise the driver's receive epilogue with descriptor/skb shared storage.

The driver is tested as its recipe builds it for the line: on 6.12 a local
fix keeps a skb the stack already has from being freed; NXP's lf-6.18.37_2.1.0
release carries that fix itself."""

from ask_orch.process import run_process
import os

import _host_mwifiex as mwifiex
from _host_flowtable import (function)


def test_cleanup(tmp_path):
    tree = tmp_path / "mwifiex"
    tree.mkdir()
    mwifiex.unpack(tree)
    epilogue = function((tree / "mlinux/moal_shim.c").read_text(), "moal_recv_packet").split("\ndone:\n")[1]
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
