"""Check the in-kernel PCD builder programs what fmc's compiled model says."""

from pathlib import Path
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).with_name("golden") / "cdx_pcd_model.json"

SHIMS = {
    "linux/types.h": """#pragma once
#include <stdint.h>
#include <stdbool.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
""",
    # This directory shadows /usr/include/linux, and glibc's <errno.h> chain
    # passes through linux/errno.h -- so mirror what the real one does rather
    # than including <errno.h> and recursing into an already-guarded header.
    "linux/errno.h": "#pragma once\n#include <asm/errno.h>\n",
    "linux/string.h": "#pragma once\n#include <string.h>\n",
    "linux/module.h": "#pragma once\n",
    "linux/kernel.h": """#pragma once
#include <stdio.h>
#include <linux/types.h>
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#define pr_err(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
""",
    "linux/slab.h": """#pragma once
#include <stdlib.h>
#define GFP_KERNEL 0
static inline void *kzalloc(size_t n, int f) { (void)f; return calloc(1, n); }
static inline void kfree(void *p) { free(p); }
""",
    # Only the two fields of the FMan wrapper the builder reaches into, plus the
    # port arrays it indexes. The real header needs most of the kernel.
    "lnxwrp_fm.h": """#pragma once
#include "fm_ext.h"
#include "fm_port_ext.h"
typedef struct { bool active; t_Handle h_Dev; } t_LnxWrpFmPortDev;
typedef struct {
    uint8_t id;
    t_Handle h_Dev;
    t_Handle h_PcdDev;
    t_LnxWrpFmPortDev opPorts[FM_MAX_NUM_OF_OH_PORTS - 1];
    t_LnxWrpFmPortDev rxPorts[FM_MAX_NUM_OF_RX_PORTS];
} t_LnxWrpFmDev;
""",
}


INDEX_NAMES = {0: "e_FM_PCD_HDR_INDEX_NONE", 255: "e_FM_PCD_HDR_INDEX_LAST"}


def sdk_tree():
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not (sdk / "inc").exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE")
    return sdk


def net_header_fields(sdk):
    """Resolve the NET_HEADER_FIELD_* constants the golden names.

    They are defined in terms of each other -- NET_HEADER_FIELD_IPv6_DST_IP is
    (NET_HEADER_FIELD_IPv6_VER << 3) -- so substitute until everything is
    numeric rather than hardcoding the values here.
    """
    text = (sdk / "inc/net_ext.h").read_text()
    raw = {}
    for name, body in re.findall(r"#define\s+(NET_HEADER_FIELD_\w+)\s+(.+)", text):
        body = re.sub(r"/\*.*", "", body).strip()
        if body and body.count("(") == body.count(")"):
            raw[name] = body
    values, pending = {}, dict(raw)
    while pending:
        progressed = False
        for name, body in list(pending.items()):
            expr = body
            for other in re.findall(r"NET_HEADER_FIELD_\w+", body):
                if other not in values:
                    break
                expr = expr.replace(other, str(values[other]))
            else:
                values[name] = eval(expr, {"__builtins__": {}})
                del pending[name]
                progressed = True
        if not progressed:
            break
    return values


def build(tmp_path):
    sdk = sdk_tree()

    for name, body in SHIMS.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"),
                    tmp_path / "types_linux.h")

    binary = tmp_path / "cdx_pcd_build"
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-Werror=implicit-function-declaration",
               # error_ext.h names the errno constants but reaches them through
               # core_ext.h, which the fixture suppresses for <linux/smp.h>.
               "-include", "errno.h",
               "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path), "-I", str(ROOT / "cdx")]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib",
                "inc/integrations/LS1043"]:
        command += ["-I", str(sdk / inc)]
    command += [str(Path(__file__).with_name("cdx_pcd_build.c")), "-o", str(binary)]
    subprocess.run(command, check=True)
    return subprocess.run([str(binary)], check=True, capture_output=True,
                          text=True).stdout


def parse(dump):
    """Turn the harness dump into the same shape as the golden."""
    got = {"tables": [], "schemes": [], "units": [], "setpcd": []}
    scheme = None
    for line in dump.splitlines():
        if m := re.match(r"calls netenv=(\d+) prs=(\d+) adv=(\d+) "
                         r"pcd_disable=(\d+) pcd_enable=(\d+)", line):
            got["once"] = [int(v) for v in m.groups()]
        elif m := re.match(r"calls tables=(\d+) schemes=(\d+) trees=(\d+) "
                           r"setpcd=(\d+) ports=(\d+)", line):
            got["counts"] = [int(v) for v in m.groups()]
        elif m := re.match(r"softparse base=(\d+) size=(\d+) labels=(\d+)", line):
            got["softparse"] = [int(v) for v in m.groups()]
        elif m := re.match(r"  unit \d+ (\w+)", line):
            got["units"].append(m.group(1))
        elif m := re.match(r"table \d+ keys=(\d+) stats=(\d+) keysize=(\d+) "
                           r"mask=(\d+) shift=(\d+) type=(\d+)", line):
            keys, stats, keysize, mask, shift, _ = (int(v) for v in m.groups())
            got["tables"].append({"max_keys": keys, "statistics_mode": stats,
                                  "key_size": keysize, "hash_res_mask": mask,
                                  "hash_shift": shift})
        elif m := re.match(r"scheme \d+ relid=(\d+) grp=(\d+) fqid=(\d+) nfq=(\d+) "
                           r"shared=(\d+) units=(\d+) extracts=(\d+)", line):
            relid, grp, fqid, nfq, shared, _, _ = (int(v) for v in m.groups())
            scheme = {"relid": relid, "grp": grp, "base_fqid": fqid,
                      "num_fqids": nfq, "shared": shared,
                      "units": [], "extracts": []}
            got["schemes"].append(scheme)
        elif m := re.match(r"    unit (\d+)", line):
            scheme["units"].append(int(m.group(1)))
        elif m := re.match(r"    extract (\w+) idx=(\d+) field=(\d+) fulltype=(\d+)", line):
            scheme["extracts"].append({"hdr": m.group(1), "index": int(m.group(2)),
                                       "field": int(m.group(3)),
                                       "fulltype": int(m.group(4))})
        elif m := re.match(r"    or type=(\d+) mask=(\d+) bitoffset=(\d+) n=(\d+)", line):
            scheme["or"] = [int(v) for v in m.groups()]
        elif m := re.match(r"tree \d+ groups=(\d+) own_tables_in_group_order=(\d+)", line):
            got.setdefault("trees", []).append([int(v) for v in m.groups()])
        elif m := re.match(r"setpcd \d+ support=(\d+) prs_private=(\d+) first=(\w+) "
                           r"addl=(\d+) schemes=(\d+)", line):
            got["setpcd"].append({"support": int(m.group(1)),
                                  "prs_private": int(m.group(2)),
                                  "first": m.group(3), "addl": int(m.group(4)),
                                  "schemes": int(m.group(5))})
    return got


def test_cdx_pcd_build(tmp_path):
    want = json.loads(GOLDEN.read_text())
    fields = net_header_fields(sdk_tree())
    got = parse(build(tmp_path))

    ports = want["counts"]["port_count"]
    groups = len(want["tables"])

    # One soft parser, one net env, one advanced-offload selection per FMan.
    assert got["once"] == [1, 1, 1, 1, 1], got["once"]
    assert got["counts"] == [ports * groups, groups, ports, ports, ports]
    assert got["counts"][0] == want["counts"]["htnode_count"]
    assert got["counts"][1] == want["counts"]["scheme_count"]

    assert got["units"] == want["units"]

    # Every port's CC root tree holds that port's own twelve tables, in group
    # order -- what a scheme's grpId indexes and what cdx_sp.xml offsets past.
    # The golden records the same as contiguous per-port ccroot runs.
    assert got["trees"] == [[groups, 1]] * ports, got["trees"]
    for i, port in enumerate(want["ports"]):
        assert port["ccroot"] == list(range(i * groups, (i + 1) * groups)), i

    # Tables: every port repeats the same twelve shapes, so compare the first
    # twelve against the golden and assert the rest are identical to them.
    for i, table in enumerate(want["tables"]):
        for key in ("max_keys", "statistics_mode", "key_size", "hash_res_mask",
                    "hash_shift"):
            assert got["tables"][i][key] == table[key], (i, key, table["name"])

    # Schemes come out in group order; the golden is keyed the same way.
    for grp, scheme in enumerate(want["schemes"]):
        mine = got["schemes"][grp]
        assert mine["grp"] == grp
        assert mine["base_fqid"] == scheme["base_fqid"], scheme["name"]
        assert mine["num_fqids"] == scheme["num_fqids"], scheme["name"]
        assert mine["shared"] == scheme["shared"], scheme["name"]
        assert mine["units"] == scheme["units"], scheme["name"]
        assert len(mine["extracts"]) == len(scheme["extracts"]), scheme["name"]
        for a, b in zip(mine["extracts"], scheme["extracts"]):
            assert a["hdr"] == b["hdr"], scheme["name"]
            assert INDEX_NAMES[a["index"]] == b["index"], (scheme["name"], b)
            # The field constant is what actually selects the bytes hashed, so
            # compare the value the builder programmed against the value the
            # name in fmc's model resolves to.
            assert a["field"] == fields[b["field"]], (scheme["name"], b["field"])
        # The port id is OR'd into FQID bits 16-19 on every scheme.
        assert mine["or"][1:] == [15, 16, 1], scheme["name"]

    # The relative scheme id is the KeyGen's match priority, and fmc set it from
    # the policy dist_order -- the reverse of group order. Getting this backwards
    # would let the catch-all L2 scheme outrank every specific one.
    priority = [s["grp"] for s in sorted(got["schemes"], key=lambda s: s["relid"])]
    assert priority == want["scheme_priority"], priority

    # Each port is programmed with its own logical port id, which is what
    # cdx_sp.xml reads as $logicalportid.
    expected_ids = [p["prs_private_info"] for p in want["ports"]]
    assert [p["prs_private"] for p in got["setpcd"]] == expected_ids
    for entry in got["setpcd"]:
        assert entry["first"] == "HEADER_TYPE_ETH"
        assert entry["schemes"] == groups
        assert entry["addl"] == len(want["units"])
