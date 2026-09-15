#!/usr/bin/env python3
"""Convert fmc's softparse.h into the kernel header cdx loads at startup.

fmc emits softparse.h next to fmc_config_data.c when it compiles cdx_sp.xml.
That file is a single SOFT_PARSE_CODE macro holding a t_FmPcdPrsSwParams
initialiser with the assembled bytecode as a compound literal. cdx wants the
same data as a plain array plus a small descriptor it can hand to
FM_PCD_PrsLoadSw, so this rewrites it.

Regenerate after any change to cdx_sp.xml -- see docs/in-kernel-pcd.md for how
to build the host-mode fmc that produces the input.

    tools/gen_cdx_softparse.py <softparse.h> cdx/cdx_softparse.h
"""

import re
import sys


def parse(text):
    def scalar(label):
        m = re.search(r"(\S+),\s*\\?\s*/\*\s*%s\s*\*/" % label, text, re.I)
        if not m:
            raise SystemExit("cannot find /*%s*/ in the input" % label)
        return m.group(1)

    code_block = re.search(r"/\*Code\*/(.*?)\n\s*},", text, re.S)
    if not code_block:
        raise SystemExit("cannot find the /*Code*/ block in the input")
    code = [int(b, 16) for b in re.findall(r"0x([0-9A-Fa-f]{2})", code_block.group(1))]

    labels_block = re.search(r"/\*numOfLabels\*/(.*)", text, re.S)
    labels = re.findall(
        r"(0x[0-9A-Fa-f]+),\s*\\?\s*/\*offset\*/\s*\\?\s*"
        r"(\w+),\s*\\?\s*/\*prevProto\*/\s*\\?\s*"
        r"(\d+),\s*\\?\s*/\*index\*/",
        labels_block.group(1) if labels_block else "",
    )

    size = int(scalar("Size"))
    if size != len(code):
        raise SystemExit("declared size %d != %d bytes of code" % (size, len(code)))
    num_labels = int(scalar("numOfLabels"))
    if num_labels != len(labels):
        raise SystemExit("declared numOfLabels %d != %d parsed" % (num_labels, len(labels)))

    return {"size": size, "base": scalar("Base"), "code": code, "labels": labels}


def emit(sp, source):
    rows = [
        "\t" + " ".join("0x%02x," % b for b in sp["code"][i:i + 12])
        for i in range(0, len(sp["code"]), 12)
    ]
    labels = "".join(
        "\t{ .instructionOffset = %s, .hdr = %s, .indexPerHdr = %s },\n" % lab
        for lab in sp["labels"]
    )
    return """/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * FMan software-parser bytecode, assembled from %s.
 *
 * GENERATED FILE -- do not edit. Regenerate with:
 *     tools/gen_cdx_softparse.py <softparse.h> cdx/cdx_softparse.h
 * See docs/in-kernel-pcd.md for building the host-mode fmc that emits the
 * input, and keep this in step with %s.
 */
#ifndef CDX_SOFTPARSE_H
#define CDX_SOFTPARSE_H

#define CDX_SP_BASE %s
#define CDX_SP_SIZE %u
#define CDX_SP_NUM_LABELS %u

/* FM_PCD_PrsLoadSw() takes a non-const p_Code and copies it into MURAM. */
static u8 cdx_sp_code[CDX_SP_SIZE] = {
%s
};

static const t_FmPcdPrsLabelParams cdx_sp_labels[CDX_SP_NUM_LABELS] = {
%s};

#endif /* CDX_SOFTPARSE_H */
""" % (
        source,
        source,
        sp["base"],
        sp["size"],
        len(sp["labels"]),
        "\n".join(rows),
        labels,
    )


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__.strip().splitlines()[-1].strip())
    with open(sys.argv[1]) as handle:
        sp = parse(handle.read())
    with open(sys.argv[2], "w") as handle:
        handle.write(emit(sp, "dpa_app/files/etc/cdx_sp.xml"))
    print("%s: %u bytes of code at base %s, %u labels"
          % (sys.argv[2], sp["size"], sp["base"], len(sp["labels"])))


if __name__ == "__main__":
    main()
