#!/usr/bin/env python3
"""Distil fmc's compiled model into the golden the PCD host test checks against.

fmc is what the in-kernel builder replaces, so its output is the only
independent statement of what the classifier should look like. This reduces
fmc_config_data.c to the parts the builder is responsible for and writes them as
JSON, so the expectation survives fmc's removal.

Regenerate after any change to cdx_pcd.xml or cdx_cfg.xml -- see
docs/in-kernel-pcd.md for rebuilding the retired host-mode fmc that produces
the input.

    tools/gen_cdx_pcd_golden.py <fmc_config_data.c> tools/host_tests/golden/cdx_pcd_model.json
"""

import copy
import json
import re
import sys

PORT_TYPES = {
    "e_FM_PORT_TYPE_RX": "1g",
    "e_FM_PORT_TYPE_RX_10G": "10g",
    "e_FM_PORT_TYPE_OH_OFFLINE_PARSING": "offline",
}


def scalar(text, pattern, cast=str):
    """fmc emits both "x = 1," and "x =1,", so every pattern here allows either.
    A missed field would silently become null and the golden would assert
    nothing, so refuse instead."""
    match = re.search(pattern, text)
    if not match:
        raise SystemExit("no match for %r -- fmc's output format changed" % pattern)
    return cast(match.group(1))


def load(path):
    text = open(path).read()
    model = {}

    model["counts"] = {
        key: scalar(text, r"\.%s =\s*(\d+)," % key, int)
        for key in ("fman_count", "port_count", "scheme_count", "htnode_count",
                    "ccnode_count", "policer_count", "replicator_count")
    }

    # Distinction units, in the order the net env receives them.
    model["units"] = re.findall(
        r"port\[0\]\.distinctionUnits\.units\[\d+\]\.hdrs\[0\]\.hdr =\s*(\w+)", text)

    # Ports, in cdx_cfg.xml order.
    ports = []
    for idx in range(model["counts"]["port_count"]):
        chunk = r"port\[%d\]\." % idx
        ports.append({
            "type": PORT_TYPES[scalar(text, chunk + r"type =\s*(\w+),")],
            "number": scalar(text, chunk + r"number =\s*(\d+),", int),
            "portid": scalar(text, chunk + r"portid =\s*(\d+),", int),
            "prs_private_info": scalar(
                text, chunk + r"prsParam\.prsResultPrivateInfo =\s*(\d+),", int),
            "units": re.findall(chunk + r"distinctionUnits\.units\[\d+\]\.hdrs\[0\]\.hdr =\s*(\w+)", text),
            "schemes": [int(v) for v in re.findall(chunk + r"schemes\[\d+\] =\s*(\d+)", text)],
            "parser_labels": scalar(text, chunk + r"prsParam\.numOfHdrsWithAdditionalParams =\s*(\d+),", int),
            "ccroot": [int(v) for v in re.findall(chunk + r"ccroot\[\d+\] =\s*(\d+)", text)],
        })
    model["ports"] = ports

    # Keep every port: the SEC port has a different table set.
    tables = []
    for idx in range(model["counts"]["htnode_count"]):
        chunk = r"htnode\[%d\]\." % idx
        tables.append({
            "name": scalar(text, r'htnode_name\[%d\] = "[^"]*ccnode/(\w+)"' % idx),
            "max_keys": scalar(text, chunk + r"maxNumOfKeys =\s*(\d+),", int),
            "statistics_mode": scalar(text, chunk + r"statisticsMode =\s*(\d+),", int),
            "key_size": scalar(text, chunk + r"matchKeySize =\s*(\d+),", int),
            "hash_res_mask": scalar(text, chunk + r"hashResMask =\s*(\d+),", int),
            "hash_shift": scalar(text, chunk + r"hashShift =\s*(\d+),", int),
            "prefilled_entries": scalar(text, r"htentry_count\[%d\] =\s*(\d+)," % idx, int),
        })
    model["tables"] = tables

    # Schemes, keyed by their model index; policies reuse group numbers.
    schemes = {}
    for idx in range(model["counts"]["scheme_count"]):
        chunk = r"scheme\[%d\]\." % idx
        block = re.search(
            chunk + r"keyExtractAndHashParams\.numOfUsedExtracts.*?(?=scheme_name\[|\Z)",
            text, re.S).group(0)
        extracts = [
            {"hdr": hdr, "index": index, "field": field}
            for hdr, index, _, field in re.findall(
                r"extractByHdr\.hdr\s*=(\w+),.*?extractByHdr\.hdrIndex\s*=(\w+),"
                r".*?fullField\.(\w+)\s*=(\w+),", block, re.S)
        ]
        grp = scalar(text, chunk + r"kgNextEngineParams\.cc\.grpId =\s*(\d+),", int)
        schemes[idx] = {
            "group": grp,
            "name": scalar(text, r'scheme_name\[%d\] = "fm0/dist/(\w+)"' % idx),
            "base_fqid": scalar(text, chunk + r"baseFqid =\s*(\d+),", int),
            "num_fqids": scalar(
                text,
                chunk + r"keyExtractAndHashParams\.hashDistributionNumOfFqids =\s*(\d+),",
                int),
            "shared": scalar(text, chunk + r"shared =\s*(\d+),", int),
            "units": [int(v) for v in re.findall(
                chunk + r"netEnvParams\.unitIds\[\d+\] =\s*(\d+)", text)],
            "extracts": extracts,
            "extracted_or": {
                "type": scalar(text, chunk + r"extractedOrs\[0\]\.type =\s*(\w+),"),
                "mask": scalar(text, chunk + r"extractedOrs\[0\]\.mask =\s*(\d+),", int),
                "bit_offset_in_fqid": scalar(
                    text, chunk + r"extractedOrs\[0\]\.bitOffsetInFqid =\s*(\d+),", int),
            },
        }
    model["schemes"] = [schemes[grp] for grp in sorted(schemes)]

    # Apply order gives the KeyGen match priority: fmc numbers schemes in the
    # order it applies them, and the builder has to reproduce that, not the
    # group order. Recorded as group ids, highest priority first.
    model["scheme_priority"] = [
        int(v) for v in re.findall(r"FMC_APPLY_ORDER\(\s*\d+, FMCScheme\s*,\s*(\d+)\s*\)", text)
    ]
    if len(model["scheme_priority"]) != model["counts"]["scheme_count"]:
        raise SystemExit("apply order lists %d schemes, model has %d"
                         % (len(model["scheme_priority"]),
                            model["counts"]["scheme_count"]))
    add_receive_identity(model)
    return model


def add_receive_identity(model):
    """The loader's post-FMC tuple/PPPoE adjustments (9b5ecd7, 59b29ea).

    Keep this transformation independent of the kernel descriptors: XML still
    describes the base tuples, and this records the former loader's final model.
    """
    original = len(model["schemes"])
    for idx in range(original):
        scheme = model["schemes"][idx]
        match = re.fullmatch(r"cdx_(tcp|udp)([46])_dist", scheme["name"])
        if not match:
            continue
        family = int(match[2])
        scheme["extracts"] = [e for e in scheme["extracts"]
                              if e["field"] not in ("NET_HEADER_FIELD_IPv4_PROTO",
                                                    "NET_HEADER_FIELD_IPv6_NEXT_HDR")]
        generic = [("IPv4", 9, 1), ("IPv6", 6, 1), ("IPv6", 8, 16),
                   ("IPv6", 24, 16), ("IPv6", 40, 1)] if family == 4 else [
                   ("IPv6", 6, 1), ("IPv4", 9, 1), ("IPv4", 12, 8)]
        scheme["generic"] = [["HEADER_TYPE_" + h, o, n] for h, o, n in generic]
        scheme["generic"].append(["HEADER_TYPE_PPPoE", 0, 8])
        clone = copy.deepcopy(scheme)
        clone["name"] += "_pppoe"
        clone["generic"][-1:] = [["HEADER_TYPE_ETH", 6, 6], ["HEADER_TYPE_PPPoE", 2, 2]]
        clone["units"].append(model["units"].index("HEADER_TYPE_PPPoE"))
        clone_idx = len(model["schemes"])
        model["schemes"].append(clone)
        at = model["scheme_priority"].index(idx)
        model["scheme_priority"].insert(at, clone_idx)
        for port in model["ports"]:
            if idx in port["schemes"]:
                at = port["schemes"].index(idx)
                port["schemes"].insert(at, clone_idx)
        table_name = scheme["name"].replace("_dist", "_cc")
        for table in model["tables"]:
            if table["name"] == table_name:
                table["key_size"] = 56 if family == 4 else 55
    model["counts"]["scheme_count"] = len(model["schemes"])


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__.strip().splitlines()[-1].strip())
    model = load(sys.argv[1])
    with open(sys.argv[2], "w") as handle:
        json.dump(model, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("%s: %d ports, %d tables, %d schemes"
          % (sys.argv[2], len(model["ports"]), len(model["tables"]),
             len(model["schemes"])))


if __name__ == "__main__":
    main()
