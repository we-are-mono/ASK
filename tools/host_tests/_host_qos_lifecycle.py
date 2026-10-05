"""Shared support for qos lifecycle."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    # An explicit list of return types rather than "anything": it is what
    # keeps a forward declaration or a call site from being mistaken for the
    # definition. Widen it when a new one is needed.
    match = re.search(r"^(?:static )?(?:inline )?(?:int\s+|void |bool |U8 |U16 |u8 |u16 |u32 |u64 |uint32_t |"
                      r"unsigned int |unsigned long |size_t |const char \*|"
                      r"struct qman_fq \*|struct en_exthash_tbl_entry ?\* ?|"
                      r"struct net_device ?\* ?|struct ft_mc_group ?\* ?|"
                      r"struct ft_mc_flow ?\* ?|const struct br_ip ?\* ?|"
                      r"const struct ft_mc_route ?\* ?|"
                      r"struct ft_mr_group ?\* ?|struct ft_mr_event ?\* ?|"
                      r"struct xfrm_state ?\* ?|struct ft_ipsec_watch ?\* ?|const struct xfrmdev_ops ?\* ?|"
                      r"struct ft_ipsec_retirement ?\* ?|"
                      r"struct rtable ?\* ?|struct dst_entry ?\* ?|struct tcf_block ?\* ?|"
                      r"enum ft_mr_state |enum qman_cb_dqrr_result )"
                      # __init/__exit sit between the return type and the name.
                      r"(?:__init |__exit )?"
                      + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    start = match.start()
    end = match.end()
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"
