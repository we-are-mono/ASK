"""Shared support for sdk scheme delete."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r"^(?:static\s+)?(?:__inline__\s+)?"
                      r"(?:t_Error|t_Handle|t_(?:HcFrame|FmPcdLock)\s*\*|void|bool|uint(?:8|32)_t|"
                      r"enum qman_cb_dqrr_result)\s*"
                      + name + r"\s*\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"
