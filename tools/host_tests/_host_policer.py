"""The policer layer the tc and devlink owners program, lifted whole for a host
harness built over plcr_fixture.h."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def function(source: str, name: str) -> str:
    """Lift one function definition out of a production source file."""
    # The line has to begin with a return type, not with the ` * ' of a comment
    # continuation: a comment naming `foo()' above the definition of foo would
    # otherwise be lifted instead, and the brace matching below would run from
    # there to whatever it found next.
    match = re.search(rf"^(?:static\s+)?\w[\w \*]*\b{name}\(", source, re.M)
    assert match, name
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def after_includes(source: str) -> str:
    """Everything a production file defines: the text after its last include."""
    return source[max(m.end() for m in re.finditer(r"^#include .*$", source, re.M)):]


def policer_layer(tmp_path: Path) -> None:
    """The records, writes and counter reads the owners reach: cdx_qos.c whole,
    the accessors dpa_cfg.c wraps it in, and the counter types cdx_common.h
    declares for both. Whole rather than function by function, so a record,
    a lock or a retry the layer gains is compiled in without a list here
    having to learn its name."""
    common = (ROOT / "cdx/cdx_common.h").read_text()
    module_qm = (ROOT / "cdx/module_qm.h").read_text()
    cfg = (ROOT / "cdx/dpa_cfg.c").read_text()
    (tmp_path / "plcr_types.inc").write_text(
        "\n".join(re.findall(r"^struct cdx_police_\w+ \{.*?^\};", common, re.S | re.M)) + "\n"
        + "\n".join(re.findall(r"^#define DEFAULT_INGRESS_BYTE_MODE_[CP]BS\s.*$",
                               module_qm, re.M)) + "\n")
    (tmp_path / "plcr_qos.inc").write_text(after_includes((ROOT / "cdx/cdx_qos.c").read_text()))
    (tmp_path / "plcr_cfg.inc").write_text(
        # The exception-path defaults the profiles are created from.
        cfg[cfg.index("#define CDX_EXPT_ETH_DEFA_LIMIT"):
            cfg.index("static void dpa_cfg_set_expt_defaults")]
        + "".join(function(cfg, name) for name in [
            "dpa_cfg_set_expt_defaults", "cdx_get_policer_profile_id",
            "cdx_expt_rate_is_packet_mode", "cdx_expt_rate_config",
            "cdx_expt_rate_counters", "cdx_set_expt_rate",
            "cdx_ingress_enable_or_disable_qos", "cdx_ingress_policer_modify_config",
            "cdx_ingress_policer_peak", "cdx_ingress_policer_counters"]))
