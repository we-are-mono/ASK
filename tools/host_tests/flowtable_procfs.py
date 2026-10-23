"""The /proc/ask_flowtable contract, read off the source and its reference.

docs/flowtable/procfs.md says what each file holds and under which lock; these
keep the code and that page from drifting apart."""

import re

from _host_flowtable import ROOT, flowtable_source, function

DOC = ROOT / "docs/flowtable/procfs.md"
# What a status or stats line's key may be: the column it is padded to holds
# the key, its colon and at least one space.
KEY_MAX = 34
# Module parameters, read from /sys/module/*/parameters and never repeated.
PARAMETERS = ("observe", "transit", "mcast_enabled", "multicast", "qos_mark_mask",
              "qos_default_class", "route_mark_mask")
# The CDX accessors that assert the transaction is held.
HELD = ("cdx_ft_failed(", "cdx_ft_bypassed(", "cdx_ft_restarts(", "cdx_ft_resume_failures(",
        "cdx_ft_pending(", "cdx_ft_owed(", "cdx_ft_stats_retention(", "cdx_mc_group_ids(",
        "ft_can_rearm(", "cdx_ft_begin(")


def keys(body):
    return re.findall(r'ft_kv\(seq, "([a-z0-9_]+)"', body)


def refusal_classes(source):
    table = source[source.index("} ft_sec_refusal[CDX_SEC_REFUSAL_CLASSES] = {"):]
    table = table[:table.index("\n};")]
    return re.findall(r'=\s*\{ "([a-z0-9_]+)"', table)


def files():
    source = flowtable_source()
    status = function(source, "ft_status_show") + function(source, "ft_l2_status")
    stats = (function(source, "ft_stats_show") + function(source, "ft_l2_stats")
             + function(source, "ft_sec_refusal_stats"))
    return source, status, stats


def test_every_key_is_short_unique_and_documented():
    source, status, stats = files()
    names = keys(status) + keys(stats)
    names += ["ipsec_sec_refused_" + name for name in refusal_classes(source)]
    assert len(names) == len(set(names)), sorted(n for n in names if names.count(n) > 1)
    doc = DOC.read_text()
    for name in names:
        assert len(name) <= KEY_MAX, name
        if not name.startswith("ipsec_sec_refused_"):
            assert f"`{name}`" in doc, f"{name} is not in {DOC.name}"
    # Every class's key, through the one pattern the page names them by.
    assert "`ipsec_sec_refused_<class>`" in doc
    assert "ft_sec_refusal_stats(seq);" in function(source, "ft_stats_show")
    assert "ft_l2_status(seq);" in function(source, "ft_status_show")
    assert "ft_l2_stats(seq);" in function(source, "ft_stats_show")


def test_levels_under_the_transaction_counts_without_it():
    _, status, stats = files()
    show = function(flowtable_source(), "ft_status_show")
    assert show.index("cdx_ft_begin();") < show.index("ft_kv(") and \
        show.rindex("ft_kv(") < show.index("cdx_ft_end();")
    for accessor in HELD:
        assert accessor not in stats, accessor
    # Each count is loaded once, marked; none is read plain.
    for line in stats.splitlines():
        if "ft_kv(seq, " in line and "ft_kv(seq, key" not in line:
            value = line.split(",", 2)[2]
            assert re.search(r"READ_ONCE\(|atomic64_read\(|detour\.|cdx_ft_qos_|total", value), line


def test_parameters_are_not_repeated():
    _, status, stats = files()
    for name in PARAMETERS:
        assert name not in keys(status) + keys(stats), name


def test_the_directory_and_its_files():
    init = function(flowtable_source(), "ft_proc_init")
    assert 'proc_mkdir("ask_flowtable", NULL)' in init
    made = re.findall(r'proc_create(?:_single|_seq)?\("([a-z0-9]+)", 0400, dir, ', init)
    assert made == ["status", "stats", "devices", "flows", "l2", "mcast", "mroute"], made
    doc = DOC.read_text()
    for name in made:
        assert re.search(rf"^  {name}\s", doc, re.M), name
    # A failure takes the directory back with whatever was made in it.
    assert "proc_remove(dir);" in init
    # Nothing outside the directory.
    source = flowtable_source()
    assert source.count("proc_mkdir(") == 1
    assert len(re.findall(r"\bproc_create(?:_single|_seq)?\(", source)) == 7
