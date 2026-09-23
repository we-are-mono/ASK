"""The ask-flowtable policy engine, compiled and driven natively.

The offload policy is now a C daemon (flowtable/src). This test compiles its
validator, renderer, and ownership fingerprint into a small harness
(flowtable_policy.c) and feeds it conf snippets, so the accept/reject surface,
the injection guards, and the rendered nftables output are covered off the rig.
"""
import os
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "flowtable" / "src"
HARNESS = Path(__file__).with_name("flowtable_policy.c")

BASE = """\
enabled yes
devices eth3 eth4
scope 192.0.2.0/24 -> 198.51.100.2
exclude tcp 21
"""


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    out = tmp_path_factory.mktemp("ft") / "flowtable_policy"
    cc = os.environ.get("HOSTCC", "cc")
    subprocess.run([
        cc, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(ENGINE),
        str(ENGINE / "policy.c"), str(ENGINE / "conf.c"),
        str(ENGINE / "render.c"), str(ENGINE / "sha256.c"), str(ENGINE / "marker.c"),
        str(HARNESS), "-o", str(out),
    ], check=True)
    return out


def run(engine, conf, *args):
    env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
           "UBSAN_OPTIONS": "halt_on_error=1"}
    return subprocess.run([str(engine), *args], input=conf, text=True,
                          capture_output=True, env=env)


def check(engine, conf):
    return run(engine, conf, "check")


def render(engine, conf, mask=None):
    args = ["render"] + (["--mask", hex(mask)] if mask is not None else [])
    r = run(engine, conf, *args)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


# --- validation: accept -----------------------------------------------------

def test_accepts_the_default_and_base(engine):
    for conf in (BASE, "devices auto\nscope any\nexclude tcp 21\nexclude udp 5060\n"):
        r = check(engine, conf)
        assert r.returncode == 0 and r.stdout.startswith("OK "), r.stdout + r.stderr


@pytest.mark.parametrize("conf", [
    "enabled yes\ndevices eth3 eth4\nscope any\n",
    "devices auto\nscope any\n",                                  # auto defers count
    "enabled no\n",                                               # disabled needs nothing
    "devices eth3 eth4\nscope proto tcp dport 443 saddr 10.0.0.0/24\n",
    "devices eth3 eth4\nscope 10.0.0.0/8 -> 1.2.3.4\nexclude mark 0x10/0xf0\n",
    "devices pppoe-wan br-lan br-guest br-iot\nscope any\n",      # a port per bridge
])
def test_accepts(engine, conf):
    r = check(engine, conf)
    assert r.returncode == 0, r.stdout + r.stderr


# --- validation: reject -----------------------------------------------------

@pytest.mark.parametrize("conf,msg", [
    ("version 2\ndevices eth3 eth4\nscope any\n", "version"),
    ("enabled maybe\ndevices eth3 eth4\nscope any\n", "yes or no"),
    ("devices eth3\nscope any\n", "2 to"),
    ("devices eth3 eth3\nscope any\n", "duplicate"),
    ('devices "eth3; flush ruleset" eth4\nscope any\n', "invalid interface name"),
    ("devices eth3 eth4\n", "admission scope"),                   # enabled, no scope
    ("devices eth3 eth4\nscope saddr 192.0.2.1/24\n", "host bits"),
    ("devices eth3 eth4\nscope saddr 2001:db8::/32\n", "IPv4"),
    ("devices eth3 eth4\nexclude proto icmp\n", "tcp and udp"),
    ("devices eth3 eth4\nexclude name lonely\n", "at least one selector"),
    ("devices eth3 eth4\nscope proto tcp dport 70000\n", "1..65535"),
    ("devices eth3 eth4\nscope port 100-1\n", "min exceeds max"),
    ("devices eth3 eth4\nscope any\nbogus line\n", "unknown configuration key"),
    ("devices eth3 eth4\nscope badkey 5\n", "unknown selector"),
    ("enabled yes\nenabled no\ndevices eth3 eth4\nscope any\n", "duplicate key: enabled"),
    ("devices eth3 eth4\ndevices eth5 eth6\nscope any\n", "duplicate key: devices"),
])
def test_rejects(engine, conf, msg):
    r = check(engine, conf)
    assert r.returncode != 0, "expected rejection: " + r.stdout
    assert msg in r.stdout, f"want {msg!r} in {r.stdout!r}"


def test_rejects_oversized_device_list(engine):
    devs = " ".join(f"eth{i}" for i in range(41))
    r = check(engine, f"devices {devs}\nscope any\n")
    assert r.returncode != 0 and ("at most 40" in r.stdout or "2 to 40" in r.stdout), r.stdout


def _heavy(n):
    """n rules that each render four long lines: every selector, port shorthand."""
    rule = ("scope proto tcp saddr 203.0.113.254/32 daddr 198.51.100.254/32 "
            "reply-saddr 198.51.100.254/32 reply-daddr 203.0.113.254/32 "
            "mark 0xffffffff/0xffffffff port 65534-65535\n")
    return "devices eth3 eth4\n" + rule * n


def test_every_accepted_policy_renders(engine):
    """check and apply must agree. A policy well inside the 64 KiB and
    256-rule limits used to pass check and then be refused at apply with
    "rendered ruleset exceeds buffer", because a port rule renders four lines.
    The validator now measures the rendered table and names the limit."""
    rejected = 0
    for n in (64, 128, 129, 131, 160, 192, 224, 256):
        conf = _heavy(n)
        assert len(conf) <= 65536
        r = check(engine, conf)
        if r.returncode:
            assert "renders to" in r.stdout and "byte limit" in r.stdout, r.stdout
            rejected += 1
            continue
        out = run(engine, conf, "render")
        assert out.returncode == 0, (n, out.stdout[-200:])
    assert rejected, "the largest of these policies should exceed the render limit"


def test_rejects_config_over_64k(engine):
    conf = "devices eth3 eth4\nscope any\n" + "# pad\n" * 20000
    r = check(engine, conf)
    assert r.returncode != 0 and "64 KiB" in r.stdout, r.stdout


# --- rendering --------------------------------------------------------------

def test_render_port_shorthand_expands_all_fields(engine):
    rules = render(engine, BASE)
    for expr in ("ct original proto-src 21", "ct original proto-dst 21",
                 "ct reply proto-src 21", "ct reply proto-dst 21"):
        assert "meta l4proto tcp " + expr + " return" in rules


def test_render_addresses_ports_and_scope(engine):
    conf = ("devices eth3 eth4\n"
            "scope 192.0.2.0/24 -> 198.51.100.2\n"
            "exclude reply-daddr 203.0.113.4 sport 1000-2000 mark 0x2/0x3\n")
    rules = render(engine, conf)
    assert ("ct reply ip daddr 203.0.113.4/32 ct original proto-src 1000-2000 "
            "ct mark & 0x3 == 0x2 return") in rules
    assert "ct original ip saddr 192.0.2.0/24 ct original ip daddr 198.51.100.2/32 flow add @fast" in rules


def test_render_is_offload_only_and_clean(engine):
    rules = render(engine, BASE)
    assert "flags offload" in rules
    assert "counter" not in rules and "flush" not in rules
    assert "ct status snat" not in rules and "ct status dnat" not in rules


def test_render_admits_both_address_families(engine):
    """The family gate must not exclude IPv6.

    It did, for five days after the adapter grew IPv6, and no test caught it:
    every IPv6 test on the rig writes an nft table of its own and never renders
    this chain, so the one path a shipped box actually uses -- the default-on
    service, with no configuration at all -- offloaded IPv4 and silently
    nothing else. The profile tests were the first to drive IPv6 through the
    rendered policy and the first to see it.
    """
    rules = render(engine, BASE)
    assert "  meta nfproto != { ipv4, ipv6 } return" in rules.splitlines()
    assert "meta nfproto != ipv4 return" not in rules


def test_render_port_per_bridge_binds_each(engine):
    conf = "devices pppoe-wan br-lan br-guest br-iot\nscope any\n"
    line = next(l for l in render(engine, conf).splitlines() if "flowtable fast" in l)
    for dev in ("pppoe-wan", "br-lan", "br-guest", "br-iot"):
        assert f'"{dev}"' in line


def test_render_marker_stable_and_present(engine):
    rules = render(engine, BASE)
    m = re.search(r'comment "ask-flowtable/v1:([0-9a-f]{64})"', rules)
    assert m
    got = check(engine, BASE).stdout.split()[1]
    assert m.group(1) == got, "table marker must equal the policy hash"


def test_render_admission_mask_follows_the_adapter(engine):
    # No mask: every mark still declines to software (historical ct mark != 0).
    assert "  ct mark & 0xffffffff != 0x0 return" in render(engine, BASE, 0).splitlines()
    # A class mask leaves the class bits for the adapter; other bits refuse.
    assert "  ct mark & 0xff00ffff != 0x0 return" in render(engine, BASE, 0x00ff0000).splitlines()
    # The mask changes the guard but not the marker: a reboot under a different
    # mask is not a different policy.
    plain, masked = render(engine, BASE, 0), render(engine, BASE, 0x00ff0000)
    assert plain != masked
    marker = 'comment "ask-flowtable/v1:' + check(engine, BASE).stdout.split()[1] + '"'
    assert marker in plain and marker in masked


HEX = "0" * 64


@pytest.mark.parametrize("text,owned", [
    # Our own table: marker is the table comment, before the chain.
    (f'table inet ask_flowtable {{\n\tcomment "ask-flowtable/v1:{HEX}"\n\t'
     f'flowtable fast {{ }}\n\tchain admit {{ }}\n}}\n', True),
    # Regression guard: "flowtable " also occurs in the table NAME; the bound
    # must not exclude our own comment on the line above the flowtable object.
    (f'table inet ask_flowtable {{ # ask_flowtable\n\tcomment "ask-flowtable/v1:{HEX}"\n\t'
     f'flowtable fast {{ }}\n\tchain c {{ }}\n}}\n', True),
    # Foreign table, same name, marker only inside a rule comment (in a chain):
    # must NOT be mistaken for ours (else we would delete a foreign table).
    (f'table inet ask_flowtable {{\n\tcomment "not ours"\n\tchain c {{ '
     f'ip saddr 1.2.3.4 comment "ask-flowtable/v1:{HEX}" }}\n}}\n', False),
    # No marker at all.
    ('table inet ask_flowtable {\n\tcomment "foreign"\n}\n', False),
    # Truncated hash.
    ('table inet ask_flowtable {\n\tcomment "ask-flowtable/v1:dead"\n\tchain c {}\n}\n', False),
])
def test_marker_ownership(engine, text, owned):
    r = run(engine, text, "marker")
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.startswith("OWNED " if owned else "FOREIGN"), r.stdout


# --- device membership ------------------------------------------------------

AUTO = "devices auto\nscope any\nexclude tcp 21\n"
HOOK = "hook ingress priority 0;"


def marker(rules):
    return re.search(r'comment "ask-flowtable/v1:([0-9a-f]{64})"', rules)[1]


def flowtable_line(rules):
    return next(line for line in rules.splitlines() if "flowtable fast" in line)


def test_auto_identity_is_the_configuration_not_the_ports(engine):
    """Under `devices auto` the ports are live state: the marker is the
    configuration's hash whichever ports resolution found up, and equals the
    hash `check` computes without resolving any. When it covered the ports, a
    spare port's link changing was a different policy, and the daemon replaced
    the table -- retiring every offloaded flow on every port."""
    configured = check(engine, AUTO).stdout.split()[1]
    for ports in ("eth3,eth4", "eth3,eth4,eth5", "eth0,eth3"):
        r = run(engine, AUTO, "render", "--resolve", ports)
        assert r.returncode == 0, r.stdout + r.stderr
        assert marker(r.stdout) == configured, (ports, r.stdout)
        assert re.findall(r'"([^"]+)"', flowtable_line(r.stdout)) == ports.split(","), r.stdout


def test_explicit_device_list_is_part_of_the_identity(engine):
    hashes = {check(engine, f"devices {devices}\nscope any\nexclude tcp 21\n").stdout for devices in
              ("eth3 eth4", "eth3 eth4 eth5", "eth4 eth3")}
    hashes.add(check(engine, AUTO).stdout)
    assert len(hashes) == 4 and all(h.startswith("OK ") for h in hashes), hashes


def membership(engine, installed, resolved):
    r = run(engine, AUTO, "membership", "--installed", installed, "--resolve", resolved)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout.splitlines()


@pytest.mark.parametrize("installed,resolved,update", [
    ("eth3,eth4", "eth3,eth4,eth5",
     ['add flowtable inet ask_flowtable fast { ' + HOOK + ' devices = { "eth5" }; flags offload; }']),
    ("eth3,eth4,eth5", "eth3,eth4",
     ['delete flowtable inet ask_flowtable fast { ' + HOOK + ' devices = { "eth5" }; }']),
    ("eth3,eth4", "eth3,eth5,eth6",
     ['add flowtable inet ask_flowtable fast { ' + HOOK + ' devices = { "eth5", "eth6" }; flags offload; }',
      'delete flowtable inet ask_flowtable fast { ' + HOOK + ' devices = { "eth4" }; }']),
    ("eth4,eth3", "eth3,eth4", []),
])
def test_membership_update_names_only_the_changed_devices(engine, installed, resolved, update):
    """The add and delete are one script, so one nft transaction, and each
    names only the devices that change. Netfilter refuses an update on another
    hook or priority, or whose flags differ in offload from the live
    flowtable's, so both restate what the table declares."""
    assert membership(engine, installed, resolved) == update
    declared = flowtable_line(render(engine, AUTO))
    assert f"{{ {HOOK} devices" in declared and declared.endswith("flags offload; }")


LISTED = """table inet ask_flowtable {{
\tcomment "ask-flowtable/v1:{hex}"
\tflowtable fast {{
\t\thook ingress priority filter
{devices}\t\tflags offload
\t}}

\tchain admit {{
\t\ttype filter hook forward priority filter + 10; policy accept;
\t\tmeta nfproto != {{ ipv4, ipv6 }} return
\t}}
}}
"""


@pytest.mark.parametrize("devices,read", [
    ("\t\tdevices = { eth3, eth4 }\n", "DEVICES eth3 eth4"),           # nft 1.1.1
    ('\t\tdevices = { "eth3", "eth4" }\n', "DEVICES eth3 eth4"),       # nft 1.1.6
    ("\t\tdevices = { eth3 }\n", "DEVICES eth3"),
    ("", "DEVICES"),                                                   # every device deleted
    ('\t\tdevices = { eth3, "e;th4" }\n', "UNREADABLE -1"),
    ("\t\tdevices = { " + ", ".join(f"eth{i}" for i in range(41)) + " }\n", "UNREADABLE -1"),
])
def test_listed_devices_are_read_back(engine, devices, read):
    r = run(engine, LISTED.format(hex="0" * 64, devices=devices), "devices")
    assert r.returncode == 0 and r.stdout.strip() == read, r.stdout + r.stderr


def test_rendered_devices_are_read_back(engine):
    r = run(engine, render(engine, AUTO), "devices")
    assert r.stdout.strip() == "DEVICES eth3 eth4", r.stdout


def test_devices_outside_the_flowtable_are_not_read(engine):
    """Only the table's own flowtable declaration, ahead of the chains, is
    read: a `devices = {` inside a chain is not a flowtable's."""
    text = LISTED.format(hex="0" * 64, devices="").replace("flowtable fast", "flowtable other")
    text = text.replace("\t\tmeta nfproto", '\t\tcomment "flowtable fast { devices = { eth9 } }"\n\t\tmeta nfproto')
    r = run(engine, text, "devices")
    assert r.stdout.strip() == "UNREADABLE -1", r.stdout


def test_builtin_default_is_the_shipped_configuration(engine):
    """With /etc/ask/offload.conf absent the daemon falls back to a policy
    compiled into main.c, and the image installs config/offload.conf in that
    path. Both describe what an unconfigured box does, so they must be one
    policy: the fingerprint's canonical form covers enablement, device
    resolution and every scope and exclusion in order, so an edit to either
    that is not made to the other changes it."""
    recipe = (ROOT / "meta-ask/recipes-ask/config/config_1.0.bb").read_text()
    assert "${ASK_SRCROOT}/config/offload.conf ${D}${sysconfdir}/ask/offload.conf" in recipe
    source = (ENGINE / "main.c").read_text()
    literal = re.search(r"static const char DEFAULT_CONF\[\] =(.*?);", source, re.S)
    assert literal, "main.c no longer defines DEFAULT_CONF"
    pieces = re.findall(r'"((?:[^"\\]|\\.)*)"', re.sub(r"/\*.*?\*/", "", literal[1], flags=re.S))
    builtin = "".join(pieces).encode().decode("unicode_escape")
    shipped = (ROOT / "config/offload.conf").read_text()
    compiled, installed = check(engine, builtin), check(engine, shipped)
    assert compiled.returncode == 0 and compiled.stdout.startswith("OK "), compiled.stdout + compiled.stderr
    assert installed.returncode == 0 and installed.stdout.startswith("OK "), installed.stdout + installed.stderr
    assert compiled.stdout == installed.stdout, (builtin, shipped)
    assert render(engine, builtin) == render(engine, shipped)


def test_device_bound_matches_the_adapter():
    """FT_MAX_DEVICES restates CDX_FT_MAX_TABLE_DEVICES, the adapter's bound for
    one table. Drift would refuse a policy the adapter would have taken, or
    accept one it will only half bind."""
    header = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    policy_h = (ENGINE / "policy.h").read_text()
    adapter = int(re.search(r"^#define CDX_FT_MAX_TABLE_DEVICES\s+(\d+)", header, re.M)[1])
    engine_max = int(re.search(r"^#define FT_MAX_DEVICES\s+(\d+)", policy_h, re.M)[1])
    assert adapter == engine_max
