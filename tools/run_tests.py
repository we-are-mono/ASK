"""Make's argument adapter; pytest owns selection, reporting and exit status."""

import argparse
import os
import shlex
import sys
from pathlib import Path


def command(suite, environ, executable=sys.executable):
    root = Path(__file__).resolve().parents[1]
    env = dict(environ)
    for short, names in {
        "DUT_IP": ("ASK_TARGET_IP",),
        "WAN_IP": ("ASK_WAN_IP", "ASK_WAN_IPERF_IP"),
        "WAN_AGENT_IP": ("ASK_WAN_IP",),
    }.items():
        if env.get(short):
            env.update((name, env[short]) for name in names)
    env["PYTHONPATH"] = str(root / "tools")
    paths = {
        "host": ["host_tests"],
        "dut": ["tests"],
        "startup": ["startup_tests"],
        "all": ["host_tests", "tests"],
    }
    argv = [executable, "-m", "pytest", "-c", str(root / "tools/pyproject.toml")]
    argv += [str(root / "tools" / path) for path in paths[suite]]
    if env.get("K"):
        argv.extend(["-k", env["K"]])
    argv += shlex.split(env.get("ASK_TEST_ARGS", "")) + shlex.split(env.get("ARGS", ""))
    if suite != "host" and os.geteuid() != 0:
        # argv stays an argument list: spaces, quotes and shell metacharacters
        # in settings never become shell syntax at the sudo boundary.
        settings = [
            f"{key}={value}"
            for key, value in env.items()
            if key.startswith("ASK_") or key == "PYTHONPATH"
        ]
        argv = ["sudo", "env", *settings, *argv]
    return argv, env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=("all", "host", "dut", "startup"))
    args = parser.parse_args()
    argv, env = command(args.suite, os.environ)
    os.execvpe(argv[0], argv, env)


if __name__ == "__main__":
    main()
