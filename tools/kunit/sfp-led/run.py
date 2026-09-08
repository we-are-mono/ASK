#!/usr/bin/env python3
"""Build and run the SFP LED tests in a disposable Linux source tree."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path, help="disposable Linux 6.12 source tree")
    parser.add_argument("build", type=Path, help="separate UML build directory")
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    build = args.build.resolve()
    tests = Path(__file__).resolve().parent
    repo = tests.parents[2]
    driver = repo / "meta-ask/recipes-kernel/sfp-led/files/sfp-led.c"
    if not (kernel / "tools/testing/kunit/kunit.py").is_file():
        parser.error("kernel must contain a Linux source tree with KUnit")
    if kernel == (repo / "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"):
        parser.error("use a disposable copy, not the active Yocto kernel tree")

    dest = kernel / "drivers/leds/sfp-led-kunit"
    dest.mkdir(exist_ok=True)
    subprocess.run(
        ["dtc", "-I", "dts", "-O", "dtb", "-o", str(dest / "test.dtb"),
         str(tests / "test.dts")], check=True,
    )
    (dest / "sfp-led.c").write_text(driver.read_text() + '\n#include "test.c"\n')
    shutil.copyfile(tests / "test.c", dest / "test.c")
    (dest / "Makefile").write_text("obj-$(CONFIG_SFP_LED_KUNIT_TEST) += sfp-led.o\n")

    kconfig = kernel / "drivers/leds/Kconfig"
    if "config SFP_LED_KUNIT_TEST" not in kconfig.read_text():
        with kconfig.open("a") as stream:
            stream.write(
                '\nconfig SFP_LED_KUNIT_TEST\n\tbool "Mono SFP LED KUnit tests"\n'
                "\tdepends on KUNIT && OF && I2C && PHYLIB && LEDS_CLASS && LEDS_TRIGGERS\n"
            )
    makefile = kernel / "drivers/leds/Makefile"
    if "sfp-led-kunit/" not in makefile.read_text():
        with makefile.open("a") as stream:
            stream.write("\nobj-$(CONFIG_SFP_LED_KUNIT_TEST) += sfp-led-kunit/\n")

    env = dict(os.environ)
    env.setdefault("TMPDIR", "/tmp")
    subprocess.run(
        [sys.executable, "tools/testing/kunit/kunit.py", "run",
         f"--kunitconfig={tests / '.kunitconfig'}", f"--build_dir={build}",
         f"--jobs={args.jobs}", "--timeout=90",
         f"--kernel_args=dtb={dest / 'test.dtb'}", "sfp-led"],
        cwd=kernel, env=env, check=True,
    )


if __name__ == "__main__":
    main()
