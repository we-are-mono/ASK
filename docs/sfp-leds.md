# SFP port LEDs

The `sfp-led` kernel module monitors both Mono Gateway SFP cages every
100 ms. Each cage has a green link LED and an orange activity LED.

| State | Green | Orange |
| --- | --- | --- |
| No module responding on I²C | Off | Off |
| Module present, no physical link or interface down | Off | Solid |
| Module present, interface up, physical link established | On | Blinks on traffic |

The driver reads the module's mandatory EEPROM at address `0x50`, byte 0,
to detect presence. It reads the associated XFI PCS through the existing
MDIO controller to determine link state. This works the same way for DACs
and optical modules: it requires no optional module diagnostics and does
not classify or cache cable types. An I²C or MDIO error is retried on the
next poll. An unanswered MDIO read (`0xffff`) cannot assert link.

The PCS register is clause 45 device 3, register 1 (`MDIO_STAT1`), bit 2
(`MDIO_STAT1_LSTATUS`). Two reads under the MDIO bus lock clear its
latched-low indication before sampling the current state. This is the
register used by Linux's `phylink_mii_c45_pcs_get_state()` for the Lynx
10GBASE-R PCS. The driver issues no PCS configuration writes.

Activity comes from `dev_get_stats()`, including the ASK hardware
forwarding statistics. The first sample after link-up establishes a
baseline, so historical packet counts do not generate an activity blink.
A user-selected LED trigger takes precedence on either LED.

## Device tree and lifetime

The configuration uses existing properties in
[`mono-gateway-dk.dts`](../dts/mono-gateway-dk.dts): each `mono,sfp-led`
child references its SFP and two LEDs. The driver finds the matching
`fsl,fman-memac` node by its `sfp` reference and selects the `xfi` entry
from `pcs-handle-names` and `pcs-handle`. Both board ports use a 10 Gb/s
fixed-link configuration.

Every enabled port must acquire its I²C adapter, MDIO bus and both LEDs
before polling starts. Missing providers defer the whole probe; failure
releases any resources acquired for earlier ports. Disabled children are
ignored. A device link stops the monitor before MDIO controller removal.

Netdev lookup and packet-counter access occur under RTNL on each poll.
The driver retains no netdev reference between polls, so netdev removal
can complete and a replacement device can be discovered. A busy RTNL
lock postpones that sample. Driver removal cancels all polling before
releasing the corresponding resources.

The LED monitor does not change the DPAA fixed PHY's carrier state.
Consequently, `ethtool` and `operstate` can still report the configured
fixed link when the far end is disconnected; the green LED follows the
physical PCS status instead.

## Validation

The tests in [`tools/kunit/sfp-led`](../tools/kunit/sfp-led) exercise the
production driver with real kernel I²C, MDIO, LED, DT and netdev APIs and
fake hardware callbacks. They cover fixed carrier with PCS down,
activity baselines, latched status, read errors and recovery, module
removal, administrative down, busy RTNL, netdev unregister, user triggers
and deferred I²C/MDIO/LED providers. The two-port probe test checks that
failure on the second port releases the first port's adapter reference.

Use a **disposable Linux 6.12 source tree**: the runner adds the driver and
tests to that tree's LED Kconfig and Makefile. The UML build directory must
be separate. The host needs the kernel's UML build dependencies and `dtc`.

```sh
python3 tools/kunit/sfp-led/run.py /tmp/sfp-led-linux /tmp/sfp-led-kunit
```

Build the board image with `make ask-image`. On the DUT, test both cages
with a DAC and an optical module. Check an empty cage, a connected link,
traffic, administrative down/up, removal of only the far end, and local
module removal/reinsertion. Removing the far end must turn green off
while orange remains solid. Also unload and reload `sfp-led` and verify
that monitoring resumes. Check the kernel log for lockdep or reference
warnings after these operations.
