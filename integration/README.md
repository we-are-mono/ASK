# Platform recovery integration

These files connect ASK's health check to the **OS-owned hardware watchdog**.
They are installed by the consumer's ASK package; the ASK test image does not
enable automatic recovery because fault tests deliberately stop the datapath.

## Shared requirements

- Enable the board's watchdog in the kernel and device tree. Gateway-DK uses
  `CONFIG_IMX2_WDT` (`imx2-wdt`), not SP805.
- Install `fw_printenv` and `fw_setenv`. The platform must supply a verified
  `/etc/fw_env.config` for the firmware medium it actually boots from. ASK
  neither guesses flash offsets nor changes the firmware's boot/slot variables.
- Install `ask-recovery-monitor` as `/usr/libexec/ask-recovery-monitor`, mode 0755.
- Gate **all ASK hardware activation** on the recovery budget and monitor being
  ready, including flowtables created by a firewall or another service. Remove
  unconditional adapter autoload when it would bypass that gate. With the budget
  exhausted or the watchdog unavailable, leave ASK disabled and Linux networking
  available; keep the OS watchdog running.

`ask-flowtable health` returns 0 while networking is responsive, and 1 on a
terminal CDX latch, invalid diagnostics, or a five-second probe timeout. It
checks RTNL even when no flow exists. Recoverable in-place datapath restarts
are allowed. A blocked kernel reader cannot prevent the command's parent from
reporting failure.

`recovery-arm` reserves one recovery attempt per kernel boot in the separate
U-Boot variable `ask_recovery` (`count boot-UUID reason`). Return 2 means three unconfirmed boots have already been
allowed; return 1 means the environment or hook failed. Both prevent activation.
Repeated starts in the same boot do not spend another attempt. `recovery-failed`
saves the terminal reason without acquiring RTNL. An abrupt hard hang retains
the previously stored “armed; detail unavailable” record. Read the reason
before arming the next boot; arming also logs the previous record.

The monitor calls `recovery-clear` after one continuous hour of successful
probes. This is a consecutive-boot limit, independent of RTC time or persistent
root storage. An operator can also clear the budget after repair and restart the
services. Normal reboots before the healthy hour conservatively spend an attempt.
Environment writes happen at arm, failure, and confirmation, not on each probe.

## systemd: Armbian, NixOS, VyOS

These units use PID 1 as the watchdog owner. Merge the manager settings with
the platform's existing watchdog configuration. The supplied paths match Armbian.
NixOS/VyOS packaging should translate paths
and service names to its own service definitions.

1. Install `systemd/ask-watchdog.conf` in `/etc/systemd/system.conf.d/` and
   the three `ask-recovery*.service` files in `/etc/systemd/system/`.
2. Install `systemd/ask-flowtable.service.d/recovery.conf` in the matching
   `/etc/systemd/system/ask-flowtable.service.d/` directory. Apply the same
   dependencies to any earlier service that activates ASK hardware.
3. Apply the manager settings at the next boot. Verify that PID 1 owns
   `/dev/watchdog0`; the budget service checks this before reserving an attempt.
   Starting the consumer's `ask-flowtable.service` pulls in recovery automatically.

The monitor sends systemd a heartbeat only after a successful probe. Probe
failure or a stalled monitor activates `ask-recovery-reboot.service`, which
records the reason and requests an immediate reboot. Immediate reboot bypasses
normal filesystem shutdown; use it here because orderly shutdown may wait on
the same stuck networking locks. The hardware watchdog covers a stuck PID 1 or
reboot. Budget failure itself has **no** reboot action.

## OpenWrt

1. Install `openwrt/ask-recovery` as `/etc/init.d/ask-recovery`, mode 0755,
   then enable it. It uses the existing `ubus`, `jsonfilter`, and procd APIs.
2. In the consumer's ASK activation path, require successful
   `/etc/init.d/ask-recovery start` **and** `ask-flowtable recovery-arm` before
   loading/enabling the hardware adapter. An rcS order alone is not a failure
   dependency: a failed earlier init script does not stop later scripts.
3. Keep the firewall in software mode when that gate fails. Do not enable
   hardware flow offload through a separate path before the gate succeeds.

procd owns `/dev/watchdog`. The init script enables its hardware watchdog if
necessary, preserves a running watchdog's settings, and checks the returned
status. Its per-service watchdog restarts a
stalled monitor. On datapath failure the monitor saves the reason and asks
procd to stop feeding **without magic close**, allowing the hardware to reset.
No ASK process opens the watchdog device. Stopping this service deliberately
removes ASK health monitoring; the general OS watchdog continues running.

## Qualification

ASK's KASAN test image passed actual hardware resets after a terminal datapath
failure, a CPU hard-locked holding RTNL, and a stopped external watchdog feeder.
The fourth attempt was refused; reasons/counts survived TFTP boots and all
non-ASK U-Boot variables were preserved. Host checks exercise the health timeout,
budget, and platform hooks; systemd unit validation uses version 257.

Before enabling these files in a consumer image, test terminal failure, a CPU
stuck holding RTNL, and three consecutive resets on that image. The OS service
manager, its shutdown path, and firmware watchdog handoff are part of the test.
Configuration validation and ASK initramfs tests do not establish that a
different consumer image's complete recovery path works.
