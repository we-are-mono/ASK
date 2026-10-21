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

`ask-flowtable health` returns 0 while networking is responsive and 1 on
invalid diagnostics, RTNL not answering within five seconds, or CDX's
transaction held by one holder for five seconds. It checks RTNL even when no
flow exists. Its read of `/proc/cdx_flowtable` waits for the transaction behind
every caller queued for it; still waiting at the deadline while the
transaction changes hands (`/sys/module/cdx/parameters/flowtable_hold_ms`, how
long the current holder has held it, below five seconds), the datapath is busy,
not dead, and the probe passes (A411). A CDX datapath restart after an
unproven deletion is healthy however long it waits: the classifier is bypassed
and the ports forward in software meanwhile (`bypassed 1` in
`/proc/cdx_flowtable`, the wait in
`/sys/module/cdx/parameters/flowtable_degraded_reason`). A blocked kernel
reader cannot prevent the command's parent from reporting.

The monitor resets the platform after three consecutive failed probes; nothing
resets it at once. A slow but live datapath (a probe over its deadline, a
transient diagnostics error) therefore costs no reboot and no recovery attempt
unless it persists for about half a minute. The monitor keeps feeding the
service watchdog meanwhile, since it is itself running; a hung monitor still
lets the watchdog expire.

`recovery-arm` reserves one recovery attempt per kernel boot in the separate
U-Boot variable `ask_recovery` (`count boot-UUID reason`). Return 2 means three unconfirmed boots have already been
allowed; return 1 means the environment or hook failed. Both prevent activation.
Repeated starts in the same boot do not spend another attempt. `recovery-failed`
saves the failure -- and what a datapath restart waited for, if one was under
way -- without acquiring RTNL. An abrupt hard hang retains
the previously stored “armed; detail unavailable” record. Read the reason
before arming the next boot; arming also logs the previous record.

The monitor calls `recovery-clear` after one continuous hour of successful
probes. This is a consecutive-boot limit, independent of RTC time or persistent
root storage. An operator can also clear the budget after repair and restart the
services.

`recovery-clean` refunds the attempt a boot spent when the system shuts down
in order and the datapath still passes `health` -- a reboot or poweroff, not a
plain stop or restart of the service, which refunds and writes nothing. A hang
or a watchdog reset never runs a shutdown, a teardown that wedged on the way
down fails the health check, and a failure recorded after a refund takes the
attempt back. So a box rebooted a few times in its first hour keeps its
offload, while a power loss, which cannot be told from a hang, still counts.

`recovery-retry` turns an exhausted budget into one more attempt. The platform
calls it after a day up in software with the budget spent, so a passing cause
does not keep hardware offload off for good, and a datapath that still hangs
costs at most one reset a day. It does nothing otherwise. The day is uptime: a
box rebooted every night never gets there and needs `recovery-clear`.

Only `recovery-arm` records the boot it ran in, so a start later in a boot
that `retry` or `clear` ran in still spends its attempt -- as does a start
after a refund in the same boot. A sysupgrade stops services without their
stop scripts, so it never refunds: three flashes inside an hour turn offload
off until the retry a day later. The budget carries
over a firmware upgrade unchanged; clearing it on first boot would let an image
that hangs reset the count every time, and the retry already recovers a box
whose new image fixed the cause.

Environment writes happen at arm, failure, refund, retry and confirmation, not
on each probe.

## systemd: Armbian, NixOS, VyOS

These units use PID 1 as the watchdog owner. Merge the manager settings with
the platform's existing watchdog configuration. The supplied paths match Armbian.
NixOS/VyOS packaging should translate paths
and service names to its own service definitions.

1. Install `systemd/ask-watchdog.conf` in `/etc/systemd/system.conf.d/`, the
   four `ask-recovery*.service` files and `ask-recovery-retry.timer` in
   `/etc/systemd/system/`, and enable the timer. The budget unit's `ExecStop`
   is the shutdown refund, gated on `health`.
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
   Its stop at a system shutdown refunds a healthy boot's attempt; with the
   budget exhausted it runs a `retry` instance that calls `recovery-retry`
   after a day up, and it writes `armed`, `exhausted`, `unavailable` or
   `stopped` to `/var/run/ask-recovery.state` for a UI to show.
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

ASK's KASAN test image passed actual hardware resets after a datapath failure
that was then terminal (since A403 none is), a CPU hard-locked holding RTNL,
and a stopped external watchdog feeder. The fourth attempt was refused;
reasons/counts survived TFTP boots and all non-ASK U-Boot variables were
preserved. Host checks exercise the health timeout, budget, and platform hooks;
systemd unit validation uses version 257.

Before enabling these files in a consumer image, test a CPU stuck holding
RTNL, a probe that times out, and three consecutive resets on that image. The OS service
manager, its shutdown path, and firmware watchdog handoff are part of the test.
Configuration validation and ASK initramfs tests do not establish that a
different consumer image's complete recovery path works.
