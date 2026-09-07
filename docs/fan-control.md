# Kernel fan control

The test image uses the built-in `linear` thermal governor to control both
EMC2305 fan channels from the CPU cluster temperature. Both channels have an
unconditional **20% PWM minimum**. They stay at 20% below 40°C and increase
linearly to 100% at 80°C. Thermal and hwmon requests cannot stop either fan
or drive it below 20%.

Both fan nodes remain enabled in the device tree. Only fan 1 is populated on
the current DUT; an absent fan 2 does not affect fan 1. The image includes
the lm-sensors `sensors` command and its library for monitoring. Fancontrol,
its configuration and its startup scripts are not installed.

## Board configuration

The canonical configuration is [`dts/mono-gateway-dk.dts`](../dts/mono-gateway-dk.dts).

| Setting | Value |
| --- | --- |
| Sensor | TMU channel 3, `cluster-thermal` |
| Sampling | Every 1000 ms |
| Minimum duty | PWM 51 (20%) on both channels |
| Curve start | 40°C, map limits 51–255, zero hysteresis |
| Full speed | 80°C, map limits 255–255, zero hysteresis |
| Startup | Controller hardware spin-up |
| CPU throttling | Passive trip at 85°C, 2°C hysteresis |
| Critical shutdown | 95°C |

The fan requires at least 20% duty for stable operation, and the board
requires continuous airflow. There is no fan-stop threshold or on/off
hysteresis.

Between 40°C and 80°C, using millidegrees Celsius:

```text
PWM = 51 + floor((temperature_mC - 40000) * 204 / 40000)
```

| Temperature | PWM | Duty |
| --- | --- | --- |
| At or below 40°C | 51 | 20% |
| 50°C | 102 | 40% |
| 60°C | 153 | 60% |
| 70°C | 204 | 80% |
| At or above 80°C | 255 | 100% |

These are PWM duty values, not RPM targets. The fan's RPM response need not
be linear in PWM.

Each active cooling map interpolates to the next higher active trip bound
to the same cooling device in the same zone. A terminal map requests its
upper limit. Thermal core combines requests from all maps and zones by
selecting the maximum. Passive CPU cooling uses the step-wise algorithm;
critical handling remains in thermal core.

## Driver and bindings

The kernel patch series contains:

- `120-emc2305-dt-fan-control.patch`: DT fan registration, PWM requests on the
  0–255 scale, an unconditional per-channel duty floor, serialized
  thermal/hwmon access, tachometer handling and driver tests.
- `130-thermal-linear-governor.patch`: the linear thermal governor and tests.

The driver changes and governor are local implementations. The EMC2305
schema uses the upstream binding plus the local per-fan property
`microchip,pwm-min`. It specifies the minimum drive on the 0–255 scale,
including for zero requests, and is set to 51 on both board fan nodes.
Thermal trips and cooling maps use existing thermal DT properties;
interpolation is implemented by the local governor.

The EMC2305 `pwms` tuple specifies frequency in Hz, polarity and output type.
The board uses 26000 Hz, inverted polarity and push-pull output. Probe selects
direct PWM mode and the approximately 500 RPM tachometer range. It preserves
boot duty above the board floor and raises lower boot duty before exposing
the control interfaces. The controller's minimum-drive register only applies
to RPM mode, so direct PWM requests are clamped in the driver.

The effective drive is the maximum of the board floor, manual hwmon minimum
and thermal demand. Startup is handled by the controller's hardware spin-up
routine, which is preserved and may temporarily drive above the software
request. The driver applies each request synchronously under its mutex.

| DT node | Cooling device type | hwmon duty | Tachometer |
| --- | --- | --- | --- |
| `fan0` / `fan@0` | `emc2305_fan1` | `pwm1` | `fan1_input` |
| `fan1` / `fan@1` | `emc2305_fan2` | `pwm2` | `fan2_input` |

Writing zero to a hwmon PWM attribute clears the additional manual minimum;
it leaves the board floor in force. Requests from 1 through 50 are also
clamped to 51. Direct cooling-device writes obey the floor and are replaced
by thermal demand on the next governor update. `cur_state` reports cached
software drive; the hwmon PWM attribute reads the hardware drive register.

The governor reapplies demand each sample to retry transient I2C errors.
Sensor errors retain the last demand and use thermal core's retry behavior.
The driver does not implement RPM feedback, continuous stall monitoring or
an independent sensor watchdog. The floor prevents software-commanded stops
while the driver controls the powered fan.

## Build and stage

```sh
cd meta-ask
kas build .config.yaml
cd ..
make stage-image
```

Load both staged artifacts using the board's TFTP/booti procedure:

- `/srv/tftp/Image-ask-test.gz`, also hard-linked as
  `Image.gz-initramfs-ask-ls1046a.bin`.
- `/srv/tftp/mono-gateway-dk.dtb`.

The kernel and matching DTB are both required for the floor and curve. Keep
the kernel, decompression buffer and DTB at separate RAM addresses.

The base configs select `CONFIG_THERMAL_DEFAULT_GOV_LINEAR=y`. The Yocto test
config also enables thermal emulation for verification. KUnit and the
`user_space` governor are not enabled in the DUT image.

## Verification

Run KUnit in a Linux 6.12.103 tree with patches 120 and 130 applied:

```sh
cat > /tmp/fan.kunitconfig <<'EOF'
CONFIG_KUNIT=y
CONFIG_I2C=y
CONFIG_HWMON=y
CONFIG_THERMAL=y
CONFIG_SENSORS_EMC2305=y
CONFIG_SENSORS_EMC2305_KUNIT_TEST=y
CONFIG_THERMAL_DEFAULT_GOV_LINEAR=y
CONFIG_THERMAL_GOV_LINEAR_KUNIT_TEST=y
EOF
python3 tools/testing/kunit/kunit.py run --kunitconfig=/tmp/fan.kunitconfig
```

The tests exercise the actual driver callbacks with a simulated SMBus adapter
and the governor with registered thermal zones and cooling devices. They
cover PWM resolution, independent floors, boot takeover, error
handling, interpolation, hysteresis, passive cooling, critical callbacks and
shared-device arbitration. Floor tests inspect every drive write, including
when thermal or manual requests are zero.

On the DUT, discover devices by name rather than relying on sysfs numbering:

```sh
for d in /sys/class/thermal/thermal_zone*; do
    [ "$(cat "$d/type")" = cluster-thermal ] && fan_zone=$d
done
for d in /sys/class/hwmon/hwmon*; do
    [ "$(cat "$d/name")" = emc2305 ] && fan_hwmon=$d
done
cat "$fan_zone/policy"             # linear
cat "$fan_zone/temp"
cat "$fan_hwmon/pwm1" "$fan_hwmon/fan1_input"
cat "$fan_hwmon/pwm2" "$fan_hwmon/fan2_input"
sensors
```

Confirm both fan nodes declare `microchip,pwm-min = <51>`, both cooling
devices report `max_state=255`, and both fans bind to the 40/80°C active trips.
Verify that the 85°C passive and 95°C critical trips are present.

With the correct kernel and DTB confirmed, use brief thermal-emulation checks
at 20/37/39/40°C (PWM 51), 50/60/70°C (102/153/204), and 80°C (255), then cool
back below 40°C. Both channels must remain at least 51 and fan 1 must keep
rotating. Check the actual sensor temperature separately, allow RPM to settle,
and always restore `emul_temp` to zero in a shell trap or `finally` block.
Do not emulate the critical shutdown temperature during a fan-curve test.
