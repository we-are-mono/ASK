FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Override the stock /etc/fancontrol with our board-specific pwm/temp mappings
# (hwmon3 emc2305 PWM driven by cluster_thermal temp sensor).
SRC_URI += "file://fancontrol"
