# The test agent's USB serial port (recipes-ask/config S04usb-agent) gets a
# root login without a getty. The harness is its only user, and a USB serial
# port hangs up whenever its host closes it: a getty respawning under a typed
# username splits the login between two processes. `login -f` skips the
# username and password but still sets up the session as a login does --
# HOME, and with it the profile's sbin PATH -- and init respawns it.
do_install:append() {
    echo "ttyGS0::respawn:/bin/login -f root" >> ${D}${sysconfdir}/inittab
}
