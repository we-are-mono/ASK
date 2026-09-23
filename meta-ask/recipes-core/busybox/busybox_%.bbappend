# devmem: read and write device registers and FMAN MURAM (the microcode's
# parameter blocks) on the test image, where there is nothing else to do it.
FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"

SRC_URI += "file://devmem.cfg"
