# Enable zstd in kmod (and kmod-native) so depmod can index zstd-compressed
# modules — our kernel builds .ko.zst (CONFIG_MODULE_COMPRESS_ZSTD=y) and
# OE-core's default PACKAGECONFIG omits zstd, which silently skips every
# compressed module when depmodwrapper runs at do_rootfs.
PACKAGECONFIG:append = " zstd"
