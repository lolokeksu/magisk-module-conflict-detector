#!/system/bin/sh
# Native post-boot lifecycle hook for KernelSU-family and APatch.
MODDIR=${0%/*}
BOOT_HELPER="$MODDIR/bin/mcd-boot-scan"
[ -x "$BOOT_HELPER" ] || exit 127
exec "$BOOT_HELPER" boot-completed
