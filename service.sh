#!/system/bin/sh
# Magisk-compatible late_start fallback. Do not background this process:
# some root managers terminate child jobs when the lifecycle script exits.
MODDIR=${0%/*}
BOOT_HELPER="$MODDIR/bin/mcd-boot-scan"
[ -x "$BOOT_HELPER" ] || exit 127
exec "$BOOT_HELPER" service
