#!/system/bin/sh
MODDIR=${0%/*}
MCD_BIN="$MODDIR/bin/mcd-ctrl"
[ -x "$MCD_BIN" ] || { echo "! mcd-ctrl not found"; exit 1; }
"$MCD_BIN" scan --deep
printf '\n--- Critical findings ---\n'
"$MCD_BIN" report --critical-only
printf '\nFull report: /data/adb/mcd/conflicts.log\n'
