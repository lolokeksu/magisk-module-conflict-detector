#!/system/bin/sh
# Module Conflict Detector v1.2 - action.sh
# Magisk/KernelSU/APatch action: run scan and show text report.

MODDIR=${0%/*}
MCD_BIN="$MODDIR/bin/mcd-ctrl"

if [ ! -x "$MCD_BIN" ]; then
    echo "! mcd-ctrl not found or not executable"
    exit 1
fi

"$MCD_BIN" scan
printf '\n--- Report ---\n'
"$MCD_BIN" report
