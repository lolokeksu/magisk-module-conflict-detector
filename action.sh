#!/system/bin/sh
MODDIR=${0%/*}
MENU="$MODDIR/bin/mcd-menu"
[ -x "$MENU" ] || { echo "! mcd-menu not found"; exit 1; }
exec sh "$MENU"
