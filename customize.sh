#!/system/bin/sh
# Module Conflict Detector v1.2 - customize.sh

SKIPUNZIP=0

MCD_DIR="/data/adb/mcd"
CONFIG_FILE="$MCD_DIR/config.conf"

ui_print "*******************************"
ui_print " Module Conflict Detector v1.2 "
ui_print "    by ExchNow (Lolokeksu)     "
ui_print "*******************************"
ui_print "- Keeping public id/name for GitHub/4PDA compatibility"
ui_print "- id: ModuleConflictDetector"
ui_print "- CLI: mcd-ctrl"

mkdir -p "$MCD_DIR" "$MCD_DIR/reports" "$MCD_DIR/tmp"

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" <<'CFG'
# Module Conflict Detector config
# 1 = scan after boot, 0 = manual scan only
auto_scan=1

# Delay after sys.boot_completed=1 before automatic scan
boot_delay_seconds=30

# Maximum path examples saved for one .replace masking conflict
replace_examples_limit=20
CFG
fi

# Remove legacy external binary from v1.0/v1.1 layout.
# v1.2 keeps CLI inside the module directory and only stores reports/config in /data/adb/mcd.
rm -f "$MCD_DIR/bin/mcd-ctrl" 2>/dev/null
rmdir "$MCD_DIR/bin" 2>/dev/null

mkdir -p "$MODPATH/bin" "$MODPATH/system/bin"

if [ ! -f "$MODPATH/bin/mcd-ctrl" ]; then
    abort "! Missing $MODPATH/bin/mcd-ctrl"
fi

if [ ! -f "$MODPATH/system/bin/mcd-ctrl" ]; then
    cat > "$MODPATH/system/bin/mcd-ctrl" <<'WRAP'
#!/system/bin/sh
exec /data/adb/modules/ModuleConflictDetector/bin/mcd-ctrl "$@"
WRAP
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/mcd-ctrl" 0 0 0755
set_perm "$MODPATH/system/bin/mcd-ctrl" 0 0 0755
[ -f "$MODPATH/service.sh" ] && set_perm "$MODPATH/service.sh" 0 0 0755
[ -f "$MODPATH/action.sh" ] && set_perm "$MODPATH/action.sh" 0 0 0755
[ -f "$MODPATH/uninstall.sh" ] && set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm_recursive "$MCD_DIR" 0 0 0755 0644

ui_print "- Installed"
ui_print "- Manual scan: mcd-ctrl scan"
ui_print "- Report:      mcd-ctrl report"
ui_print "- JSON:        mcd-ctrl report --json"
ui_print "- Doctor:      mcd-ctrl doctor"
