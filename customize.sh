#!/system/bin/sh
# Module Conflict Detector v1.4 installer
SKIPUNZIP=0

MCD_DIR="/data/adb/mcd"
CONFIG_FILE="$MCD_DIR/config.conf"
KNOWN_FILE="$MCD_DIR/known-conflicts.conf"

ui_print "********************************"
ui_print " Module Conflict Detector v1.4 "
ui_print "    by ExchNow (Lolokeksu)      "
ui_print "********************************"
ui_print "- id: ModuleConflictDetector"
ui_print "- CLI: mcd-ctrl"
ui_print "- Menu: su -c 'mcd-ctrl'"

mkdir -p "$MCD_DIR" "$MCD_DIR/reports/history" "$MCD_DIR/snapshots" "$MCD_DIR/tmp" "$MCD_DIR/cache"

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" <<'CFG'
auto_scan=1
boot_delay_seconds=30
replace_examples_limit=20
script_scan=1
overlayd_scan=1
hash_conflicts=1
known_conflicts=1
hash_cache=1
report_history_limit=10
language=ru
interactive=1
CFG
else
    ensure_key() {
        grep -q "^$1=" "$CONFIG_FILE" 2>/dev/null || printf '%s=%s\n' "$1" "$2" >> "$CONFIG_FILE"
    }
    ensure_key hash_cache 1
    ensure_key report_history_limit 10
    ensure_key language ru
    ensure_key interactive 1
fi

[ -f "$MCD_DIR/whitelist.conf" ] || : > "$MCD_DIR/whitelist.conf"
[ -f "$MCD_DIR/cache/hashes.tsv" ] || : > "$MCD_DIR/cache/hashes.tsv"
if [ ! -f "$KNOWN_FILE" ] && [ -f "$MODPATH/config/known-conflicts.conf" ]; then
    cp -f "$MODPATH/config/known-conflicts.conf" "$KNOWN_FILE"
fi

rm -f "$MCD_DIR/bin/mcd-ctrl" 2>/dev/null
rmdir "$MCD_DIR/bin" 2>/dev/null

[ -f "$MODPATH/bin/mcd-ctrl" ] || abort "! Missing bin/mcd-ctrl"
[ -f "$MODPATH/bin/lib/60-runtime-v14.sh" ] || abort "! Missing bin/lib/60-runtime-v14.sh"
[ -f "$MODPATH/bin/lib/65-menu-v14.sh" ] || abort "! Missing bin/lib/65-menu-v14.sh"
[ -f "$MODPATH/system/bin/mcd-ctrl" ] || abort "! Missing system/bin/mcd-ctrl"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/mcd-ctrl" 0 0 0755
set_perm "$MODPATH/system/bin/mcd-ctrl" 0 0 0755
set_perm "$MODPATH/bin/mcd-boot-scan" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/boot-completed.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm_recursive "$MCD_DIR" 0 0 0755 0644

ui_print "- Installed successfully"
ui_print "- Interactive: su -c 'mcd-ctrl'"
ui_print "- Deep scan:   su -c 'mcd-ctrl scan --deep'"
ui_print "- Report:      su -c 'mcd-ctrl report'"
