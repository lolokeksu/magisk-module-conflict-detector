#!/system/bin/sh
# Module Conflict Detector v1.4 installer
SKIPUNZIP=0

MCD_DIR="/data/adb/mcd"
CONFIG_FILE="$MCD_DIR/config.conf"
KNOWN_LEGACY_FILE="$MCD_DIR/known-conflicts.conf"
KNOWN_LOCAL_FILE="$MCD_DIR/known-conflicts.local.conf"

ui_print "********************************"
ui_print "Module Conflict Detector v1.4"
ui_print "    by ExchNow (Lolokeksu)      "
ui_print "********************************"
ui_print "- id: ModuleConflictDetector"
ui_print "- CLI: mcd-ctrl"

mkdir -p "$MCD_DIR" "$MCD_DIR/reports" "$MCD_DIR/snapshots" "$MCD_DIR/tmp"

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" <<'CFG'
auto_scan=1
boot_delay_seconds=30
replace_examples_limit=20
script_scan=1
overlayd_scan=1
sepolicy_scan=1
hash_conflicts=1
known_conflicts=1
trust_module_priority=0
baseline_compare_on_scan=1
CFG
fi

ensure_config_key() {
    key="$1"
    value="$2"
    grep -q "^[[:space:]]*$key=" "$CONFIG_FILE" 2>/dev/null || printf '%s=%s\n' "$key" "$value" >> "$CONFIG_FILE"
}
ensure_config_key auto_scan 1
ensure_config_key boot_delay_seconds 30
ensure_config_key replace_examples_limit 20
ensure_config_key script_scan 1
ensure_config_key overlayd_scan 1
ensure_config_key sepolicy_scan 1
ensure_config_key hash_conflicts 1
ensure_config_key known_conflicts 1
ensure_config_key trust_module_priority 0
ensure_config_key baseline_compare_on_scan 1

rm -f "$MCD_DIR/ui-language.conf" 2>/dev/null
[ -f "$MCD_DIR/whitelist.conf" ] || : > "$MCD_DIR/whitelist.conf"
if [ ! -f "$KNOWN_LOCAL_FILE" ]; then
    if [ -f "$KNOWN_LEGACY_FILE" ]; then
        cp -f "$KNOWN_LEGACY_FILE" "$KNOWN_LOCAL_FILE"
    else
        cat > "$KNOWN_LOCAL_FILE" <<'DB'
# User-maintained known-conflict rules.
# TSV columns:
# rule_id module_a module_b min_a max_a min_b max_b root_family sdk_min sdk_max severity category reason source added
DB
    fi
fi

rm -f "$MCD_DIR/bin/mcd-ctrl" 2>/dev/null
rmdir "$MCD_DIR/bin" 2>/dev/null

[ -f "$MODPATH/bin/mcd-ctrl" ] || abort "! Missing bin/mcd-ctrl"
[ -f "$MODPATH/system/bin/mcd-ctrl" ] || abort "! Missing system/bin/mcd-ctrl"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/mcd-ctrl" 0 0 0755
set_perm "$MODPATH/bin/mcd-menu" 0 0 0755
set_perm "$MODPATH/system/bin/mcd-ctrl" 0 0 0755
set_perm "$MODPATH/bin/mcd-boot-scan" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/boot-completed.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm_recursive "$MCD_DIR" 0 0 0755 0644

ui_print "- Installed successfully"
ui_print "- Menu:     su -c 'mcd-ctrl'"
ui_print "- Quick:    su -c 'mcd-ctrl scan'"
ui_print "- Full:     su -c 'mcd-ctrl scan --deep'"
ui_print "- Report:   su -c 'mcd-ctrl report'"
