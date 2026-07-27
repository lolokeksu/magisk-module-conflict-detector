#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
export MCD_DIR="$ROOT/mcd"
export MCD_MODULES_DIR="$ROOT/modules"
export MCD_ROOT_DATA_ADB="$ROOT/data/adb"
export MCD_PROC_ROOT="$ROOT/proc"
export MCD_LIVE_ROOT="$ROOT/live"
mkdir -p "$MCD_DIR" "$MCD_MODULES_DIR" "$MCD_ROOT_DATA_ADB/modules_update" "$MCD_PROC_ROOT/self" "$MCD_LIVE_ROOT/system/etc"

cat > "$ROOT/stub.sh" <<'STUB'
#!/bin/sh
MCD_DIR="${MCD_DIR}"
MODULES_DIR="${MCD_MODULES_DIR}"
ROOT_DATA_ADB="${MCD_ROOT_DATA_ADB}"
PROC_ROOT="${MCD_PROC_ROOT}"
LIVE_ROOT="${MCD_LIVE_ROOT}"
REPORTS_DIR="$MCD_DIR/reports"
SNAPSHOTS_DIR="$MCD_DIR/snapshots"
TMP_DIR="$MCD_DIR/tmp"
CONFIG_FILE="$MCD_DIR/config.conf"
WHITELIST_FILE="$MCD_DIR/whitelist.conf"
KNOWN_FILE="$MCD_DIR/known-conflicts.conf"
LOG_FILE="$MCD_DIR/conflicts.log"
JSON_FILE="$MCD_DIR/report.json"
BOOT_LOG_FILE="$MCD_DIR/boot-scan.log"
MODULE_FILE="$TMP_DIR/modules.tsv"
ENTRY_FILE="$TMP_DIR/entries.tsv"
REPLACE_FILE="$TMP_DIR/replace.tsv"
PROP_FILE="$TMP_DIR/properties.tsv"
SCRIPT_FILE="$TMP_DIR/script-events.tsv"
PATH_GROUP_FILE="$TMP_DIR/path-groups.tsv"
REPLACE_GROUP_FILE="$TMP_DIR/replace-groups.tsv"
REPLACE_MASK_FILE="$TMP_DIR/replace-masks.tsv"
PROP_GROUP_FILE="$TMP_DIR/property-groups.tsv"
SCRIPT_GROUP_FILE="$TMP_DIR/script-groups.tsv"
JSON_ITEMS_FILE="$TMP_DIR/findings.jsonl"
COUNT_FINDINGS_FILE="$TMP_DIR/count.findings"
COUNT_CONFLICTS_FILE="$TMP_DIR/count.conflicts"
COUNT_CRITICAL_FILE="$TMP_DIR/count.critical"
COUNT_HIGH_FILE="$TMP_DIR/count.high"
COUNT_MEDIUM_FILE="$TMP_DIR/count.medium"
COUNT_LOW_FILE="$TMP_DIR/count.low"
COUNT_INFO_FILE="$TMP_DIR/count.info"
QUIET=0; BOOT_MODE=0; DEEP_MODE=1; CRITICAL_ONLY=0
msg(){ printf '%s\n' "$*"; }
get_config(){ key=$1; def=$2; val=$(grep "^$key=" "$CONFIG_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true); [ -n "$val" ] && printf '%s' "$val" || printf '%s' "$def"; }
write_default_known_db(){ : > "$KNOWN_FILE"; }
module_prop_value(){ sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -n1; }
json_escape(){ printf '%s' "$1" | sed 's/\\/\\\\/g;s/"/\\"/g'; }
owners_to_json(){ out=""; for x in $1; do [ -n "$out" ] && out="$out,\"$x\"" || out="\"$x\""; done; printf '%s' "$out"; }
count_inc(){ n=$(cat "$1" 2>/dev/null || echo 0); echo $((n+1)) > "$1"; }
count_get(){ cat "$1" 2>/dev/null || echo 0; }
fingerprint_live(){ fingerprint_source file "$LIVE_ROOT$1"; }
device_value(){ printf '%s' "$2"; }
detect_root_manager_info(){ ROOT_MANAGER=APatch; ROOT_MANAGER_FAMILY=APatch; ROOT_DETECTION_METHOD=su_version; ROOT_DETECTION_CONFIDENCE=high; ROOT_DETECTION_EVIDENCE=test; }
do_snapshot(){ :; }
do_whitelist(){ :; }
do_config(){ sed '/^#/d;/^$/d' "$CONFIG_FILE"; }
do_doctor(){ echo doctor=OK; }
do_boot_status(){ echo boot_scan_status=success; }
do_clear(){ :; }
do_scan(){ :; }
getenforce(){ echo Enforcing; }
STUB

. "$ROOT/stub.sh"
for lib in 60-runtime-v14.sh 61-evidence-v14.sh 62-parser-v14.sh 63-report-v14.sh 64-commands-v14.sh 65-menu-v14.sh; do
    . "$REPO_ROOT/bin/lib/$lib"
done
ensure_dirs

mkdir -p "$MODULES_DIR/a/system/etc" "$MODULES_DIR/b/system/etc" "$MODULES_DIR/off"
printf 'name=A\nversion=1\n' > "$MODULES_DIR/a/module.prop"
printf 'name=B\nversion=2\n' > "$MODULES_DIR/b/module.prop"
printf 'name=Off\nversion=1\n' > "$MODULES_DIR/off/module.prop"
: > "$MODULES_DIR/off/disable"
printf 'A' > "$MODULES_DIR/a/system/etc/test.conf"
printf 'B' > "$MODULES_DIR/b/system/etc/test.conf"
printf 'B' > "$LIVE_ROOT/system/etc/test.conf"
printf '1 1 0:1 / /system/etc/test.conf rw - bind /data/adb/modules/b/system/etc/test.conf rw\n' > "$PROC_ROOT/self/mountinfo"

mkdir -p "$TMP_DIR"
count_init
: > "$LOG_FILE"
: > "$JSON_ITEMS_FILE"
printf '/system/etc/test.conf\ta\tfile\t%s\n' "$MODULES_DIR/a/system/etc/test.conf" > "$ENTRY_FILE"
printf '/system/etc/test.conf\tb\tfile\t%s\n' "$MODULES_DIR/b/system/etc/test.conf" >> "$ENTRY_FILE"
analyze_path_candidates /system/etc/test.conf 'a b'
[ "$WINNER" = b ]
[ "$WINNER_METHOD" = mount_source_match ]
[ "$WINNER_CONF" = 100 ]
add_finding path_content_conflict /system/etc/test.conf MEDIUM 'a b' "$WINNER" "$WINNER_CONF" "$WINNER_METHOD" different '[]' 1
SCAN_STARTED_EPOCH=$(date +%s)
write_json_report 2026-07-22T00:00:00+0000 2 2 0 0 0
python -m json.tool "$JSON_FILE" >/dev/null
grep -q '"version": "v1.4"' "$JSON_FILE"
grep -q '"status":"CONFIRMED"' "$JSON_FILE"
grep -q '"winner_method":"mount_source_match"' "$JSON_FILE"
grep -q '"state":"disabled"' "$JSON_FILE"
ID=$(cut -f1 "$CURRENT_INDEX_FILE")
[ -n "$ID" ]
explain_out=$(do_explain explain "$ID"); grep -q 'Применён: b' <<EOFEXPLAIN
$explain_out
EOFEXPLAIN
summary_out=$(do_summary); grep -q 'Подтверждённых: 1' <<EOFSUMMARY
$summary_out
EOFSUMMARY
cache_out=$(do_cache cache status); grep -q 'hash_cache_entries=' <<EOFCACHE
$cache_out
EOFCACHE
help_ru=$(show_help); grep -q 'Интерактивное меню' <<EOFHELP
$help_ru
EOFHELP
set_config_value language en >/dev/null
help_en=$(show_help); grep -q 'Interactive menu' <<EOFHELP
$help_en
EOFHELP
printf '0\n' | do_interactive >/dev/null
printf 'v14-layer-tests=OK\n'
