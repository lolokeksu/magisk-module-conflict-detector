#!/system/bin/sh
# Module Conflict Detector v1.3
# Read-only conflict analysis for Magisk / KernelSU / APatch modules.

VERSION="v1.3"
VERSION_CODE="130"
SELF_ID="ModuleConflictDetector"

MCD_DIR="${MCD_DIR:-/data/adb/mcd}"
MODULES_DIR="${MCD_MODULES_DIR:-/data/adb/modules}"
GLOBAL_OVERLAYD_DIR="${MCD_OVERLAYD_DIR:-/data/adb/overlay.d}"
ROOT_DATA_ADB="${MCD_ROOT_DATA_ADB:-/data/adb}"
PROC_ROOT="${MCD_PROC_ROOT:-/proc}"
LIVE_ROOT="${MCD_LIVE_ROOT:-}"
REPORTS_DIR="$MCD_DIR/reports"
SNAPSHOTS_DIR="$MCD_DIR/snapshots"
TMP_DIR="$MCD_DIR/tmp"
CONFIG_FILE="$MCD_DIR/config.conf"
WHITELIST_FILE="$MCD_DIR/whitelist.conf"
KNOWN_FILE="$MCD_DIR/known-conflicts.conf"
LOG_FILE="$MCD_DIR/conflicts.log"
JSON_FILE="$MCD_DIR/report.json"
LOCK_DIR="$MCD_DIR/.scan.lock"
BOOT_STATUS_FILE="$MCD_DIR/boot-scan.status"
BOOT_LOG_FILE="$MCD_DIR/boot-scan.log"
LAST_BOOT_ID_FILE="$MCD_DIR/last-boot-scan.id"

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

MOUNT_ROOTS="vendor product system_ext odm system_dlkm vendor_dlkm odm_dlkm"
QUIET=0
BOOT_MODE=0
DEEP_MODE=0
CRITICAL_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --quiet) QUIET=1 ;;
        --boot) BOOT_MODE=1 ;;
        --deep) DEEP_MODE=1 ;;
        --critical-only) CRITICAL_ONLY=1 ;;
    esac
done

msg() {
    [ "$QUIET" = "0" ] && printf '%s\n' "$*"
}

write_default_config() {
    cat > "$CONFIG_FILE" <<'CFG'
# Module Conflict Detector v1.3 configuration
# 1 = scan after boot, 0 = manual scan only
auto_scan=1

# Delay after sys.boot_completed=1 before automatic scan
boot_delay_seconds=30

# Maximum file examples in one .replace masking finding
replace_examples_limit=20

# Analyze service.sh, post-fs-data.sh, boot-completed.sh and action.sh
script_scan=1

# Analyze module-local overlay.d and inventory global /data/adb/overlay.d
overlayd_scan=1

# Hash candidates only when the same target is claimed by multiple modules
hash_conflicts=1

# Check exact module pairs listed in known-conflicts.conf
known_conflicts=1
CFG
}

write_default_known_db() {
    cat > "$KNOWN_FILE" <<'DB'
# Exact known-conflict database.
# Format:
# module_id_a|module_id_b|SEVERITY|reason
#
# Keep entries evidence-based. Examples are intentionally commented out:
# ModuleA|ModuleB|HIGH|Both modules manage the same subsystem.
DB
}

ensure_dirs() {
    mkdir -p "$MCD_DIR" "$REPORTS_DIR" "$SNAPSHOTS_DIR" "$TMP_DIR" 2>/dev/null
    [ -f "$CONFIG_FILE" ] || write_default_config
    [ -f "$WHITELIST_FILE" ] || : > "$WHITELIST_FILE"
    [ -f "$KNOWN_FILE" ] || write_default_known_db
}

get_config() {
    key="$1"
    def="$2"
    val=""
    if [ -f "$CONFIG_FILE" ]; then
        val=$(grep -E "^[[:space:]]*$key=" "$CONFIG_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)
    fi
    [ -n "$val" ] && printf '%s' "$val" || printf '%s' "$def"
}

is_enabled() {
    [ "$(get_config "$1" "$2")" = "1" ]
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'

}

owners_to_json() {
    list="$1"
    out=""
    for owner in $list; do
        esc=$(json_escape "$owner")
        if [ -n "$out" ]; then
            out="$out,\"$esc\""
        else
            out="\"$esc\""
        fi
    done
    printf '%s' "$out"
}

count_init() {
    for f in "$COUNT_FINDINGS_FILE" "$COUNT_CONFLICTS_FILE" "$COUNT_CRITICAL_FILE" \
             "$COUNT_HIGH_FILE" "$COUNT_MEDIUM_FILE" "$COUNT_LOW_FILE" "$COUNT_INFO_FILE"; do
        echo 0 > "$f"
    done
}

count_inc() {
    f="$1"
    n=$(cat "$f" 2>/dev/null)
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    echo $((n + 1)) > "$f"
}

count_get() {
    n=$(cat "$1" 2>/dev/null)
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    printf '%s' "$n"
}

severity_of_path() {
    case "$1" in
        /overlay.d/*|*/etc/init/*|*/etc/permissions/*|*/etc/sysconfig/*|*/etc/vintf/*|*sepolicy*|*/bin/*|*/xbin/*|*/apex/*)
            echo "CRITICAL" ;;
        */framework/*|*/priv-app/*|*/app/*|*/overlay/*|*/lib64/*|*/lib/*|*/build.prop|*/default.prop|*/system.prop)
            echo "HIGH" ;;
        */etc/*|*/fonts/*|*/media/*|*/usr/*)
            echo "MEDIUM" ;;
        *)
            echo "LOW" ;;
    esac
}

severity_of_prop() {
    case "$1" in
        ro.*|persist.*|sys.*|debug.*|dalvik.*|vendor.*|ctl.*)
            echo "HIGH" ;;
        *)
            echo "MEDIUM" ;;
    esac
}

severity_of_resource() {
    resource="$1"
    case "$resource" in
        sepolicy:*|mount:/system*|mount:/vendor*|mount:/product*|mount:/system_ext*|mount:/odm*|fileop:/system/bin/*|fileop:/system/xbin/*)
            echo "CRITICAL" ;;
        prop:*) severity_of_prop "${resource#prop:}" ;;
        sysfs:*thermal*|sysfs:*cpufreq*|sysfs:*gpu*|sysfs:*kgsl*|sysfs:*devfreq*|sysctl:*|device_config:*|setting:*)
            echo "HIGH" ;;
        mount:*|fileop:*|perm:*)
            echo "MEDIUM" ;;
        *)
            echo "LOW" ;;
    esac
}

in_whitelist() {
    needle="$1"
    [ -f "$WHITELIST_FILE" ] || return 1
    while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        [ "$line" = "$needle" ] && return 0
    done < "$WHITELIST_FILE"
    return 1
}

cleanup_scan_temp() {
    rm -f "$MODULE_FILE" "$ENTRY_FILE" "$REPLACE_FILE" "$PROP_FILE" "$SCRIPT_FILE" \
        "$PATH_GROUP_FILE" "$REPLACE_GROUP_FILE" "$REPLACE_MASK_FILE" \
        "$PROP_GROUP_FILE" "$SCRIPT_GROUP_FILE" "$JSON_ITEMS_FILE" \
        "$COUNT_FINDINGS_FILE" "$COUNT_CONFLICTS_FILE" "$COUNT_CRITICAL_FILE" \
        "$COUNT_HIGH_FILE" "$COUNT_MEDIUM_FILE" "$COUNT_LOW_FILE" "$COUNT_INFO_FILE" \
        "$TMP_DIR"/*.work "$TMP_DIR"/*.sorted "$TMP_DIR"/*.candidate "$TMP_DIR"/*.manifest 2>/dev/null
}

release_lock() {
    rm -f "$LOCK_DIR/pid" 2>/dev/null
    rmdir "$LOCK_DIR" 2>/dev/null
}

scan_exit_cleanup() {
    cleanup_scan_temp
    release_lock
}

acquire_scan_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo "$$" > "$LOCK_DIR/pid"
    else
        oldpid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
        stale=0
        case "$oldpid" in ''|*[!0-9]*) stale=1 ;; *) kill -0 "$oldpid" 2>/dev/null || stale=1 ;; esac
        if [ "$stale" = "1" ]; then
            rm -rf "$LOCK_DIR" 2>/dev/null
            mkdir "$LOCK_DIR" 2>/dev/null || { msg "! Cannot create scan lock: $LOCK_DIR"; exit 2; }
            echo "$$" > "$LOCK_DIR/pid"
        else
            msg "! Scan already running (pid=$oldpid)"
            exit 2
        fi
    fi
    trap 'scan_exit_cleanup' EXIT HUP INT TERM
}

# Root-manager detection deliberately separates strong runtime evidence from
# weak on-disk leftovers. Magisk-compatible module managers share /data/adb,
# so directories alone must never override an active su/daemon/core binary.
ROOT_DETECTION_DONE=0
ROOT_MANAGER="unknown"
ROOT_MANAGER_FAMILY="unknown"
ROOT_DETECTION_METHOD="none"
ROOT_DETECTION_CONFIDENCE="low"
ROOT_DETECTION_EVIDENCE="no manager-specific runtime evidence"

