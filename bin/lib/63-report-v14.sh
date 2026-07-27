write_json_report() {
    scan_time="$1"; module_count="$2"; entry_count="$3"; replace_count="$4"; prop_count="$5"; script_count="$6"
    findings=$(awk 'BEGIN{first=1}{if(!first)printf ",";printf "%s",$0;first=0}' "$JSON_ITEMS_FILE" 2>/dev/null)
    android=$(device_value ro.build.version.release unknown); sdk=$(device_value ro.build.version.sdk unknown)
    abi=$(device_value ro.product.cpu.abi unknown); model=$(device_value ro.product.model unknown)
    fingerprint=$(device_value ro.build.fingerprint unknown); kernel=$(uname -r 2>/dev/null); [ -n "$kernel" ] || kernel=unknown
    selinux=$(getenforce 2>/dev/null); [ -n "$selinux" ] || selinux=unknown
    detect_root_manager_info; manager="$ROOT_MANAGER"
    now=$(date +%s 2>/dev/null); case "$now" in ''|*[!0-9]*) now=0 ;; esac
    case "$SCAN_STARTED_EPOCH" in ''|*[!0-9]*) SCAN_STARTED_EPOCH=0 ;; esac
    if [ "$SCAN_STARTED_EPOCH" -gt 0 ] && [ "$now" -ge "$SCAN_STARTED_EPOCH" ]; then duration=$((now-SCAN_STARTED_EPOCH)); else duration=0; fi
    modules_json=$(module_states_json)

    cat > "$JSON_FILE" <<EOFJSON
{
  "tool": "Module Conflict Detector",
  "version": "$VERSION",
  "version_code": $VERSION_CODE,
  "schema_version": 2,
  "scan_time": "$(json_escape "$scan_time")",
  "scan_duration_seconds": $duration,
  "boot_scan": $([ "$BOOT_MODE" = "1" ] && echo true || echo false),
  "deep_scan": $([ "$DEEP_MODE" = "1" ] && echo true || echo false),
  "device": {
    "model": "$(json_escape "$model")",
    "android": "$(json_escape "$android")",
    "sdk": "$(json_escape "$sdk")",
    "abi": "$(json_escape "$abi")",
    "kernel": "$(json_escape "$kernel")",
    "selinux": "$(json_escape "$selinux")",
    "root_manager": "$(json_escape "$manager")",
    "root_manager_family": "$(json_escape "$ROOT_MANAGER_FAMILY")",
    "root_detection_method": "$(json_escape "$ROOT_DETECTION_METHOD")",
    "root_detection_confidence": "$(json_escape "$ROOT_DETECTION_CONFIDENCE")",
    "root_detection_evidence": "$(json_escape "$ROOT_DETECTION_EVIDENCE")",
    "build_fingerprint": "$(json_escape "$fingerprint")"
  },
  "summary": {
    "modules_scanned": $module_count,
    "modules_total": $(wc -l < "$MODULE_STATE_FILE" 2>/dev/null | tr -d ' '),
    "mounted_entries_scanned": $entry_count,
    "replace_dirs_scanned": $replace_count,
    "property_definitions_scanned": $prop_count,
    "script_events_scanned": $script_count,
    "findings_count": $(count_get "$COUNT_FINDINGS_FILE"),
    "conflicts_count": $(count_get "$COUNT_CONFLICTS_FILE"),
    "confirmed": $(count_get "$COUNT_CONFIRMED_FILE"),
    "probable": $(count_get "$COUNT_PROBABLE_FILE"),
    "possible": $(count_get "$COUNT_POSSIBLE_FILE"),
    "informational": $(count_get "$COUNT_INFORMATIONAL_FILE"),
    "critical": $(count_get "$COUNT_CRITICAL_FILE"),
    "high": $(count_get "$COUNT_HIGH_FILE"),
    "medium": $(count_get "$COUNT_MEDIUM_FILE"),
    "low": $(count_get "$COUNT_LOW_FILE"),
    "info": $(count_get "$COUNT_INFO_FILE")
  },
  "modules": [$modules_json],
  "findings": [$findings]
}
EOFJSON
    cp -f "$JSON_FILE" "$REPORTS_DIR/report-latest.json" 2>/dev/null
    cp -f "$LOG_FILE" "$REPORTS_DIR/conflicts-latest.log" 2>/dev/null
    cp -f "$FINDING_INDEX_FILE" "$CURRENT_INDEX_FILE" 2>/dev/null
    stamp=$(date '+%Y%m%d-%H%M%S' 2>/dev/null); [ -n "$stamp" ] || stamp="scan-$now"
    [ -e "$HISTORY_DIR/$stamp.json" ] && stamp="$stamp-$$"
    cp -f "$JSON_FILE" "$HISTORY_DIR/$stamp.json" 2>/dev/null
    cp -f "$LOG_FILE" "$HISTORY_DIR/$stamp.log" 2>/dev/null
    cp -f "$FINDING_INDEX_FILE" "$HISTORY_DIR/$stamp.tsv" 2>/dev/null
    prune_history
}

report_critical_only() {
    [ -s "$LOG_FILE" ] || { echo "- No text report. Run: mcd-ctrl scan"; return; }
    out=$(awk '/^\[CRITICAL\]/{show=1}/^\[[A-Z]+\]/&&!/^\[CRITICAL\]/{show=0}show{print}' "$LOG_FILE")
    [ -n "$out" ] && printf '%s\n' "$out" || echo "- No critical conflicts"
}

filter_report() {
    mode="$1"; value="$2"
    [ -s "$LOG_FILE" ] || { echo "- No text report. Run: mcd-ctrl scan"; return; }
    awk -v mode="$mode" -v value="$value" '
        /^\[[A-Z]+\]/ {
            show=0
            if(mode=="severity" && index($0,"[" value "]")==1)show=1
            if(mode=="id" && index($0,"[" value "]")>0)show=1
            block=$0 "\n"; next
        }
        {block=block $0 "\n"; if(mode=="module" && $0 ~ /^    modules:/ && index(" " $0 " "," " value " ")>0)show=1}
        /^$/ {if(show)printf "%s",block; block=""; show=0}
        END{if(show)printf "%s",block}
    ' "$LOG_FILE"
}

