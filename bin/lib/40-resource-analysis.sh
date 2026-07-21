build_prop_groups() {
    : > "$PROP_GROUP_FILE"
    [ -s "$PROP_FILE" ] || return
    awk -F '\t' 'BEGIN{OFS="\t"}
        function flush(){if(key!=""&&count>1)print key,owners}
        {
            if(NR==1||$1!=key){flush();key=$1;owners=$2;seen=" "$2" ";count=1}
            else if(index(seen," "$2" ")==0){owners=owners" "$2;seen=seen$2" ";count++}
        }
        END{flush()}
    ' "$PROP_FILE" > "$PROP_GROUP_FILE"
}

analyze_property_candidates() {
    key="$1"
    owners="$2"
    candidate="$TMP_DIR/prop.candidate"
    awk -F '\t' -v k="$key" '$1==k {print}' "$PROP_FILE" > "$candidate"
    values="$TMP_DIR/prop.values.work"
    : > "$values"
    evidence=""
    while IFS="$(printf '\t')" read -r pkey module value source; do
        printf '%s\t%s\n' "$module" "$value" >> "$values"
        jm=$(json_escape "$module"); jv=$(json_escape "$value"); js=$(json_escape "$source")
        item="{\"module\":\"$jm\",\"value\":\"$jv\",\"source\":\"$js\"}"
        [ -n "$evidence" ] && evidence="$evidence,$item" || evidence="$item"
    done < "$candidate"
    EVIDENCE_JSON="[$evidence]"
    unique=$(cut -f2- "$values" | sort -u | wc -l | tr -d ' ')
    case "$unique" in ''|*[!0-9]*) unique=0 ;; esac
    [ "$unique" -le 1 ] && VALUE_STATE="identical" || VALUE_STATE="different"

    WINNER=""; WINNER_CONF=0; WINNER_METHOD="unresolved"
    current=$(prop_get "$key")
    if [ -n "$current" ]; then
        matches=$(awk -F '\t' -v v="$current" '$2==v {print $1}' "$values" | sort -u)
        count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
        case "$count" in ''|*[!0-9]*) count=0 ;; esac
        if [ "$count" -eq 1 ]; then WINNER="$matches"; WINNER_CONF=85; WINNER_METHOD="current_property_value_match"; return; fi
        if [ "$count" -gt 1 ]; then WINNER=$(lexical_winner "$matches"); WINNER_CONF=60; WINNER_METHOD="current_value_matches_multiple_modules"; return; fi
    fi
    WINNER=$(lexical_winner "$owners"); WINNER_CONF=45; WINNER_METHOD="lexical_module_id_heuristic"
}

process_property_conflicts() {
    build_prop_groups
    [ -s "$PROP_GROUP_FILE" ] || return
    while IFS="$(printf '\t')" read -r key owners; do
        [ -n "$key" ] || continue
        whitelist_key="system.prop:$key"
        in_whitelist "$whitelist_key" && continue
        analyze_property_candidates "$key" "$owners"
        if [ "$VALUE_STATE" = "identical" ]; then
            add_finding "property_duplicate_same_value" "$whitelist_key" "INFO" "$owners" "$WINNER" "$WINNER_CONF" "$WINNER_METHOD" "multiple modules define the same property with the same value" "$EVIDENCE_JSON" 0
        else
            severity=$(severity_of_prop "$key")
            add_finding "property_value_conflict" "$whitelist_key" "$severity" "$owners" "$WINNER" "$WINNER_CONF" "$WINNER_METHOD" "multiple modules define different values for the same property" "$EVIDENCE_JSON" 1
        fi
    done < "$PROP_GROUP_FILE"
}

build_script_groups() {
    : > "$SCRIPT_GROUP_FILE"
    [ -s "$SCRIPT_FILE" ] || return
    awk -F '\t' 'BEGIN{OFS="\t"}
        function flush(){if(resource!=""&&count>1)print resource,owners}
        {
            if(NR==1||$1!=resource){flush();resource=$1;owners=$2;seen=" "$2" ";count=1}
            else if(index(seen," "$2" ")==0){owners=owners" "$2;seen=seen$2" ";count++}
        }
        END{flush()}
    ' "$SCRIPT_FILE" > "$SCRIPT_GROUP_FILE"
}

current_resource_value() {
    resource="$1"
    case "$resource" in
        prop:*) prop_get "${resource#prop:}" ;;
        sysfs:*)
            path="${resource#sysfs:}"
            [ -r "$LIVE_ROOT$path" ] && head -n 1 "$LIVE_ROOT$path" 2>/dev/null
            ;;
        *) printf '' ;;
    esac
}

analyze_script_candidates() {
    resource="$1"
    owners="$2"
    candidate="$TMP_DIR/script.candidate"
    awk -F '\t' -v r="$resource" '$1==r {print}' "$SCRIPT_FILE" > "$candidate"
    values="$TMP_DIR/script.values.work"
    : > "$values"
    evidence=""
    while IFS="$(printf '\t')" read -r r module value source op; do
        printf '%s\t%s\n' "$module" "$value" >> "$values"
        jm=$(json_escape "$module"); jv=$(json_escape "$value"); js=$(json_escape "$source"); jo=$(json_escape "$op")
        item="{\"module\":\"$jm\",\"value\":\"$jv\",\"source\":\"$js\",\"operation\":\"$jo\"}"
        [ -n "$evidence" ] && evidence="$evidence,$item" || evidence="$item"
    done < "$candidate"
    EVIDENCE_JSON="[$evidence]"
    unique=$(cut -f2- "$values" | sort -u | wc -l | tr -d ' ')
    case "$unique" in ''|*[!0-9]*) unique=0 ;; esac
    [ "$unique" -le 1 ] && VALUE_STATE="identical" || VALUE_STATE="different"

    WINNER=""; WINNER_CONF=0; WINNER_METHOD="runtime_order_unresolved"
    current=$(current_resource_value "$resource")
    if [ -n "$current" ]; then
        matches=$(awk -F '\t' -v v="$current" '$2==v {print $1}' "$values" | sort -u)
        count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
        case "$count" in ''|*[!0-9]*) count=0 ;; esac
        if [ "$count" -eq 1 ]; then WINNER="$matches"; WINNER_CONF=75; WINNER_METHOD="current_runtime_value_match"; fi
    fi
}

process_script_conflicts() {
    build_script_groups
    [ -s "$SCRIPT_GROUP_FILE" ] || return
    while IFS="$(printf '\t')" read -r resource owners; do
        [ -n "$resource" ] || continue
        whitelist_key="script:$resource"
        in_whitelist "$whitelist_key" && continue
        analyze_script_candidates "$resource" "$owners"
        if [ "$VALUE_STATE" = "identical" ]; then
            add_finding "script_duplicate_same_action" "$resource" "INFO" "$owners" "$WINNER" "$WINNER_CONF" "$WINNER_METHOD" "multiple runtime scripts target the same resource with the same parsed value" "$EVIDENCE_JSON" 0
        else
            severity=$(severity_of_resource "$resource")
            add_finding "script_resource_conflict" "$resource" "$severity" "$owners" "$WINNER" "$WINNER_CONF" "$WINNER_METHOD" "runtime scripts target the same resource with different parsed values or operations" "$EVIDENCE_JSON" 1
        fi
    done < "$SCRIPT_GROUP_FILE"
}

module_is_active() {
    id="$1"
    awk -F '\t' -v id="$id" '$1==id {found=1} END{exit found?0:1}' "$MODULE_FILE"
}

process_known_conflicts() {
    is_enabled known_conflicts 1 || return
    [ -s "$KNOWN_FILE" ] || return
    while IFS='|' read -r a b severity reason; do
        case "$a" in ''|'#'*) continue ;; esac
        [ -n "$b" ] || continue
        case "$severity" in CRITICAL|HIGH|MEDIUM|LOW) ;; *) severity=MEDIUM ;; esac
        module_is_active "$a" || continue
        module_is_active "$b" || continue
        key="known:$a+$b"
        in_whitelist "$key" && continue
        er=$(json_escape "$reason")
        evidence="[{\"module_a\":\"$(json_escape "$a")\",\"module_b\":\"$(json_escape "$b")\",\"reason\":\"$er\"}]"
        add_finding "known_module_pair" "$key" "$severity" "$a $b" "" 0 "database_rule" "$reason" "$evidence" 1
    done < "$KNOWN_FILE"
}

process_global_overlayd() {
    is_enabled overlayd_scan 1 || return
    [ -d "$GLOBAL_OVERLAYD_DIR" ] || return
    count=$(find "$GLOBAL_OVERLAYD_DIR" \( -type f -o -type l \) 2>/dev/null | wc -l | tr -d ' ')
    case "$count" in ''|*[!0-9]*) count=0 ;; esac
    [ "$count" -gt 0 ] || return
    add_finding "global_overlayd_inventory" "$GLOBAL_OVERLAYD_DIR" "INFO" "@global-overlay.d" "" 0 "unattributed_global_directory" "$count entries found; ownership cannot be reconstructed reliably after installation" "[]" 0
}

write_json_report() {
    scan_time="$1"
    module_count="$2"
    entry_count="$3"
    replace_count="$4"
    prop_count="$5"
    script_count="$6"

    findings=$(awk 'BEGIN{first=1}{if(!first)printf ",";printf "%s",$0;first=0}' "$JSON_ITEMS_FILE" 2>/dev/null)
    android=$(device_value ro.build.version.release unknown)
    sdk=$(device_value ro.build.version.sdk unknown)
    abi=$(device_value ro.product.cpu.abi unknown)
    model=$(device_value ro.product.model unknown)
    fingerprint=$(device_value ro.build.fingerprint unknown)
    kernel=$(uname -r 2>/dev/null); [ -n "$kernel" ] || kernel=unknown
    selinux=$(getenforce 2>/dev/null); [ -n "$selinux" ] || selinux=unknown
    detect_root_manager_info
    manager="$ROOT_MANAGER"

    cat > "$JSON_FILE" <<EOFJSON
{
  "tool": "Module Conflict Detector",
  "version": "$VERSION",
  "version_code": $VERSION_CODE,
  "scan_time": "$(json_escape "$scan_time")",
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
    "mounted_entries_scanned": $entry_count,
    "replace_dirs_scanned": $replace_count,
    "property_definitions_scanned": $prop_count,
    "script_events_scanned": $script_count,
    "findings_count": $(count_get "$COUNT_FINDINGS_FILE"),
    "conflicts_count": $(count_get "$COUNT_CONFLICTS_FILE"),
    "critical": $(count_get "$COUNT_CRITICAL_FILE"),
    "high": $(count_get "$COUNT_HIGH_FILE"),
    "medium": $(count_get "$COUNT_MEDIUM_FILE"),
    "low": $(count_get "$COUNT_LOW_FILE"),
    "info": $(count_get "$COUNT_INFO_FILE")
  },
  "findings": [$findings]
}
EOFJSON
    cp -f "$JSON_FILE" "$REPORTS_DIR/report-latest.json" 2>/dev/null
    cp -f "$LOG_FILE" "$REPORTS_DIR/conflicts-latest.log" 2>/dev/null
}

report_critical_only() {
    [ -s "$LOG_FILE" ] || { echo "- No text report. Run: mcd-ctrl scan"; return; }
    awk '
        /^\[CRITICAL\]/ {show=1}
        /^\[[A-Z]+\]/ && !/^\[CRITICAL\]/ {show=0}
        show {print}
    ' "$LOG_FILE"
}

