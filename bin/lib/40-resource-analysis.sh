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
        if [ "$count" -gt 1 ]; then
            WINNER=$(precedence_winner "$matches" 2>/dev/null)
            if [ -n "$WINNER" ]; then WINNER_CONF=80; WINNER_METHOD="current_value_plus_explicit_priority"
            else WINNER=$(lexical_winner "$matches"); WINNER_CONF=45; WINNER_METHOD="current_value_multiple_lexical_heuristic"; fi
            return
        fi
    fi
    WINNER=$(precedence_winner "$owners" 2>/dev/null)
    if [ -n "$WINNER" ]; then WINNER_CONF=70; WINNER_METHOD="explicit_module_priority"
    else WINNER=$(lexical_winner "$owners"); WINNER_CONF=25; WINNER_METHOD="lexical_module_id_heuristic"; fi
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

module_version() {
    id="$1"
    awk -F '\t' -v id="$id" '$1==id {print $3; exit}' "$MODULE_FILE"
}

version_compare() {
    a="$1"; b="$2"
    awk -v a="$a" -v b="$b" 'BEGIN {
        na=split(a,A,/[^0-9]+/); nb=split(b,B,/[^0-9]+/); n=na>nb?na:nb
        for(i=1;i<=n;i++){x=A[i]+0;y=B[i]+0;if(x<y){print -1;exit}if(x>y){print 1;exit}}
        print 0
    }'
}

version_allowed() {
    value="$1"; min="$2"; max="$3"
    [ -z "$min" ] || [ "$min" = "*" ] || [ "$(version_compare "$value" "$min")" -ge 0 ] || return 1
    [ -z "$max" ] || [ "$max" = "*" ] || [ "$(version_compare "$value" "$max")" -le 0 ] || return 1
    return 0
}

known_rule_matches_environment() {
    family="$1"; sdk_min="$2"; sdk_max="$3"
    detect_root_manager_info
    [ -z "$family" ] || [ "$family" = "*" ] || [ "$family" = "$ROOT_MANAGER_FAMILY" ] || return 1
    sdk=$(device_value ro.build.version.sdk 0)
    case "$sdk" in ''|*[!0-9]*) sdk=0 ;; esac
    [ -z "$sdk_min" ] || [ "$sdk_min" = "*" ] || [ "$sdk" -ge "$sdk_min" ] || return 1
    [ -z "$sdk_max" ] || [ "$sdk_max" = "*" ] || [ "$sdk" -le "$sdk_max" ] || return 1
    return 0
}

process_known_conflicts() {
    is_enabled known_conflicts 1 || return
    [ -s "$KNOWN_FILE" ] || return
    while IFS="$(printf '\t')" read -r rule_id a b min_a max_a min_b max_b family sdk_min sdk_max severity category reason source added; do
        case "$rule_id" in ''|'#'*) continue ;; esac
        case "$rule_id" in *'|'*)
            old="$rule_id"
            a=$(printf '%s' "$old" | cut -d'|' -f1); b=$(printf '%s' "$old" | cut -d'|' -f2)
            severity=$(printf '%s' "$old" | cut -d'|' -f3); reason=$(printf '%s' "$old" | cut -d'|' -f4-)
            rule_id="LEGACY-$(hash_text "$a|$b" | cut -c1-8)"; min_a='*'; max_a='*'; min_b='*'; max_b='*'; family='*'; sdk_min='*'; sdk_max='*'; category='legacy'; source='legacy'; added='unknown'
            ;;
        esac
        [ -n "$a" ] && [ -n "$b" ] || continue
        case "$severity" in CRITICAL|HIGH|MEDIUM|LOW) ;; *) severity=MEDIUM ;; esac
        module_is_active "$a" || continue; module_is_active "$b" || continue
        va=$(module_version "$a"); vb=$(module_version "$b")
        version_allowed "$va" "$min_a" "$max_a" || continue
        version_allowed "$vb" "$min_b" "$max_b" || continue
        known_rule_matches_environment "$family" "$sdk_min" "$sdk_max" || continue
        key="known:$a+$b"
        in_whitelist "$key" && continue
        evidence="[{\"rule_id\":\"$(json_escape "$rule_id")\",\"module_a\":\"$(json_escape "$a")\",\"module_b\":\"$(json_escape "$b")\",\"version_a\":\"$(json_escape "$va")\",\"version_b\":\"$(json_escape "$vb")\",\"category\":\"$(json_escape "$category")\",\"source\":\"$(json_escape "$source")\",\"added\":\"$(json_escape "$added")\"}]"
        add_finding "known_module_pair" "$key" "$severity" "$a $b" "" 100 "database_rule:$rule_id" "$reason" "$evidence" 1
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
    active_count=$(awk -F '\t' '$4=="active"||$4=="active_skip_mount"{n++}END{print n+0}' "$MODULE_STATUS_FILE" 2>/dev/null)
    disabled_count=$(awk -F '\t' '$4=="disabled"{n++}END{print n+0}' "$MODULE_STATUS_FILE" 2>/dev/null)
    remove_count=$(awk -F '\t' '$4=="remove_pending"{n++}END{print n+0}' "$MODULE_STATUS_FILE" 2>/dev/null)
    skip_count=$(awk -F '\t' '$4=="active_skip_mount"{n++}END{print n+0}' "$MODULE_STATUS_FILE" 2>/dev/null)
    known_db_version=$(sed -n 's/^# database_version=//p' "$KNOWN_FILE" 2>/dev/null | head -n 1)
    case "$known_db_version" in ''|*[!0-9]*) known_db_version=1 ;; esac

    cat > "$JSON_FILE" <<EOFJSON
{
  "tool": "Module Conflict Detector",
  "version": "$VERSION",
  "version_code": $VERSION_CODE,
  "scan_time": "$(json_escape "$scan_time")",
  "boot_scan": $([ "$BOOT_MODE" = "1" ] && echo true || echo false),
  "deep_scan": $([ "$DEEP_MODE" = "1" ] && echo true || echo false),
  "known_database_version": $known_db_version,
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
    "modules_active": $active_count,
    "modules_disabled": $disabled_count,
    "modules_remove_pending": $remove_count,
    "modules_skip_mount": $skip_count,
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
    cp -f "$MODULE_STATUS_FILE" "$MODULE_STATUS_REPORT" 2>/dev/null
    cp -f "$FINDINGS_INDEX_FILE" "$REPORTS_DIR/findings-latest.tsv" 2>/dev/null
    build_manifest "$SCAN_MANIFEST_FILE" 2>/dev/null
}

report_critical_only() {
    [ -s "$LOG_FILE" ] || { echo "- No text report. Run: mcd-ctrl scan"; return; }
    awk '
        /^\[CRITICAL\]/ {show=1}
        /^\[[A-Z]+\]/ && !/^\[CRITICAL\]/ {show=0}
        show {print}
    ' "$LOG_FILE"
}
