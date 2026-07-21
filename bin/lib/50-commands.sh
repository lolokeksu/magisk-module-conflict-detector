do_scan() {
    ensure_dirs
    [ -d "$MODULES_DIR" ] || { msg "! Modules directory not found: $MODULES_DIR"; exit 1; }
    acquire_scan_lock
    cleanup_scan_temp
    count_init
    : > "$JSON_ITEMS_FILE"

    scan_time=$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null)
    [ -n "$scan_time" ] || scan_time="unknown"
    {
        printf 'Module Conflict Detector %s\n' "$VERSION"
        printf 'Scan time: %s\n' "$scan_time"
        printf 'Modules dir: %s\n' "$MODULES_DIR"
        detect_root_manager_info
        printf 'Root manager: %s\n' "$ROOT_MANAGER"
        printf 'Root detection: %s (%s)\n\n' "$ROOT_DETECTION_METHOD" "$ROOT_DETECTION_CONFIDENCE"
    } > "$LOG_FILE"

    collect_modules
    process_path_conflicts
    process_replace_conflicts
    process_property_conflicts
    process_script_conflicts
    process_known_conflicts
    process_global_overlayd

    module_count=$(wc -l < "$MODULE_FILE" 2>/dev/null | tr -d ' ')
    entry_count=$(wc -l < "$ENTRY_FILE" 2>/dev/null | tr -d ' ')
    replace_count=$(wc -l < "$REPLACE_FILE" 2>/dev/null | tr -d ' ')
    prop_count=$(wc -l < "$PROP_FILE" 2>/dev/null | tr -d ' ')
    script_count=$(wc -l < "$SCRIPT_FILE" 2>/dev/null | tr -d ' ')
    for v in module_count entry_count replace_count prop_count script_count; do
        eval n=\$$v
        case "$n" in ''|*[!0-9]*) eval "$v=0" ;; esac
    done

    write_json_report "$scan_time" "$module_count" "$entry_count" "$replace_count" "$prop_count" "$script_count"
    conflicts=$(count_get "$COUNT_CONFLICTS_FILE")
    findings=$(count_get "$COUNT_FINDINGS_FILE")
    critical=$(count_get "$COUNT_CRITICAL_FILE")

    if [ "$conflicts" -gt 0 ]; then
        msg "! Conflicts: $conflicts; findings: $findings; critical: $critical"
        msg "  Text: mcd-ctrl report"
        msg "  JSON: mcd-ctrl report --json"
    else
        msg "- No actionable conflicts found; informational findings: $findings"
    fi

    if [ "$CRITICAL_ONLY" = "1" ] && [ "$QUIET" = "0" ]; then
        printf '\n'
        report_critical_only
    fi

    scan_exit_cleanup
    trap - EXIT HUP INT TERM
}

do_report() {
    case "$2" in
        --json)
            [ -f "$JSON_FILE" ] && cat "$JSON_FILE" || echo '{"error":"no scan data","hint":"run mcd-ctrl scan"}'
            ;;
        --critical-only)
            report_critical_only
            ;;
        --text|'')
            [ -s "$LOG_FILE" ] && cat "$LOG_FILE" || echo "- No text report. Run: mcd-ctrl scan"
            ;;
        *)
            echo "Usage: mcd-ctrl report [--json|--text|--critical-only]"
            exit 1
            ;;
    esac
}

do_clear() {
    ensure_dirs
    rm -f "$LOG_FILE" "$JSON_FILE" "$REPORTS_DIR/report-latest.json" "$REPORTS_DIR/conflicts-latest.log" 2>/dev/null
    rm -rf "$TMP_DIR" "$LOCK_DIR" 2>/dev/null
    mkdir -p "$TMP_DIR" 2>/dev/null
    if [ "$2" = "--all" ]; then
        rm -f "$WHITELIST_FILE" "$CONFIG_FILE" "$KNOWN_FILE" 2>/dev/null
        write_default_config
        : > "$WHITELIST_FILE"
        write_default_known_db
        msg "- Cleared reports, temp files, whitelist, known database and config"
    else
        msg "- Cleared reports and temp files"
    fi
}

do_whitelist() {
    ensure_dirs
    case "$2" in
        add)
            [ -n "$3" ] || { echo "Usage: mcd-ctrl whitelist add TARGET"; exit 1; }
            if grep -Fxq -- "$3" "$WHITELIST_FILE" 2>/dev/null; then msg "- Already whitelisted: $3"; else printf '%s\n' "$3" >> "$WHITELIST_FILE"; msg "+ Whitelisted: $3"; fi
            ;;
        remove)
            [ -n "$3" ] || { echo "Usage: mcd-ctrl whitelist remove TARGET"; exit 1; }
            tmp="$TMP_DIR/whitelist.work"
            grep -Fvx -- "$3" "$WHITELIST_FILE" > "$tmp" 2>/dev/null || :
            mv "$tmp" "$WHITELIST_FILE"
            msg "- Removed: $3"
            ;;
        list)
            [ -s "$WHITELIST_FILE" ] && sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$WHITELIST_FILE" || echo "- Whitelist is empty"
            ;;
        *) echo "Usage: mcd-ctrl whitelist add|remove|list [TARGET]"; exit 1 ;;
    esac
}

valid_config_key() {
    case "$1" in
        auto_scan|boot_delay_seconds|replace_examples_limit|script_scan|overlayd_scan|hash_conflicts|known_conflicts) return 0 ;;
        *) return 1 ;;
    esac
}

set_config_value() {
    key="$1"; value="$2"; tmp="$TMP_DIR/config.work"
    valid_config_key "$key" || { echo "! Unknown config key: $key"; exit 1; }
    case "$key" in
        auto_scan|script_scan|overlayd_scan|hash_conflicts|known_conflicts)
            case "$value" in 0|1) ;; *) echo "! $key must be 0 or 1"; exit 1 ;; esac ;;
        boot_delay_seconds|replace_examples_limit)
            case "$value" in ''|*[!0-9]*) echo "! $key must be numeric"; exit 1 ;; esac ;;
    esac
    if grep -q "^$key=" "$CONFIG_FILE" 2>/dev/null; then
        sed "s|^$key=.*|$key=$value|" "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$CONFIG_FILE"
    fi
    msg "+ Config updated: $key=$value"
}

do_config() {
    ensure_dirs
    case "$2" in
        list|'') sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$CONFIG_FILE" ;;
        get)
            [ -n "$3" ] || { echo "Usage: mcd-ctrl config get KEY"; exit 1; }
            valid_config_key "$3" || { echo "! Unknown config key: $3"; exit 1; }
            get_config "$3" ""; echo
            ;;
        set)
            [ -n "$3" ] && [ -n "$4" ] || { echo "Usage: mcd-ctrl config set KEY VALUE"; exit 1; }
            set_config_value "$3" "$4"
            ;;
        *) echo "Usage: mcd-ctrl config list|get|set [KEY] [VALUE]"; exit 1 ;;
    esac
}

sanitize_snapshot_name() {
    name="$1"
    case "$name" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
    printf '%s' "$name"
}

build_manifest() {
    out="$1"
    : > "$out"
    while IFS="$(printf '\t')" read -r module name version root; do
        printf 'M\t%s\t%s\t%s\n' "$module" "$name" "$version" >> "$out"
    done < "$MODULE_FILE"
    while IFS="$(printf '\t')" read -r target module kind source; do
        fp=$(fingerprint_source "$kind" "$source")
        printf 'F\t%s\t%s\t%s\t%s\n' "$target" "$module" "$kind" "$fp" >> "$out"
    done < "$ENTRY_FILE"
    while IFS="$(printf '\t')" read -r key module value source; do
        printf 'P\t%s\t%s\t%s\n' "$key" "$module" "$value" >> "$out"
    done < "$PROP_FILE"
    while IFS="$(printf '\t')" read -r resource module value source op; do
        printf 'S\t%s\t%s\t%s\t%s\n' "$resource" "$module" "$value" "$op" >> "$out"
    done < "$SCRIPT_FILE"
    while IFS="$(printf '\t')" read -r target module source; do
        printf 'R\t%s\t%s\n' "$target" "$module" >> "$out"
    done < "$REPLACE_FILE"
    sort -u "$out" -o "$out" 2>/dev/null
}

snapshot_collect_current() {
    acquire_scan_lock
    cleanup_scan_temp
    collect_modules
    build_manifest "$TMP_DIR/current.manifest"
}

do_snapshot() {
    ensure_dirs
    case "$2" in
        create)
            mcd_snap_name="$3"
            [ -n "$mcd_snap_name" ] || mcd_snap_name=$(date '+%Y%m%d-%H%M%S' 2>/dev/null)
            mcd_snap_name=$(sanitize_snapshot_name "$mcd_snap_name") || { echo "! Snapshot name may contain only A-Z a-z 0-9 . _ -"; exit 1; }
            mcd_snap_path="$SNAPSHOTS_DIR/$mcd_snap_name.tsv"
            [ -e "$mcd_snap_path" ] && { echo "! Snapshot already exists: $mcd_snap_name"; exit 1; }
            snapshot_collect_current
            cp "$TMP_DIR/current.manifest" "$mcd_snap_path"
            mcd_snap_lines=$(wc -l < "$mcd_snap_path" | tr -d ' ')
            scan_exit_cleanup; trap - EXIT HUP INT TERM
            echo "+ Snapshot created: $mcd_snap_name ($mcd_snap_lines records)"
            ;;
        list)
            mcd_snap_found=0
            for mcd_snap_path in "$SNAPSHOTS_DIR"/*.tsv; do
                [ -f "$mcd_snap_path" ] || continue
                mcd_snap_found=1
                mcd_snap_name=$(basename "$mcd_snap_path" .tsv)
                mcd_snap_lines=$(wc -l < "$mcd_snap_path" | tr -d ' ')
                printf '%s\t%s records\n' "$mcd_snap_name" "$mcd_snap_lines"
            done
            [ "$mcd_snap_found" = "1" ] || echo "- No snapshots"
            ;;
        compare)
            mcd_snap_name=$(sanitize_snapshot_name "$3") || { echo "Usage: mcd-ctrl snapshot compare NAME"; exit 1; }
            mcd_snap_old="$SNAPSHOTS_DIR/$mcd_snap_name.tsv"
            [ -f "$mcd_snap_old" ] || { echo "! Snapshot not found: $mcd_snap_name"; exit 1; }
            snapshot_collect_current
            mcd_snap_current="$TMP_DIR/current.manifest"
            mcd_snap_added="$TMP_DIR/snapshot-added.work"
            mcd_snap_removed="$TMP_DIR/snapshot-removed.work"
            awk 'NR==FNR{old[$0]=1;next}!($0 in old){print}' "$mcd_snap_old" "$mcd_snap_current" > "$mcd_snap_added"
            awk 'NR==FNR{now[$0]=1;next}!($0 in now){print}' "$mcd_snap_current" "$mcd_snap_old" > "$mcd_snap_removed"
            mcd_snap_added_count=$(wc -l < "$mcd_snap_added" | tr -d ' ')
            mcd_snap_removed_count=$(wc -l < "$mcd_snap_removed" | tr -d ' ')
            echo "Snapshot: $mcd_snap_name"
            echo "Added/changed records: $mcd_snap_added_count"
            sed 's/^/+ /' "$mcd_snap_added"
            echo "Removed/changed records: $mcd_snap_removed_count"
            sed 's/^/- /' "$mcd_snap_removed"
            scan_exit_cleanup; trap - EXIT HUP INT TERM
            ;;
        delete)
            mcd_snap_name=$(sanitize_snapshot_name "$3") || { echo "Usage: mcd-ctrl snapshot delete NAME"; exit 1; }
            mcd_snap_path="$SNAPSHOTS_DIR/$mcd_snap_name.tsv"
            [ -f "$mcd_snap_path" ] || { echo "! Snapshot not found: $mcd_snap_name"; exit 1; }
            rm -f "$mcd_snap_path" && echo "- Snapshot deleted: $mcd_snap_name"
            ;;
        *)
            echo "Usage: mcd-ctrl snapshot create [NAME]|list|compare NAME|delete NAME"
            exit 1
            ;;
    esac
}

do_doctor() {
    ensure_dirs
    echo "Module Conflict Detector $VERSION ($VERSION_CODE)"
    echo "id=$SELF_ID"
    detect_root_manager_info
    echo "root_manager=$ROOT_MANAGER"
    echo "root_manager_family=$ROOT_MANAGER_FAMILY"
    echo "root_detection_method=$ROOT_DETECTION_METHOD"
    echo "root_detection_confidence=$ROOT_DETECTION_CONFIDENCE"
    echo "root_detection_evidence=$ROOT_DETECTION_EVIDENCE"
    echo "android=$(device_value ro.build.version.release unknown)"
    echo "sdk=$(device_value ro.build.version.sdk unknown)"
    echo "abi=$(device_value ro.product.cpu.abi unknown)"
    echo "kernel=$(uname -r 2>/dev/null)"
    echo "selinux=$(getenforce 2>/dev/null || echo unknown)"
    echo "modules_dir=$MODULES_DIR"
    echo "mcd_dir=$MCD_DIR"
    echo "global_overlayd_dir=$GLOBAL_OVERLAYD_DIR"
    echo
    [ -d "$MODULES_DIR" ] && echo "modules_dir_status=OK" || echo "modules_dir_status=MISSING"
    [ -w "$MCD_DIR" ] && echo "mcd_dir_writable=1" || echo "mcd_dir_writable=0"
    for cmd in awk sed grep sort find sha256sum readlink getprop getenforce; do
        command -v "$cmd" >/dev/null 2>&1 && echo "command_$cmd=OK" || echo "command_$cmd=MISSING"
    done
    echo
    do_config config list
    echo
    if [ -f "$BOOT_STATUS_FILE" ]; then
        cat "$BOOT_STATUS_FILE"
    else
        echo "boot_scan_status=never"
    fi
    echo "boot_scan_log=$BOOT_LOG_FILE"
}

do_boot_status() {
    ensure_dirs
    if [ -f "$BOOT_STATUS_FILE" ]; then
        cat "$BOOT_STATUS_FILE"
    else
        echo "boot_scan_status=never"
    fi
    echo "boot_scan_log=$BOOT_LOG_FILE"
    if [ -f "$LAST_BOOT_ID_FILE" ]; then
        echo "last_boot_scan_id=$(cat "$LAST_BOOT_ID_FILE" 2>/dev/null)"
    fi
}

show_help() {
    cat <<EOFHELP
Module Conflict Detector $VERSION

Usage:
  mcd-ctrl scan [--deep] [--quiet] [--critical-only]
  mcd-ctrl report [--json|--text|--critical-only]
  mcd-ctrl snapshot create [NAME]
  mcd-ctrl snapshot list
  mcd-ctrl snapshot compare NAME
  mcd-ctrl snapshot delete NAME
  mcd-ctrl whitelist add|remove|list [TARGET]
  mcd-ctrl config list|get|set [KEY] [VALUE]
  mcd-ctrl doctor
  mcd-ctrl boot-status
  mcd-ctrl clear [--all]
  mcd-ctrl version

Detected classes:
  path_content_conflict          same target, different file/link content
  path_duplicate_identical       same target, identical content (informational)
  replace_dir_collision          multiple .replace owners
  replace_masks_tree             .replace masks another module tree
  property_value_conflict        different system.prop values
  property_duplicate_same_value  identical system.prop values (informational)
  script_resource_conflict       runtime scripts write different values/actions
  script_duplicate_same_action   duplicate runtime action (informational)
  known_module_pair              exact rule from known-conflicts.conf
  global_overlayd_inventory      unattributed global overlay.d inventory

Winner resolution:
  1. Match the live file/property/runtime value to a module candidate.
  2. If no exact match is possible, report a clearly labelled lexical heuristic.
EOFHELP
}

