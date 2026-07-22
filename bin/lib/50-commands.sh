do_scan() {
    ensure_dirs
    [ -d "$MODULES_DIR" ] || { msg "! Modules directory not found: $MODULES_DIR"; exit 1; }
    acquire_scan_lock
    cleanup_scan_temp
    count_init
    : > "$JSON_ITEMS_FILE"
    : > "$FINDINGS_INDEX_FILE"

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
    update_baseline_diff_after_scan
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
    rm -f "$LOG_FILE" "$JSON_FILE" "$FINDINGS_INDEX_FILE" "$MODULE_STATUS_REPORT" "$SCAN_MANIFEST_FILE" "$BASELINE_DIFF_FILE" "$REPORTS_DIR/report-latest.json" "$REPORTS_DIR/conflicts-latest.log" "$REPORTS_DIR/findings-latest.tsv" 2>/dev/null
    rm -rf "$TMP_DIR" "$LOCK_DIR" 2>/dev/null
    mkdir -p "$TMP_DIR" 2>/dev/null
    if [ "$2" = "--all" ]; then
        rm -f "$WHITELIST_FILE" "$CONFIG_FILE" "$KNOWN_FILE" "$BASELINE_FILE" 2>/dev/null
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
        auto_scan|boot_delay_seconds|replace_examples_limit|script_scan|overlayd_scan|hash_conflicts|known_conflicts|baseline_compare_on_scan) return 0 ;;
        *) return 1 ;;
    esac
}

set_config_value() {
    key="$1"; value="$2"; tmp="$TMP_DIR/config.work"
    valid_config_key "$key" || { echo "! Unknown config key: $key"; exit 1; }
    case "$key" in
        auto_scan|script_scan|overlayd_scan|hash_conflicts|known_conflicts|baseline_compare_on_scan)
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

find_finding_record() {
    wanted=$(printf '%s' "$1" | tr 'a-z' 'A-Z')
    awk -F '\t' -v id="$wanted" 'toupper($1)==id {print; exit}' "$FINDINGS_INDEX_FILE" 2>/dev/null
}

do_explain() {
    ensure_dirs
    id="$2"
    [ -n "$id" ] || { echo "Использование: mcd-ctrl explain ID"; exit 1; }
    record=$(find_finding_record "$id")
    [ -n "$record" ] || { echo "! Находка не найдена: $id"; echo "  Сначала выполните: mcd-ctrl scan --deep"; exit 1; }
    get_record_field() { printf '%s\n' "$record" | awk -F '\t' -v n="$1" '{print $n}'; }
    fid=$(get_record_field 1); severity=$(get_record_field 2); type=$(get_record_field 3)
    target=$(get_record_field 4); owners=$(get_record_field 5); winner=$(get_record_field 6)
    confidence=$(get_record_field 7); method=$(get_record_field 8); actionability=$(get_record_field 9)
    reason_codes=$(get_record_field 10); detail=$(get_record_field 11); impact=$(get_record_field 12)
    recommendation=$(get_record_field 13)
    evidence=$(get_record_field 14)
    cat <<EOFEXPLAIN
Находка: $fid
Уровень: $severity
Тип: $type

Цель:
  $target

Модули:
  $owners
EOFEXPLAIN
    if [ -n "$winner" ]; then
        cat <<EOFEXPLAIN

Победитель:
  $winner

Метод:
  $method

Уверенность:
  $confidence%
EOFEXPLAIN
    else
        printf '\nПобедитель:\n  не определён\n'
    fi
    cat <<EOFEXPLAIN

Срочность:
  $actionability

Причины:
  $reason_codes

Описание:
  $detail

Возможное влияние:
  $impact

Рекомендация:
  $recommendation
EOFEXPLAIN
    if [ -n "$evidence" ] && [ "$evidence" != "[]" ]; then
        echo
        echo "Доказательства:"
        printf '%s\n' "$evidence" | sed 's/^[[]//; s/[]]$//; s/},{/ | /g; s/[{}"]//g; s/,/; /g; s/:/: /g; s/^/  /'
    fi
}

baseline_build_current() {
    out="$1"
    : > "$out"
    [ -f "$MODULE_STATUS_REPORT" ] && awk -F '\t' 'BEGIN{OFS="\t"}{print "M",$1,$3,$4}' "$MODULE_STATUS_REPORT" >> "$out"
    [ -f "$SCAN_MANIFEST_FILE" ] && awk 'BEGIN{OFS="\t"}{print "S",$0}' "$SCAN_MANIFEST_FILE" >> "$out"
    [ -f "$FINDINGS_INDEX_FILE" ] && awk -F '\t' 'BEGIN{OFS="\t"}{print "F",$1,$2,$3,$4,$5}' "$FINDINGS_INDEX_FILE" >> "$out"
    sort -u "$out" -o "$out" 2>/dev/null
}

baseline_compare_files() {
    baseline="$1"; current="$2"; output="$3"
    added="$TMP_DIR/baseline-added.work"; removed="$TMP_DIR/baseline-removed.work"
    awk 'NR==FNR{old[$0]=1;next}!($0 in old){print}' "$baseline" "$current" > "$added"
    awk 'NR==FNR{now[$0]=1;next}!($0 in now){print}' "$current" "$baseline" > "$removed"
    ac=$(wc -l < "$added" 2>/dev/null | tr -d ' '); rc=$(wc -l < "$removed" 2>/dev/null | tr -d ' ')
    case "$ac" in ''|*[!0-9]*) ac=0 ;; esac
    case "$rc" in ''|*[!0-9]*) rc=0 ;; esac
    {
        echo "Baseline comparison"
        echo "Added/changed: $ac"
        awk -F '\t' '$1=="M"{printf "+ module %s version=%s status=%s\n",$2,$3,$4}$1=="F"{printf "+ finding %s [%s] %s %s\n",$2,$3,$4,$5}$1=="S"{printf "+ state %s target=%s module=%s value=%s\n",$2,$3,$4,$NF}' "$added"
        echo "Removed/changed: $rc"
        awk -F '\t' '$1=="M"{printf "- module %s version=%s status=%s\n",$2,$3,$4}$1=="F"{printf "- finding %s [%s] %s %s\n",$2,$3,$4,$5}$1=="S"{printf "- state %s target=%s module=%s value=%s\n",$2,$3,$4,$NF}' "$removed"
    } > "$output"
}

update_baseline_diff_after_scan() {
    [ "$(get_config baseline_compare_on_scan 1)" = "1" ] || return 0
    [ -s "$BASELINE_FILE" ] || return 0
    current="$TMP_DIR/baseline-current.manifest"
    baseline_build_current "$current"
    baseline_compare_files "$BASELINE_FILE" "$current" "$BASELINE_DIFF_FILE"
}

do_baseline() {
    ensure_dirs
    case "$2" in
        create|reset)
            [ -f "$FINDINGS_INDEX_FILE" ] || { echo "! Сначала выполните сканирование"; exit 1; }
            current="$TMP_DIR/baseline-current.manifest"
            baseline_build_current "$current"
            cp -f "$current" "$BASELINE_FILE"
            echo "+ Baseline сохранён: $BASELINE_FILE"
            ;;
        compare|'')
            [ -s "$BASELINE_FILE" ] || { echo "! Baseline отсутствует. Выполните: mcd-ctrl baseline create"; exit 1; }
            current="$TMP_DIR/baseline-current.manifest"
            baseline_build_current "$current"
            baseline_compare_files "$BASELINE_FILE" "$current" "$BASELINE_DIFF_FILE"
            cat "$BASELINE_DIFF_FILE"
            ;;
        show) [ -s "$BASELINE_FILE" ] && cat "$BASELINE_FILE" || echo "- Baseline отсутствует" ;;
        *) echo "Использование: mcd-ctrl baseline create|compare|reset|show"; exit 1 ;;
    esac
}

find_busybox_zip() {
    for bb in busybox /data/adb/magisk/busybox /data/adb/ap/bin/busybox /data/adb/ksu/bin/busybox; do
        if [ "$bb" = busybox ]; then command -v busybox >/dev/null 2>&1 || continue
        else [ -x "$bb" ] || continue; fi
        "$bb" zip 2>&1 | grep -qi 'usage\|zip' && { printf '%s' "$bb"; return 0; }
    done
    return 1
}

redact_json() {
    src="$1"; dst="$2"
    sed -E 's/("build_fingerprint"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"redacted"/; s/("root_detection_evidence"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"redacted"/' "$src" > "$dst"
}

do_export() {
    ensure_dirs
    privacy=0
    [ "$2" = "--privacy" ] && privacy=1
    stamp=$(date '+%Y%m%d-%H%M%S' 2>/dev/null)
    [ -n "$stamp" ] || stamp="export-$$"
    outdir="/storage/emulated/0/MCD_Reports"
    mkdir -p "$outdir" 2>/dev/null || outdir="$EXPORT_FALLBACK_DIR"
    work="$TMP_DIR/export-$stamp"
    rm -rf "$work"; mkdir -p "$work"

    {
        echo "Module Conflict Detector $VERSION ($VERSION_CODE)"
        echo "Export time: $(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null)"
        echo "Privacy mode: $privacy"
        [ -f "$JSON_FILE" ] && grep -E '"scan_time"|"boot_scan"|"root_manager"|"findings_count"|"conflicts_count"|"critical"' "$JSON_FILE"
    } > "$work/summary.txt"
    do_doctor > "$work/doctor.txt" 2>&1
    if [ "$privacy" = "1" ]; then
        sed 's/^root_detection_evidence=.*/root_detection_evidence=redacted/' "$work/doctor.txt" > "$work/doctor.redacted"
        mv -f "$work/doctor.redacted" "$work/doctor.txt"
    fi
    [ -f "$LOG_FILE" ] && cp -f "$LOG_FILE" "$work/conflicts.log"
    if [ -f "$JSON_FILE" ]; then
        [ "$privacy" = "1" ] && redact_json "$JSON_FILE" "$work/report.json" || cp -f "$JSON_FILE" "$work/report.json"
    fi
    for pair in "$BOOT_LOG_FILE:boot-scan.log" "$BOOT_STATUS_FILE:boot-scan.status" "$MODULE_STATUS_REPORT:module-status.tsv" "$SCAN_MANIFEST_FILE:scan-manifest.tsv" "$FINDINGS_INDEX_FILE:findings.tsv" "$BASELINE_DIFF_FILE:baseline-diff.txt"; do
        src=${pair%%:*}; name=${pair#*:}; [ -f "$src" ] && cp -f "$src" "$work/$name"
    done
    (cd "$work" && { command -v sha256sum >/dev/null 2>&1 && sha256sum * > checksums.sha256 2>/dev/null || cksum * > checksums.cksum 2>/dev/null; })

    archive="$outdir/ModuleConflictDetector-$stamp.zip"
    if command -v zip >/dev/null 2>&1; then
        (cd "$work" && zip -q -r "$archive" .) || exit 1
    else
        bb=$(find_busybox_zip)
        if [ -n "$bb" ]; then
            (cd "$work" && "$bb" zip -q -r "$archive" .) || exit 1
        else
            archive="$outdir/ModuleConflictDetector-$stamp.tar.gz"
            tar -czf "$archive" -C "$work" . 2>/dev/null || { echo "! Нет zip/tar провайдера"; exit 1; }
            echo "! ZIP недоступен, создан безопасный tar.gz"
        fi
    fi
    rm -rf "$work"
    echo "+ Экспорт: $archive"
}

self_test_line() { printf '[%s] %s\n' "$1" "$2"; }

do_self_test() {
    ensure_dirs
    failures=0
    [ -d "$MODULES_DIR" ] && self_test_line OK "module directory" || { self_test_line FAIL "module directory"; failures=$((failures+1)); }
    [ -w "$MCD_DIR" ] && self_test_line OK "runtime directory" || { self_test_line FAIL "runtime directory"; failures=$((failures+1)); }
    for cmd in awk sed grep sort find readlink; do
        command -v "$cmd" >/dev/null 2>&1 && self_test_line OK "$cmd" || { self_test_line FAIL "$cmd"; failures=$((failures+1)); }
    done
    command -v getprop >/dev/null 2>&1 && self_test_line OK "getprop" || self_test_line WARN "getprop unavailable in host test"
    detect_root_manager_info
    [ "$ROOT_MANAGER" != "unknown" ] && self_test_line OK "root detection: $ROOT_MANAGER" || self_test_line WARN "root detection unknown"
    [ -f "$JSON_FILE" ] && grep -q '"findings"' "$JSON_FILE" && self_test_line OK "report schema" || self_test_line WARN "no valid report yet"
    [ -r "$MCD_SELF_BIN" ] && self_test_line OK "CLI readable" || { self_test_line FAIL "CLI readable"; failures=$((failures+1)); }

    if [ "$2" = "--full" ]; then
        box="$TMP_DIR/self-test-$$"
        rm -rf "$box"
        mkdir -p "$box/modules/A/system/etc" "$box/modules/B/system/etc" "$box/live/system/etc" "$box/data"
        printf 'id=A\nname=Fixture A\nversion=1.0\n' > "$box/modules/A/module.prop"
        printf 'id=B\nname=Fixture B\nversion=2.0\n' > "$box/modules/B/module.prop"
        printf 'A\n' > "$box/modules/A/system/etc/mcd-test.conf"
        printf 'B\n' > "$box/modules/B/system/etc/mcd-test.conf"
        cp "$box/modules/B/system/etc/mcd-test.conf" "$box/live/system/etc/mcd-test.conf"
        printf 'debug.mcd.fixture=1\n' > "$box/modules/A/system.prop"
        printf 'debug.mcd.fixture=2\n' > "$box/modules/B/system.prop"
        MCD_DIR="$box/data" MCD_MODULES_DIR="$box/modules" MCD_LIVE_ROOT="$box/live" MCD_ROOT_DATA_ADB="$box/root" MCD_SELF_BIN="$MCD_SELF_BIN" sh "$MCD_SELF_BIN" scan --deep --quiet >/dev/null 2>&1
        if grep -q 'path_content_conflict' "$box/data/report.json" 2>/dev/null && grep -q 'property_value_conflict' "$box/data/report.json" 2>/dev/null; then
            self_test_line OK "sandbox conflict fixture"
        else
            self_test_line FAIL "sandbox conflict fixture"; failures=$((failures+1))
        fi
        rm -rf "$box"
    fi
    [ "$failures" -eq 0 ] || exit 1
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

Команды:
  menu          Открыть меню
  scan          Проверка
  report        Отчёт
  explain ID    Объяснить находку
  baseline      Сравнение состояния
  export        Экспорт диагностики
  self-test     Самопроверка
  boot-status   Автозапуск
  doctor        Диагностика
  snapshot      Снимки
  config        Настройки
  help-all      Полная справка

Быстрый запуск:
  mcd-ctrl scan --deep
  mcd-ctrl report
EOFHELP
}

show_help_all() {
    cat <<EOFHELP
Module Conflict Detector $VERSION

scan [--deep] [--quiet]
report [--json|--text|--critical-only]
explain ID
baseline create|compare|reset|show
export [--privacy]
self-test [--full]
snapshot create [NAME]|list|compare NAME|delete NAME
whitelist add|remove|list [TARGET]
config list|get|set [KEY] [VALUE]
boot-status
doctor
clear [--all]
version

Классы находок:
  path_content_conflict
  path_duplicate_identical
  replace_dir_collision
  replace_masks_tree
  property_value_conflict
  property_duplicate_same_value
  script_resource_conflict
  script_duplicate_same_action
  known_module_pair
  global_overlayd_inventory

Победитель:
  live/current match = подтверждён
  explicit priority = сильная подсказка
  lexical heuristic = низкая уверенность
EOFHELP
}
