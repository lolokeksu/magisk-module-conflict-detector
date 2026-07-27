do_scan() {
    ensure_dirs
    [ -d "$MODULES_DIR" ] || { msg "! Каталог модулей не найден: $MODULES_DIR"; exit 1; }
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
        printf 'Scan profile: %s\n' "$SCAN_PROFILE"
        printf 'Modules dir: %s\n' "$MODULES_DIR"
        detect_root_manager_info
        printf 'Root manager: %s\n' "$ROOT_MANAGER"
        printf 'Root detection: %s (%s)\n\n' "$ROOT_DETECTION_METHOD" "$ROOT_DETECTION_CONFIDENCE"
    } > "$LOG_FILE"

    collect_modules
    process_path_conflicts
    process_replace_conflicts
    process_property_conflicts
    [ "$DEEP_MODE" = "1" ] && process_script_conflicts
    [ "$DEEP_MODE" = "1" ] && process_sepolicy_conflicts
    process_known_conflicts
    if [ "$DEEP_MODE" = "1" ] && [ "$(get_config overlayd_scan 1)" = "1" ]; then
        process_global_overlayd
    fi

    module_count=$(wc -l < "$MODULE_FILE" 2>/dev/null | tr -d ' ')
    entry_count=$(wc -l < "$ENTRY_FILE" 2>/dev/null | tr -d ' ')
    replace_count=$(wc -l < "$REPLACE_FILE" 2>/dev/null | tr -d ' ')
    prop_count=$(wc -l < "$PROP_FILE" 2>/dev/null | tr -d ' ')
    script_count=$(wc -l < "$SCRIPT_FILE" 2>/dev/null | tr -d ' ')
    sepolicy_count=$(wc -l < "$SEPOLICY_FILE" 2>/dev/null | tr -d ' ')
    for v in module_count entry_count replace_count prop_count script_count sepolicy_count; do
        eval n=\$$v
        case "$n" in ''|*[!0-9]*) eval "$v=0" ;; esac
    done

    write_json_report "$scan_time" "$module_count" "$entry_count" "$replace_count" "$prop_count" "$script_count" "$sepolicy_count"
    update_baseline_diff_after_scan
    conflicts=$(count_get "$COUNT_CONFLICTS_FILE")
    findings=$(count_get "$COUNT_FINDINGS_FILE")
    critical=$(count_get "$COUNT_CRITICAL_FILE")

    if [ "$conflicts" -gt 0 ]; then
        msg "! Конфликтов: $conflicts; находок: $findings; критических: $critical"
        msg "  Отчёт: mcd-ctrl report"
        msg "  JSON:   mcd-ctrl report --json"
    else
        msg "- Опасные конфликты не обнаружены; информационных находок: $findings"
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
        rm -f "$WHITELIST_FILE" "$CONFIG_FILE" "$KNOWN_LOCAL_FILE" "$BASELINE_FILE" 2>/dev/null
        write_default_config
        : > "$WHITELIST_FILE"
        : > "$KNOWN_LOCAL_FILE"
        msg "- Очищены отчёты, временные данные, исключения, пользовательская база и настройки"
    else
        msg "- Очищены отчёты и временные данные"
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
        auto_scan|boot_delay_seconds|replace_examples_limit|script_scan|overlayd_scan|sepolicy_scan|hash_conflicts|known_conflicts|trust_module_priority|baseline_compare_on_scan) return 0 ;;
        *) return 1 ;;
    esac
}

set_config_value() {
    key="$1"; value="$2"; tmp="$TMP_DIR/config.work"
    valid_config_key "$key" || { echo "! Unknown config key: $key"; exit 1; }
    case "$key" in
        auto_scan|script_scan|overlayd_scan|sepolicy_scan|hash_conflicts|known_conflicts|trust_module_priority|baseline_compare_on_scan)
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
    while IFS="$(printf '\t')" read -r key module action rule source; do
        printf 'L\t%s\t%s\t%s\t%s\n' "$key" "$module" "$action" "$rule" >> "$out"
    done < "$SEPOLICY_FILE"
    while IFS="$(printf '\t')" read -r target module source; do
        printf 'R\t%s\t%s\n' "$target" "$module" >> "$out"
    done < "$REPLACE_FILE"
    sort -u "$out" -o "$out" 2>/dev/null
}

snapshot_collect_current() {
    acquire_scan_lock
    cleanup_scan_temp
    previous_deep="$DEEP_MODE"
    previous_profile="$SCAN_PROFILE"
    DEEP_MODE=1
    SCAN_PROFILE="full"
    collect_modules
    build_manifest "$TMP_DIR/current.manifest"
    DEEP_MODE="$previous_deep"
    SCAN_PROFILE="$previous_profile"
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

format_baseline_records() {
    prefix="$1"
    awk -F '\t' -v p="$prefix" '
        $1=="M" {printf "%s модуль %s версия=%s статус=%s\n",p,$2,$3,$4; next}
        $1=="F" {printf "%s находка %s [%s] %s цель=%s\n",p,$2,$3,$4,$5; next}
        $1=="S" && $2=="M" {printf "%s состояние модуля %s имя=%s версия=%s\n",p,$3,$4,$5; next}
        $1=="S" && $2=="F" {printf "%s файл цель=%s модуль=%s тип=%s отпечаток=%s\n",p,$3,$4,$5,$6; next}
        $1=="S" && $2=="P" {printf "%s свойство %s модуль=%s значение=%s\n",p,$3,$4,$5; next}
        $1=="S" && $2=="S" {printf "%s runtime %s модуль=%s значение=%s операция=%s\n",p,$3,$4,$5,$6; next}
        $1=="S" && $2=="L" {printf "%s sepolicy ключ=%s модуль=%s действие=%s правило=%s\n",p,$3,$4,$5,$6; next}
        $1=="S" && $2=="R" {printf "%s replace цель=%s модуль=%s\n",p,$3,$4; next}
        {printf "%s %s\n",p,$0}
    '
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
        echo "Сравнение с baseline"
        echo "Добавлено или изменено: $ac"
        format_baseline_records "+" < "$added"
        echo "Удалено или изменено: $rc"
        format_baseline_records "-" < "$removed"
    } > "$output"
}

update_baseline_diff_after_scan() {
    [ "$(get_config baseline_compare_on_scan 1)" = "1" ] || return 0
    [ -s "$BASELINE_FILE" ] || return 0
    current="$TMP_DIR/baseline-current.manifest"
    baseline_build_current "$current"
    baseline_compare_files "$BASELINE_FILE" "$current" "$BASELINE_DIFF_FILE"
}

refresh_scan_for_baseline() {
    [ -r "$MCD_SELF_BIN" ] || { echo "! CLI недоступен: $MCD_SELF_BIN"; return 1; }
    echo "- Обновляю текущее состояние полным сканированием..." >&2
    sh "$MCD_SELF_BIN" scan --deep --quiet || { echo "! Не удалось обновить состояние"; return 1; }
}

do_baseline() {
    ensure_dirs
    case "$2" in
        create)
            refresh_scan_for_baseline || exit 1
            current="$TMP_DIR/baseline-current.manifest"
            baseline_build_current "$current"
            cp -f "$current" "$BASELINE_FILE"
            rm -f "$BASELINE_DIFF_FILE"
            echo "+ Baseline сохранён: $BASELINE_FILE"
            ;;
        compare|'')
            [ -s "$BASELINE_FILE" ] || { echo "! Baseline отсутствует. Выполните: mcd-ctrl baseline create"; exit 1; }
            refresh_scan_for_baseline || exit 1
            current="$TMP_DIR/baseline-current.manifest"
            baseline_build_current "$current"
            baseline_compare_files "$BASELINE_FILE" "$current" "$BASELINE_DIFF_FILE"
            cat "$BASELINE_DIFF_FILE"
            ;;
        show)
            [ -s "$BASELINE_DIFF_FILE" ] && cat "$BASELINE_DIFF_FILE" || echo "- Последнее сравнение отсутствует. Выполните: mcd-ctrl baseline compare"
            ;;
        raw)
            [ -s "$BASELINE_FILE" ] && cat "$BASELINE_FILE" || echo "- Baseline отсутствует"
            ;;
        reset)
            rm -f "$BASELINE_FILE" "$BASELINE_DIFF_FILE"
            echo "- Baseline и последняя разница удалены"
            ;;
        *) echo "Использование: mcd-ctrl baseline create|compare|show|raw|reset"; exit 1 ;;
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
    sed -E \
        -e 's/("model"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"redacted"/' \
        -e 's/("kernel"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"redacted"/' \
        -e 's/("build_fingerprint"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"redacted"/' \
        -e 's/("root_detection_evidence"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"redacted"/' \
        "$src" > "$dst"
}

export_cleanup() {
    [ -n "${EXPORT_WORK_DIR:-}" ] && rm -rf "$EXPORT_WORK_DIR" 2>/dev/null
}

do_export() {
    ensure_dirs
    redact=0
    case "$2" in --privacy|--redact) redact=1 ;; esac
    stamp=$(date '+%Y%m%d-%H%M%S' 2>/dev/null)
    [ -n "$stamp" ] || stamp="export-$$"
    outdir="${MCD_EXPORT_DIR:-/storage/emulated/0/MCD_Reports}"
    mkdir -p "$outdir" 2>/dev/null || outdir="$EXPORT_FALLBACK_DIR"
    work="$TMP_DIR/export-$stamp"
    rm -rf "$work"; mkdir -p "$work" || { echo "! Не удалось создать временный каталог"; return 1; }
    EXPORT_WORK_DIR="$work"
    trap 'export_cleanup' EXIT HUP INT TERM

    {
        echo "Module Conflict Detector $VERSION ($VERSION_CODE)"
        echo "Export time: $(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null)"
        echo "Device identifiers redacted: $redact"
        echo "Note: module IDs and conflict paths are retained because they are required for diagnosis."
        [ -f "$JSON_FILE" ] && grep -E '"scan_time"|"scan_profile"|"boot_scan"|"root_manager"|"findings_count"|"conflicts_count"|"critical"' "$JSON_FILE"
    } > "$work/summary.txt"
    do_doctor > "$work/doctor.txt" 2>&1
    if [ "$redact" = "1" ]; then
        sed \
            -e 's/^root_detection_evidence=.*/root_detection_evidence=redacted/' \
            -e 's/^kernel=.*/kernel=redacted/' \
            "$work/doctor.txt" > "$work/doctor.redacted"
        mv -f "$work/doctor.redacted" "$work/doctor.txt"
    fi
    [ -f "$LOG_FILE" ] && cp -f "$LOG_FILE" "$work/conflicts.log"
    if [ -f "$JSON_FILE" ]; then
        [ "$redact" = "1" ] && redact_json "$JSON_FILE" "$work/report.json" || cp -f "$JSON_FILE" "$work/report.json"
    fi
    for pair in "$BOOT_LOG_FILE:boot-scan.log" "$BOOT_STATUS_FILE:boot-scan.status" "$MODULE_STATUS_REPORT:module-status.tsv" "$SCAN_MANIFEST_FILE:scan-manifest.tsv" "$FINDINGS_INDEX_FILE:findings.tsv" "$BASELINE_DIFF_FILE:baseline-diff.txt"; do
        src=${pair%%:*}; name=${pair#*:}; [ -f "$src" ] && cp -f "$src" "$work/$name"
    done
    (cd "$work" && { command -v sha256sum >/dev/null 2>&1 && sha256sum * > checksums.sha256 2>/dev/null || cksum * > checksums.cksum 2>/dev/null; })

    archive="$outdir/ModuleConflictDetector-$stamp.zip"
    rc=0
    if command -v zip >/dev/null 2>&1; then
        (cd "$work" && zip -q -r "$archive" .) || rc=$?
    else
        bb=$(find_busybox_zip)
        if [ -n "$bb" ]; then
            (cd "$work" && "$bb" zip -q -r "$archive" .) || rc=$?
        else
            archive="$outdir/ModuleConflictDetector-$stamp.tar.gz"
            tar -czf "$archive" -C "$work" . 2>/dev/null || rc=$?
            [ "$rc" -eq 0 ] && echo "! ZIP недоступен, создан tar.gz"
        fi
    fi
    if [ "$rc" -ne 0 ]; then
        echo "! Не удалось создать диагностический архив (код $rc)"
        export_cleanup
        trap - EXIT HUP INT TERM
        return "$rc"
    fi

    export_cleanup
    trap - EXIT HUP INT TERM
    echo "+ Экспорт: $archive"
}

self_test_line() { printf '[%s] %s\n' "$1" "$2"; }

has_sha_provider() {
    command -v sha256sum >/dev/null 2>&1 && return 0
    for bb in busybox /data/adb/magisk/busybox /data/adb/ap/bin/busybox /data/adb/ksu/bin/busybox; do
        if [ "$bb" = busybox ]; then command -v busybox >/dev/null 2>&1 || continue
        else [ -x "$bb" ] || continue; fi
        "$bb" sha256sum </dev/null >/dev/null 2>&1 && return 0
    done
    return 1
}

validate_json_strict_awk() {
    file="$1"
    [ -s "$file" ] || return 1
    awk '
        function skip_ws(    c) {
            while (pos <= total) {
                c=substr(json,pos,1)
                if (c==" " || c=="\t" || c=="\r" || c=="\n") pos++
                else break
            }
        }
        function parse_string(    c,e,h) {
            if (substr(json,pos,1)!="\"") return 0
            pos++
            while (pos <= total) {
                c=substr(json,pos,1)
                if (c=="\"") { pos++; return 1 }
                if (c=="\\") {
                    pos++
                    if (pos > total) return 0
                    e=substr(json,pos,1)
                    if (e=="\"" || e=="\\" || e=="/" || e=="b" || e=="f" || e=="n" || e=="r" || e=="t") {
                        pos++
                        continue
                    }
                    if (e=="u") {
                        h=substr(json,pos+1,4)
                        if (length(h)!=4 || h !~ /^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$/) return 0
                        pos+=5
                        continue
                    }
                    return 0
                }
                if (c ~ /[[:cntrl:]]/) return 0
                pos++
            }
            return 0
        }
        function parse_number(    rest) {
            rest=substr(json,pos)
            if (match(rest,/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/)) {
                pos+=RLENGTH
                return 1
            }
            return 0
        }
        function parse_literal(word) {
            if (substr(json,pos,length(word))==word) {
                pos+=length(word)
                return 1
            }
            return 0
        }
        function parse_array(    c) {
            if (substr(json,pos,1)!="[") return 0
            pos++
            skip_ws()
            if (substr(json,pos,1)=="]") { pos++; return 1 }
            while (pos <= total) {
                if (!parse_value()) return 0
                skip_ws()
                c=substr(json,pos,1)
                if (c=="]") { pos++; return 1 }
                if (c!=",") return 0
                pos++
                skip_ws()
            }
            return 0
        }
        function parse_object(    c) {
            if (substr(json,pos,1)!="{") return 0
            pos++
            skip_ws()
            if (substr(json,pos,1)=="}") { pos++; return 1 }
            while (pos <= total) {
                if (!parse_string()) return 0
                skip_ws()
                if (substr(json,pos,1)!=":") return 0
                pos++
                skip_ws()
                if (!parse_value()) return 0
                skip_ws()
                c=substr(json,pos,1)
                if (c=="}") { pos++; return 1 }
                if (c!=",") return 0
                pos++
                skip_ws()
            }
            return 0
        }
        function parse_value(    c) {
            skip_ws()
            c=substr(json,pos,1)
            if (c=="{") return parse_object()
            if (c=="[") return parse_array()
            if (c=="\"") return parse_string()
            if (c=="-" || c ~ /[0-9]/) return parse_number()
            if (c=="t") return parse_literal("true")
            if (c=="f") return parse_literal("false")
            if (c=="n") return parse_literal("null")
            return 0
        }
        {
            if (NR==1) json=$0
            else json=json "\n" $0
        }
        END {
            total=length(json)
            pos=1
            ok=parse_value()
            skip_ws()
            exit(ok && pos>total ? 0 : 1)
        }
    ' "$file"
}

validate_report_json() {
    file="$1"
    [ -s "$file" ] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 -m json.tool "$file" >/dev/null 2>&1 || return 1
    elif command -v python >/dev/null 2>&1; then
        python -m json.tool "$file" >/dev/null 2>&1 || return 1
    elif command -v jq >/dev/null 2>&1; then
        jq empty "$file" >/dev/null 2>&1 || return 1
    else
        validate_json_strict_awk "$file" || return 1
    fi
    grep -Eq '^[[:space:]]*\{' "$file" || return 1
    grep -Eq '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$file" || return 1
    grep -Eq '"summary"[[:space:]]*:[[:space:]]*\{' "$file" || return 1
    grep -Eq '"findings"[[:space:]]*:[[:space:]]*\[' "$file" || return 1
    return 0
}


do_self_test() {
    ensure_dirs
    failures=0
    [ -d "$MODULES_DIR" ] && self_test_line OK "module directory" || { self_test_line FAIL "module directory"; failures=$((failures+1)); }
    [ -w "$MCD_DIR" ] && self_test_line OK "runtime directory" || { self_test_line FAIL "runtime directory"; failures=$((failures+1)); }
    for cmd in awk sed grep sort uniq find readlink cmp; do
        command -v "$cmd" >/dev/null 2>&1 && self_test_line OK "$cmd" || { self_test_line FAIL "$cmd"; failures=$((failures+1)); }
    done
    has_sha_provider && self_test_line OK "SHA-256 provider" || { self_test_line FAIL "SHA-256 provider"; failures=$((failures+1)); }
    command -v getprop >/dev/null 2>&1 && self_test_line OK "getprop" || self_test_line WARN "getprop unavailable in host test"
    detect_root_manager_info
    [ "$ROOT_MANAGER" != "unknown" ] && self_test_line OK "root detection: $ROOT_MANAGER" || self_test_line WARN "root detection unknown"
    if [ -f "$JSON_FILE" ]; then
        validate_report_json "$JSON_FILE" && self_test_line OK "report JSON" || { self_test_line FAIL "report JSON invalid"; failures=$((failures+1)); }
    else
        self_test_line WARN "no report yet"
    fi
    [ -r "$MCD_SELF_BIN" ] && self_test_line OK "CLI readable" || { self_test_line FAIL "CLI readable"; failures=$((failures+1)); }
    [ -x "$MCD_MODULE_ROOT/bin/mcd-boot-scan" ] && self_test_line OK "boot helper executable" || { self_test_line FAIL "boot helper executable"; failures=$((failures+1)); }
    [ -x "$MCD_MODULE_ROOT/service.sh" ] && [ -x "$MCD_MODULE_ROOT/boot-completed.sh" ] && self_test_line OK "boot hooks executable" || { self_test_line FAIL "boot hooks executable"; failures=$((failures+1)); }

    if [ "$2" = "--full" ]; then
        box="$TMP_DIR/self-test-$$"
        rm -rf "$box"
        mkdir -p "$box/bin" "$box/modules/A/system/etc" "$box/modules/B/system/etc" "$box/live/system/etc" "$box/data" "$box/root"
        cat > "$box/bin/getprop" <<'GETPROP'
#!/bin/sh
case "$1" in
  ro.build.version.release) echo 13 ;;
  ro.build.version.sdk) echo 33 ;;
  ro.product.cpu.abi) echo arm64-v8a ;;
  ro.product.model) echo TestDevice ;;
  ro.build.fingerprint) echo test/fingerprint ;;
  debug.mcd.fixture) echo 2 ;;
  sys.boot_completed) echo 1 ;;
  *) echo ;;
esac
GETPROP
        chmod 0755 "$box/bin/getprop"
        printf 'id=A\nname=Fixture A\nversion=1.0\npriority=100\n' > "$box/modules/A/module.prop"
        printf 'id=B\nname=Fixture B\nversion=2.0\npriority=1\n' > "$box/modules/B/module.prop"
        printf 'A\n' > "$box/modules/A/system/etc/mcd-test.conf"
        printf 'B\n' > "$box/modules/B/system/etc/mcd-test.conf"
        cp "$box/modules/B/system/etc/mcd-test.conf" "$box/live/system/etc/mcd-test.conf"
        touch "$box/modules/A/system/etc/.replace" "$box/modules/B/system/etc/.replace"
        printf 'debug.mcd.fixture=1\n' > "$box/modules/A/system.prop"
        printf 'debug.mcd.fixture=2\n' > "$box/modules/B/system.prop"
        printf 'allow fixture_src fixture_tgt fixture_class fixture_perm\n' > "$box/modules/A/sepolicy.rule"
        printf 'deny fixture_src fixture_tgt fixture_class fixture_perm\n' > "$box/modules/B/sepolicy.rule"

        test_path="$box/bin:$PATH"
        PATH="$test_path" MCD_DIR="$box/data" MCD_MODULES_DIR="$box/modules" MCD_LIVE_ROOT="$box/live" MCD_ROOT_DATA_ADB="$box/root" MCD_SU_BINARY="" MCD_SELF_BIN="$MCD_SELF_BIN" sh "$MCD_SELF_BIN" scan --deep --quiet >/dev/null 2>&1
        first_ids="$box/ids.first"
        cut -f1 "$box/data/findings.tsv" | sort > "$first_ids"
        duplicate_ids=$(uniq -d "$first_ids")
        if [ -z "$duplicate_ids" ]; then
            self_test_line OK "unique finding IDs"
        else
            self_test_line FAIL "duplicate finding IDs: $duplicate_ids"; failures=$((failures+1))
        fi
        replace_id_count=$(awk -F '\t' '$3=="replace_masks_tree" {print $1}' "$box/data/findings.tsv" | sort -u | wc -l | tr -d ' ')
        [ "$replace_id_count" = "2" ] && self_test_line OK "distinct replace finding IDs" || { self_test_line FAIL "distinct replace finding IDs"; failures=$((failures+1)); }
        printf '{"version":"v1.4","summary":{},"findings":[invalid]}\n' > "$box/invalid.json"
        if validate_json_strict_awk "$box/invalid.json"; then
            self_test_line FAIL "strict malformed JSON rejection"; failures=$((failures+1))
        else
            self_test_line OK "strict malformed JSON rejection"
        fi
        validate_json_strict_awk "$box/data/report.json" && self_test_line OK "strict valid JSON acceptance" || { self_test_line FAIL "strict valid JSON acceptance"; failures=$((failures+1)); }
        if validate_report_json "$box/data/report.json" && \
           grep -q 'path_content_conflict' "$box/data/report.json" && \
           grep -q 'property_value_conflict' "$box/data/report.json" && \
           grep -q 'sepolicy_rule_conflict' "$box/data/report.json" && \
           grep -Eq '"target":"/system/etc".*"severity":"HIGH"' "$box/data/report.json" && \
           grep -Eq '"winner":"B".*"winner_method":"live_content_match"' "$box/data/report.json" && \
           ! grep -q 'lexical_module_id_heuristic' "$box/data/report.json"; then
            self_test_line OK "sandbox conflict fixture"
        else
            self_test_line FAIL "sandbox conflict fixture"; failures=$((failures+1))
        fi

        PATH="$test_path" MCD_DIR="$box/data" MCD_MODULES_DIR="$box/modules" MCD_LIVE_ROOT="$box/live" MCD_ROOT_DATA_ADB="$box/root" MCD_SU_BINARY="" MCD_SELF_BIN="$MCD_SELF_BIN" sh "$MCD_SELF_BIN" scan --deep --quiet >/dev/null 2>&1
        cut -f1 "$box/data/findings.tsv" | sort > "$box/ids.second"
        cmp -s "$first_ids" "$box/ids.second" && self_test_line OK "stable finding IDs" || { self_test_line FAIL "stable finding IDs"; failures=$((failures+1)); }

        cat > "$box/fake-scan" <<EOFSCAN
#!/bin/sh
count_file="$box/boot-count"
n=0
[ -f "\$count_file" ] && n=\$(cat "\$count_file")
echo \$((n + 1)) > "\$count_file"
exit 0
EOFSCAN
        chmod 0755 "$box/fake-scan"
        printf 'boot-test-id\n' > "$box/boot-id"
        mkdir -p "$box/boot-data"
        printf 'auto_scan=1\nboot_delay_seconds=0\n' > "$box/boot-data/config.conf"
        MCD_DIR="$box/boot-data" MCD_BOOT_BIN="$box/fake-scan" MCD_BOOT_ID_FILE="$box/boot-id" sh "$MCD_MODULE_ROOT/bin/mcd-boot-scan" boot-completed >/dev/null 2>&1
        MCD_DIR="$box/boot-data" MCD_BOOT_BIN="$box/fake-scan" MCD_BOOT_ID_FILE="$box/boot-id" sh "$MCD_MODULE_ROOT/bin/mcd-boot-scan" boot-completed >/dev/null 2>&1
        [ "$(cat "$box/boot-count" 2>/dev/null)" = "1" ] && self_test_line OK "boot scan deduplication" || { self_test_line FAIL "boot scan deduplication"; failures=$((failures+1)); }
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
  scan          Быстрая проверка
  scan --deep   Полная проверка
  report        Последний отчёт
  explain ID    Объяснить находку
  baseline      Сравнить состояние
  export        Экспорт диагностики
  self-test     Самопроверка
  boot-status   Статус автозапуска
  doctor        Диагностика
  snapshot      Снимки
  config        Настройки
  help-all      Полная справка

Примеры:
  mcd-ctrl scan --deep
  mcd-ctrl report
EOFHELP
}

show_help_all() {
    cat <<EOFHELP
Module Conflict Detector $VERSION

scan [--deep] [--quiet]
  Без --deep: файлы, .replace, system.prop,
  статусы модулей и известные пары.
  С --deep: дополнительно скрипты,
  overlay.d и sepolicy.rule.

report [--json|--text|--critical-only]
explain ID
baseline create|compare|show|raw|reset
export [--privacy|--redact]
self-test [--full]
snapshot create [NAME]|list|compare NAME|delete NAME
whitelist add|remove|list [TARGET]
config list|get|set [KEY] [VALUE]
boot-status
doctor
clear [--all]
version

Основные классы:
  path_content_conflict
  path_duplicate_identical
  replace_dir_collision
  replace_masks_tree
  property_value_conflict
  property_duplicate_same_value
  script_resource_conflict
  script_duplicate_same_action
  sepolicy_rule_conflict
  sepolicy_audit_conflict
  sepolicy_duplicate_rule
  known_module_pair
  global_overlayd_inventory

Определение победителя:
  live/current match = подтверждено
  user priority hint = слабая эвристика
  unresolved = доказательств недостаточно

Параметр trust_module_priority по умолчанию
отключён, поскольку priority не является
универсальным стандартом root-менеджеров.
EOFHELP
}
