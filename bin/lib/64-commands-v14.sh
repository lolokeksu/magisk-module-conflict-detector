do_report() {
    case "$2" in
        --json) [ -f "$JSON_FILE" ] && cat "$JSON_FILE" || echo '{"error":"no scan data","hint":"run mcd-ctrl scan"}' ;;
        --critical-only) report_critical_only ;;
        --severity) [ -n "$3" ] || { echo "Usage: mcd-ctrl report --severity LEVEL"; return 1; }; filter_report severity "$3" ;;
        --module) [ -n "$3" ] || { echo "Usage: mcd-ctrl report --module MODULE_ID"; return 1; }; filter_report module "$3" ;;
        --id) [ -n "$3" ] || { echo "Usage: mcd-ctrl report --id FINDING_ID"; return 1; }; filter_report id "$3" ;;
        --text|'') [ -s "$LOG_FILE" ] && cat "$LOG_FILE" || echo "- No text report. Run: mcd-ctrl scan" ;;
        *) echo "Usage: mcd-ctrl report [--json|--text|--critical-only|--severity LEVEL|--module ID|--id FINDING_ID]"; return 1 ;;
    esac
}

latest_history_files() {
    find "$HISTORY_DIR" -maxdepth 1 -type f -name '*.tsv' 2>/dev/null | sort -r
}

do_history() {
    ensure_dirs
    case "$2" in
        show)
            name="$3"
            if [ -z "$name" ] || [ "$name" = "LAST" ]; then file=$(find "$HISTORY_DIR" -maxdepth 1 -type f -name '*.log' 2>/dev/null | sort -r | head -n 1)
            else file="$HISTORY_DIR/${name%.log}.log"; fi
            [ -f "$file" ] && cat "$file" || echo "- History entry not found"
            ;;
        list|'')
            found=0
            for file in $(find "$HISTORY_DIR" -maxdepth 1 -type f -name '*.json' 2>/dev/null | sort -r); do
                found=1; basename "$file" .json
            done
            [ "$found" = "1" ] || echo "- No scan history"
            ;;
        *) echo "Usage: mcd-ctrl history [list|show LAST|show NAME]"; return 1 ;;
    esac
}

do_diff() {
    ensure_dirs
    a="$2"; b="$3"
    if [ -n "$a" ] && [ -n "$b" ]; then
        old="$HISTORY_DIR/${a%.tsv}.tsv"; new="$HISTORY_DIR/${b%.tsv}.tsv"
    else
        files=$(latest_history_files | head -n 2)
        new=$(printf '%s\n' "$files" | sed -n '1p'); old=$(printf '%s\n' "$files" | sed -n '2p')
    fi
    [ -f "$old" ] && [ -f "$new" ] || { echo "- Two history scans are required"; return 1; }
    old_ids="$TMP_DIR/diff-old.work"; new_ids="$TMP_DIR/diff-new.work"
    cut -f1 "$old" | sort -u > "$old_ids"; cut -f1 "$new" | sort -u > "$new_ids"
    added="$TMP_DIR/diff-added.work"; removed="$TMP_DIR/diff-removed.work"
    awk 'NR==FNR{a[$0]=1;next}!($0 in a){print}' "$old_ids" "$new_ids" > "$added"
    awk 'NR==FNR{a[$0]=1;next}!($0 in a){print}' "$new_ids" "$old_ids" > "$removed"
    echo "Old: $(basename "$old" .tsv)"
    echo "New: $(basename "$new" .tsv)"
    echo "Added findings: $(wc -l < "$added" | tr -d ' ')"
    while IFS= read -r id; do [ -n "$id" ] && awk -F '\t' -v id="$id" '$1==id {print}' "$new"; done < "$added"
    echo "Removed findings: $(wc -l < "$removed" | tr -d ' ')"
    while IFS= read -r id; do [ -n "$id" ] && awk -F '\t' -v id="$id" '$1==id {print}' "$old"; done < "$removed"
}

lang_get() {
    lang=$(get_config language ru)
    case "$lang" in ru|en) printf '%s' "$lang" ;; *) printf 'ru' ;; esac
}

do_explain() {
    ensure_dirs
    id="$2"
    [ -n "$id" ] || { echo "Usage: mcd-ctrl explain FINDING_ID"; return 1; }
    [ -f "$CURRENT_INDEX_FILE" ] || { echo "- No finding index. Run: mcd-ctrl scan"; return 1; }
    row=$(awk -F '\t' -v id="$id" '$1==id {print; exit}' "$CURRENT_INDEX_FILE")
    [ -n "$row" ] || { echo "- Finding not found: $id"; return 1; }
    IFS="$(printf '\t')" read -r fid type target severity status owners winner confidence method detail is_conflict <<EOFROW
$row
EOFROW
    if [ "$(lang_get)" = "ru" ]; then
        echo "ID: $fid"; echo "Тип: $type"; echo "Цель: $target"; echo "Опасность: $severity"; echo "Достоверность: $status"
        echo "Модули: $owners"; [ -n "$winner" ] && echo "Применён: $winner" || echo "Применён: не определён"
        echo "Метод: $method"; echo "Уверенность: $confidence%"; echo "Подробности: $detail"
    else
        echo "ID: $fid"; echo "Type: $type"; echo "Target: $target"; echo "Severity: $severity"; echo "Evidence status: $status"
        echo "Modules: $owners"; [ -n "$winner" ] && echo "Effective: $winner" || echo "Effective: unresolved"
        echo "Method: $method"; echo "Confidence: $confidence%"; echo "Details: $detail"
    fi
}

do_summary() {
    [ -f "$JSON_FILE" ] || { echo "- No report. Run: mcd-ctrl scan"; return 1; }
    value(){ grep -m1 "\"$1\"" "$JSON_FILE" | sed 's/.*:[[:space:]]*//;s/[,\"]//g'; }
    if [ "$(lang_get)" = "ru" ]; then
        echo "Module Conflict Detector $VERSION"
        echo "Модулей: $(value modules_total)"
        echo "Конфликтов: $(value conflicts_count)"
        echo "Подтверждённых: $(value confirmed)"
        echo "Вероятных: $(value probable)"
        echo "Возможных: $(value possible)"
        echo "Информационных: $(value informational)"
        echo "CRITICAL: $(value critical)  HIGH: $(value high)  MEDIUM: $(value medium)  LOW: $(value low)"
        echo "Время: $(value scan_duration_seconds) сек."
    else
        echo "Module Conflict Detector $VERSION"
        echo "Modules: $(value modules_total)"
        echo "Conflicts: $(value conflicts_count)"
        echo "Confirmed: $(value confirmed)"
        echo "Probable: $(value probable)"
        echo "Possible: $(value possible)"
        echo "Informational: $(value informational)"
        echo "CRITICAL: $(value critical)  HIGH: $(value high)  MEDIUM: $(value medium)  LOW: $(value low)"
        echo "Duration: $(value scan_duration_seconds) sec."
    fi
}

do_cache() {
    ensure_dirs
    case "$2" in
        clear) : > "$HASH_CACHE_FILE"; echo "- Hash cache cleared" ;;
        status|'')
            lines=$(wc -l < "$HASH_CACHE_FILE" 2>/dev/null | tr -d ' '); [ -n "$lines" ] || lines=0
            bytes=$(wc -c < "$HASH_CACHE_FILE" 2>/dev/null | tr -d ' '); [ -n "$bytes" ] || bytes=0
            echo "hash_cache_entries=$lines"; echo "hash_cache_bytes=$bytes"; echo "hash_cache_file=$HASH_CACHE_FILE"
            ;;
        *) echo "Usage: mcd-ctrl cache [status|clear]"; return 1 ;;
    esac
}

do_support_bundle() {
    ensure_dirs
    stamp=$(date '+%Y%m%d-%H%M%S' 2>/dev/null); [ -n "$stamp" ] || stamp="unknown"
    out_dir="/sdcard/ModuleConflictDetector"
    mkdir -p "$out_dir" 2>/dev/null || out_dir="/data/local/tmp/ModuleConflictDetector"
    mkdir -p "$out_dir" 2>/dev/null || { echo "! Cannot create support directory"; return 1; }
    work="$TMP_DIR/support-$stamp"; rm -rf "$work"; mkdir -p "$work"
    do_doctor > "$work/doctor.txt" 2>&1
    [ -f "$JSON_FILE" ] && cp "$JSON_FILE" "$work/report.json"
    [ -f "$LOG_FILE" ] && cp "$LOG_FILE" "$work/conflicts.log"
    [ -f "$BOOT_LOG_FILE" ] && cp "$BOOT_LOG_FILE" "$work/boot-scan.log"
    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$work/config.conf"
    [ -f "$CURRENT_INDEX_FILE" ] && cp "$CURRENT_INDEX_FILE" "$work/findings-index.tsv"
    collect_module_states; cp "$MODULE_STATE_FILE" "$work/modules.tsv" 2>/dev/null
    archive="$out_dir/MCD-support-$stamp.tar.gz"
    if command -v tar >/dev/null 2>&1; then tar -czf "$archive" -C "$work" . 2>/dev/null
    elif command -v busybox >/dev/null 2>&1; then busybox tar -czf "$archive" -C "$work" . 2>/dev/null
    else echo "! tar not available"; rm -rf "$work"; return 1; fi
    rm -rf "$work"
    [ -f "$archive" ] && echo "+ Support bundle: $archive" || { echo "! Support bundle failed"; return 1; }
}

toggle_language() {
    ensure_dirs
    [ "$(lang_get)" = "ru" ] && set_config_value language en || set_config_value language ru
}

pause_menu() {
    [ "$(lang_get)" = "ru" ] && printf '\nНажмите Enter...' || printf '\nPress Enter...'
    IFS= read -r _mcd_pause
}

