show_main_menu() {
    if [ "$(lang_get)" = "ru" ]; then
        cat <<EOF

Module Conflict Detector $VERSION

1. Быстрое сканирование
2. Показать отчёт
3. Расширенное меню
4. English
0. Выход
EOF
        printf 'Выбор: '
    else
        cat <<EOF

Module Conflict Detector $VERSION

1. Quick scan
2. Show report
3. Advanced menu
4. Русский
0. Exit
EOF
        printf 'Select: '
    fi
}

show_advanced_menu() {
    if [ "$(lang_get)" = "ru" ]; then
        cat <<'EOF'

Расширенное меню

1. Глубокое сканирование
2. Только критические
3. Краткий итог
4. Диагностика
5. Статус автосканирования
6. Снимки состояния
7. История проверок
8. Сравнить две проверки
9. Создать пакет диагностики
10. Кэш SHA-256
11. Настройки
12. Whitelist
13. English
0. Назад
EOF
        printf 'Выбор: '
    else
        cat <<'EOF'

Advanced menu

1. Deep scan
2. Critical findings only
3. Summary
4. Diagnostics
5. Boot scan status
6. Snapshots
7. Scan history
8. Compare two scans
9. Create support bundle
10. SHA-256 cache
11. Configuration
12. Whitelist
13. Русский
0. Back
EOF
        printf 'Select: '
    fi
}

snapshot_menu() {
    if [ "$(lang_get)" = "ru" ]; then
        printf '1.Создать  2.Список  3.Сравнить  4.Удалить  0.Назад\nВыбор: '
    else
        printf '1.Create  2.List  3.Compare  4.Delete  0.Back\nSelect: '
    fi
    IFS= read -r choice
    case "$choice" in
        1) printf 'Name (optional): '; IFS= read -r name; do_snapshot snapshot create "$name" ;;
        2) do_snapshot snapshot list ;;
        3) printf 'Name: '; IFS= read -r name; do_snapshot snapshot compare "$name" ;;
        4) printf 'Name: '; IFS= read -r name; do_snapshot snapshot delete "$name" ;;
    esac
}

advanced_menu() {
    while :; do
        show_advanced_menu
        IFS= read -r choice || return
        case "$choice" in
            1) DEEP_MODE=1; CRITICAL_ONLY=0; SCAN_STARTED_EPOCH=$(date +%s 2>/dev/null); do_scan scan --deep; do_summary; pause_menu ;;
            2) report_critical_only; pause_menu ;;
            3) do_summary; pause_menu ;;
            4) do_doctor; pause_menu ;;
            5) do_boot_status; pause_menu ;;
            6) snapshot_menu; pause_menu ;;
            7) do_history history list; pause_menu ;;
            8) do_diff diff; pause_menu ;;
            9) do_support_bundle; pause_menu ;;
            10) do_cache cache status; pause_menu ;;
            11) do_config config list; pause_menu ;;
            12) do_whitelist whitelist list; pause_menu ;;
            13) toggle_language ;;
            0) return ;;
            *) : ;;
        esac
    done
}

do_interactive() {
    ensure_dirs
    while :; do
        show_main_menu
        IFS= read -r choice || return
        case "$choice" in
            1) DEEP_MODE=0; CRITICAL_ONLY=0; SCAN_STARTED_EPOCH=$(date +%s 2>/dev/null); do_scan scan; do_summary; pause_menu ;;
            2) do_report report; pause_menu ;;
            3) advanced_menu ;;
            4) toggle_language ;;
            0) return ;;
            *) : ;;
        esac
    done
}

show_help() {
    ensure_dirs
    if [ "$(lang_get)" = "ru" ]; then
        cat <<EOF
Module Conflict Detector $VERSION

mcd-ctrl                 Интерактивное меню
mcd-ctrl scan --deep     Глубокая проверка
mcd-ctrl report          Отчёт
mcd-ctrl summary         Краткий итог
mcd-ctrl explain ID      Объяснить находку
mcd-ctrl history         История
mcd-ctrl diff            Сравнить проверки
mcd-ctrl support-bundle  Пакет диагностики
mcd-ctrl help-all        Все команды
EOF
    else
        cat <<EOF
Module Conflict Detector $VERSION

mcd-ctrl                 Interactive menu
mcd-ctrl scan --deep     Deep scan
mcd-ctrl report          Report
mcd-ctrl summary         Summary
mcd-ctrl explain ID      Explain finding
mcd-ctrl history         History
mcd-ctrl diff            Compare scans
mcd-ctrl support-bundle  Diagnostic bundle
mcd-ctrl help-all        All commands
EOF
    fi
}

show_help_all() {
    cat <<EOF
Module Conflict Detector $VERSION ($VERSION_CODE)

mcd-ctrl | menu
mcd-ctrl scan [--deep] [--quiet] [--critical-only]
mcd-ctrl report [--json|--text|--critical-only]
mcd-ctrl report --severity LEVEL
mcd-ctrl report --module MODULE_ID
mcd-ctrl report --id FINDING_ID
mcd-ctrl summary
mcd-ctrl explain FINDING_ID
mcd-ctrl history [list|show LAST|show NAME]
mcd-ctrl diff [OLD NEW]
mcd-ctrl support-bundle
mcd-ctrl cache [status|clear]
mcd-ctrl snapshot create [NAME]|list|compare NAME|delete NAME
mcd-ctrl whitelist add|remove|list [TARGET]
mcd-ctrl config list|get|set [KEY] [VALUE]
mcd-ctrl doctor
mcd-ctrl boot-status
mcd-ctrl clear [--all]
mcd-ctrl version
EOF
}

# v1.4 removes lexical owner guessing for properties and .replace collisions.
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
        if [ "$count" -eq 1 ]; then
            WINNER="$matches"; WINNER_CONF=90; WINNER_METHOD="current_property_value_match"; return
        fi
        if [ "$count" -gt 1 ]; then
            WINNER=""; WINNER_CONF=35; WINNER_METHOD="current_value_matches_multiple_modules"; return
        fi
    fi
}

process_replace_conflicts() {
    build_replace_groups
    if [ -s "$REPLACE_GROUP_FILE" ]; then
        while IFS="$(printf '\t')" read -r path owners; do
            [ -n "$path" ] || continue
            in_whitelist "$path" && continue
            severity=$(severity_of_path "$path")
            add_finding "replace_dir_collision" "$path" "$severity" "$owners" "" 0 "unresolved" "multiple active modules declare .replace for the same directory" "[]" 1
        done < "$REPLACE_GROUP_FILE"
    fi

    build_replace_masks
    [ -s "$REPLACE_MASK_FILE" ] || return
    limit=$(get_config replace_examples_limit 20)
    case "$limit" in ''|*[!0-9]*) limit=20 ;; esac
    awk -F '\t' -v limit="$limit" 'BEGIN{OFS="\t"}
        function addu(list,item){if(item=="")return list;if(index(" "list" "," "item" ")>0)return list;return list==""?item:list" "item}
        function flush(){if(key!="")print dir,replacer,affected,count,examples}
        {
            newkey=$1 FS $2
            if(NR==1||newkey!=key){flush();key=newkey;dir=$1;replacer=$2;affected=$3;count=1;examples=$4;ex=1}
            else{affected=addu(affected,$3);count++;if(ex<limit){examples=examples", "$4;ex++}}
        }
        END{flush()}
    ' "$REPLACE_MASK_FILE" > "$TMP_DIR/replace-mask-groups.work"

    while IFS="$(printf '\t')" read -r path replacer affected count examples; do
        owners="$replacer $affected"
        severity=$(severity_of_path "$path")
        detail="replace_owner=$replacer; masked_entries=$count; examples=$examples"
        add_finding "replace_masks_tree" "$path" "$severity" "$owners" "$replacer" 100 "explicit_replace_owner" "$detail" "[]" 1
    done < "$TMP_DIR/replace-mask-groups.work"
}
