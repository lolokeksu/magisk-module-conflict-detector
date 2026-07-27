add_finding() {
    type="$1"; target="$2"; severity="$3"; owners="$4"; winner="$5"
    confidence="$6"; method="$7"; detail="$8"; evidence_json="$9"; is_conflict="${10}"
    [ -n "$evidence_json" ] || evidence_json="[]"
    case "$confidence" in ''|*[!0-9]*) confidence=0 ;; esac
    id=$(stable_finding_id "$type" "$target")
    status=$(finding_status "$is_conflict" "$confidence" "$method")
    modules_json=$(owners_to_json "$owners")
    et=$(json_escape "$type"); ep=$(json_escape "$target"); es=$(json_escape "$severity")
    ew=$(json_escape "$winner"); em=$(json_escape "$method"); ed=$(json_escape "$detail")
    ei=$(json_escape "$id"); est=$(json_escape "$status")
    [ "$is_conflict" = "1" ] && conflict_json=true || conflict_json=false

    {
        printf '[%s][%s][%s] %s\n' "$severity" "$status" "$id" "$target"
        printf '    type: %s\n' "$type"
        printf '    modules: %s\n' "$owners"
        if [ -n "$winner" ]; then
            printf '    effective_winner: %s (%s%%, %s)\n' "$winner" "$confidence" "$method"
        else
            printf '    effective_winner: unresolved (0%%, %s)\n' "$method"
        fi
        [ -n "$detail" ] && printf '    detail: %s\n' "$detail"
        printf '\n'
    } >> "$LOG_FILE"

    printf '{"finding_id":"%s","type":"%s","target":"%s","severity":"%s","status":"%s","is_conflict":%s,"modules":[%s],"winner":"%s","winner_confidence":%s,"winner_method":"%s","detail":"%s","evidence":%s}\n' \
        "$ei" "$et" "$ep" "$es" "$est" "$conflict_json" "$modules_json" "$ew" "$confidence" "$em" "$ed" "$evidence_json" >> "$JSON_ITEMS_FILE"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$type" "$(clean_tsv "$target")" "$severity" "$status" "$(clean_tsv "$owners")" \
        "$(clean_tsv "$winner")" "$confidence" "$method" "$(clean_tsv "$detail")" "$is_conflict" >> "$FINDING_INDEX_FILE"

    count_inc "$COUNT_FINDINGS_FILE"
    [ "$is_conflict" = "1" ] && count_inc "$COUNT_CONFLICTS_FILE"
    case "$severity" in
        CRITICAL) count_inc "$COUNT_CRITICAL_FILE" ;;
        HIGH) count_inc "$COUNT_HIGH_FILE" ;;
        MEDIUM) count_inc "$COUNT_MEDIUM_FILE" ;;
        LOW) count_inc "$COUNT_LOW_FILE" ;;
        *) count_inc "$COUNT_INFO_FILE" ;;
    esac
    case "$status" in
        CONFIRMED) count_inc "$COUNT_CONFIRMED_FILE" ;;
        PROBABLE) count_inc "$COUNT_PROBABLE_FILE" ;;
        POSSIBLE) count_inc "$COUNT_POSSIBLE_FILE" ;;
        *) count_inc "$COUNT_INFORMATIONAL_FILE" ;;
    esac
}

mountinfo_winner() {
    path="$1"
    owners="$2"
    file="$PROC_ROOT/self/mountinfo"
    [ -r "$file" ] || file="$PROC_ROOT/1/mountinfo"
    [ -r "$file" ] || return 1
    line=$(awk -v p="$path" '$5==p {last=$0} END{print last}' "$file" 2>/dev/null)
    [ -n "$line" ] || return 1
    matches=""
    for owner in $owners; do
        case "$line" in
            *"/data/adb/modules/$owner/"*|*"/data/adb/modules/$owner "*) matches="$matches $owner" ;;
        esac
    done
    matches=$(printf '%s\n' "$matches" | tr ' ' '\n' | sed '/^$/d' | sort -u)
    count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
    [ "$count" = "1" ] || return 1
    printf '%s' "$matches"
}

inode_signature() {
    file="$1"
    if command -v stat >/dev/null 2>&1; then stat -c '%d:%i:%s' "$file" 2>/dev/null && return; fi
    if command -v busybox >/dev/null 2>&1; then busybox stat -c '%d:%i:%s' "$file" 2>/dev/null && return; fi
}

analyze_path_candidates() {
    path="$1"
    owners="$2"
    candidate="$TMP_DIR/path.candidate"
    : > "$candidate"
    awk -F '\t' -v p="$path" '$1==p {print}' "$ENTRY_FILE" > "$candidate"

    evidence=""
    hashes="$TMP_DIR/path.hashes.work"
    : > "$hashes"
    hash_enabled=$(get_config hash_conflicts 1)
    [ "$DEEP_MODE" = "1" ] && hash_enabled=1
    while IFS="$(printf '\t')" read -r target module kind source; do
        [ -n "$module" ] || continue
        if [ "$hash_enabled" = "1" ]; then fp=$(fingerprint_source "$kind" "$source"); else fp="not-computed:$kind"; fi
        printf '%s\t%s\t%s\n' "$module" "$fp" "$source" >> "$hashes"
        jm=$(json_escape "$module"); jk=$(json_escape "$kind"); js=$(json_escape "$source"); jf=$(json_escape "$fp")
        item="{\"module\":\"$jm\",\"kind\":\"$jk\",\"source\":\"$js\",\"fingerprint\":\"$jf\"}"
        [ -n "$evidence" ] && evidence="$evidence,$item" || evidence="$item"
    done < "$candidate"
    EVIDENCE_JSON="[$evidence]"

    unique_hashes=$(cut -f2 "$hashes" 2>/dev/null | sort -u | wc -l | tr -d ' ')
    case "$unique_hashes" in ''|*[!0-9]*) unique_hashes=0 ;; esac
    if [ "$hash_enabled" != "1" ]; then HASH_STATE="unhashed"
    elif grep -q 'unavailable:' "$hashes" 2>/dev/null; then HASH_STATE="unavailable"
    elif [ "$unique_hashes" -le 1 ]; then HASH_STATE="identical"
    else HASH_STATE="different"; fi

    WINNER=""; WINNER_CONF=0; WINNER_METHOD="unresolved"
    mounted_owner=$(mountinfo_winner "$path" "$owners")
    if [ -n "$mounted_owner" ]; then
        WINNER="$mounted_owner"; WINNER_CONF=100; WINNER_METHOD="mount_source_match"; return
    fi

    live="$LIVE_ROOT$path"
    if [ -e "$live" ] || [ -L "$live" ]; then
        live_inode=$(inode_signature "$live")
        if [ -n "$live_inode" ]; then
            inode_matches=""
            while IFS="$(printf '\t')" read -r module fp source; do
                [ "$(inode_signature "$source")" = "$live_inode" ] && inode_matches="$inode_matches $module"
            done < "$hashes"
            inode_matches=$(printf '%s\n' "$inode_matches" | tr ' ' '\n' | sed '/^$/d' | sort -u)
            inode_count=$(printf '%s\n' "$inode_matches" | sed '/^$/d' | wc -l | tr -d ' ')
            if [ "$inode_count" = "1" ]; then WINNER="$inode_matches"; WINNER_CONF=98; WINNER_METHOD="live_inode_match"; return; fi
        fi
    fi

    livefp=""
    [ "$hash_enabled" = "1" ] && livefp=$(fingerprint_live "$path")
    case "$livefp" in unavailable:*|unknown) livefp="" ;; esac
    if [ -n "$livefp" ]; then
        matches=$(awk -F '\t' -v f="$livefp" '$2==f {print $1}' "$hashes" | sort -u)
        match_count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
        case "$match_count" in ''|*[!0-9]*) match_count=0 ;; esac
        if [ "$match_count" -eq 1 ]; then WINNER="$matches"; WINNER_CONF=95; WINNER_METHOD="live_content_match"; return; fi
        if [ "$match_count" -gt 1 ]; then WINNER=""; WINNER_CONF=40; WINNER_METHOD="live_content_matches_multiple_modules"; return; fi
    fi
}

# Improved literal-oriented shell parser. Dynamic expressions are retained as
# evidence but never treated as proven values.
