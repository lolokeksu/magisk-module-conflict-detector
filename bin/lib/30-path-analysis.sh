fingerprint_source() {
    kind="$1"
    source="$2"
    case "$kind" in
        symlink)
            target=$(readlink "$source" 2>/dev/null)
            [ -n "$target" ] && printf 'link:%s' "$target" || printf 'unavailable:symlink'
            ;;
        whiteout)
            printf 'whiteout:char-device'
            ;;
        file)
            if command -v sha256sum >/dev/null 2>&1; then
                hash=$(sha256sum "$source" 2>/dev/null | awk '{print $1}')
                [ -n "$hash" ] && { printf 'sha256:%s' "$hash"; return; }
            fi
            if command -v busybox >/dev/null 2>&1; then
                hash=$(busybox sha256sum "$source" 2>/dev/null | awk '{print $1}')
                [ -n "$hash" ] && { printf 'sha256:%s' "$hash"; return; }
            fi
            if command -v cksum >/dev/null 2>&1; then
                fallback=$(cksum "$source" 2>/dev/null | awk '{printf "cksum:%s:%s", $1, $2}')
                [ -n "$fallback" ] && printf '%s' "$fallback" || printf 'unavailable:file'
            else
                printf 'unavailable:file'
            fi
            ;;
        *) printf 'unknown' ;;
    esac
}

fingerprint_live() {
    target="$1"
    live="$LIVE_ROOT$target"
    if [ -L "$live" ]; then
        printf 'link:%s' "$(readlink "$live" 2>/dev/null)"
    elif [ -f "$live" ]; then
        fingerprint_source file "$live"
    elif [ -c "$live" ]; then
        printf 'whiteout:char-device'
    else
        printf ''
    fi
}

lexical_winner() {
    printf '%s\n' $1 | LC_ALL=C sort 2>/dev/null | tail -n 1
}

add_finding() {
    type="$1"
    target="$2"
    severity="$3"
    owners="$4"
    winner="$5"
    confidence="$6"
    method="$7"
    detail="$8"
    evidence_json="$9"
    is_conflict="${10}"

    [ -n "$evidence_json" ] || evidence_json="[]"
    modules_json=$(owners_to_json "$owners")
    et=$(json_escape "$type")
    ep=$(json_escape "$target")
    es=$(json_escape "$severity")
    ew=$(json_escape "$winner")
    em=$(json_escape "$method")
    ed=$(json_escape "$detail")
    case "$confidence" in ''|*[!0-9]*) confidence=0 ;; esac
    [ "$is_conflict" = "1" ] && conflict_json=true || conflict_json=false

    {
        printf '[%s][%s] %s\n' "$severity" "$type" "$target"
        printf '    modules: %s\n' "$owners"
        [ -n "$winner" ] && printf '    effective_or_likely_winner: %s (%s%%, %s)\n' "$winner" "$confidence" "$method"
        [ -n "$detail" ] && printf '    detail: %s\n' "$detail"
        printf '\n'
    } >> "$LOG_FILE"

    printf '{"type":"%s","target":"%s","severity":"%s","is_conflict":%s,"modules":[%s],"winner":"%s","winner_confidence":%s,"winner_method":"%s","detail":"%s","evidence":%s}\n' \
        "$et" "$ep" "$es" "$conflict_json" "$modules_json" "$ew" "$confidence" "$em" "$ed" "$evidence_json" >> "$JSON_ITEMS_FILE"

    count_inc "$COUNT_FINDINGS_FILE"
    [ "$is_conflict" = "1" ] && count_inc "$COUNT_CONFLICTS_FILE"
    case "$severity" in
        CRITICAL) count_inc "$COUNT_CRITICAL_FILE" ;;
        HIGH) count_inc "$COUNT_HIGH_FILE" ;;
        MEDIUM) count_inc "$COUNT_MEDIUM_FILE" ;;
        LOW) count_inc "$COUNT_LOW_FILE" ;;
        *) count_inc "$COUNT_INFO_FILE" ;;
    esac
}

build_path_groups() {
    : > "$PATH_GROUP_FILE"
    [ -s "$ENTRY_FILE" ] || return
    awk -F '\t' 'BEGIN{OFS="\t"}
        function addu(list,item) {
            if (item=="") return list
            if (index(" " list " ", " " item " ")>0) return list
            return list=="" ? item : list " " item
        }
        function flush() { if (path!="" && count>1) print path, owners, kinds }
        {
            if (NR==1 || $1!=path) {
                flush(); path=$1; owners=$2; kinds=$3; seen=" " $2 " "; count=1
            } else {
                if (index(seen," " $2 " ")==0) { owners=owners " " $2; seen=seen $2 " "; count++ }
                kinds=addu(kinds,$3)
            }
        }
        END{flush()}
    ' "$ENTRY_FILE" > "$PATH_GROUP_FILE"
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
        if [ "$hash_enabled" = "1" ]; then
            fp=$(fingerprint_source "$kind" "$source")
        else
            fp="not-computed:$kind"
        fi
        printf '%s\t%s\n' "$module" "$fp" >> "$hashes"
        jm=$(json_escape "$module")
        jk=$(json_escape "$kind")
        js=$(json_escape "$source")
        jf=$(json_escape "$fp")
        item="{\"module\":\"$jm\",\"kind\":\"$jk\",\"source\":\"$js\",\"fingerprint\":\"$jf\"}"
        [ -n "$evidence" ] && evidence="$evidence,$item" || evidence="$item"
    done < "$candidate"
    EVIDENCE_JSON="[$evidence]"

    unique_hashes=$(cut -f2- "$hashes" 2>/dev/null | sort -u | wc -l | tr -d ' ')
    case "$unique_hashes" in ''|*[!0-9]*) unique_hashes=0 ;; esac
    if [ "$hash_enabled" != "1" ]; then
        HASH_STATE="unhashed"
    elif grep -q 'unavailable:' "$hashes" 2>/dev/null; then
        HASH_STATE="unavailable"
    elif [ "$unique_hashes" -le 1 ]; then
        HASH_STATE="identical"
    else
        HASH_STATE="different"
    fi

    WINNER=""
    WINNER_CONF=0
    WINNER_METHOD="unresolved"
    livefp=""
    [ "$hash_enabled" = "1" ] && livefp=$(fingerprint_live "$path")
    case "$livefp" in unavailable:*|unknown) livefp="" ;; esac
    if [ -n "$livefp" ]; then
        matches=$(awk -F '\t' -v f="$livefp" '$2==f {print $1}' "$hashes" | sort -u)
        match_count=$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')
        case "$match_count" in ''|*[!0-9]*) match_count=0 ;; esac
        if [ "$match_count" -eq 1 ]; then
            WINNER="$matches"
            WINNER_CONF=95
            WINNER_METHOD="live_content_match"
            return
        elif [ "$match_count" -gt 1 ]; then
            WINNER=$(lexical_winner "$matches")
            WINNER_CONF=70
            WINNER_METHOD="live_content_matches_multiple_modules"
            return
        fi
    fi

    WINNER=$(lexical_winner "$owners")
    WINNER_CONF=55
    WINNER_METHOD="lexical_module_id_heuristic"
}

process_path_conflicts() {
    build_path_groups
    [ -s "$PATH_GROUP_FILE" ] || return
    while IFS="$(printf '\t')" read -r path owners kinds; do
        [ -n "$path" ] || continue
        in_whitelist "$path" && continue
        analyze_path_candidates "$path" "$owners"
        if [ "$HASH_STATE" = "identical" ]; then
            add_finding "path_duplicate_identical" "$path" "INFO" "$owners" "$WINNER" "$WINNER_CONF" "$WINNER_METHOD" "same target and identical effective content; entry_types=$kinds" "$EVIDENCE_JSON" 0
        else
            severity=$(severity_of_path "$path")
            add_finding "path_content_conflict" "$path" "$severity" "$owners" "$WINNER" "$WINNER_CONF" "$WINNER_METHOD" "same target with different content or entry type; entry_types=$kinds" "$EVIDENCE_JSON" 1
        fi
    done < "$PATH_GROUP_FILE"
}

build_replace_groups() {
    : > "$REPLACE_GROUP_FILE"
    [ -s "$REPLACE_FILE" ] || return
    awk -F '\t' 'BEGIN{OFS="\t"}
        function flush(){if(path!=""&&count>1)print path,owners}
        {
            if(NR==1||$1!=path){flush();path=$1;owners=$2;seen=" "$2" ";count=1}
            else if(index(seen," "$2" ")==0){owners=owners" "$2;seen=seen$2" ";count++}
        }
        END{flush()}
    ' "$REPLACE_FILE" > "$REPLACE_GROUP_FILE"
}

build_replace_masks() {
    : > "$REPLACE_MASK_FILE"
    [ -s "$REPLACE_FILE" ] || return
    [ -s "$ENTRY_FILE" ] || return
    while IFS="$(printf '\t')" read -r rdir rmod rsource; do
        [ -n "$rdir" ] || continue
        in_whitelist "$rdir" && continue
        while IFS="$(printf '\t')" read -r path mod kind source; do
            [ "$mod" = "$rmod" ] && continue
            case "$path" in
                "$rdir"|"$rdir"/*) printf '%s\t%s\t%s\t%s\n' "$rdir" "$rmod" "$mod" "$path" >> "$REPLACE_MASK_FILE" ;;
            esac
        done < "$ENTRY_FILE"
    done < "$REPLACE_FILE"
    sort -u "$REPLACE_MASK_FILE" -o "$REPLACE_MASK_FILE" 2>/dev/null
}

process_replace_conflicts() {
    build_replace_groups
    if [ -s "$REPLACE_GROUP_FILE" ]; then
        while IFS="$(printf '\t')" read -r path owners; do
            [ -n "$path" ] || continue
            in_whitelist "$path" && continue
            winner=$(lexical_winner "$owners")
            severity=$(severity_of_path "$path")
            add_finding "replace_dir_collision" "$path" "$severity" "$owners" "$winner" 45 "lexical_module_id_heuristic" "multiple active modules declare .replace for the same directory" "[]" 1
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
        add_finding "replace_masks_tree" "$path" "$severity" "$owners" "$replacer" 90 "explicit_replace_owner" "$detail" "[]" 1
    done < "$TMP_DIR/replace-mask-groups.work"
}

