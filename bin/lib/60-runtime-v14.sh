#!/system/bin/sh
# Module Conflict Detector v1.4 feature layer.
# Loaded after the stable v1.3 engine and overrides selected functions only.

VERSION="v1.4"
VERSION_CODE="140"
HISTORY_DIR="$REPORTS_DIR/history"
CACHE_DIR="$MCD_DIR/cache"
HASH_CACHE_FILE="$CACHE_DIR/hashes.tsv"
MODULE_STATE_FILE="$TMP_DIR/module-states.tsv"
FINDING_INDEX_FILE="$TMP_DIR/findings-index.tsv"
CURRENT_INDEX_FILE="$MCD_DIR/findings-index.tsv"
COUNT_CONFIRMED_FILE="$TMP_DIR/count.confirmed"
COUNT_PROBABLE_FILE="$TMP_DIR/count.probable"
COUNT_POSSIBLE_FILE="$TMP_DIR/count.possible"
COUNT_INFORMATIONAL_FILE="$TMP_DIR/count.informational"
SCAN_STARTED_EPOCH="${SCAN_STARTED_EPOCH:-0}"

write_default_config() {
    cat > "$CONFIG_FILE" <<'CFG'
# Module Conflict Detector v1.4 configuration
auto_scan=1
boot_delay_seconds=30
replace_examples_limit=20
script_scan=1
overlayd_scan=1
hash_conflicts=1
known_conflicts=1
hash_cache=1
report_history_limit=10
language=ru
interactive=1
CFG
}

ensure_config_key() {
    key="$1"
    value="$2"
    grep -q "^$key=" "$CONFIG_FILE" 2>/dev/null || printf '%s=%s\n' "$key" "$value" >> "$CONFIG_FILE"
}

ensure_dirs() {
    mkdir -p "$MCD_DIR" "$REPORTS_DIR" "$HISTORY_DIR" "$SNAPSHOTS_DIR" "$TMP_DIR" "$CACHE_DIR" 2>/dev/null
    [ -f "$CONFIG_FILE" ] || write_default_config
    ensure_config_key auto_scan 1
    ensure_config_key boot_delay_seconds 30
    ensure_config_key replace_examples_limit 20
    ensure_config_key script_scan 1
    ensure_config_key overlayd_scan 1
    ensure_config_key hash_conflicts 1
    ensure_config_key known_conflicts 1
    ensure_config_key hash_cache 1
    ensure_config_key report_history_limit 10
    ensure_config_key language ru
    ensure_config_key interactive 1
    [ -f "$WHITELIST_FILE" ] || : > "$WHITELIST_FILE"
    [ -f "$KNOWN_FILE" ] || write_default_known_db
    [ -f "$HASH_CACHE_FILE" ] || : > "$HASH_CACHE_FILE"
}

valid_config_key() {
    case "$1" in
        auto_scan|boot_delay_seconds|replace_examples_limit|script_scan|overlayd_scan|hash_conflicts|known_conflicts|hash_cache|report_history_limit|language|interactive) return 0 ;;
        *) return 1 ;;
    esac
}

set_config_value() {
    key="$1"
    value="$2"
    tmp="$TMP_DIR/config.work"
    valid_config_key "$key" || { echo "! Unknown config key: $key"; return 1; }
    case "$key" in
        auto_scan|script_scan|overlayd_scan|hash_conflicts|known_conflicts|hash_cache|interactive)
            case "$value" in 0|1) ;; *) echo "! $key must be 0 or 1"; return 1 ;; esac ;;
        boot_delay_seconds|replace_examples_limit|report_history_limit)
            case "$value" in ''|*[!0-9]*) echo "! $key must be numeric"; return 1 ;; esac ;;
        language)
            case "$value" in ru|en) ;; *) echo "! language must be ru or en"; return 1 ;; esac ;;
    esac
    if grep -q "^$key=" "$CONFIG_FILE" 2>/dev/null; then
        sed "s|^$key=.*|$key=$value|" "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$CONFIG_FILE"
    fi
    msg "+ Config updated: $key=$value"
}

cleanup_scan_temp() {
    rm -f "$MODULE_FILE" "$ENTRY_FILE" "$REPLACE_FILE" "$PROP_FILE" "$SCRIPT_FILE" \
        "$PATH_GROUP_FILE" "$REPLACE_GROUP_FILE" "$REPLACE_MASK_FILE" \
        "$PROP_GROUP_FILE" "$SCRIPT_GROUP_FILE" "$JSON_ITEMS_FILE" \
        "$MODULE_STATE_FILE" "$FINDING_INDEX_FILE" \
        "$COUNT_FINDINGS_FILE" "$COUNT_CONFLICTS_FILE" "$COUNT_CRITICAL_FILE" \
        "$COUNT_HIGH_FILE" "$COUNT_MEDIUM_FILE" "$COUNT_LOW_FILE" "$COUNT_INFO_FILE" \
        "$COUNT_CONFIRMED_FILE" "$COUNT_PROBABLE_FILE" "$COUNT_POSSIBLE_FILE" \
        "$COUNT_INFORMATIONAL_FILE" "$TMP_DIR"/*.work "$TMP_DIR"/*.sorted \
        "$TMP_DIR"/*.candidate "$TMP_DIR"/*.manifest 2>/dev/null
}

module_state_value() {
    root="$1"
    id="$2"
    if [ -f "$root/remove" ]; then
        printf 'pending_removal'
    elif [ -f "$root/disable" ]; then
        printf 'disabled'
    elif [ -d "$ROOT_DATA_ADB/modules_update/$id" ]; then
        printf 'pending_update'
    elif [ ! -f "$root/module.prop" ]; then
        printf 'incomplete'
    else
        printf 'active'
    fi
}

collect_module_states() {
    : > "$MODULE_STATE_FILE"
    for module_dir in "$MODULES_DIR"/*; do
        [ -d "$module_dir" ] || continue
        root="${module_dir%/}"
        id=$(basename "$root")
        prop="$root/module.prop"
        name=$(module_prop_value "$prop" name)
        version=$(module_prop_value "$prop" version)
        [ -n "$name" ] || name="$id"
        [ -n "$version" ] || version="unknown"
        state=$(module_state_value "$root" "$id")
        [ -f "$root/skip_mount" ] && mount_mode="skip_mount" || mount_mode="mounted"
        name=$(printf '%s' "$name" | tr '\t\r\n' '   ')
        version=$(printf '%s' "$version" | tr '\t\r\n' '   ')
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$version" "$state" "$mount_mode" "$root" >> "$MODULE_STATE_FILE"
    done
    if [ -d "$ROOT_DATA_ADB/modules_update" ]; then
        for update_dir in "$ROOT_DATA_ADB/modules_update"/*; do
            [ -d "$update_dir" ] || continue
            id=$(basename "$update_dir")
            awk -F '\t' -v id="$id" '$1==id {found=1} END{exit found?0:1}' "$MODULE_STATE_FILE" 2>/dev/null && continue
            prop="$update_dir/module.prop"
            name=$(module_prop_value "$prop" name); [ -n "$name" ] || name="$id"
            version=$(module_prop_value "$prop" version); [ -n "$version" ] || version="unknown"
            printf '%s\t%s\t%s\tpending_update\tunknown\t%s\n' "$id" "$name" "$version" "$update_dir" >> "$MODULE_STATE_FILE"
        done
    fi
    sort -u "$MODULE_STATE_FILE" -o "$MODULE_STATE_FILE" 2>/dev/null
}

count_init() {
    for f in "$COUNT_FINDINGS_FILE" "$COUNT_CONFLICTS_FILE" "$COUNT_CRITICAL_FILE" \
             "$COUNT_HIGH_FILE" "$COUNT_MEDIUM_FILE" "$COUNT_LOW_FILE" "$COUNT_INFO_FILE" \
             "$COUNT_CONFIRMED_FILE" "$COUNT_PROBABLE_FILE" "$COUNT_POSSIBLE_FILE" \
             "$COUNT_INFORMATIONAL_FILE"; do
        echo 0 > "$f"
    done
    : > "$FINDING_INDEX_FILE"
    collect_module_states
}

stat_signature() {
    file="$1"
    if command -v stat >/dev/null 2>&1; then
        stat -c '%s:%Y:%i' "$file" 2>/dev/null && return
    fi
    if command -v busybox >/dev/null 2>&1; then
        busybox stat -c '%s:%Y:%i' "$file" 2>/dev/null && return
    fi
    printf 'unknown'
}

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
            cache_enabled=$(get_config hash_cache 1)
            sig=$(stat_signature "$source")
            if [ "$cache_enabled" = "1" ] && [ "$sig" != "unknown" ] && [ -f "$HASH_CACHE_FILE" ]; then
                cached=$(awk -F '\t' -v p="$source" -v s="$sig" '$1==p && $2==s {v=$3} END{print v}' "$HASH_CACHE_FILE" 2>/dev/null)
                [ -n "$cached" ] && { printf '%s' "$cached"; return; }
            fi
            hash=""
            if command -v sha256sum >/dev/null 2>&1; then
                hash=$(sha256sum "$source" 2>/dev/null | awk '{print $1}')
            elif command -v busybox >/dev/null 2>&1; then
                hash=$(busybox sha256sum "$source" 2>/dev/null | awk '{print $1}')
            fi
            if [ -n "$hash" ]; then
                result="sha256:$hash"
            elif command -v cksum >/dev/null 2>&1; then
                result=$(cksum "$source" 2>/dev/null | awk '{printf "cksum:%s:%s", $1, $2}')
                [ -n "$result" ] || result="unavailable:file"
            else
                result="unavailable:file"
            fi
            if [ "$cache_enabled" = "1" ] && [ "$sig" != "unknown" ]; then
                printf '%s\t%s\t%s\n' "$source" "$sig" "$result" >> "$HASH_CACHE_FILE"
            fi
            printf '%s' "$result"
            ;;
        *) printf 'unknown' ;;
    esac
}

stable_finding_id() {
    type="$1"
    target="$2"
    case "$type" in
        path_*) prefix="PATH" ;;
        replace_*) prefix="REPLACE" ;;
        property_*) prefix="PROP" ;;
        script_*) prefix="SCRIPT" ;;
        known_*) prefix="KNOWN" ;;
        *overlay*|init_*|rro_*) prefix="OVERLAY" ;;
        *) prefix="GEN" ;;
    esac
    sum=$(printf '%s' "$type|$target" | cksum 2>/dev/null | awk '{print $1}')
    case "$sum" in ''|*[!0-9]*) sum=0 ;; esac
    hex=$(printf '%08X' "$sum" 2>/dev/null)
    [ -n "$hex" ] || hex="$sum"
    printf 'MCD-%s-%s' "$prefix" "$hex"
}

finding_status() {
    is_conflict="$1"
    confidence="$2"
    method="$3"
    [ "$is_conflict" = "1" ] || { printf 'INFORMATIONAL'; return; }
    case "$method" in
        mount_source_match|live_inode_match|live_content_match|current_property_value_match|current_runtime_value_match|explicit_replace_owner|database_rule)
            printf 'CONFIRMED'; return ;;
    esac
    case "$confidence" in ''|*[!0-9]*) confidence=0 ;; esac
    if [ "$confidence" -ge 75 ]; then
        printf 'CONFIRMED'
    elif [ "$confidence" -ge 50 ]; then
        printf 'PROBABLE'
    else
        printf 'POSSIBLE'
    fi
}

clean_tsv() {
    printf '%s' "$1" | tr '\t\r\n' '   '
}

