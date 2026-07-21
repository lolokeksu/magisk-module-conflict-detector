emit_entry() {
    base="$1"
    root="$2"
    source="$3"
    module="$4"
    kind="$5"
    rel="${source#$base}"
    [ "$rel" = "$source" ] && return
    target=$(canonical_target "$root" "$rel")
    case "$target" in */.replace) return ;; esac
    printf '%s\t%s\t%s\t%s\n' "$target" "$module" "$kind" "$source" >> "$ENTRY_FILE"
}

emit_replace() {
    base="$1"
    root="$2"
    source="$3"
    module="$4"
    rel="${source#$base}"
    [ "$rel" = "$source" ] && return
    rel_dir="${rel%/.replace}"
    target=$(canonical_target "$root" "$rel_dir")
    printf '%s\t%s\t%s\n' "$target" "$module" "$source" >> "$REPLACE_FILE"
}

scan_tree() {
    module_root="$1"
    module="$2"
    root="$3"
    base="$module_root/$root"
    [ -d "$base" ] || return

    find "$base" -type f 2>/dev/null | while IFS= read -r source; do
        case "$source" in */.replace) continue ;; esac
        emit_entry "$base" "$root" "$source" "$module" "file"
    done
    find "$base" -type l 2>/dev/null | while IFS= read -r source; do
        emit_entry "$base" "$root" "$source" "$module" "symlink"
    done
    find "$base" -type c 2>/dev/null | while IFS= read -r source; do
        emit_entry "$base" "$root" "$source" "$module" "whiteout"
    done
    if [ "$root" != "overlay.d" ]; then
        find "$base" -name '.replace' -type f 2>/dev/null | while IFS= read -r source; do
            emit_replace "$base" "$root" "$source" "$module"
        done
    fi
}

scan_system_prop() {
    module_root="$1"
    module="$2"
    file="$module_root/system.prop"
    [ -f "$file" ] || return

    awk -v module="$module" -v source="$file" '
        BEGIN { OFS="\t" }
        {
            line=$0
            sub(/\r$/, "", line)
            if (line ~ /^[[:space:]]*#/ || line ~ /^[[:space:]]*$/) next
            eq=index(line, "=")
            if (!eq) next
            key=substr(line, 1, eq-1)
            value=substr(line, eq+1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (key !~ /^[A-Za-z0-9_.-]+$/) next
            if (!(key in seen)) { order[++n]=key; seen[key]=1 }
            latest[key]=value
            latest_line[key]=NR
        }
        END {
            for (i=1; i<=n; i++) {
                key=order[i]
                print key, module, latest[key], source ":" latest_line[key]
            }
        }
    ' "$file" >> "$PROP_FILE"
}

scan_script() {
    module_root="$1"
    module="$2"
    script_name="$3"
    file="$module_root/$script_name"
    [ -f "$file" ] || return

    awk -v module="$module" -v script="$script_name" '
        BEGIN { OFS="\t" }
        function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
        function clean_token(s) {
            gsub(/^["'"'"']+|["'"'"',;]+$/, "", s)
            return s
        }
        function literal(s) {
            return s != "" && s !~ /[$`*?\[\]{}()]/
        }
        function command_name(s) { sub(/^.*\//, "", s); return s }
        function emit(resource, value, op) {
            resource=clean_token(resource)
            value=trim(value)
            if (!literal(resource)) return
            print resource, module, value, script ":" NR, op
        }
        {
            raw=$0
            sub(/\r$/, "", raw)
            work=trim(raw)
            if (work == "" || work ~ /^#/) next
            n=split(work, a, /[[:space:]]+/)

            for (i=1; i<=n; i++) {
                cmd=command_name(clean_token(a[i]))

                if (cmd == "setprop" || cmd == "resetprop") {
                    j=i+1
                    deleted=0
                    while (j<=n && a[j] ~ /^-/) {
                        if (a[j] == "--delete" || a[j] == "-d") deleted=1
                        j++
                    }
                    key=clean_token(a[j]); value=clean_token(a[j+1])
                    if (deleted) value="__DELETE__"
                    if (literal(key)) emit("prop:" key, value, cmd)
                }

                if (cmd == "settings" && a[i+1] == "put") {
                    ns=clean_token(a[i+2]); key=clean_token(a[i+3]); value=clean_token(a[i+4])
                    if (literal(ns) && literal(key)) emit("setting:" ns ":" key, value, "settings_put")
                }

                if (cmd == "device_config" && a[i+1] == "put") {
                    ns=clean_token(a[i+2]); key=clean_token(a[i+3]); value=clean_token(a[i+4])
                    if (literal(ns) && literal(key)) emit("device_config:" ns ":" key, value, "device_config_put")
                }

                if (cmd == "sysctl") {
                    for (j=i+1; j<=n; j++) {
                        token=clean_token(a[j])
                        if (token ~ /^[A-Za-z0-9_.-]+=/) {
                            eq=index(token, "=")
                            key=substr(token, 1, eq-1); value=substr(token, eq+1)
                            emit("sysctl:" key, value, "sysctl")
                        }
                    }
                }

                if (cmd == "write" && a[i+1] ~ /^\//) {
                    target=clean_token(a[i+1]); value=clean_token(a[i+2])
                    emit("sysfs:" target, value, "write")
                }

                if (cmd == "mount" || cmd == "umount") {
                    target=""
                    for (j=i+1; j<=n; j++) {
                        token=clean_token(a[j])
                        if (token ~ /^\// && literal(token)) target=token
                    }
                    if (target != "") {
                        if (cmd == "umount") emit("mount:" target, "unmount", "umount")
                        else emit("mount:" target, work, "mount")
                    }
                }

                if (cmd == "magiskpolicy" || cmd == "supolicy") {
                    if (work ~ /--live/) emit("sepolicy:live", work, cmd)
                }

                if (cmd == "rm") {
                    for (j=i+1; j<=n; j++) {
                        target=clean_token(a[j])
                        if (target ~ /^\/(system|vendor|product|system_ext|odm|data\/adb|sys|proc\/sys)(\/|$)/ && literal(target))
                            emit("fileop:" target, "remove", "rm")
                    }
                }

                if (cmd == "cp" || cmd == "mv" || cmd == "ln") {
                    target=""
                    for (j=i+1; j<=n; j++) {
                        token=clean_token(a[j])
                        if (token ~ /^\// && literal(token)) target=token
                    }
                    if (target ~ /^\/(system|vendor|product|system_ext|odm|data\/adb)(\/|$)/)
                        emit("fileop:" target, cmd, cmd)
                }

                if (cmd == "chmod" || cmd == "chown") {
                    mode=clean_token(a[i+1]); target=""
                    for (j=i+2; j<=n; j++) {
                        token=clean_token(a[j])
                        if (token ~ /^\// && literal(token)) target=token
                    }
                    if (target != "") emit("perm:" target, mode, cmd)
                }
            }

            if (match(work, />[[:space:]]*\/[^[:space:];&|]+/)) {
                redir=substr(work, RSTART, RLENGTH)
                sub(/^>[[:space:]]*/, "", redir)
                target=clean_token(redir)
                before=substr(work, 1, RSTART-1)
                if (target ~ /^\/sys\// || target ~ /^\/proc\/sys\//) {
                    value=before
                    sub(/^[[:space:]]*(echo|printf)[[:space:]]+/, "", value)
                    emit("sysfs:" target, value, "redirect")
                }
            }
        }
    ' "$file" >> "$SCRIPT_FILE"
}

collect_modules() {
    : > "$MODULE_FILE"
    : > "$ENTRY_FILE"
    : > "$REPLACE_FILE"
    : > "$PROP_FILE"
    : > "$SCRIPT_FILE"

    script_scan=$(get_config script_scan 1)
    overlay_scan=$(get_config overlayd_scan 1)
    [ "$DEEP_MODE" = "1" ] && { script_scan=1; overlay_scan=1; }

    for module_dir in "$MODULES_DIR"/*; do
        [ -d "$module_dir" ] || continue
        module_root="${module_dir%/}"
        module=$(basename "$module_root")
        [ -f "$module_root/disable" ] && continue
        [ -f "$module_root/remove" ] && continue
        module_has_relevant_content "$module_root" || continue

        prop="$module_root/module.prop"
        name=$(module_prop_value "$prop" name)
        version=$(module_prop_value "$prop" version)
        [ -n "$name" ] || name="$module"
        [ -n "$version" ] || version="unknown"
        name=$(printf '%s' "$name" | tr '\t\r\n' '   ')
        version=$(printf '%s' "$version" | tr '\t\r\n' '   ')
        printf '%s\t%s\t%s\t%s\n' "$module" "$name" "$version" "$module_root" >> "$MODULE_FILE"

        if [ ! -f "$module_root/skip_mount" ]; then
            scan_tree "$module_root" "$module" system
            for root in $MOUNT_ROOTS; do scan_tree "$module_root" "$module" "$root"; done
        fi
        [ "$overlay_scan" = "1" ] && scan_tree "$module_root" "$module" overlay.d
        scan_system_prop "$module_root" "$module"

        if [ "$script_scan" = "1" ]; then
            for script in service.sh post-fs-data.sh boot-completed.sh action.sh; do
                scan_script "$module_root" "$module" "$script"
            done
        fi
    done

    sort -u "$MODULE_FILE" -o "$MODULE_FILE" 2>/dev/null
    sort -u "$ENTRY_FILE" -o "$ENTRY_FILE" 2>/dev/null
    sort -u "$REPLACE_FILE" -o "$REPLACE_FILE" 2>/dev/null
    sort -u "$PROP_FILE" -o "$PROP_FILE" 2>/dev/null
    sort -u "$SCRIPT_FILE" -o "$SCRIPT_FILE" 2>/dev/null
}

