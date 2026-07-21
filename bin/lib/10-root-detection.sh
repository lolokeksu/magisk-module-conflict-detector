first_executable() {
    for candidate in "$@"; do
        [ -n "$candidate" ] || continue
        case "$candidate" in
            */*)
                [ -f "$candidate" ] && [ -x "$candidate" ] && {
                    printf '%s' "$candidate"
                    return 0
                }
                ;;
            *)
                resolved=$(command -v "$candidate" 2>/dev/null)
                [ -n "$resolved" ] && [ -x "$resolved" ] && {
                    printf '%s' "$resolved"
                    return 0
                }
                ;;
        esac
    done
    return 1
}

process_name_running() {
    wanted="$1"
    [ -d "$PROC_ROOT" ] || return 1
    for proc_dir in "$PROC_ROOT"/[0-9]*; do
        [ -d "$proc_dir" ] || continue
        proc_name=$(cat "$proc_dir/comm" 2>/dev/null)
        [ "$proc_name" = "$wanted" ] && return 0
        if [ -r "$proc_dir/cmdline" ]; then
            proc_cmd=$(tr '\000' ' ' < "$proc_dir/cmdline" 2>/dev/null)
            proc_cmd=${proc_cmd%% *}
            proc_cmd=${proc_cmd##*/}
            [ "$proc_cmd" = "$wanted" ] && return 0
        fi
    done
    return 1
}

classify_root_signature() {
    signature=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    ROOT_CLASSIFIED_MANAGER=""
    ROOT_CLASSIFIED_FAMILY=""
    case "$signature" in
        *resukisu*)
            ROOT_CLASSIFIED_MANAGER="ReSukiSU"
            ROOT_CLASSIFIED_FAMILY="KernelSU"
            ;;
        *sukisu*)
            ROOT_CLASSIFIED_MANAGER="SukiSU Ultra"
            ROOT_CLASSIFIED_FAMILY="KernelSU"
            ;;
        *kernelsu*next*|*kernel*su*next*|*ksu*next*)
            ROOT_CLASSIFIED_MANAGER="KernelSU Next"
            ROOT_CLASSIFIED_FAMILY="KernelSU"
            ;;
        *kernelsu*|*kernel*su*|*ksud*)
            ROOT_CLASSIFIED_MANAGER="KernelSU"
            ROOT_CLASSIFIED_FAMILY="KernelSU"
            ;;
        *apatch*|*kernelpatch*)
            ROOT_CLASSIFIED_MANAGER="APatch"
            ROOT_CLASSIFIED_FAMILY="APatch"
            ;;
        *kitsune*)
            ROOT_CLASSIFIED_MANAGER="Kitsune Mask"
            ROOT_CLASSIFIED_FAMILY="Magisk"
            ;;
        *magisk*alpha*)
            ROOT_CLASSIFIED_MANAGER="Magisk Alpha"
            ROOT_CLASSIFIED_FAMILY="Magisk"
            ;;
        *magisk*delta*)
            ROOT_CLASSIFIED_MANAGER="Magisk Delta"
            ROOT_CLASSIFIED_FAMILY="Magisk"
            ;;
        *magisk*|*magisksu*)
            ROOT_CLASSIFIED_MANAGER="Magisk"
            ROOT_CLASSIFIED_FAMILY="Magisk"
            ;;
    esac
    [ -n "$ROOT_CLASSIFIED_MANAGER" ]
}

find_su_binary() {
    if [ "${MCD_SU_BINARY+x}" = "x" ]; then
        [ -n "$MCD_SU_BINARY" ] && [ -x "$MCD_SU_BINARY" ] && printf '%s' "$MCD_SU_BINARY"
        return
    fi
    first_executable su /system/bin/su /system/xbin/su
}

read_su_signature() {
    su_bin=$(find_su_binary)
    [ -n "$su_bin" ] || return 1
    for su_opt in -v --version; do
        su_out=$("$su_bin" "$su_opt" 2>/dev/null | head -n 2)
        [ -n "$su_out" ] || continue
        if classify_root_signature "$su_out"; then
            ROOT_SU_BINARY="$su_bin"
            ROOT_SU_SIGNATURE="$su_out"
            return 0
        fi
    done
    return 1
}

set_root_detection() {
    ROOT_MANAGER="$1"
    ROOT_MANAGER_FAMILY="$2"
    ROOT_DETECTION_METHOD="$3"
    ROOT_DETECTION_CONFIDENCE="$4"
    ROOT_DETECTION_EVIDENCE="$5"
    ROOT_DETECTION_DONE=1
}

join_detected_managers() {
    joined=""
    [ "$1" = "1" ] && joined="Magisk"
    if [ "$2" = "1" ]; then
        [ -n "$joined" ] && joined="$joined+KernelSU" || joined="KernelSU"
    fi
    if [ "$3" = "1" ]; then
        [ -n "$joined" ] && joined="$joined+APatch" || joined="APatch"
    fi
    printf '%s' "$joined"
}

detect_root_manager_info() {
    [ "$ROOT_DETECTION_DONE" = "1" ] && return

    # 1. The current su provider is the strongest portable signal and also
    # distinguishes common Magisk/KernelSU forks when they expose their name.
    if read_su_signature; then
        su_evidence=$(printf '%s' "$ROOT_SU_SIGNATURE" | tr '\n\r\t' '   ')
        set_root_detection "$ROOT_CLASSIFIED_MANAGER" "$ROOT_CLASSIFIED_FAMILY" \
            "su_version" "high" "$ROOT_SU_BINARY: $su_evidence"
        return
    fi

    # 2. Exact daemon names are stronger than paths and stale directories.
    magisk_proc=0; ksu_proc=0; apatch_proc=0
    process_name_running magiskd && magisk_proc=1
    process_name_running ksud && ksu_proc=1
    process_name_running apd && apatch_proc=1
    proc_count=$((magisk_proc + ksu_proc + apatch_proc))
    if [ "$proc_count" -gt 0 ]; then
        proc_manager=$(join_detected_managers "$magisk_proc" "$ksu_proc" "$apatch_proc")
        if [ "$proc_count" = "1" ]; then
            case "$proc_manager" in
                Magisk) proc_family="Magisk" ;;
                KernelSU) proc_family="KernelSU" ;;
                APatch) proc_family="APatch" ;;
            esac
        else
            proc_family="mixed"
        fi
        set_root_detection "$proc_manager" "$proc_family" "active_daemon" "high" \
            "magiskd=$magisk_proc,ksud=$ksu_proc,apd=$apatch_proc"
        return
    fi

    # 3. Native manager-owned core binaries. These are accepted only when
    # executable; merely retaining /data/adb/magisk is not enough.
    magisk_bin=$(first_executable \
        "$ROOT_DATA_ADB/magisk/magisk" /sbin/magisk /debug_ramdisk/magisk magisk)
    ksu_bin=$(first_executable \
        "$ROOT_DATA_ADB/ksud" "$ROOT_DATA_ADB/ksu/bin/ksud" \
        "$ROOT_DATA_ADB/ksu/ksud" ksud)
    apatch_bin=$(first_executable "$ROOT_DATA_ADB/ap/bin/apd" apd)

    magisk_core=0; ksu_core=0; apatch_core=0
    [ -n "$magisk_bin" ] && magisk_core=1
    [ -n "$ksu_bin" ] && ksu_core=1
    [ -n "$apatch_bin" ] && apatch_core=1
    core_count=$((magisk_core + ksu_core + apatch_core))

    if [ "$core_count" = "1" ]; then
        if [ "$apatch_core" = "1" ]; then
            set_root_detection "APatch" "APatch" "core_binary" "medium" "$apatch_bin"
        elif [ "$ksu_core" = "1" ]; then
            set_root_detection "KernelSU-compatible" "KernelSU" "core_binary" "medium" "$ksu_bin"
        else
            set_root_detection "Magisk-compatible" "Magisk" "core_binary" "medium" "$magisk_bin"
        fi
        return
    elif [ "$core_count" -gt 1 ]; then
        core_manager=$(join_detected_managers "$magisk_core" "$ksu_core" "$apatch_core")
        set_root_detection "unknown (multiple root cores: $core_manager)" "mixed" \
            "multiple_core_binaries" "low" \
            "magisk=${magisk_bin:-none},ksud=${ksu_bin:-none},apd=${apatch_bin:-none}"
        return
    fi

    # 4. Last-resort layout hints. They are explicitly labelled low confidence
    # because these directories are often shared or left behind after migration.
    magisk_dir=0; ksu_dir=0; apatch_dir=0
    [ -d "$ROOT_DATA_ADB/magisk" ] && magisk_dir=1
    [ -d "$ROOT_DATA_ADB/ksu" ] && ksu_dir=1
    [ -d "$ROOT_DATA_ADB/ap" ] && apatch_dir=1
    dir_count=$((magisk_dir + ksu_dir + apatch_dir))
    if [ "$dir_count" = "1" ]; then
        if [ "$apatch_dir" = "1" ]; then
            set_root_detection "APatch-compatible (layout only)" "APatch" "layout_hint" "low" "$ROOT_DATA_ADB/ap"
        elif [ "$ksu_dir" = "1" ]; then
            set_root_detection "KernelSU-compatible (layout only)" "KernelSU" "layout_hint" "low" "$ROOT_DATA_ADB/ksu"
        else
            set_root_detection "Magisk-compatible (layout only)" "Magisk" "layout_hint" "low" "$ROOT_DATA_ADB/magisk"
        fi
    elif [ "$dir_count" -gt 1 ]; then
        set_root_detection "unknown (shared or stale root layout)" "unknown" \
            "layout_ambiguous" "low" \
            "magisk_dir=$magisk_dir,ksu_dir=$ksu_dir,apatch_dir=$apatch_dir"
    else
        set_root_detection "unknown" "unknown" "none" "low" \
            "no su signature, daemon, executable core, or unique layout"
    fi
}

detect_root_manager() {
    detect_root_manager_info
    printf '%s' "$ROOT_MANAGER"
}

prop_get() {
    key="$1"
    if command -v getprop >/dev/null 2>&1; then
        getprop "$key" 2>/dev/null
    else
        printf ''
    fi
}

device_value() {
    key="$1"
    fallback="$2"
    value=$(prop_get "$key")
    [ -n "$value" ] && printf '%s' "$value" || printf '%s' "$fallback"
}

module_prop_value() {
    file="$1"
    key="$2"
    sed -n "s/^[[:space:]]*$key=//p" "$file" 2>/dev/null | tail -n 1
}

module_has_relevant_content() {
    root="$1"
    [ -d "$root/system" ] && return 0
    for part in $MOUNT_ROOTS; do [ -d "$root/$part" ] && return 0; done
    [ -d "$root/overlay.d" ] && return 0
    [ -f "$root/system.prop" ] && return 0
    [ -f "$root/sepolicy.rule" ] && return 0
    for script in service.sh post-fs-data.sh boot-completed.sh action.sh; do
        [ -f "$root/$script" ] && return 0
    done
    return 1
}

canonical_target() {
    root="$1"
    rel="$2"
    case "$root" in
        system)
            case "$rel" in
                /vendor|/vendor/*) printf '%s' "$rel" ;;
                /product|/product/*) printf '%s' "$rel" ;;
                /system_ext|/system_ext/*) printf '%s' "$rel" ;;
                /odm|/odm/*) printf '%s' "$rel" ;;
                /system_dlkm|/system_dlkm/*) printf '%s' "$rel" ;;
                /vendor_dlkm|/vendor_dlkm/*) printf '%s' "$rel" ;;
                /odm_dlkm|/odm_dlkm/*) printf '%s' "$rel" ;;
                *) printf '/system%s' "$rel" ;;
            esac
            ;;
        overlay.d) printf '/overlay.d%s' "$rel" ;;
        *) printf '/%s%s' "$root" "$rel" ;;
    esac
}

