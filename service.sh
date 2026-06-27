#!/system/bin/sh
# Module Conflict Detector v1.2 - service.sh
# Late-start automatic scan. Read-only scan; no mounts, props, SELinux or kernel writes.

MODDIR=${0%/*}
MCD_BIN="$MODDIR/bin/mcd-ctrl"
MCD_DIR="/data/adb/mcd"
CONFIG_FILE="$MCD_DIR/config.conf"

get_conf() {
    key="$1"
    def="$2"
    val=""
    if [ -f "$CONFIG_FILE" ]; then
        val=$(grep -E "^[[:space:]]*$key=" "$CONFIG_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-)
    fi
    [ -n "$val" ] && printf '%s' "$val" || printf '%s' "$def"
}

(
    until [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ]; do
        sleep 5
    done

    auto_scan=$(get_conf auto_scan 1)
    [ "$auto_scan" = "1" ] || exit 0

    delay=$(get_conf boot_delay_seconds 30)
    case "$delay" in
        ''|*[!0-9]*) delay=30 ;;
    esac
    sleep "$delay"

    [ -x "$MCD_BIN" ] && "$MCD_BIN" scan --quiet --boot
) &
