#!/system/bin/sh
# Module Conflict Detector v1.0 - service.sh
# Отложенный автоскан после полной загрузки. Только чтение, нулевой риск.

MCD_BIN="/data/adb/mcd/bin/mcd-ctrl"

(
    # Ждём завершения загрузки
    until [ "$(getprop sys.boot_completed)" = "1" ]; do
        sleep 5
    done
    sleep 30  # даём системе устаканиться

    [ -x "$MCD_BIN" ] && "$MCD_BIN" scan --quiet
) &