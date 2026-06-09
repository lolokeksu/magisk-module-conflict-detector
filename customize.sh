#!/system/bin/sh
# Module Conflict Detector v1.0 - customize.sh

SKIPUNZIP=0

ui_print "*******************************"
ui_print " Module Conflict Detector v1.0 "
ui_print "    by ExchNow (Lolokeksu)     "
ui_print "*******************************"

# Рабочая директория
MCD_DIR="/data/adb/mcd"
mkdir -p "$MCD_DIR"

# Переносим CLI в постоянное место
mkdir -p "$MCD_DIR/bin"
cp -f "$MODPATH/mcd-ctrl" "$MCD_DIR/bin/mcd-ctrl"
rm -f "$MODPATH/mcd-ctrl"

# Симлинк в PATH через оверлей модуля
mkdir -p "$MODPATH/system/bin"
ln -sf "$MCD_DIR/bin/mcd-ctrl" "$MODPATH/system/bin/mcd-ctrl"

# Права
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MCD_DIR/bin/mcd-ctrl" 0 0 0755

ui_print "- Установлено. После перезагрузки: mcd-ctrl scan"