#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/data" "$TMP/root" "$TMP/proc" \
  "$TMP/modules/A/system/etc" "$TMP/modules/B/system/etc" \
  "$TMP/modules/C/system/etc" "$TMP/modules/D/system/etc" \
  "$TMP/live/system/etc"
cat > "$TMP/bin/getprop" <<'EOF'
#!/bin/sh
case "$1" in
 ro.build.version.release) echo 13 ;;
 ro.build.version.sdk) echo 33 ;;
 ro.product.cpu.abi) echo arm64-v8a ;;
 ro.product.model) echo TestDevice ;;
 ro.build.fingerprint) echo test/fingerprint ;;
 debug.mcd.fixture) echo 2 ;;
 sys.boot_completed) echo 1 ;;
 *) echo ;;
esac
EOF
chmod +x "$TMP/bin/getprop"
cat > "$TMP/modules/A/module.prop" <<'EOF'
id=A
name=Fixture A
version=1.0
priority=10
EOF
cat > "$TMP/modules/B/module.prop" <<'EOF'
id=B
name=Fixture B
version=2.0
priority=20
EOF
cat > "$TMP/modules/C/module.prop" <<'EOF'
id=C
name=Disabled C
version=1.0
EOF
cat > "$TMP/modules/D/module.prop" <<'EOF'
id=D
name=SkipMount D
version=1.0
priority=5
EOF
touch "$TMP/modules/C/disable" "$TMP/modules/D/skip_mount"
printf 'A\n' > "$TMP/modules/A/system/etc/mcd-test.conf"
printf 'B\n' > "$TMP/modules/B/system/etc/mcd-test.conf"
printf 'C\n' > "$TMP/modules/C/system/etc/mcd-test.conf"
printf 'D\n' > "$TMP/modules/D/system/etc/mcd-test.conf"
printf 'B\n' > "$TMP/live/system/etc/mcd-test.conf"
printf 'debug.mcd.fixture=1\n' > "$TMP/modules/A/system.prop"
printf 'debug.mcd.fixture=2\n' > "$TMP/modules/B/system.prop"
printf 'debug.mcd.fixture=2\n' > "$TMP/modules/D/system.prop"

export PATH="$TMP/bin:$PATH"
export MCD_DIR="$TMP/data"
export MCD_MODULES_DIR="$TMP/modules"
export MCD_LIVE_ROOT="$TMP/live"
export MCD_ROOT_DATA_ADB="$TMP/root"
export MCD_PROC_ROOT="$TMP/proc"

for file in "$ROOT"/bin/mcd-ctrl "$ROOT"/bin/mcd-menu "$ROOT"/bin/mcd-boot-scan "$ROOT"/bin/lib/*.sh "$ROOT"/customize.sh "$ROOT"/service.sh "$ROOT"/boot-completed.sh "$ROOT"/action.sh "$ROOT"/uninstall.sh; do
  sh -n "$file"
done

sh "$ROOT/bin/mcd-ctrl" scan --deep --quiet
python3 -m json.tool "$MCD_DIR/report.json" >/dev/null
python3 - "$MCD_DIR/report.json" <<'PY'
import json,re,sys
j=json.load(open(sys.argv[1]))
assert j['version']=='v1.4'
assert j['version_code']==140
assert j['known_database_version']==2
s=j['summary']
assert s['modules_disabled']==1
assert s['modules_skip_mount']==1
assert s['conflicts_count']==2
by={x['type']:x for x in j['findings']}
assert by['path_content_conflict']['winner']=='B'
assert by['path_content_conflict']['winner_method']=='live_content_match'
assert by['property_value_conflict']['winner']=='B'
assert by['property_value_conflict']['winner_method']=='current_value_plus_explicit_priority'
for item in j['findings']:
    assert re.fullmatch(r'MCD-[0-9A-F]{12}',item['id'])
    assert isinstance(item['reason_codes'],list)
    assert item['actionability'] in {'immediate','review','informational'}
PY

ID=$(awk -F '\t' 'NR==1{print $1}' "$MCD_DIR/findings.tsv")
EXPLAIN_OUT=$(sh "$ROOT/bin/mcd-ctrl" explain "$ID")
grep -q "Находка: $ID" <<<"$EXPLAIN_OUT"

sh "$ROOT/bin/mcd-ctrl" baseline create >/dev/null
printf 'A changed\n' > "$TMP/modules/A/system/etc/mcd-test.conf"
sh "$ROOT/bin/mcd-ctrl" scan --deep --quiet
BASELINE_OUT=$(sh "$ROOT/bin/mcd-ctrl" baseline compare)
grep -q 'Added/changed: 1' <<<"$BASELINE_OUT"

SELF_OUT=$(sh "$ROOT/bin/mcd-ctrl" self-test --full)
grep -q '\[OK\] sandbox conflict fixture' <<<"$SELF_OUT"

MAX=$(sh "$ROOT/bin/mcd-ctrl" help | python3 -c 'import sys; print(max(map(len,sys.stdin.read().splitlines())))')
[ "$MAX" -le 42 ]

MENU_RU=$(printf '0\n' | sh "$ROOT/bin/mcd-ctrl")
grep -q '1. Быстрая проверка' <<<"$MENU_RU"
grep -q '3. Расширенное меню' <<<"$MENU_RU"
MENU_EN=$(printf '4\n0\n' | sh "$ROOT/bin/mcd-ctrl")
grep -q '1. Quick scan' <<<"$MENU_EN"
grep -q '3. Advanced menu' <<<"$MENU_EN"
printf 'ru\n' > "$MCD_DIR/ui-language.conf"

echo "v1.4 regression tests: PASS"
