# Module Conflict Detector v1.4

Read-only diagnostic module for Magisk-compatible, KernelSU-family and APatch module systems. It detects file, property, `.replace`, overlay and runtime-script conflicts without changing modules, mounts, properties, sysfs or SELinux policy.

## Main changes in v1.4

- Interactive `mcd-ctrl` menu with numbered actions.
- Russian and English interface with persistent language selection.
- Advanced menu opened from the default menu.
- Real winner detection through `/proc/*/mountinfo`, inode matching and live SHA-256 matching.
- No fabricated lexical winner when ownership cannot be proven.
- Evidence states: `CONFIRMED`, `PROBABLE`, `POSSIBLE`, `INFORMATIONAL`.
- Stable finding IDs and `mcd-ctrl explain FINDING_ID`.
- Module states: active, disabled, pending removal, pending update, incomplete and `skip_mount`.
- Scan history and comparison with `history` and `diff`.
- SHA-256 cache for repeated deep scans.
- Diagnostic archive with `support-bundle`.
- JSON report schema v2 with module states and evidence status.
- Extended runtime parser for variables, multiline commands, `tee`, delete operations, overlay/package state, netfilter and traffic-control actions.

## Interactive control

Run:

```sh
su -c 'mcd-ctrl'
```

Default menu:

```text
1. Quick scan / Быстрое сканирование
2. Show report / Показать отчёт
3. Advanced menu / Расширенное меню
4. English / Русский
0. Exit / Выход
```

## Direct commands

```sh
su -c 'mcd-ctrl scan --deep'
su -c 'mcd-ctrl report'
su -c 'mcd-ctrl report --critical-only'
su -c 'mcd-ctrl report --severity HIGH'
su -c 'mcd-ctrl report --module MODULE_ID'
su -c 'mcd-ctrl summary'
su -c 'mcd-ctrl explain FINDING_ID'
su -c 'mcd-ctrl history'
su -c 'mcd-ctrl diff'
su -c 'mcd-ctrl cache status'
su -c 'mcd-ctrl support-bundle'
su -c 'mcd-ctrl doctor'
su -c 'mcd-ctrl boot-status'
```

## Reports

- `/data/adb/mcd/conflicts.log`
- `/data/adb/mcd/report.json`
- `/data/adb/mcd/findings-index.tsv`
- `/data/adb/mcd/reports/history/*`
- `/data/adb/mcd/boot-scan.log`
- `/sdcard/ModuleConflictDetector/MCD-support-*.tar.gz`

## Safety

The scanner remains read-only. It does not disable modules, alter mounted files, write properties or sysfs, change SELinux policy, or automatically resolve conflicts.
