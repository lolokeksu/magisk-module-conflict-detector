# Module Conflict Detector v1.4

Read-only diagnostic module for Magisk-compatible, KernelSU-family and APatch module systems.

## v1.4 highlights

- Stable finding IDs such as `MCD-2A31F4B9C810`.
- `mcd-ctrl explain ID` with winner evidence, confidence, impact and safe recommendation.
- Interactive Android-friendly menu through the module action button or `mcd-ctrl menu`.
- Baseline comparison before and after installing modules.
- Privacy-aware diagnostic export.
- Versioned known-conflict rules with module-version, root-family and SDK constraints.
- Self-test and isolated full fixture test.
- Active/disabled/remove-pending/skip-mount inventory.

## Interactive menu

Running `mcd-ctrl` without arguments opens a compact bilingual menu with Quick scan, Full scan and Advanced menu. Option 4 switches between Russian and English and persists the choice in `/data/adb/mcd/ui-language.conf`.

## Commands

```sh
su -c 'mcd-ctrl'        # interactive menu
su -c 'mcd-ctrl menu'   # explicit menu
su -c 'mcd-ctrl scan --deep'
su -c 'mcd-ctrl report'
su -c 'mcd-ctrl report --critical-only'
su -c 'mcd-ctrl explain MCD-XXXXXXXXXXXX'
su -c 'mcd-ctrl baseline create'
su -c 'mcd-ctrl baseline compare'
su -c 'mcd-ctrl export --privacy'
su -c 'mcd-ctrl self-test --full'
su -c 'mcd-ctrl boot-status'
su -c 'mcd-ctrl doctor'
```

## Reports

- `/data/adb/mcd/conflicts.log`
- `/data/adb/mcd/report.json`
- `/data/adb/mcd/findings.tsv`
- `/data/adb/mcd/module-status.tsv`
- `/data/adb/mcd/baseline.tsv`
- `/data/adb/mcd/baseline-diff.txt`
- `/data/adb/mcd/boot-scan.log`

## Safety

The scanner does not disable modules, modify mounts, write properties or sysfs, or alter SELinux policy. Recommendations are advisory. Low-confidence winner methods are explicitly labelled as heuristics.
