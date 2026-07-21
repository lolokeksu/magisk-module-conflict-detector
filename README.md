# Module Conflict Detector v1.3

Read-only diagnostic module for Magisk-compatible, KernelSU-family and APatch module systems. It finds collisions between active root modules without modifying modules, mounts, properties, sysfs or SELinux policy.

## Supported root-manager families

- Magisk and managers exposing a Magisk-compatible `su`/module environment.
- KernelSU, KernelSU Next, SukiSU Ultra, ReSukiSU and other `ksud`-compatible forks.
- APatch and managers exposing an APatch-compatible `apd` environment.

The module directory remains `/data/adb/modules`, which is shared by these module systems.

## Root-manager detection

Detection is evidence-ranked to prevent stale directories from producing false combinations:

1. Current `su -v` or `su --version` provider signature.
2. Exact active daemon: `magiskd`, `ksud` or `apd`.
3. Executable manager-owned core binary.
4. Unique directory layout as a low-confidence fallback only.

A retained `/data/adb/magisk`, `/data/adb/ksu` or `/data/adb/ap` directory alone never overrides stronger evidence. Ambiguous leftovers are reported as `unknown`, not as multiple simultaneously active managers.

`mcd-ctrl doctor` and `report.json` include:

- `root_manager`
- `root_manager_family`
- `root_detection_method`
- `root_detection_confidence`
- `root_detection_evidence`

## Conflict-analysis capabilities

- Canonical path collision detection across `system`, `vendor`, `product`, `system_ext`, `odm` and `*_dlkm` overlays.
- SHA-256 comparison: different content is actionable; identical duplicates are informational.
- Live winner resolution by matching the mounted file, current property or current sysfs value to module candidates.
- Explicit lexical fallback when an effective owner cannot be proven.
- `.replace` collision and tree-masking analysis.
- Module-local `overlay.d` analysis and global `/data/adb/overlay.d` inventory.
- `system.prop` key and value comparison.
- Runtime-script analysis for `service.sh`, `post-fs-data.sh`, `boot-completed.sh` and `action.sh`.
- Detection of conflicting property, settings, device_config, sysctl, sysfs, mount, file-operation, permission and live-sepolicy actions.
- Exact known-pair database, whitelist, snapshots and stale-lock recovery.

## Installation

1. Download `ModuleConflictDetector-v1.3.zip` from the GitHub release.
2. Install it in Magisk, KernelSU-family or APatch manager.
3. Reboot.
4. Verify with `su -c 'mcd-ctrl doctor'`.

## Commands

```sh
su -c 'mcd-ctrl version'
su -c 'mcd-ctrl doctor'
su -c 'mcd-ctrl boot-status'
su -c 'mcd-ctrl scan --deep'
su -c 'mcd-ctrl report'
su -c 'mcd-ctrl report --json'
su -c 'mcd-ctrl report --critical-only'

su -c 'mcd-ctrl snapshot create before-install'
su -c 'mcd-ctrl snapshot compare before-install'
su -c 'mcd-ctrl snapshot list'
su -c 'mcd-ctrl snapshot delete before-install'

su -c 'mcd-ctrl whitelist add /system/bin/example'
su -c 'mcd-ctrl whitelist add system.prop:debug.hwui.renderer'
su -c 'mcd-ctrl whitelist add script:prop:debug.hwui.renderer'
su -c 'mcd-ctrl whitelist list'

su -c 'mcd-ctrl config list'
su -c 'mcd-ctrl config set auto_scan 0'
su -c 'mcd-ctrl clear'
```

## Automatic boot scan

- Magisk-compatible managers use the non-backgrounded `service.sh` fallback.
- KernelSU-family and APatch managers can use the native `boot-completed.sh` hook.
- Both lifecycle paths call one shared launcher with a per-boot ID and process lock, so only one scan is written per boot.
- Status: `/data/adb/mcd/boot-scan.status`.
- Diagnostic log: `/data/adb/mcd/boot-scan.log`.
- A successful automatic report contains `"boot_scan": true`.

## Reports

- `/data/adb/mcd/conflicts.log`
- `/data/adb/mcd/report.json`
- `/data/adb/mcd/reports/conflicts-latest.log`
- `/data/adb/mcd/reports/report-latest.json`
- `/data/adb/mcd/snapshots/*.tsv`

## Safety

The scanner is read-only. It does not mount or unmount filesystems, change properties, write sysfs, modify SELinux policy or disable modules.
