# Module Conflict Detector

Magisk / KernelSU / APatch module that detects likely overlay conflicts between installed root modules.

The public module identity is intentionally preserved for GitHub and 4PDA compatibility:

```text
id=ModuleConflictDetector
name=Module Conflict Detector
```

## Problem

When several modules mount or replace the same system path, the effective result can depend on module order and implementation details. This can silently break fonts, spoofing modules, framework patches, system apps, native libraries, init scripts, permissions XML, or other overlays.

Module Conflict Detector performs a read-only scan of installed active modules and reports suspicious collisions before the user starts disabling modules blindly.

## Features

- Scans active modules in `/data/adb/modules`.
- Detects same-path collisions across module overlays.
- Detects file, symlink and character-device/whiteout path collisions.
- Detects `.replace` directory collisions.
- Detects `.replace` directories that mask files from another module.
- Detects likely `system.prop` key collisions.
- Classifies findings by severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- Generates human-readable and JSON reports.
- Supports whitelist entries for accepted conflicts.
- Provides optional auto-scan after boot.
- Provides `action.sh` support for module managers.

## Safety

The scan is read-only. It does not mount, unmount, edit system properties, modify SELinux policy, touch kernel settings, tune thermal nodes, or change installed modules.

## Installation

1. Flash `ModuleConflictDetector-v1.2.zip` in Magisk, KernelSU, APatch, or a compatible module manager.
2. Reboot.
3. Run a manual scan or use the module action button.

## Commands

```sh
su -c mcd-ctrl scan
su -c mcd-ctrl scan --quiet
su -c mcd-ctrl report
su -c mcd-ctrl report --json
su -c mcd-ctrl doctor
su -c mcd-ctrl clear
```

Whitelist:

```sh
su -c 'mcd-ctrl whitelist add /system/bin/example'
su -c 'mcd-ctrl whitelist remove /system/bin/example'
su -c 'mcd-ctrl whitelist list'
```

Config:

```sh
su -c 'mcd-ctrl config list'
su -c 'mcd-ctrl config set auto_scan 0'
su -c 'mcd-ctrl config set auto_scan 1'
su -c 'mcd-ctrl config set boot_delay_seconds 45'
```

## Output files

```text
/data/adb/mcd/conflicts.log
/data/adb/mcd/report.json
/data/adb/mcd/config.conf
/data/adb/mcd/whitelist.conf
```

## Severity guide

| Severity | Typical paths |
|---|---|
| `CRITICAL` | `/system/bin`, `/system/xbin`, `init`, `sepolicy`, permissions, sysconfig |
| `HIGH` | `build.prop`, framework, app, priv-app, native libraries |
| `MEDIUM` | fonts, media, general `/etc` resources |
| `LOW` | other overlay paths |

## Notes

This module reports likely conflicts. It cannot prove runtime behavior for every root implementation because Magisk, KernelSU and APatch can differ in overlay and replace semantics.

## License

GPL-3.0
