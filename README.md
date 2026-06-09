# Module Conflict Detector

![Version](https://img.shields.io/badge/version-v1.0-blue)
![Platform](https://img.shields.io/badge/platform-Magisk%20%7C%20KSU%20%7C%20APatch-orange)
![Android](https://img.shields.io/badge/android-8.0%2B-green)
![License](https://img.shields.io/badge/license-GPL--3.0-red)

Magisk/KSU/APatch module that detects file overlay conflicts between installed modules.

---

## Problem

When multiple modules are active, each mounts a file overlay via magic mount. If two modules replace the **same system file**, the last one alphabetically wins — silently. No warning is shown.

**Common conflict scenarios:**
- Two modules both modify `build.prop`
- Two font mods replace the same `.ttf` files
- A performance tweaker and another module both target the same sysfs node
- Two hide/spoof modules overwrite the same system library

---

## Features

- Scans all active modules and their `/system` overlays
- Detects files claimed by more than one module
- Identifies the winning module (alphabetical order = last wins)
- Classifies conflicts by severity: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`
- Human-readable log + machine-readable JSON report
- Auto-scan on every boot (non-blocking, runs in background)
- CLI control via `mcd-ctrl`

---

## Requirements

- Android 8.0+
- Magisk 20.4+ / KernelSU / APatch
- BusyBox (bundled with Magisk)

---

## Installation

1. Download the latest `.zip` from [Releases](../../releases)
2. Flash via Magisk / KSU / APatch
3. Reboot
4. First scan runs automatically ~30 seconds after boot

---

## Usage

```sh
# Run via Termux or any root terminal:
su -c mcd-ctrl scan          # scan for conflicts
su -c mcd-ctrl report        # human-readable report
su -c mcd-ctrl report --json # JSON report
su -c mcd-ctrl clear         # clear logs
```

---

## Severity Levels

| Level | Paths |
|---|---|
| `CRITICAL` | `/bin`, `/xbin`, `sepolicy`, `init` scripts |
| `HIGH` | `build.prop`, `/framework`, `/lib`, `/lib64` |
| `MEDIUM` | `/fonts`, `/media`, `/etc` |
| `LOW` | Everything else |

---

## Output Files

| File | Description |
|---|---|
| `/data/adb/mcd/conflicts.log` | Human-readable conflict report |
| `/data/adb/mcd/report.json` | JSON report for scripting |

### Example `report.json`

```json
{
  "scan_time": "2026-06-09T14:32:00",
  "modules_scanned": 6,
  "files_scanned": 843,
  "conflicts_count": 2,
  "conflicts": [
    {
      "path": "/system/build.prop",
      "modules": ["BootIntegrityMask", "PlayIntegrityFix"],
      "winner": "PlayIntegrityFix",
      "severity": "HIGH"
    }
  ]
}
```

---

## Author

**ExchNow (by Lolokeksu)** — [4PDA](https://4pda.to/forum/index.php?showtopic=915158&view=findpost&p=143786143)

---

## License

[GPL-3.0](LICENSE)
