# Changelog

## v1.4 - 27.07.2026

- Added a full interactive menu optimized for smartphone screens.
- Running `mcd-ctrl` without arguments now opens the main menu.
- Added separate quick and full scan modes.
- Added an advanced menu, editable settings and improved help output.
- Every finding now receives a stable unique ID in the `MCD-XXXXXXXXXXXX` format.
- Added detailed finding explanations through `mcd-ctrl explain ID`.
- Reports now include confidence, reason codes, possible impact and recommendations.
- Improved effective-winner detection; unverified results are reported as `unresolved`.
- Added separate handling for active, disabled, pending-removal and `skip_mount` modules.
- Fixed `.replace` risk classification for critical system directories.
- Added basic conservative analysis of conflicting `sepolicy.rule` entries.
- Added baseline creation and comparison for before-and-after module state checks.
- Added diagnostic archive export with device-data redaction.
- Separated the built-in known-conflict database from user-defined rules and prepared it for expansion.
- Expanded `mcd-ctrl self-test --full`.
- Added finding-ID uniqueness and stability checks.
- Added strict JSON validation without requiring Python or `jq` on the device.
- Improved stale scan-lock recovery and duplicate boot-scan protection.
- `report --critical-only` now shows a clear message when no critical findings exist.
- Improved text and JSON reports.
- Preserved compatibility with Magisk, KernelSU, APatch and supported forks.
- The module does not modify system settings or other modules; it writes only its own reports, settings and diagnostic files.

## v1.3 - 21.07.2026

- Completely redesigned the conflict-detection engine.
- Fixed root-manager detection on devices containing remnants of other root solutions.
- Added accurate detection of Magisk, KernelSU, APatch and supported forks.
- Added the root-detection method, confidence level and diagnostic evidence.
- Fixed false combined Magisk and APatch detection.
- Added SHA-256 comparison for conflicting files.
- Identical files are now reported as informational duplicates instead of real conflicts.
- Added effective-winner detection using the current file, property or runtime value.
- Added path normalization for `system`, `vendor`, `product`, `system_ext`, `odm` and `*_dlkm`.
- Improved detection of file, symlink, whiteout and path collisions.
- Improved `.replace` analysis and detection of one module masking another module's tree.
- Added scanning of module-local and global `overlay.d` directories.
- Improved `system.prop` analysis with property-value comparison.
- Added analysis of `service.sh`, `post-fs-data.sh`, `boot-completed.sh` and `action.sh`.
- Added detection of conflicting `settings`, `device_config`, `sysctl`, sysfs, mount, `chmod`, `chown` and `resetprop` operations.
- Added a database of known incompatible module pairs.
- Added module-state snapshots and snapshot comparison.
- Added deep scanning through `mcd-ctrl scan --deep`.
- Added critical-only reporting through `mcd-ctrl report --critical-only`.
- Added `mcd-ctrl boot-status`, boot-scan status and a dedicated automatic-scan log.
- Fixed automatic post-boot scanning on APatch and FolkPatch.
- Added `boot-completed.sh` support for APatch and KernelSU.
- Added duplicate-launch protection, boot-ID binding and stale scan-lock recovery.
- Improved the `doctor`, `config`, `whitelist` and `clear` commands.
- Improved text and JSON reports.
- Added device, Android, ABI, kernel and SELinux information.
- Added a compact menu optimized for smartphone screens.
- Translated unknown-command messages into Russian.
- Verified root detection, deep scanning and boot scanning on APatch and FolkPatch.
- Compatibility: Magisk, KernelSU, APatch and supported forks.
