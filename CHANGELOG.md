# Changelog

## v1.4 - 22.07.2026

- Default `mcd-ctrl` now opens a compact bilingual Russian/English menu with three primary actions and a separate advanced mode.
- Added a compact interactive mobile menu for module action and `mcd-ctrl menu`.
- Added stable finding IDs and `mcd-ctrl explain ID` with risk, impact and recommendation.
- Added confidence, actionability and reason codes to text and JSON findings.
- Added explicit module-priority winner resolution before low-confidence lexical fallback.
- Added active, disabled, pending-removal and `skip_mount` module inventory.
- Added baseline create/compare/reset and automatic post-scan baseline diff.
- Added privacy-aware diagnostic export with ZIP and safe tar.gz fallback.
- Added a versioned TSV known-conflict database with version, root-family and SDK constraints.
- Added `mcd-ctrl self-test` and isolated `--full` conflict fixtures.
- Added compact and full help modes suitable for narrow Android terminals.

## v1.3 - 21.07.2026

- Replaced the v1.2 scanner core with a value-aware and content-aware engine.
- Added SHA-256 candidate comparison and informational classification for identical duplicates.
- Added live effective-owner matching for mounted files, properties and sysfs values, with method and confidence fields.
- Added canonical path normalization across `system`, `vendor`, `product`, `system_ext`, `odm` and `*_dlkm` overlays.
- Added `.replace` collision and tree-masking analysis.
- Added module-local `overlay.d` scanning and global `/data/adb/overlay.d` inventory.
- Added `system.prop` value comparison and current-value matching.
- Added runtime-script analysis for properties, settings, device_config, sysctl, sysfs, mounts, file operations, permissions and live sepolicy actions.
- Added exact known-pair database support, whitelist handling, snapshots and before/after comparison.
- Added device metadata and an expanded JSON report schema.
- Added stale scan-lock recovery and `--critical-only` reporting.
- Fixed false combined root-manager results caused by stale/shared `/data/adb` directories.
- Root-manager detection now prioritizes the active `su` provider signature, then exact daemon names, then manager-owned executable binaries.
- Added family-aware detection for Magisk-compatible, KernelSU-family and APatch managers, including identifiable forks.
- Added root detection method, confidence, family and evidence to `doctor` and JSON reports.
- Fixed automatic scans on APatch/FolkPatch where a background child could be terminated after `service.sh` exited.
- Added native `boot-completed.sh` support for APatch and KernelSU-family managers.
- Added a shared one-shot boot launcher with per-boot deduplication, process locking and stale-lock recovery.
- Added `/data/adb/mcd/boot-scan.status`, `/data/adb/mcd/boot-scan.log` and `mcd-ctrl boot-status`.
- Added a bounded wait for `sys.boot_completed` in the Magisk-compatible service fallback.

## v1.2 - 28.06.2026

- Refactored the module layout while preserving `id=ModuleConflictDetector`.
- Fixed relative-path construction in path collision scanning.
- Moved the CLI to `bin/mcd-ctrl` and added a `/system/bin` entry point.
- Added action, uninstall, lock, config, doctor, whitelist safety, symlink/whiteout scanning, `.replace` masking and `system.prop` key scanning.

## v1.1 - 10.06.2026

- Added whitelist support and `.replace` collision detection.
- Fixed conflict count generation.

## v1.0 - 09.06.2026

- Initial public release.
