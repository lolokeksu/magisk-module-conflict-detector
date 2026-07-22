# Changelog

## v1.4 - 22.07.2026

- Added an interactive default `mcd-ctrl` menu with numbered actions.
- Added persistent Russian and English UI switching.
- Added an advanced menu accessible from the default menu.
- Added mountinfo-based effective owner detection with 100% confidence when the module source is proven.
- Added inode and live-content fallback matching.
- Removed lexical winner guessing for file, property and `.replace` collisions when evidence is unavailable.
- Added evidence states: CONFIRMED, PROBABLE, POSSIBLE and INFORMATIONAL.
- Added stable finding IDs to text and JSON reports.
- Added `mcd-ctrl explain FINDING_ID`.
- Added `mcd-ctrl summary`.
- Added report filtering by severity, module and finding ID.
- Added active, disabled, pending-removal, pending-update, incomplete and skip-mount module states.
- Added timestamped report history with configurable retention.
- Added `mcd-ctrl history` and `mcd-ctrl diff`.
- Added persistent SHA-256 cache and cache management commands.
- Added `mcd-ctrl support-bundle` with privacy-conscious diagnostic collection.
- Added JSON schema v2 with module states, evidence status and scan duration.
- Extended runtime-script parsing for multiline commands, literal variables, tee writes, delete operations, setenforce, overlay/package state, netfilter and traffic control.
- Improved critical-only output when no critical conflicts exist.
- Added v1.4 regression tests for ownership evidence, finding IDs, module states, JSON, language switching and interactive control.

## v1.3 - 21.07.2026

- Replaced the scanner core with value-aware and content-aware conflict analysis.
- Added robust root-manager detection and reliable boot scanning across Magisk, KernelSU-family and APatch.
- Added SHA-256 comparison, live winner checks, snapshots, JSON reports and mobile CLI help.

## v1.2 - 28.06.2026

- Refactored the module structure and fixed path collision scanning.

## v1.1 - 10.06.2026

- Added whitelist support and `.replace` collision detection.

## v1.0 - 09.06.2026

- Initial public release.
