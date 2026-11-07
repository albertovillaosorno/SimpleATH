# SimpleATH — mandatory instructions for every agent

**Target:** Qualcomm Atheros AR9565 / QCA9565 (PCI 168c:0036) native Wi-Fi
for Intel macOS Tahoe on Dell Inspiron 5567.
**Owner:** albertovillaosorno.
**Status:** experimental; NOT verified as a working Wi-Fi driver.
Read TODO.md, README.md and relevant docs/design/ records before editing.
Source code, comments, documents and commits are written in English.

## Absolute rule: source-only work and no hardware prerequisites

**EVERY TODO EXCEPT THE SINGLE FINAL USER-TEST TODO MUST BE COMPLETABLE
ENTIRELY THROUGH THEORY, ONLINE SOURCE CODE, PUBLISHED DOCUMENTATION,
STATIC ANALYSIS, AND REASONED SOURCE IMPLEMENTATION.**

**NEVER require physical hardware verification, a Dell boot, EEPROM
dumps from the owner's hardware, Wi-Fi scans, logs, RF measurements,
kext injection, real-world QA, or owner diagnostics to finish a
pre-final TODO.** Study Linux ath9k, published standards, public
macOS/IOKit ABI references and source from other drivers instead.
If the public evidence is incomplete, record assumptions and implement
safe rejection/rollback. Do not make up evidence or label assumptions
as proven behavior.

**FIRST finish every pre-final TODO. THEN harden the source and research
indefinitely**, without scheduling builds or requesting physical tests.
The hold has no expiry or target date. The owner alone decides when
to end it and begin the FINAL TODO. Theoretical completion can be
declared without hardware, but it is NOT proof of working networking.

Only the final TODO permits experimental hardware activity after fresh,
explicit owner authorization. The owner will physically test the
Dell and share diagnostics in THIS ChatGPT conversation. Agents use
their existing coordination chat to discuss source fixes; source
changes will continue until the owner is satisfied. Bluetooth and
AirDrop have separate hardware/Continuity dependencies and cannot
be guaranteed from AR9565 source analysis alone.

## Collaboration: direct main only, absolutely no PRs

- **All agents work, commit and push DIRECTLY to main. Pull requests
  are permanently prohibited unless the owner explicitly reverses this.**
  Do not open PRs, create feature branches or agent worktrees.
- Use the existing AGENT COORDINATION CHAT to claim files, discuss
  interfaces and sequence work. Only one writer at a time per shared
  file; never overwrite another agent's uncommitted changes.
- Before modifying or committing, inspect git status and recent
  history. Commit only your own files, in small source-focused units.
  Push normally to origin/main. Never force-push or rewrite history.
- Shared files such as src/SimpleATH.cpp, src/Info.plist, the Xcode
  project, AGENTS.md, TODO.md, README.md and lint settings must be
  coordinated via that chat before editing.
- All source changes may be researched and discussed in parallel;
  only Git writes to overlapping files require serialization.

## Ten agent work areas (not hexagonal architecture)

| Agent | Source-only responsibility |
| --- | --- |
| A1 | Exact Tahoe ABI and public KDK/IOPCIFamily/IO80211 evidence |
| A2 | Safe AR9565 PCI access, identity, BAR/MMIO, power and rollback |
| A3 | EEPROM/OTP parsing, acquisition algorithms, board calibration |
| A4 | RF/PHY, revision tables, calibration, regulatory/power policy |
| A5 | AR9003 EDMA, interrupts, IOMMU and packet ownership |
| A6 | 802.11 scanning, MAC management, association, rate selection |
| A7 | WPA2, CCMP, cryptography and key lifetime |
| A8 | Tahoe-native IO80211/Skywalk AirPort interface |
| A9 | Complete Wi-Fi pipeline, packets, suspend and recovery |
| A10 | Static hardening, minimal lint, docs and integration hygiene |

This division is a coordination aid only. Do not impose hexagonal
ports/adapters or relocate files merely for a tooling convention.
Respect ath9k licenses and the origin of third-party materials.

## Prohibitions and tooling

New kext compilation, CI/build tags, test suites, actual PCI/RF
activity, root patches and USB/EFI/OpenCore/SSD modifications remain
UNAUTHORIZED until the owner expressly authorizes those steps.
A boot or registry match alone is not proof of Wi-Fi function.

**SIMPLEATH IS AN EXPLICIT EXCEPTION TO THE JIG RULE. IT DOES NOT
USE JIG.** Do not run Jig, add hooks, enforce Jig architecture,
make Jig a required status check, or change existing .jig/ materials.
Leave .jig/ exactly as it is and inactive.

**The only dedicated validation entrypoint is tools/validate.py**:
an extremely lightweight, source-only runner for the existing Clang
formatter and, when a compilation database is already available,
Clang-Tidy on C/Objective-C/C++. It must never build, link, run
tests, fetch tools or create compilation databases. Keep existing
root .clang-format, .clang-tidy and .editorconfig rules. Do not
download linter configurations or dependencies.

## Completion reporting

A pre-final TODO is complete when its researched source and integration
are implemented on main, documented and logically reviewed, with no
known source-resolvable blockers. Record unverified ABI assumptions
and fail-closed paths. Source review is not a statement of runtime
reliability or cryptographic certification. Do not invent scan results,
kernel logs, MACs, throughput or a claim of 100% tested Wi-Fi.

**No agent may begin the final experiment or ask the owner to start it.
The owner alone ends the indefinite theoretical-hardening hold.**
