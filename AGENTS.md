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

When only the final acceptance TODO remains, the committed AR9565 source
must be complete and integrated for all required paths, with no known
source-resolvable blocker, placeholder, permanently disabled substitute,
or invented readiness state. The owner must be able to request the first
GitHub compilation of that exact commit through ONE explicitly authorized
`build-v*` tag. This readiness criterion is not permission to create the
tag or run a build. Local builds and other CI triggers are not substitutes.
The required outcome is fully functional native Wi-Fi for PCI 168c:0036;
neither source review nor lint can promise 100% runtime success before
the owner-controlled experiment. Document unresolved platform assumptions
honestly rather than marking an unavailable native interface complete.

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
- No agent owns a file or work area exclusively. Coordinate overlapping
  edits temporarily and preserve concurrent work; the lanes below are
  responsibilities, not separate repositories or ownership boundaries.
- Before modifying or committing, inspect git status and recent
  history. Commit only your own files, in small source-focused units.
  Push normally to origin/main. Never force-push or rewrite history.
- Shared files such as src/SimpleATH.cpp, src/Info.plist, the Xcode
  project, AGENTS.md, TODO.md, README.md and lint settings must be
  coordinated via that chat before editing.
- All source changes may be researched and discussed in parallel;
  only Git writes to overlapping files require serialization.

## Priority, live coordination and handoff

Work in numerical priority order P0 -> P1 -> P2 -> P3 -> P4 -> P5,
respecting each record's dependencies. Select the highest-priority ready
unfinished work. If a prerequisite is unresolved, implement/research that
prerequisite first; record the exact blocker and advance independent work
without pretending the blocked task is complete. Parallel work may proceed
on independent dependency-ready paths, with temporary file coordination.
If the highest-priority path is already being implemented by a live peer,
coordinate its interface and choose independent ready work; do not steal
claims or wait idly for an entire task to finish.
Do not spend the project on repeated low-priority polishing while known
missing PCI/native-Wi-Fi/radio/data paths remain unassigned.

Use the existing local `agent-slack` CLI (the agents service), not real Slack:
join for this repository, read members/history, announce the task, reserve
only overlapping paths temporarily and reserve @git for each Git mutation.
Keep useful decisions/evidence in these TODO records because chat is volatile.
The owner designated the active TODO/validator coordinator as temporary lead;
that role lasts only while its chat lease is valid and it is actively working.
Heartbeat at least every five minutes while working; leases expire after
15 minutes. On explicit leave or lease expiry, peers take over highest-priority
work without waiting for the prior coordinator. This is a coordination handoff,
not evidence that code is complete or authorization for experiments. Do not
leave an autonomous background heartbeat running after work stops.

Create tests only for material behavior, regressions or error paths that
benefit from execution. Use root tests/ and tools/validate.py --tests; no
mandatory tests for trivial formatting/docs edits and no new test framework.
Tests must use synthetic data/fakes and stay offline with no device, RF,
EFI, root-patch, install, CI or network effects. Host tests do not verify
Tahoe kernel ABI or physical Wi-Fi. Keep failures/skips distinct from passes.

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

## Linux reference and implementation ledger

Maintain `linux-port-ledger.jsonl` when consulting or porting a file under
`linux/`. Follow `docs/design/LINUX-PORT-LEDGER.md`: record the exact source
SHA-256, the scope implemented, destination files, evidence and remaining
source work. Reading a file is not implementing it; a partial port is not
whole-file completion. An unrecorded use is unknown, not proof of non-use.

**Keep the Linux references until the dedicated Linux-reference retirement
TODO is complete.** The owner's later instruction authorizes deleting the
local `linux/` tree only AFTER the required AR9565 scopes are implemented
and integrated, every ledger entry is assessed for that target, and no
retained tool requires the local tree. Use the existing inline notices and
THIRD_PARTY_NOTICES.md; do not add archival bundles or provenance machinery.
Do not port unrelated chipsets or delete references merely
because they have been read or partially ported. Follow the retirement
record's conditions; they are not met by the present partial ledger.
Preserve each file's license and Qualcomm/Atheros copyrights. Append full
replacement records for status updates; the last record for a source path
is current. Commit the ledger with the related source change. No separate
database, WAL service, framework, build or test runner is needed.

## Prohibitions and tooling

New kext compilation, CI/build tags, actual PCI/RF activity, root patches
and USB/EFI/OpenCore/SSD modifications remain UNAUTHORIZED until the owner
expressly authorizes those steps. The owner has separately authorized
necessary offline host tests under root tests/: Python, C++ and
Objective-C++. This permits compiling/running isolated host test programs,
not building/loading a kext or exercising devices.
A boot or registry match alone is not proof of Wi-Fi function.

**SIMPLEATH IS AN EXPLICIT EXCEPTION TO THE JIG RULE. IT DOES NOT
USE JIG.** Do not run Jig, add hooks, enforce Jig architecture,
make Jig a required status check, or change existing .jig/ materials.
Leave .jig/ exactly as it is and inactive.

**The only dedicated validation entrypoint is tools/validate.py**:
a lightweight source-only runner for the system-installed Clang Format
and optional Clang-Tidy (C/Objective-C/C++), Ruff and BasedPyright
(Python). It reads only root .clang-format, .clang-tidy, ruff.toml,
pyrightconfig.json and .editorconfig. Unchanged files reuse
content-addressed results in .cache/validate/; report.json gives
machine-readable findings for coordinating agents. Use --no-cache
when imported dependencies change. Default execution is lint-only. The
optional --tests mode runs authorized offline tests under tests/ and may
compile standalone host test programs. Never build/link a kext, access
hardware, fetch/install tools or create compilation databases.

TODO.md indexes the canonical typed records in docs/todo/open/.
Each P0-P4 record is source-only, with acceptance and evidence separated
from the final owner-controlled P5 physical task. Accepted records move
to docs/todo/completed/ and disappear from the root TODO index.
P5 MUST remain open unless the owner explicitly requests its closure.
Build, installation or test authorization is not a closure request.

The validator-findings record hands off the interrupted Python edits. Those
working-tree edits are unfinished; review them before committing and cite a
fresh full validation report rather than a partial-file result. The owner stopped the helper agents originally invoked for that work.
A later instruction authorizes live coordination and necessary host tests;
use the local agent-slack channel before overlapping edits.

## Completion reporting

A pre-final TODO is complete when its researched source and integration
are implemented on main, documented and logically reviewed, with no
known source-resolvable blockers. Record unverified ABI assumptions
and fail-closed paths. Source review is not a statement of runtime
reliability or cryptographic certification. Do not invent scan results,
kernel logs, MACs, throughput or a claim of 100% tested Wi-Fi.

**No agent may begin the final experiment or ask the owner to start it.
The owner alone ends the indefinite theoretical-hardening hold.**

When only P5 remains and no new owner instruction arrives, continue
whole-source static hardening and web research indefinitely: compare
versioned upstream code and documentation; find and repair concrete panic,
memory, concurrency, DMA, power, security and regulatory defects. Record
evidence and useful source commits, not cosmetic churn or invented bugs.
Reopen an appropriate source TODO if new required work is discovered.
Keep the AR9565 ledger current through reference retirement. This standing
instruction never authorizes kext builds, tags, RF activity or P5 closure.
Necessary offline host tests remain within the separate authorization above.
