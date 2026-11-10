# SimpleATH TODO

Only unfinished tasks appear here. Typed records in docs/todo/open/
contain identity, priority, dependencies, acceptance and evidence.
Move source-completed records to docs/todo/completed/ and remove
their index entries without deleting their recorded provenance.

**All P0–P4 work is strictly theoretical/source-only.** No hardware
verification, Dell logs, physical scan or kext compilation may be required
to finish a pre-final task. Necessary offline Python/C++/Objective-C++ host
tests under tests/ are now authorized through tools/validate.py --tests;
they do not establish kernel or hardware success. Research online code and
documentation, document uncertainty, and make unknowns fail closed.

Ten agents coordinate in their existing chat, commit directly to main
and do not open PRs. This repository does not use Jig. Use only the
installed-tool validator tools/validate.py and its local .cache/ report.

## FIRST IMPLEMENTATION, THEN CORRECTION

Owner directive, 2026-11-09. This is the project's highest-priority order:

1. **Implement the complete production driver, 100%.** Finish and connect
   every required runtime path in the normal build target. Missing PCI,
   RF/PHY/calibration, DMA/interrupts, native AirPort, scan/connect, WPA2,
   packet delivery, Bluetooth USB/BLE, AirDrop/AWDL, power and recovery
   behavior takes precedence over
   lint-only work or speculative hardening. No passive substitutes, empty
   callbacks, experimental opt-ins or permanently disabled required features.
2. **Then validate the linters and reach zero failures.** Resolve every
   finding without weakening rules, hiding source or treating skips as passes.
   Required checks must report zero failures and zero skips on the integrated
   source. Do not substitute repeated lint sweeps for step 1.
3. **Keep CI as the mandatory build gate.** A kernel build requires successful
   CI for that exact commit; failed, canceled or skipped CI blocks the build.
4. **Then harden edge cases indefinitely and finish the remaining TODOs while
   testing the driver.** Once implementation and the zero-failure validation
   milestone are met, ongoing hardening runs alongside owner-authorized
   notebook testing. The owner shares real logs in this conversation; agents
   diagnose, implement fixes and repeat the CI/build/test loop. Hardening has
   no completion deadline and must never become an indefinite testing hold.

Source completeness is an implementation milestone, not proof of physical
Wi-Fi success. Readiness must reflect actual completed operations; never
replace missing functionality with labels or fabricated success flags.

**Priority rule:** implement missing runtime functionality first, following the
recorded dependencies. Within a priority choose the next dependency-ready
unfinished deliverable. If blocked, work on its actual prerequisite or an
independent ready item and record why; do not silently skip implementation
in favor of unlimited cosmetic hardening. Coordinate parallel work and Git
through the local agent-slack channel described in AGENTS.md. The temporary
lead role ends on explicit leave or chat-lease expiry; peers then continue
without waiting. No stale file or quiet chat proves task completion.

Each index entry has a TODO title, one summary and one typed-record link.

## Production implementation and testing milestones

**Full theoretical functionality is the exit criterion: 100% of the required
AR9565 kext behavior must be implemented and integrated.** Completion means
the source is expected to perform the entire supported workflow correctly,
with no known missing implementation. Formatting, research notes and a
successful passive match cannot establish that milestone.

All required AR9565/QCA9565 PCI 168c:0036 source must be implemented,
connected to the native Tahoe interface, included in the Xcode target and
reviewed on main. No known source-resolvable blocker, unimplemented required
callback, passive-only replacement or fabricated readiness flag may remain.
Each completed record must cite its implementation commits and concrete
static evidence; lint alone is insufficient. All validator findings must
be resolved without hiding files, weakening rules or calling skipped checks
successful. Record which checks actually ran.

After the implementation and zero-failure validation milestones, the owner
must be able to request compilation of the exact
reviewed commit in GitHub Actions using ONE expressly authorized `build-v*`
tag. Do not create a tag, dispatch CI, compile a kext locally, install or experiment
without the corresponding explicit authorization. No exact tag is authorized
by this roadmap. Source readiness must not depend on a prior build or test.

The required outcome is 100% functional native Wi-Fi for this target, followed
by the requested Bluetooth/coexistence and AirDrop acceptance. Source-only
completion is an engineering readiness claim, not proof or a guarantee that
the first build or hardware run will succeed. Unknown hardware conditions
and separate Bluetooth/Continuity support must remain honestly documented.

## P0 — Source-only

### TODO - Complete production driver implementation — highest priority

Implement and integrate 100% of the required native AR9565 driver behavior
before starting the zero-failure lint milestone. This umbrella TODO drives
all required ABI, PCI, NVM, radio, DMA, Wi-Fi and full-pipeline deliverables
below. It remains open while any required runtime path is absent or disabled.

[docs/todo/open/integration/production-implementation.mdc](docs/todo/open/integration/production-implementation.mdc)

### TODO - QCA9565 Bluetooth USB/BLE implementation

Implement the combo chip's actual Bluetooth USB HCI/firmware, native macOS
stack integration, power lifecycle and Wi-Fi coexistence in source.

[docs/todo/open/platform/bluetooth-usb.mdc](docs/todo/open/platform/bluetooth-usb.mdc)

### TODO - AirDrop Wi-Fi/BLE implementation

Integrate native AWDL/peer-to-peer Wi-Fi, BLE discovery and the required
macOS AirDrop packet/event behavior; ordinary WLAN connectivity is insufficient.

[docs/todo/open/platform/airdrop-awdl.mdc](docs/todo/open/platform/airdrop-awdl.mdc)

### TODO - Tahoe ABI

Research public Tahoe KDK/SDK exports, IOPCIFamily, IO80211FamilyLegacy,
IOSkywalkFamily and IONetworkingFamily. Document method/lifetime contracts and
source-level compatibility, with explicit unverified assumptions and
fail-closed behavior. **No live logs needed.**

[docs/todo/open/abi/exact-tahoe-abi.mdc](docs/todo/open/abi/exact-tahoe-abi.mdc)

### TODO - EEPROM/OTP

Complete bounded NVM read algorithms, dictionaries, revision matching,
MAC/board checksums, antenna and calibration data interpretation, with safe
rejection of unknown layouts. Use ath9k references; **never require a dump of
the user's actual EEPROM to finish the source task**.

[docs/todo/open/hardware/eeprom-otp.mdc](docs/todo/open/hardware/eeprom-otp.mdc)

## P1 — Source-only

### TODO - Native PCI

Complete source for exact-device identification, PCI ownership and power D0,
BAR/MMIO access, concurrency, command rollback and safe teardown, based on
documented APIs and public source. **No physical PCI reads.**

[docs/todo/open/platform/native-pci.mdc](docs/todo/open/platform/native-pci.mdc)

### TODO - RF/PHY/regulatory

Finish revision-aware radio power/reset, PLL/synthesizer, gains, channel
selection, ANI/noise handling, RF-kill, calibration and legal per-channel TX
power constraints. Source must reject unknown board or country states. **No
live signal or transmission tests.**

[docs/todo/open/hardware/rf-phy-regulatory.mdc](docs/todo/open/hardware/rf-phy-regulatory.mdc)

### TODO - EDMA/interrupts

Implement ring allocation, IOMMU/DMA contracts, RX/TX ownership, descriptors,
completion, interrupt handling, memory safety, sleep and fault recovery in
source. Consult public ath9k and IOKit documentation. **No physical packet
transfer required.**

[docs/todo/open/hardware/edma-interrupts.mdc](docs/todo/open/hardware/edma-interrupts.mdc)

## P2 — Source-only

### TODO - 802.11 MAC

Complete scanning/channel-dwell decisions, beacons, RSN, advertised rates,
authentication, association, BSS snapshots, timeouts and reconnection. **No
actual Wi-Fi scan or screenshot required.**

[docs/todo/open/wifi/ieee80211-mac.mdc](docs/todo/open/wifi/ieee80211-mac.mdc)

### TODO - WPA2/CCMP

Complete theoretically reviewed PMK/PTK, EAPOL MIC and four-way handshake, AES
unwrap, CCMP, keycache, group rekey and packet-number/replay control. Compare
algorithms with published specifications and source vectors; use necessary
offline regression tests, without claiming cryptographic certification.

[docs/todo/open/wifi/wpa2-ccmp.mdc](docs/todo/open/wifi/wpa2-ccmp.mdc)

### TODO - Tahoe AirPort

Complete the proposed native IO80211Controller/IO80211Interface integration,
Wi-Fi UI scan/connect/status requests, networking, power transitions and packet
contracts. Research public code and documentation without copying incompatible
proprietary or third-party ABI code. **No live Wi-Fi UI acceptance
prerequisite.**

[docs/todo/open/platform/native-tahoe-airport.mdc](docs/todo/open/platform/native-tahoe-airport.mdc)

## P3 — Source-only

### TODO - Integrate the entire theoretical source pipeline

PCI → PHY → DMA → 802.11 MAC → WPA2/CCMP → native AirPort. Resolve
state/locking ownership, data movement, failures, cleanup, suspend/resume and
reconnection in code. Remove placeholders and invented readiness indicators.
**Source completeness only; not physical connectivity.**

[docs/todo/open/integration/full-wifi-pipeline.mdc](docs/todo/open/integration/full-wifi-pipeline.mdc)

## Validation milestone — after 100% implementation

### TODO - Resolve validator findings and review interrupted Python edits

After implementing the entire required driver, finish pending lint/type
corrections and review interrupted edits under tools/. Preserve every script's
behavior and obtain a fresh full validator
report with no unresolved findings. Necessary offline host tests are allowed;
kext builds, CI and hardware experiments remain unauthorized.

[docs/todo/open/governance/validator-findings.mdc](docs/todo/open/governance/validator-findings.mdc)

## P4 — Continuous hardening and remaining source work

### TODO - Finish source-only hardening/documentation

Reason through bounds, overflow, lifetime, crypto erasure, regulatory safety,
deadlocks, interrupt races, rollback, licensing and documentation. Keep
README/AGENTS/TODO accurate. Use tools/validate.py for installed Clang, Ruff
and BasedPyright checks plus necessary offline host tests; no Jig, new
frameworks, kext compilation, CI or hardware diagnostics.

[docs/todo/open/governance/source-hardening.mdc](docs/todo/open/governance/source-hardening.mdc)

### TODO - Complete the AR9565 Linux ledger and retire local references

Finish the required AR9565 scopes, assess every ledger entry for this target,
remove local-tree tool dependencies, then delete only the repository's local
linux/ reference tree. Existing THIRD_PARTY_NOTICES.md and inline source
notices are sufficient; do not add an archive or provenance infrastructure.
Unrelated Linux features and chipsets require a justified out-of-scope record,
not an unnecessary port. The deletion conditions are not satisfied today.

[docs/todo/open/governance/linux-reference-retirement.mdc](docs/todo/open/governance/linux-reference-retirement.mdc)

## Continuous hardening alongside notebook testing

After 100% implementation and zero-failure validation, continue edge-case
hardening indefinitely and complete the remaining documentation, provenance
and maintenance TODOs. This work proceeds in parallel with the owner's
authorized notebook tests and the log-driven repair loop. It never delays
all testing until an unfinishable hardening phase is declared complete.
Every subsequent kernel build still requires successful CI.

## P5 — FINAL TODO: owner-controlled physical testing

### TODO - Owner-controlled Wi-Fi Bluetooth and AirDrop acceptance

- [ ] Run `tools/debug/SimpleATH-debug.command` on the target Mac with its
      mandatory sudo elevation. Reproduce the issue, preserve the generated
      `SimpleATH-debug-*.log` beside the tool and share it in this chat for
      Wi-Fi/Bluetooth/AirDrop diagnosis and source fixes.

The owner starts separately authorized Dell experiments only after all
required implementation, zero-failure validation and successful CI, then
shares diagnostics here during continuous hardening for
agent-guided bug fixes until the requested result is reached.
This task NEVER closes unless the owner explicitly asks to close it, even
after successful experiments. Without that request it remains open.

[docs/todo/open/owner/owner-controlled-device-acceptance.mdc](docs/todo/open/owner/owner-controlled-device-acceptance.mdc)
