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

**Order:** finish all P0–P4 tasks; then harden theoretically
**indefinitely**; only the owner may activate P5. The owner will
perform the real hardware testing and send results in this chat.

**Priority rule:** work P0 first, then P1, P2, P3 and P4, following the
recorded dependencies. Within a priority choose the next dependency-ready
unfinished deliverable. If blocked, work on its actual prerequisite or an
independent ready item and record why; do not silently skip implementation
in favor of unlimited cosmetic hardening. Coordinate parallel work and Git
through the local agent-slack channel described in AGENTS.md. The temporary
lead role ends on explicit leave or chat-lease expiry; peers then continue
without waiting. No stale file or quiet chat proves task completion.

Each index entry has a TODO title, one summary and one typed-record link.

## Criterion for leaving only the final TODO

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

At that point the owner must be able to request compilation of the exact
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

### TODO - Resolve validator findings and review interrupted Python edits

Finish the pending lint/type corrections, review the interrupted edits under
tools/, preserve every script's behavior and obtain a fresh full validator
report with no unresolved findings. Necessary offline host tests are allowed;
kext builds, CI and hardware experiments remain unauthorized.

[docs/todo/open/governance/validator-findings.mdc](docs/todo/open/governance/validator-findings.mdc)

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

## P4 — Source-only

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

## Indefinite theoretical hardening

After P0–P4 source completion, continue research and source hardening
without deadline, physical checks or owner diagnostic requests.
This hold ends ONLY by an explicit owner decision.

When the acceptance TODO below is the sole open item and the owner gives no
new instruction, keep researching with web search and reviewing the entire
driver indefinitely. Find and repair concrete panic, bounds, lifetime,
locking, interrupt, DMA, power, cryptographic and regulatory defects. Compare
versioned source/documentation and record evidence, maintain the AR9565
ledger, and reopen source tasks when newly required work is found. Never
substitute formatting churn or unsupported safety claims for implementation.

## P5 — FINAL TODO: owner-controlled physical testing

### TODO - Owner-controlled Wi-Fi Bluetooth and AirDrop acceptance

The owner starts separately authorized Dell experiments only after all
theoretical tasks and the indefinite hold, then shares diagnostics here for
agent-guided bug fixes until the requested result is reached.
This task NEVER closes unless the owner explicitly asks to close it, even
after successful experiments. Without that request it remains open while
the standing theoretical-hardening instruction continues.

[docs/todo/open/owner/owner-controlled-device-acceptance.mdc](docs/todo/open/owner/owner-controlled-device-acceptance.mdc)
