# SimpleATH — source-first roadmap and indefinite hardening

**Target:** Qualcomm Atheros AR9565/QCA9565 (PCI 168c:0036),
Dell Inspiron 5567, Intel macOS Tahoe.
**Status:** experimental source and an earlier passive kext.
Wi-Fi, Bluetooth and AirDrop are NOT verified working.

## Absolute sequence and authorization

**EVERY TODO EXCEPT THE LAST ONE IS STRICTLY THEORETICAL/SOURCE-ONLY.**
**NOTHING BEFORE THE LAST TODO MAY DEPEND ON FORMAL OR INFORMAL
VERIFICATION WITH PHYSICAL HARDWARE.** No Dell boots, kext injection,
EEPROM dumps, physical diagnostics, Wi-Fi scans, RF measurements,
network connectivity, owner-provided logs, or other hardware evidence
may become a prerequisite of a pre-final checkbox.

Research online code, published specifications, public KDK/SDK data,
existing repository sources and technical documentation. Implement
and harden code; reason about error handling and compatibility.
Where hardware facts cannot be proven offline, document assumptions
and add fail-closed behavior. Do not misrepresent theoretical
completion as experimentally verified performance.

**Mandatory order:**
1. Complete ALL of the source-only TODOs below.
2. Continue **theoretical hardening indefinitely**, using more
   online code, documentation, static inspection and source repairs.
   No expiration, automatic release, forced deadline or proactive
   demand for hardware verification exists.
3. **ONLY when the owner explicitly decides** the indefinite hold
   is over, begin the FINAL TODO. The owner personally tests the
   actual Dell and sends diagnostic results in THIS ChatGPT chat.
   The agents coordinate in their existing agent chat, commit source
   fixes directly to main, and respond to owner-guided test rounds
   until the result is satisfactory.

**Permissions today:** research, source edits, static source review,
a very small Clang-only validation helper and ordinary Git commits.
**Still prohibited:** compiling/generating a kext, running test
suites, CI/build tags, touching EFI/USB/OpenCore/SSD, live RF/PCI
access and installing or testing drivers. Later stages require
new, specific owner authorization.

**Git workflow:** AGENTS WORK DIRECTLY ON MAIN. PRs, feature
branches and agent worktrees are forbidden. Their existing
coordination chat handles shared-file ownership and sequencing.
No force-push. See AGENTS.md.

**Jig exception:** This repo DOES NOT USE JIG, its required
hexagonal layout, architecture rules or hooks. Leave existing
.jig/ content unchanged and inactive. Use only tools/validate.py
for extremely lightweight C/Objective-C/C++ Clang linting,
with already installed tools; no downloads.

## All pre-final items: source-only, no hardware prerequisites

- [ ] **A1 — Tahoe ABI:** Research public Tahoe KDK/SDK exports,
  IOPCIFamily, IO80211FamilyLegacy, IOSkywalkFamily and
  IONetworkingFamily. Document method/lifetime contracts and
  source-level compatibility, with explicit unverified
  assumptions and fail-closed behavior. **No live logs needed.**

- [ ] **A2 — Native PCI:** Complete source for exact-device
  identification, PCI ownership and power D0, BAR/MMIO access,
  concurrency, command rollback and safe teardown, based on
  documented APIs and public source. **No physical PCI reads.**

- [ ] **A3 — EEPROM/OTP:** Complete bounded NVM read algorithms,
  dictionaries, revision matching, MAC/board checksums, antenna
  and calibration data interpretation, with safe rejection of
  unknown layouts. Use ath9k references; **never require a dump
  of the user's actual EEPROM to finish the source task**.

- [ ] **A4 — RF/PHY/regulatory:** Finish revision-aware radio
  power/reset, PLL/synthesizer, gains, channel selection,
  ANI/noise handling, RF-kill, calibration and legal per-channel
  TX power constraints. Source must reject unknown board or
  country states. **No live signal or transmission tests.**

- [ ] **A5 — EDMA/interrupts:** Implement ring allocation,
  IOMMU/DMA contracts, RX/TX ownership, descriptors, completion,
  interrupt handling, memory safety, sleep and fault recovery
  in source. Consult public ath9k and IOKit documentation.
  **No physical packet transfer required.**

- [ ] **A6 — 802.11 MAC:** Complete scanning/channel-dwell
  decisions, beacons, RSN, advertised rates, authentication,
  association, BSS snapshots, timeouts and reconnection.
  **No actual Wi-Fi scan or screenshot required.**

- [ ] **A7 — WPA2/CCMP:** Complete theoretically reviewed PMK/PTK,
  EAPOL MIC and four-way handshake, AES unwrap, CCMP, keycache,
  group rekey and packet-number/replay control. Compare
  algorithms with published specifications and source vectors;
  **do not run test suites or claim crypto certification**.

- [ ] **A8 — Tahoe AirPort:** Complete the proposed native
  IO80211Controller/IO80211Interface integration, Wi-Fi UI
  scan/connect/status requests, networking, power transitions
  and packet contracts. Research public code and documentation
  without copying incompatible proprietary or third-party ABI
  code. **No live Wi-Fi UI acceptance prerequisite.**

- [ ] **A9 — Integrate the entire theoretical source pipeline:**
  PCI → PHY → DMA → 802.11 MAC → WPA2/CCMP → native AirPort.
  Resolve state/locking ownership, data movement, failures,
  cleanup, suspend/resume and reconnection in code. Remove
  placeholders and invented readiness indicators.
  **Source completeness only; not physical connectivity.**

- [ ] **A10 — Finish source-only hardening/documentation:**
  Reason through bounds, overflow, lifetime, crypto erasure,
  regulatory safety, deadlocks, interrupt races, rollback,
  licensing and documentation. Keep README/AGENTS/TODO accurate.
  Use only tools/validate.py for already available Clang checks;
  no Jig, new tools, compilation, CI or hardware diagnostics.

## After pre-final completion: indefinite theoretical hardening

**Mandatory waiting state; NOT authorization to test.** Continue
researching and reviewing code, standards, safety and platform
compatibility indefinitely. Repair newly found source-level defects
on main. Do not impose an end date. Only the owner may announce
that it is time for a first build and on-device experiment.

## FINAL TODO — owner-controlled physical test and diagnostic loop

- [ ] **Only after all source-only TODOs are done AND the owner
  voluntarily ends the indefinite hardening hold:** obtain
  specific owner approval for each build, installation and
  experiment. The owner tests the kext on the Dell, reports
  actual diagnostics in THIS ChatGPT conversation, and
  decides what to try next. Agents coordinate in their
  existing chat and implement source fixes directly on main,
  repeating owner-guided diagnostic cycles until native
  Wi-Fi scan/association, WPA2 encrypted IP, network stability,
  reconnect, sleep/wake, Bluetooth coexistence and real
  bidirectional AirDrop work to the owner's satisfaction.
  Identify the separate Bluetooth hardware and actual
  macOS Continuity support. These features **cannot be
  guaranteed by AR9565 source code alone**. This checkbox
  must remain open until real owner-authorized validation
  demonstrates the requested result.
