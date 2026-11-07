# SimpleATH TODO

Only unfinished tasks appear here. Typed records in docs/todo/open/
contain identity, priority, dependencies, acceptance and evidence.
Move source-completed records to docs/todo/completed/ and remove
their index entries without deleting their recorded provenance.

**All P0–P4 work is strictly theoretical/source-only.** No hardware
verification, Dell logs, physical scan, compilation, or test suite may
be required to finish a pre-final task. Research online code and
documentation, document uncertainty, and make unknowns fail closed.

Ten agents coordinate in their existing chat, commit directly to main
and do not open PRs. This repository does not use Jig. Use only the
installed-tool validator tools/validate.py and its local .cache/ report.

**Order:** finish all P0–P4 tasks; then harden theoretically
**indefinitely**; only the owner may activate P5. The owner will
perform the real hardware testing and send results in this chat.

Each index entry has a TODO title, one summary and one typed-record link.

## P0 — Source-only

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
algorithms with published specifications and source vectors; **do not run test
suites or claim crypto certification**.

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
and BasedPyright checks; no Jig, new tools, compilation, CI or hardware
diagnostics.

[docs/todo/open/governance/source-hardening.mdc](docs/todo/open/governance/source-hardening.mdc)

## Indefinite theoretical hardening

After P0–P4 source completion, continue research and source hardening
without deadline, physical checks or owner diagnostic requests.
This hold ends ONLY by an explicit owner decision.

## P5 — FINAL TODO: owner-controlled physical testing

### TODO - Owner-controlled Wi-Fi Bluetooth and AirDrop acceptance

The owner starts separately authorized Dell experiments only after all
theoretical tasks and the indefinite hold, then shares diagnostics here for
agent-guided bug fixes until the requested result is reached.

[docs/todo/open/owner/owner-controlled-device-acceptance.mdc](docs/todo/open/owner/owner-controlled-device-acceptance.mdc)
