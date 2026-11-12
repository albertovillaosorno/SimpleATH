# AR9565 native macOS bring-up — source-only engineering record

**Current source, 2026-11-09:** the normal target instantiates the native PCI
owner, opens/verifies the physical function, maps BAR0, quiesces MAC engines,
boots RTC and discovers EEPROM/OTP board data. Sleep/resume and termination
share the same serialization gate. PCI and DMA adapters are compiled normally.
The native controller also applies EEPROM-derived PMU1 and XTAL capacitor
registers and samples physical RF-kill after a same-epoch MAC quiesce and
keycache scrub. Configured blocked/unstable RF-kill aborts startup; missing
RF-kill wiring is unknown and grants no radio authority. A valid GPIO is
rechecked on every analog power write. The normal Xcode target now contains
board-modal, coexistence and OFDM/SGI timing code, but does not claim their
native execution or Wi-Fi operation. RF calibration, live channel/rate/country
policy, packet queues/interrupts and native AirPort registration still remain
required before Wi-Fi can scan, connect or transfer traffic. These
remaining tasks are implementation priorities, not a reason for indefinite
hardening. An authorized macOS build runs advisory CI, which warns on
failures rather than requiring a passing result (2026-11-10 override).

**Target:** Dell Inspiron 5567, Qualcomm Atheros QCA9565/AR9565
PCI `168c:0036`, macOS Tahoe 26.7.2 (Darwin 25, build 25G332),
OpenCore 1.0.8.

For the current source milestones, remaining blockers, separate authorization
scopes and recovery procedure, see [status and
recovery](STATUS-AND-RECOVERY.md).
See [macOS integration](MACOS-INTEGRATION.md) for PCI ownership/DMA/power and
the limits of the stored Tahoe ABI evidence, and [EEPROM port](EEPROM-PORT.md)
for the bounded source parser and the board acquisition still required.
See [RTC reset source](RTC-RESET-SOURCE.md) for the inactive reset sequence
and its posted-write, timing and power preconditions.

## Source components and blocking dependencies


- **Layer:** PCI detection
  - **Files:** `src/SimpleATH.cpp` and `src/Info.plist`
  - **Implemented:** Exclusive native ownership for physical 0036
  - **Blocking dependency:** macOS linkage/runtime validation

- **Layer:** Core identification
  - **Files:** `src/hardware/Ar9565Core.*`
  - **Implemented:** Physical PCI identity, type-2 SREV, 1.0/1.0.1/1.1, RTC and
    EEPROM status checks
  - **Blocking dependency:** Mapped PCI BAR with verified read32 callback

- **Layer:** Device state
  - **Files:** `Ar9565Core.*`
  - **Implemented:** Fail-closed phases; no TX/RX before implementation
  - **Blocking dependency:** EEPROM contents, reset and calibration

- **Layer:** RF configuration data
  - **Files:** `generated/Ar9565InitTables.hpp`
  - **Implemented:** 2,174 2.4GHz HT20/HT40 entries derived from 15 Linux ath9k
    source arrays
  - **Blocking dependency:** BAR writes, complete EEPROM validation, safe reset
    and delays

- **Layer:** Radio configuration planning
  - **Files:** `Ar9565InitCatalog.*`
  - **Implemented:** Revision-specific radio postamble, RX/TX gain profiles,
    channel 14 and regulatory preconditions
  - **Blocking dependency:** Calibration and board data

- **Layer:** PCI inspection session
  - **Files:** `src/platform/Ar9565PciSession.*`
  - **Implemented:** Portable ownership/D0/config/BAR0 checks, read-only
    allowlist and unwind
  - **Blocking dependency:** Native lifecycle implemented in SimpleATH; macOS
    runtime validation remains

- **Layer:** Board data parser
  - **Files:** `Ar9565Eeprom.*`
  - **Implemented:** Checked compression blocks/dump chains, five pinned
    dictionaries, 1088-byte image storage, raw board summary and gain-index
    mapping
  - **Blocking dependency:** Native acquisition/origin discovery,
    serialization/reconstruction verification, actual calibration/regulatory
    validation

- **Layer:** NVM read protocol
  - **Files:** `Ar9565NvmReader.*`
  - **Implemented:** Active EEPROM/OTP trigger/poll/byte-normalization source
    with word/capture bounds
  - **Blocking dependency:** Native caller connected; physical capture
    validation remains

- **Layer:** Power candidate calculation
  - **Files:** `Ar9565Power.*`
  - **Implemented:** EEPROM target interpolation, explicit CTL coverage,
    antenna/EIRP intersection and single-stream rate selection
  - **Blocking dependency:** Actual board/country approval, TPC conversion and
    calibrated/programmed/measured power; no TX enabled

- **Layer:** PCI DMA and interrupts
  - **Files:** `Ar9003Descriptors.*`, `Ar9003Dma.*`
  - **Implemented:** Pointer/status codecs and generation-checked ring metadata
    only
  - **Blocking dependency:** Actual DMA mapping, hardware rings, interrupts,
    completions and recovery

- **Layer:** Native packet-buffer mapping
  - **Files:** `src/platform/Ar9565NativeDma.*`
  - **Implemented:** IOBuffer/IOMapper/IODMACommand source compiled in normal
    target, 32-bit segments, client/gate handoff and token-checked retirement
  - **Blocking dependency:** controller worker/epoch ownership, ABI validation,
    coherent rings and real queues/interrupts remain missing

- **Layer:** 802.11 MAC and security
  - **Files:** `src/wifi/`
  - **Implemented:** Portable frame, scan-cache, station-state and EAPOL source;
    see WIFI-MAC-AND-DMA.md
  - **Blocking dependency:** Actual radio/queues, timers, verified crypto/key
    path, rates and OS integration

- **Layer:** macOS Wi-Fi UI
  - **Files:** Not yet written
  - **Implemented:** NOT IMPLEMENTED
  - **Blocking dependency:** Verified Tahoe IO80211/Skywalk ABI or a supported
    substitute


The native owner now invokes `src/hardware/Ar9565RtcPower.*` through ordered
active MMIO, same-device posted-write draining and live D0 checks. MCI
coexistence remains a separate required integration.

The generated Linux-derived arrays retain the original Atheros/Qualcomm
permissive copyright notice in the generated file. The new C++ control code
has no project-wide license grant. The unmodified Linux references retain their
own notices.

## V1 boot versus V1 kext injection

An earlier V1 boot reached the desktop, but OpenCore logged a RIP-relative
overflow, an Invalid Parameter injection error, and unresolved kernel
IOPCIDevice C++ symbols. That boot did NOT prove the driver was loaded.

The earlier passive source used IOKit's matching properties without directly
importing the previously unresolved IOPCIDevice methods. The later exact-build
[KDK inspection](TAHOE-25G332-KDK.md) finds both names in the x86_64 PCI image
and its packaged export list. The stored ABI profile alone omits IOPCIFamily.
Production collection provenance, full ABI/import/relocation validation and
the active native adapter remain outstanding. The last authorized Xcode build
was successful, but there is no target-kernel load confirmation yet.

The integrated native source passes SDK syntax checks. No new native kernel
binary or physical Wi-Fi result is established by those checks. Historical
V1 observations above describe earlier artifacts, not the current source.

## Platform-specific blockers

Apple PCIDriverKit supports PCI BAR/configuration access using a signed
DriverKit system extension and matching entitlements:
https://developer.apple.com/documentation/pcidriverkit

Apple NetworkingDriverKit currently supports Ethernet interfaces, not a
native AirPort/Wi-Fi interface:
https://developer.apple.com/documentation/networkingdriverkit

These APIs do not eliminate the need to integrate AR9565 with a functional
802.11 network stack and Tahoe's native or legacy wireless ABI.

## Correct order before any real Wi-Fi release

1. Secure an actual Tahoe-compatible PCI transport and safe BAR access.
   Avoid assigning the same device to a kext and DriverKit simultaneously.
2. Read true SREV, RTC and EEPROM status; fail on unknown hardware revisions.
3. Validate complete board EEPROM: MAC address, regulatory domain, antenna,
   RF calibration, RF kill and Bluetooth coexistence configuration.
4. Implement reset, wakeup, revision-correct register programming, PLL,
   per-channel synth, ANI/noise and PHY calibration with bounded timeouts.
5. Implement DMA Tx/Rx descriptors, interrupt handling, queues, safe memory
   ownership, IOMMU integration, suspend and resume.
6. Implement 802.11 scan, authentication, association, WPA/RSN security,
   rates, aggregation, disassociation and recovery.
7. Add a confirmed Tahoe-compatible Wi-Fi interface, not just Ethernet.
8. Verify progressively on the actual laptop: passive detection, power,
   RX, scan, association, DHCP, throughput, sleep and BT coexistence.

## Authorization gate

**No binary builds, new GitHub build tags, workflow runs, USB changes or
OpenCore EFI edits until expressly approved.** Ordinary source commits
to main do not trigger the tag-only CI workflow.

## Mapped-PCI shutdown after partial radio startup (2026-11-12)

The native controller now attempts to quiesce the AR9565 MAC before releasing
an available, mapped PCI session even when its keycache was never initialized.
Previously the keycache-initialized flag also skipped the physical MAC stop
on failures during RTC reset, NVM acquisition or station address setup.
Quiescence is attempted only while the provider is available and a queue is
not quarantined; a failed quiesce remains unverified. Physical key erasure
still separately requires initialized key RAM, proven quiescence and a clean
keycache reset obligation. An absent BAR or lost provider is never replaced
with an assumed hardware shutdown. The accompanying source regression cannot
establish actual physical engine silence or USB/OS runtime safety.
