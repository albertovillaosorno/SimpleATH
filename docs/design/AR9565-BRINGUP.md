# AR9565 native macOS bring-up — source-only engineering record

**Status:** Hardware data and algorithms staged. PCI transport and wireless
integration are not yet implemented. This is not a functional Wi-Fi driver.

**Target:** Dell Inspiron 5567, Qualcomm Atheros QCA9565/AR9565
PCI `168c:0036`, macOS Tahoe 26.7.2 (Darwin 25, build 25G332),
OpenCore 1.0.8.

For the current source milestones, remaining blockers, separate authorization
scopes and recovery procedure, see [status and recovery](STATUS-AND-RECOVERY.md).
See [macOS integration](MACOS-INTEGRATION.md) for PCI ownership/DMA/power and
the limits of the stored Tahoe ABI evidence, and [EEPROM port](EEPROM-PORT.md)
for the bounded source parser and the board acquisition still required.

## Source components and blocking dependencies

| Layer | Files | Implemented | Blocking dependency |
| --- | --- | --- | --- |
| PCI detection | `src/SimpleATH.cpp` and `src/Info.plist` | IOKit matching for 0036 and possible spoof 0030 | Actual runtime kext load confirmation |
| Core identification | `src/hardware/Ar9565Core.*` | Physical PCI identity, type-2 SREV, 1.0/1.0.1/1.1, RTC and EEPROM status checks | Mapped PCI BAR with verified read32 callback |
| Device state | `Ar9565Core.*` | Fail-closed phases; no TX/RX before implementation | EEPROM contents, reset and calibration |
| RF configuration data | `generated/Ar9565InitTables.hpp` | 2,174 2.4GHz HT20/HT40 entries derived from 15 Linux ath9k source arrays | BAR writes, complete EEPROM validation, safe reset and delays |
| Radio configuration planning | `Ar9565InitCatalog.*` | Revision-specific radio postamble, RX/TX gain profiles, channel 14 and regulatory preconditions | Calibration and board data |
| PCI inspection session | `src/platform/Ar9565PciSession.*` | Portable ownership/D0/config/BAR0 checks, read-only allowlist and unwind | Verified native PCI-family adapter; not connected to the passive IOService |
| Board data parser | `Ar9565Eeprom.*` | Checked compression blocks, 1088-byte image storage, raw board summary and gain-index mapping | Hardware storage access, chain restoration/templates, actual calibration/regulatory validation |
| PCI DMA and interrupts | Not yet written | NOT IMPLEMENTED | DMA mapping, rings, completions and recovery |
| 802.11 MAC and security | Not yet written | NOT IMPLEMENTED | Scan, beacons, association, WPA/RSN, rate control |
| macOS Wi-Fi UI | Not yet written | NOT IMPLEMENTED | Verified Tahoe IO80211/Skywalk ABI or a supported substitute |

The generated Linux-derived arrays retain the original Atheros/Qualcomm
permissive copyright notice in the generated file. The new C++ control code
is AGPL-3.0-only. The unmodified Linux references retain their own notices.

## V1 boot versus V1 kext injection

An earlier V1 boot reached the desktop, but OpenCore logged a RIP-relative
overflow, an Invalid Parameter injection error, and unresolved kernel
IOPCIDevice C++ symbols. That boot did NOT prove the driver was loaded.

The source was corrected to use IOKit's matching properties without directly
importing the previously unresolved IOPCIDevice methods. Exact Tahoe PCI-family
exports are still unverified; the stored ABI profile omits IOPCIFamily. Its last authorized Xcode
build was successful, but there is no target-kernel load confirmation yet.

The newer hardware core, initialization tables, PCI-session contract and
EEPROM parser are SOURCE ONLY and
HAVE NOT BEEN BUILT. The user has not authorized another binary.

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
