# SimpleATH — agent coordination

**Target:** experimental native Qualcomm Atheros AR9565 / QCA9565
(PCI 168c:0036) Wi-Fi for Intel macOS Tahoe 26.7.2 (25G332),
Dell Inspiron 5567. **Owner:** albertovillaosorno.
The project is NOT a verified functional Wi-Fi driver. The last known
bootable SimpleATH binary is a passive PCI discovery kext.

Read TODO.md, README.md, docs/design/STATUS-AND-RECOVERY.md,
docs/design/TAHOE-25G332-KDK.md,
docs/design/TAHOE-NATIVE-IO80211-REFERENCE.md, and
docs/agents/COMPLETE_SIMPLEATH_PROMPT.txt before working.

## Ten agents, ten independent lanes

Claim one lane per agent, use an independent git worktree and
agent/<lane>/<task> branch, deliver a focused PR. Never allow ten writers
to share the same main-branch worktree. Report exact changes and
unverified limitations. Update TODO.md through the integration owner.

| Lane | Scope | First-choice ownership |
| --- | --- | --- |
| A1 ABI | Tahoe 25G332 KDK, PCI/wireless exports, class/vtable contracts | docs/evidence/, tools/*abi*, docs/design/*ABI*, docs/design/TAHOE-25G332-KDK.md |
| A2 PCI | Exclusive IOPCIDevice, D0, BAR/MMIO, teardown | src/platform/Ar9565NativePci.*, src/platform/Ar9565PciSession.* |
| A3 EEPROM | NVM acquisition, OTP, board calibration, identity | src/hardware/Ar9565NvmReader.*, src/hardware/Ar9565Eeprom.* |
| A4 PHY | Radio reset, PLL, channel, gain, regulatory and power | src/hardware/Ar9565Core.*, Ar9565InitCatalog.*, Ar9565Power.* |
| A5 DMA | IOMMU, EDMA TX/RX descriptors, interrupts, quiesce | src/hardware/Ar9003*, new isolated DMA adapter |
| A6 MAC | Beacon parsing, scan, association and RSN | src/wifi/Frames.*, ScanCache.*, Station.*, LegacyScanBridge.* |
| A7 WPA2 | Cryptography, CCMP, EAPOL, PTK/GTK, replay | src/wifi/Eapol.*, Wpa2Supplicant.*, src/wifi/crypto/ |
| A8 AirPort | Native IO80211/Skywalk controller, Apple80211 requests | New isolated src/platform/*Wireless* implementation |
| A9 Integration | Packets, coordinator, lifecycle, recovery and sleep | src/wifi/DataPath.*, WifiEngine.*, LinkMonitor.*, own adapters |
| A10 Governance | Linters, GitHub metadata, docs, integration | AGENTS.md, TODO.md, .github/, documentation |

**Shared-file lock:** src/SimpleATH.cpp, src/Info.plist,
src/platform/SimpleATH.xcodeproj/project.pbxproj,
src/platform/Kernel.xcconfig, README.md, bundle identifier and
root linter configurations require integration-owner handoff.
Inspect git status, branch and worktrees before EVERY edit;
never overwrite other agents' uncommitted changes.

## Authorization and safety boundary

The owner authorized source edits, local lint configuration review,
ordinary commits/pushes,
repository metadata and agent coordination. **Still not authorized:**
compiling/generating another kext, running test suites, starting CI,
creating or pushing build-v* tags, modifying USB, EFI, OpenCore,
root patches or SSD, or performing physical PCI/RF/driver experiments.
Get new explicit authorization for each later build, installation
and hardware test. Ordinary main pushes do not trigger the tag-only
GitHub workflow. Never run an unapproved test or build via any tool.

The known-good 13-kext EFI and the current passive V1 USB remain intact.
Fail closed before any RF or TX: real PCI ownership, physical identity,
calibrated EEPROM and permitted channel/power must be demonstrated.
IORegistry properties can be spoofed and are not evidence of physical
identity. A successful macOS boot never proves functional Wi-Fi.

## Linting and architecture

Jig 26.3.0 is **NOT** an active SimpleATH requirement. Its mandatory
canonical layout insists on src/<domain>/<function>/<kind>/<part>
and tools/<function>/<kind>/<part>; its policy explicitly forbids
disabling that rule. This conflicts with the existing kext and
user-requested architecture freedom. See
docs/design/JIG-COMPATIBILITY.md. Do not create mandatory ports,
adapters, hexagonal layers or source relocation merely to satisfy Jig.

Retain existing root .clang-format, .clang-tidy, .editorconfig,
ruff.toml, pyrightconfig.json, and msvc-cpp.editorconfig.
Use already-installed clang-format, clang-tidy, Ruff and
BasedPyright; do not fetch or install linters. Static language
inspection is not authorization to run Xcode builds or test suites.
Source, docs and commit messages in English. New authored code:
AGPL-3.0-only. Preserve ath9k licenses and third-party notices.

Each change must describe ownership, error/rollback paths, ABI
assumptions and what remains unverified. Never fabricate scan output,
MIC/key success, physical MAC, transfer rates or boot logs.

## Final acceptance

TODO.md ends with separately owner-authorized real-device Wi-Fi,
Bluetooth and AirDrop testing. Bluetooth may be a separate Dell
device; AirDrop requires compatible Bluetooth, Wi-Fi and Continuity.
They remain unverified until actually demonstrated on the target Dell.
