# Portable Wi-Fi Engine — source-only integration

Status: uncompiled, unaudited and not hardware-connected (2026-11-06).

The new WifiEngine interface wires together existing portable modules:
- Bounded BSS cache, beacon and probe response parsing.
- Explicit per-channel selection and station authentication/association.
- WPA2 EAPOL M1 -> M2 and M3 -> M4 with the separately staged crypto
  adapter, requiring real CSPRNG and pairwise/group keycache callbacks.
- Ethernet-II/LLC-SNAP encapsulation for source-level open-mode data.
- Receive filtering by AP BSSID, DMA/FCS, and verified CCMP MIC/PN.
- Beacon-loss, disassociation and deauthentication monitoring.

The caller passes a separate receive-trust report from a real device
backend. Such a backend is NOT implemented: the flags must never be
manufactured from a registry property or successful frame parse alone.

No method calls MMIO, starts RF, maps DMA, installs interrupts, registers
an AirPort interface or places bytes on the air. The engine returns
descriptions of frames that an eventual native backend could send, but
the backend must first enforce complete regulatory/calibration state,
valid IOMMU/DMA and transmit power. It refuses WPA2 ordinary data frames
without proper CCMP. It always reports nativeInterfaceUsable as false.

The entire engine must be created in a persistent kernel allocation and
serialized on the eventual device work loop; it contains a 48-BSS cache,
WPA2 state and temporary EAPOL buffers. It is not suitable for interrupt
context, nor is it a substitute for a work-loop, event-source or packet
allocator implementation.

Outstanding work:
- Native PCI ownership and IOPCIFamily ABI for exact Tahoe build.
- Correct AR9565 radio/PHY reset and calibrated per-channel programming.
- Real IODMACommand/IOMapper, EDMA queues, TX/RX completions and interrupts.
- Real CCMP keycache, key replay/PN and OS entropy backend, validated crypto.
- Actual IO80211/Skywalk native Wi-Fi interface, events and user controls.
- Hardware-level scan, association timers, WPA2 group rekey, packet delivery.
- MacKernelSDK compatibility, build/import validation, testing on Dell.

The local Tahoe ABI reference omits IOPCIFamily. This is missing evidence,
not proof of impossible PCI support. Public drivers for other hardware
such as AirportRtw88 and AirPort_RTW89 have documented native IO80211 use
with restored legacy wireless components on Tahoe, but this does not
validate AR9565 nor authorize changes to the owner's OpenCore EFI.

No build, tests, CI tags, USB/EFI updates, SSD changes or hardware
experiments were performed as part of this source milestone.
