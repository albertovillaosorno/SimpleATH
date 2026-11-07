# 802.11 MAC framing and AR9003 DMA — staged source

This source was added without executing a compiler, test suite, CI workflow
or operating the physical PCI card. These are portable C++14 algorithms
and structures, NOT yet a functional driver or the complete 802.11 stack.

## Implemented building blocks

| Component | File | What is implemented |
| --- | --- | --- |
| AR9003 descriptor representation | src/hardware/Ar9003Descriptors.* | 128-byte TX pointer layout, four 32-bit DMA buffer addresses and lengths, AR9565 descriptor-id formatting, pointer checksum and link updates; 48-byte RX status parsing and error flags |
| AR9003 TX controls | src/hardware/Ar9003TxControl.* | Four retry/rate series, per-series power caps, HT40/GI/STBC/antenna selection, CCMP keycache controls, RTS/CTS duration, 36-byte TX completion flags; never enables hardware transmission |
| DMA safety checks | src/hardware/Ar9003Dma.* | Reject unmapped buffers, 64-to-32-bit truncation, 4-GiB crossing, cache-synchronization and alignment errors; bounded 64-slot TX *metadata* ownership model |
| Management frames | src/wifi/Frames.* | Bounds-checked 802.11 management/data header parsing, beacons/probe responses, SSID, DS channel, HT and RSN suites, serializers for probe, open authentication and limited WPA2-PSK CCMP association requests |
| BSS cache | src/wifi/ScanCache.* | Allocation-free maximum 48 APs, expiry, visible/hidden SSID updates, channel/security filtering and RSSI preference |
| Station protocol state | src/wifi/Station.* | Scan/candidate, authentication and association state transitions; explicit stop at unimplemented WPA2 crypto or network-interface registration |
| EAPOL-Key parsing | src/wifi/Eapol.* | EAPOL version/length/RSN descriptor and key-info validation, message 1-4 and group 1-2 classification, replay guard requiring confirmed MIC before advancing |
| WPA2-PSK handshake | src/wifi/Wpa2Supplicant.* | EAPOL messages 2/4, MIC verification, GTK unwrap and pairwise/group key installation through mandatory reviewed crypto callbacks; no active hardware backend |
| WPA2 primitives | src/wifi/crypto/ | SHA-1/HMAC, PBKDF2, PTK derivation, AES key unwrap and callback bridge; uncompiled and no platform CSPRNG or keycache backend |
| Data-frame decapsulation | src/wifi/DataFrames.* | LLC/SNAP parsing, Ethernet type, source/destination mapping, checks for protected payload, QoS A-MSDU and fragmentation rejection |
| Infrastructure data path | src/wifi/DataPath.* | Builds ToDS frames from Ethernet-II/LLC-SNAP, gates outgoing EAPOL versus WPA2 CCMP data, filters received AP-to-station frames by BSSID and decryption integrity; no physical TX/RX or network interface |
| Link monitoring | src/wifi/LinkMonitor.* | Bounds-checked AP beacon/deauth/disassoc handling, mandatory PMF verification when negotiated, beacon-loss timeout, bounded reconnect backoff; no actual radio scan or reconnect scheduler |
| Portable coordinator | src/wifi/WifiEngine.* | Connects scan, association, EAPOL, station data TX/RX and link-monitor state without making live PCI or macOS Wi-Fi calls; uncompiled |
| Legacy scan bridge | src/wifi/LegacyScanBridge.* | Bounded, stable completed BSS snapshots for a future native IO80211 scan-result handler, including exact validated RSN information elements and rate codes |

All fifteen C++ translation units were added to the existing Xcode target
for the **next separately authorized build**.

## Critical restrictions

- **TX descriptors are not connected to a working radio.** Pointer checksums
  and most non-aggregated rate/retry/power/CCMP control fields are staged, but
  rate selection and power limits still depend on verified board/OS policy.
  RX frame decapsulation rejects a caller-supplied MSDU result that overlaps
  the original frame before clearing borrowed metadata, so a forged output
  cannot corrupt the received frame in-place. The station data path also
  rejects TX output/result overlap with Ethernet or link identity, and RX
  result overlap with frame or link identity before any write. These source
  checks do not replace DMA ownership or hardware MIC/PN validation.
  Pointer relinking and TX control encoding revalidate the canonical block:
  at least one contiguous nonzero segment, 12-bit lengths, no 4-GiB crossing,
  zero unused slots, aligned link, supported queue and pointer checksum.
  A forged all-zero payload with a recomputed checksum is not valid input.
  The AR9565-only TX control encoder now rejects multi-chain selectors,
  STBC, unknown rate codes or MCS8+, HT-only flags on legacy rates and
  invalid/stale RTS/CTS rates, regardless of caller-set policy flags. These
  descriptor checks do not verify the physical board or permit RF output.
  No safe bus mastering, EDMA ring programming, interrupt completion, active
  RF calibration or 802.11 traffic pipeline exists. The descriptors must not
  be submitted to the physical device.
- **DMA ring is metadata only.** Every staged TX slot transition now requires
  its nonwrapping reservation token (index, cookie, generation), so a late
  preparation, handoff or release cannot act on a recycled slot. This does
  not prove that an actual DMA transfer completed or was quiesced. There is
  no IODMACommand allocation, IOMMU mapping, physical device access,
  interrupt acknowledgement or hardware doorbell. A multi-descriptor ring
  also requires each descriptor stride to preserve the specified alignment.
  The existing `src/platform/Ar9565PciSession.*` provides a portable read-only
  inspection contract; its native platform adapter is
  still missing. All hardware access must use one verified PCI owner.
- **Ethernet-II LLC/SNAP follows IEEE 802.1H translation rules.** Ordinary
  EtherTypes use RFC 1042 OUI 00:00:00; AARP (0x80f3) and IPX (0x8137) use
  bridge-tunnel OUI 00:00:f8. The RX decoder rejects ordinary RFC 1042
  AARP/IPX rather than misclassifying an 802.3 LLC payload as Ethernet-II.
  Only unfragmented Data/QoS Data subtypes are decapsulated; CF poll/ACK,
  null-data and A-MSDU require distinct implementations. This rule is also
  present in Linux cfg80211 `net/wireless/util.c` (see the upstream source
  in the evidence references below). RX admission also validates the selected
  unicast station/BSSID, rejects multicast WPA2-PSK handshake EAPOL and clears
  any borrowed payload pointer on failed decoding or admission.
- **802.11 management code cannot transmit.** It creates byte sequences
  but needs calibrated RF hardware, actual RX/TX queues, regulatory policy,
  beacon/scan operation, association timers and packet scheduling.
- **WPA2 depends on unavailable crypto and keycache backends.** The
  supplicant prepares EAPOL M2/M4 and coordinates PTK derivation, MIC
  validation, GTK AES unwrap, and pairwise/group key installation through
  required platform callbacks. Portable PBKDF2, HMAC-SHA1 and AES unwrap
  sources are staged but uncompiled and unaudited. There is no validated
  CSPRNG, installed CCMP keycache, OS credentials or EAPOL TX/RX path.
  It cannot independently establish secure traffic.
- **Reconnect identity must be independently supplied.** The portable link
  monitor rejects station/BSSID inputs referencing its own retained snapshot
  before a restart clears that snapshot; a stale reconnect cannot report a
  new association with zeroed identities. This is not native link proof.
- **No association means Wi-Fi connected.** The station's source-level
  state machine explicitly refuses to report a complete network interface.

## Integration gates

1. Complete verified exclusive PCI ownership, read EEPROM and SREV, validate
   board/channel, then implement radio reset and calibration.
2. Complete an ordered device register writer with correct ath9k timing and
   actual analog/eeprom board data; never execute table presets by themselves.
3. Create correct 32-bit-capable IODMACommand or DriverKit mappings and AR9003
   rate/power/crypto TX control descriptors, EDMA RX status and completion
   interrupt rings, using a correct memory synchronization policy.
4. Add management scan/association timers, HT20 channel/regulatory control,
   crypto/key install, QoS and A-MPDU/A-MSDU aggregation, stable TX/RX.
5. Verify an actual macOS Tahoe native wireless interface, not Ethernet.
   Apple NetworkingDriverKit explicitly supports Ethernet only.
6. Only then, and only with explicit owner permission, compile and test on the
   Dell. Do not claim fully functional Wi-Fi before live WPA2 association
   and IP traffic are observed without kernel hangs.

## Evidence references

- Linux ath9k (local): linux/drivers/net/wireless/ath/ath9k/ar9003_mac.c,
  ar9003_mac.h, mac.h, ar9565_1p0_initvals.h, ar9565_1p1_initvals.h
- Linux cfg80211 LLC/SNAP translation:
  https://github.com/torvalds/linux/blob/v6.12/net/wireless/util.c
- Apple PCIDriverKit: https://developer.apple.com/documentation/pcidriverkit
- Apple NetworkingDriverKit:
  https://developer.apple.com/documentation/networkingdriverkit
