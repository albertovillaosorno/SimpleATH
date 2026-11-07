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
| Data-frame decapsulation | src/wifi/DataFrames.* | LLC/SNAP parsing, Ethernet type, source/destination mapping, checks for protected payload, QoS A-MSDU and fragmentation rejection |

All nine C++ translation units were added to the existing Xcode target
for the **next separately authorized build**.

## Critical restrictions

- **TX descriptors are not connected to a working radio.** Pointer checksums
  and most non-aggregated rate/retry/power/CCMP control fields are staged, but
  rate selection and power limits still depend on verified board/OS policy.
  No safe bus mastering, EDMA ring programming, interrupt completion, active
  RF calibration or 802.11 traffic pipeline exists. The descriptors must not
  be submitted to the physical device.
- **DMA ring is metadata only.** There is no IODMACommand allocation,
  IOMMU mapping, physical device access, interrupt acknowledgement or
  hardware doorbell. The existing src/platform/Ar9565PciSession.* provides
  a portable read-only inspection contract; its native platform adapter is
  still missing. All hardware access must use one verified PCI owner.
- **802.11 management code cannot transmit.** It creates byte sequences
  but needs calibrated RF hardware, actual RX/TX queues, regulatory policy,
  beacon/scan operation, association timers and packet scheduling.
- **WPA2 depends on unavailable crypto and keycache backends.** The
  supplicant prepares EAPOL M2/M4 and coordinates PTK derivation, MIC
  validation, GTK AES unwrap, and pairwise/group key installation through
  required platform callbacks. No PBKDF2/PMK provider, HMAC-SHA1, AES unwrap,
  CCMP, hardware keycache or EAPOL TX/RX path is integrated. It cannot
  independently establish a secure connection or pass traffic.
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
- Apple PCIDriverKit: https://developer.apple.com/documentation/pcidriverkit
- Apple NetworkingDriverKit:
  https://developer.apple.com/documentation/networkingdriverkit
