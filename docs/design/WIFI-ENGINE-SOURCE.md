# Portable Wi-Fi Engine — source-only integration

Status: uncompiled, unaudited and not hardware-connected (2026-11-06).

The new WifiEngine interface wires together existing portable modules:
- Bounded BSS cache, beacon and probe response parsing. Hidden SSIDs only
  inherit a previously visible name for the same BSSID when channel and RSN
  security advertisements still match. Selection prefers measured RSSI over
  invalid/unmeasured values within the same security class; unsuccessful BSS
  lookups clear the returned snapshot.
- Explicit per-channel selection and station authentication/association.
  Channel 14 is CCK-only: mandatory OFDM rates and HT metadata make a BSS
  unjoinable there; optional OFDM rates are excluded from the negotiated
  Supported Rates IE. This matches the separate channel-14 power candidate
  restriction and prevents a software-only false association promise.
  The authentication response handler preflights the exact association TX
  buffer size before consuming the station state transition; allocation
  failures can be retried without stranding authentication. A valid AP
  authentication/association rejection reports `AccessPointRejected` and
  clears the selected candidate/supplicant, allowing a fresh scan; it never
  manufactures a successful association or attempts an automatic retry.
- WPA2 EAPOL M1 -> M2 and M3 -> M4 with the separately staged crypto
  adapter, requiring real CSPRNG and pairwise/group keycache callbacks.
- Ethernet-II/LLC-SNAP encapsulation for source-level open-mode data.
- Receive filtering by AP BSSID, DMA/FCS, and verified CCMP MIC/PN.
- Beacon-loss, disassociation and deauthentication monitoring. A radio
  stop/suspend transitions to a non-retrying RadioUnavailable state, cancels
  any pending reconnect and discards stale association identity. Only native
  reinitialization and a new actual association may restore link monitoring.
  The monitor rejects identical STA/BSSID identities and does not refresh AP
  liveness from an IBSS, zero-interval or changed-interval advertisement;
  a changed beacon cadence requires renewed association instead. An AP
  management callback arriving beyond the missed-beacon deadline now performs
  the same link-loss transition as the timer, before a late beacon can renew
  the expired lease. This is source-only timer-ordering protection, not native
  workloop or over-the-air validation. The common trusted DATA callback
  also expires a missed-beacon lease before admitting ordinary MSDU or EAPOL
  payload; an out-of-order monotonic observation cannot bypass this gate.

The caller passes a separate receive-trust report from a real device
backend. Such a backend is NOT implemented: the flags must never be
manufactured from a registry property or successful frame parse alone.
Every public engine action-producing call clears the prior `EngineAction`
(including its borrowed RX payload pointer) on ordinary failed admission. The
engine first rejects action/output storage overlapping its retained state,
DMA-backed RX or Ethernet TX input, trust metadata or one another. This
malformed-caller error reports `InvalidInput` without writing either output
or consuming station/replay state. The native callback must copy valid payload
bytes before releasing its RX buffer.
On radio stop/suspend, the owner must quiesce hardware while key callbacks
remain alive; `radioStopped()` then resets the supplicant, removes attempted
keys and revokes provider callbacks, station state, old BSS entries and channel
authority. Resume requires reconfiguration and a fresh authorized scan.

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
