# External native AirPort precedent for Tahoe — source research only

The experimental third-party AirportRtw88 project reports real native
IO80211 scanning, WPA2 association, DHCP, IPv4/IPv6 and macOS Wi-Fi menu
on Intel Tahoe 26.6.2 build 25G83 with RTL8821CE PCI 10ec:c821.
This is a reference for architectural feasibility, NOT AR9565 validation.

References (read online, never copied into SimpleATH):
- https://github.com/FolKc9/AirportRtw88
- https://github.com/FolKc9/AirportRtw88/blob/main/src/kext/RTW88AirportLegacy.cpp
- https://github.com/FolKc9/AirportRtw88/blob/main/src/kext/RTW88AirportLegacyInterface.cpp
- https://github.com/FolKc9/AirportRtw88/blob/main/src/kext/RTW88TahoeNetworkABI.cpp
- https://github.com/FolKc9/AirportRtw88/blob/main/AirportRtw88Legacy.kext/Contents/Info.plist
- https://github.com/FranciumOS-org/AirPort_RTW89

## Relevant path

A plausible native integration follows the Ventura-style
IO80211Controller and IO80211Interface ABI and the restored Tahoe
IO80211FamilyLegacy and IOSkywalkFamily components, rather than treating
Ethernet as native Wi-Fi or blending incompatible private Skywalk variants.
AirportRtw88's published legacy Info.plist explicitly depends on
IO80211FamilyLegacy 1200.12.2b1, IONetworkingFamily, IOPCIFamily and BSD/KPI
libraries. Its own native attachment/Apple80211 request logic is separate
from its Realtek hardware, just as SimpleATH's AR9565 hardware must be.

Native control-plane requirements include real SCAN_REQ, SCAN_RESULT
enumeration, SCAN_DONE lifecycle, SSID/BSSID/channel, RSSI/noise, auth type,
association state, power on/off, disconnect, interface packet ownership and
real IP traffic. Legacy Tahoe async event clients may behave differently
from old macOS; do not assume SCAN_DONE alone will be consumed before result
reads. Never report RUN state without a genuine associated radio.

Our source now keeps an allocation-bounded scan cache with SSID, BSSID,
channel, advertised rate codes, full verified RSN IE, capabilities, signal
and HT metadata. LegacyScanBridge provides a stable completed scan snapshot
that can remain visible during a later ongoing radio scan, without returning
pointers into DMA or a live mutable cache.

This is ONLY a portable result model. The actual macOS IO80211Controller
subclass, Apple80211 request dispatcher, native scan event client, AirPort
packet queue, PCI owner and key management APIs are not implemented.

## Exact 25G332 control-path evidence and source integration gates

The pinned `docs/evidence/TAHOE-25G332-KDK-SYMBOLS.json` contains global
**nlist definition candidates** in the matching `IO80211Family` x86_64 image
(UUID `4C2B4969-2B92-3646-9512-C1769BE0F9A4`). An offline exact-key lookup
confirmed the following 11 candidates in that record. It reports
`nativeWirelessAbiVerified=false` and no export trie. **A global definition is
not proof of external link eligibility, callable virtual ABI or availability
in the owner's loaded Tahoe collections.** The declarations below are
mangled-name interpretations, not implementation-ready prototypes.

| Source-side operation needed | Observed exact-build candidate | Required verification before use |
| --- | --- | --- |
| Register a real wireless interface | `IO80211Controller::attachInterface(OSObject*, IOService*)` | Superclass layout, virtual slots, caller/returned ownership and target-family dependencies. Do **not** substitute legacy `attachInterface(IONetworkInterface**, bool)` |
| Bring up interface identity | `IO80211SkywalkInterface::init(IOService*, ether_addr*)` | MAC input lifetime, object factory, superclass initialization and interface publication ordering |
| Start/finish radio scans | `IO80211Controller::scanStarted(scanSource, apple80211_scan_data*)`, `scanDone(scanSource, int)` | Valid scan-source values, true completion timing and event delivery with an active radio/registered controller |
| Start/finish association | `IO80211Controller::joinStarted(scanSource, joinStatus)`, `joinDone(scanSource, joinStatus)` | Exact join status values, key-install and network-state ordering; never emit RUN/connected from parser success |
| Map native scan controls | `apple80211setSCAN_REQ(IO80211SkywalkInterface*, apple80211_scan_data*)`, `apple80211getSCAN_RESULT(IO80211SkywalkInterface*, apple80211_scan_result*)` | Concrete request structure layouts, in/out buffer ownership, native selector dispatch and synchronous enumeration rules |
| Deliver RX packets | `IO80211SkywalkInterface::inputPacket(IO80211NetworkPacket*, packet_info_tag*, ether_header*, bool*, bool)` | Actual packet allocator, queue context, length/headroom, handoff ownership, teardown, failure-release semantics |
| Handle user/power lifetime | `IO80211SkywalkInterface::newUserClient(task_t, void*, uint32_t, OSDictionary*, IOUserClient**)`, `setPowerState(unsigned long, IOService*)` | User-client entitlements, async callback serialization, gate/sleep interactions and outstanding packet/control requests |

For exact-symbol lookup, the source evidence includes the mangled identifiers
`__ZN17IO80211Controller15attachInterfaceEP8OSObjectP9IOService`,
`__ZN17IO80211Controller8scanDoneE10scanSourcei`,
`__ZN23IO80211SkywalkInterface4initEP9IOServiceP10ether_addr`, and
`__ZN23IO80211SkywalkInterface11inputPacketEP20IO80211NetworkPacketP15packet_info_tagP12ether_headerPbb`.
These examples provide testable lookup anchors, **not** calls to import into
the current passive kext target. The separate
[25G332 KDK evidence](TAHOE-25G332-KDK.md) records the inactive target
membership and missing native dependency declarations.

The proposed adapter must serialize this progression through a single verified
native owner: exclusive PCI ownership and actual radio initialization;
scan request; bounded `ScanCache`/`LegacyScanBridge` snapshots; radio scan
completion; genuine station association and key installation; then OS link
state and packet delivery. On deauth, radio stop, sleep or provider loss, it
must first quiesce TX/RX and revoke OS packet and user-client callbacks, clear
station/key state and publish disconnection. A borrowed `WifiEngine` RX payload
cannot outlive the DMA buffer; a native packet must own its bytes until the
OS-specific completion/release contract has been established. No readiness
boolean or registered interface may be synthesized from an nlist symbol, a
registry match or the existing source-only state machines.

The **first implementable source unit** should be a bounded scan-control
translation owned by the future native controller: associate each accepted
SCAN_REQ with a monotonically increasing radio/session epoch and requested
scan serial, take only completed copies from `LegacyScanBridge`, expose one
copied result at a time and invalidate all callbacks after stop/sleep/provider
loss. Its portable portion can be host-tested with synthetic beacons and
failed/incomplete scans; it must not manufacture SCAN_DONE or a live interface.
An actual Apple80211 handler must wait for verified 25G332 request/result
sizes, selectors, callback entrypoints and memory ownership. The existing
`LegacyScanBridge` covers only the result snapshot, **not** native dispatch,
radio scanning or OS event delivery. This is the highest-leverage narrow
vertical interface, rather than another disconnected parser or a full mocked
Wi-Fi stack that cannot exercise the unavailable native ABI.

The actual exact-build package exposes `IO80211Family` **1200.13.1** and
`IOSkywalkFamily` **1.0** in its KDK record. The reference Realtek legacy
plist instead requests **`IO80211FamilyLegacy` 1200.12.2b1** on an earlier
Tahoe build. These are different evidence contexts: the KDK record does not
establish that the Realtek legacy family is present, link-eligible or loaded
on stock 25G332. Native family choice and prerequisite availability must be
resolved for the exact target, not inferred from a working patch-based sample.

Before introducing any `IO80211Controller` subclass into the Xcode Sources
phase, the P0 ABI task must supply exact-target method and virtual signatures,
verified exports/KPI eligibility, object size and superclass constructor
requirements, complete Apple80211 request/event structure layouts and queue
ownership. Only then can implementation add matching family declarations to
`Info.plist` and, when separately authorized, inspect the produced artifact's
actual imports/relocations. Those prerequisites remain **open** here; no
native adapter has been enabled or compiled.

## Compatibility and safety requirements

- Our target: Dell Inspiron 5567 AR9565 (168c:0036), macOS 26.7.2 /
  build 25G332. The reference's validated hardware and OS are different.
- Check exact kernel collection exports, IOPCIFamily, IO80211FamilyLegacy,
  IONetworkingFamily and required reserved symbols against the real Dell.
  No Apple vtable, class size, virtual selector or kernel symbol address
  can be copied from the Realtek controller unverified.
- Restoring legacy Apple Wi-Fi families may require OCLP-specific changes.
  The known bootable USB EFI and SSD must not be modified without renewed
  explicit owner authorization. Do not add a disabled legacy family to an
  active release and call it functional; match the correct stack precisely.
- The external repository contains files licensed GPL-2.0 OR BSD-3-Clause.
  We only inspect it as a reference: no third-party source is copied or
  redistributed, so SimpleATH remains new AGPL-3.0-only code.
- Wi-Fi menu integration is a separate macOS integration milestone from
  PCI access, calibrated AR9565 RF, DMA, 802.11 security and real traffic.

No build, tests, kext injection, PCI access, root patch, USB/EFI changes
or on-device experiments were performed for this research.
