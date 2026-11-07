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
