# SimpleATH

**Status: experimental macOS Tahoe 26 (Darwin 25) kernel bootstrap / passive
AR9565 PCI hardware discovery. This is NOT yet a working Wi-Fi or Bluetooth
driver.**

The v1 project targets Qualcomm Atheros QCA9565 / AR9565, PCI `168c:0036`
(and recognizes a possible `168c:0030` OpenCore compatibility spoof).

## Implemented

- Boot-time `SimpleATH` service with no obsolete Apple AirPort, Broadcom,
  IO80211 or Skywalk binary injected into the kernel.
- Separate, **passive** `SimpleATHPciProbe` service matched to AR9565 by
  `IOPCIPrimaryMatch`. It does not link to IOPCIDevice C++ methods or read
  PCI configuration words, and does not initialize the radio or Wi-Fi.
- IORegistry properties to diagnose whether the kext and PCI matching started.
- `-simpleathoff` boot argument to disable its IOService matching.
- Offline support for a pinned MacKernelSDK, macOS Intel Xcode builds and
  a tag-only GitHub Actions workflow.

The C++ bridge, firmware runtime and network interface implementation still
need to be developed and validated. There is no basis to claim Wi-Fi connectivity
until those exist and are tested on real AR9565 hardware.

## Source tree

- `src/SimpleATH.cpp`: minimal kernel entry and passive PCI discovery.
- `src/Info.plist`: two IOKit personalities and compatible KPI dependencies.
- `src/platform/SimpleATH.xcodeproj`: Xcode target.
- `src/platform/Kernel.xcconfig`: macOS kernel SDK/build configuration.
- `src/platform/abi`: pinned reference profiles and ABI data.
- `tools/bootstrap_sdk.py`: fetch the pinned kernel SDK for Xcode.
- `linux/`: owner-provided Linux reference tree, unmodified and excluded
  from the binary; file-level Linux licenses remain applicable.

## Hardware source development (not compiled yet)

The source tree now includes a native C++ AR9565 hardware core, chipset
revision decoder, EEPROM/RTC status reader, guarded initialization plan,
and real 2.4 GHz register tables generated from Linux ath9k.

The hardware port is **incomplete**: PCI BAR transport, DMA, PHY
calibration, 802.11 association, encryption, and a macOS Wi-Fi interface
do not exist yet. New modules are staged in the Xcode target, but no new
binary has been built or deployed.

See [AR9565 bring-up design](docs/design/AR9565-BRINGUP.md).
Portable 802.11 management/data/EAPOL parsing, AR9003 TX/RX descriptor
and rate/power/CCMP control codecs, and DMA-validation modules are also
staged in the Xcode target. A guarded Ethernet-II/802.11 ToDS payload
serializer and access-point RX filter are also staged. They are
**not active** on the PCI card and do not provide WPA2 or a network device;
see [Wi-Fi MAC and DMA source status](docs/design/WIFI-MAC-AND-DMA.md). WPA2 handshake sources also
coordinate key derivation, MIC verification and installation via a required
platform crypto provider that is **not yet implemented**.

The [macOS integration record](docs/design/MACOS-INTEGRATION.md) distinguishes
the PCI ownership contract from a verified native adapter. The
[EEPROM port](docs/design/EEPROM-PORT.md) reconstructs blocks and interprets
board fields without asserting calibration or regulatory validity.
See [status, blockers and recovery](docs/design/STATUS-AND-RECOVERY.md) for
source commit evidence and the separate build/install/device authorizations.
The user must explicitly authorize the next CI build and boot test.

## Local macOS build

Requires Intel macOS with Xcode and Python 3.

```sh
python3 tools/bootstrap_sdk.py
xcodebuild -project src/platform/SimpleATH.xcodeproj \
  -scheme SimpleATH -configuration Release \
  -derivedDataPath build/DerivedData -arch x86_64 \
  CODE_SIGNING_ALLOWED=NO build
```

Output: `build/DerivedData/Build/Products/Release/SimpleATH.kext`.

## GitHub Actions authorization

**No builds on commits, branches, pull requests or manual dispatch.**
Only pushing a tag matching `build-v*` starts the Xcode build. Tags are
created and pushed only after the owner explicitly authorizes compilation.

## License

New SimpleATH source is AGPL-3.0-only. The Linux sources retain their own
SPDX licenses; SimpleBCM retains its original authorship and terms. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
