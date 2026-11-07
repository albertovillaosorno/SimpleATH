# SimpleATH

**Status: experimental macOS Tahoe 26 (Darwin 25) kernel bootstrap / passive
AR9565 PCI hardware discovery. This is NOT yet a working Wi-Fi or Bluetooth
driver.**

The v1 project targets Qualcomm Atheros QCA9565 / AR9565, PCI `168c:0036`
(and recognizes a possible `168c:0030` OpenCore compatibility spoof).

## Implemented

- Boot-time `SimpleATH` service with no obsolete Apple AirPort, Broadcom,
  IO80211 or Skywalk binary injected into the kernel.
- Separate, **read-only** `SimpleATHPciProbe` service for the AR9565 PCI device.
  The probe only reads PCI identification words. It never accesses radio
  registers, enables bus mastering, requests interrupts, or transmits packets.
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
