<!--
  README.md
  SimpleATH

  Based on SimpleBCM by laobamac.
  Original copyright and third-party notices are preserved in NOTICE.md.
-->
<div align="center">

# SimpleATH

![Version](https://img.shields.io/badge/version-1.2.0-2563eb)
![macOS](https://img.shields.io/badge/macOS-Sonoma%2014%20%7C%20Sequoia%2015%20%7C%20Tahoe%2026-111827)
![Architecture](https://img.shields.io/badge/arch-x86__64-6b7280)
![OpenCore](https://img.shields.io/badge/boot-OpenCore-16a34a)

**Documentation: English**

</div>

SimpleATH is an experimental project to develop native macOS wireless support for the Qualcomm Atheros AR9565 (PCI vendor 0x168c, device 0x0036), using the architecture of [SimpleBCM](https://github.com/laobamac/SimpleBCM) as a reference.

**Current status: Stage 1, minimal kernel bootstrap only. SimpleATH does not yet provide working Atheros Wi-Fi.** The source tree retains the upstream Broadcom implementation for reference, but the current kernel target links only `SimpleATH/SimpleATH.cpp`. The Broadcom payload, loader, periodic workloop, and native wireless bridge are not executed or linked by this bootstrap.

The first source-based build failed to reach the Tahoe desktop. The new minimal-kext build has not yet been proven to boot successfully on the Dell Inspiron 5567. A successful Xcode compilation is not proof of a successful macOS boot.

## Boot and recovery

The known bootable EFI contains 13 enabled kexts without SimpleATH or legacy Atheros wireless drivers. Preserve a copy of it before testing SimpleATH. The experimental EFI enables SimpleATH as an additional, fourteenth kext.

The bootstrap registers an `IOService` named `SimpleATH` under `IOResources`. If it starts, its IORegistry properties identify `SimpleATHMode=MinimalKernelBootstrap` and `SimpleATHDriverReady=false`.

Use `-simpleathoff` as a boot argument to disable SimpleATH service matching if necessary. This fallback is not equivalent to removing a kext that fails during kernel linking.

## Building locally

Build on an Intel Mac with full Xcode and Python 3. Upstream native ABI references for Sonoma 14, Sequoia 15 and Tahoe 26 are retained unchanged in `Resources/NativeABI`.

```sh
python3 Tools/check.py
python3 Tools/native_references.py verify
python3 Tools/bootstrap.py
xcodebuild -project SimpleATH.xcodeproj -scheme SimpleATH -configuration Release -derivedDataPath build/DerivedData -arch x86_64 CODE_SIGNING_ALLOWED=NO build
```

The build product is `build/DerivedData/Build/Products/Release/SimpleATH.kext`. The full upstream adapter sources and build utilities remain in the repository for future Atheros development, but they are not part of this minimal bootstrap binary.

## GitHub Actions: explicit tag authorization only

**CI will not run on branch pushes, pull requests, releases, schedules or manual dispatch.** It runs only when a tag whose name begins with `build-v` is pushed to GitHub.

Creating a local commit or pushing an ordinary branch commit does not compile anything. Do not create or push a build tag without explicit authorization.

After authorization, a maintainer can select a unique build tag, such as `build-v1.2.0-stage1.1`, and push only that tag:

```sh
git tag build-v1.2.0-stage1.1
git push origin build-v1.2.0-stage1.1
```

Those commands are documentation only; no tag or CI run was created by this localization change.

## Project references

- [Build instructions and CI safeguards](Docs/Build.md)
- [Upstream native Skywalk architecture (not active in Stage 1)](Docs/Native-Universal.md)
- [Source-level boot repair explanation](BOOTFIX-SIMPLEATH.md)
- [Third-party licenses and attribution](NOTICE.md)
