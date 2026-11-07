<!--
  Build.md
  SimpleATH

  Based on the original SimpleBCM build documentation by laobamac.
  Copyright (c) 2026 laobamac. All rights reserved.
-->

# Building and CI

SimpleATH requires an Intel Mac, a complete installation of Xcode, and Python 3 to compile a macOS kernel extension. `Resources/NativeABI` contains reference symbols, virtual tables, class layout descriptions, and registration-entry instruction signatures for Sonoma, Sequoia, and Tahoe. Reference data is used for code generation and verification and is not embedded in the current bootstrap driver.

**Current build target:** Stage 1 is a minimal `IOService` bootstrap intended for safe kernel-load testing. The Broadcom payload sources remain available as upstream reference code but are not compiled into this target. Stage 1 is not a working Atheros Wi-Fi driver.

## Build the current minimal kernel target

```sh
python3 Tools/check.py
python3 Tools/native_references.py verify
python3 Tools/bootstrap.py
xcodebuild -project SimpleATH.xcodeproj -scheme SimpleATH -configuration Release -derivedDataPath build/DerivedData -arch x86_64 CODE_SIGNING_ALLOWED=NO build
```

The release output is `build/DerivedData/Build/Products/Release/SimpleATH.kext`. Successful compilation does not prove the kernel extension will load or boot.

## Original full-adapter development commands (reference only)

The original SimpleBCM build pipeline used these commands for the **Broadcom** runtime:

```sh
python3 -B Tools/bootstrap.py
python3 -B Tools/check.py
python3 -B Tools/build.py build --configuration Debug
python3 -B Tools/build.py build --configuration Release
python3 -B Tools/build.py analyze --configuration Release
python3 -B Tools/build.py package --configuration Debug --channel pre
python3 -B Tools/build.py package --configuration Release --channel pre
```

`bootstrap.py` fetches a pinned MacKernelSDK revision and the wireless driver archives from OpenCore Legacy Patcher. The full adapter build checks native exports and virtual tables against ABI references. It exercises relocation, call forwarding, and control-message codecs under ASan/UBSan. Release builds additionally run Clang static analysis. Optional checks for Apple private-function layouts run only when the host frameworks match.

Packaging normally requires matching build, verification, and static-analysis source fingerprints. The `--channel pre` option names alpha packages using a commit identifier, while `--channel rel` uses the formal release version. Build outputs are written to `build` and packages to `dist`. These original tools are retained for future development; the current tag-triggered workflow does not invoke them.

## Updating native ABI references

Adapter maintainers can set `SIMPLEATH_NATIVE_SOURCE=system` to read the actual kernel collections from local system volumes. By default, the tools examine the current system and `/Volumes/Macintosh HD 1` and `/Volumes/Macintosh HD 2`, matching actual OS versions and UUIDs against the systems documented in [Native-Universal.md](Native-Universal.md).

Set `SIMPLEATH_REFERENCE_ROOT` to use custom reference directories. Each system directory must contain the original `SystemVersion.plist` and `BootKernelExtensions.kc`:

```text
<SIMPLEATH_REFERENCE_ROOT>/<Sonoma|Sequoia|Tahoe>/System/Library/CoreServices/SystemVersion.plist
<SIMPLEATH_REFERENCE_ROOT>/<Sonoma|Sequoia|Tahoe>/System/Library/KernelCollections/BootKernelExtensions.kc
```

```sh
SIMPLEATH_NATIVE_SOURCE=system python3 -B Tools/build.py build --configuration Release
python3 -B Tools/native_references.py export
python3 -B Tools/native_references.py verify
```

The exporter reads native reference data from the original kernel collection, checks that registration-entry patterns are unique within the complete code segment, and updates file checksums. The original adapter selects runtime compatibility using the Darwin major version and actual ABI instead of restricting loading to reference build numbers or UUIDs.

## GitHub Actions: tag-only builds

The repository contains **one** workflow: `.github/workflows/build.yml`, using the GitHub-hosted `macos-26-intel` runner. It checks the source and ABI references, prepares dependencies, builds the minimal bootstrap with Xcode, and uploads the kernel extension and logs.

**The sole trigger is a pushed Git tag matching `build-v*`.** The workflow intentionally has no branch-push, pull-request, release, schedule, or manual-dispatch trigger, and the build job independently checks the `refs/tags/build-v` prefix.

An ordinary commit or branch push **never starts CI**. Build tags must not be created or pushed until the user explicitly authorizes a compilation. Once authorized, select a unique tag (for example `build-v1.2.0-stage1.1`) and push it deliberately:

```sh
git tag build-v1.2.0-stage1.1
git push origin build-v1.2.0-stage1.1
```

This is a documented procedure, not an instruction to run it now. The localization commit creates no tag and starts no build.

The workflow grants only `contents: read` permissions. It does not create GitHub releases, push tags, or publish packages automatically.
