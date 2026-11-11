# SimpleATH

**Native Wi-Fi, Bluetooth and AirDrop project for Intel macOS Tahoe,
targeting the Qualcomm Atheros AR9565 / QCA9565 combo chip (WLAN PCI
168c:0036) in the Dell Inspiron 5567.**

**Not yet a functional, physically verified Wi-Fi driver.** The last
authorized binary was a passive device-matching prototype; the substantial
AR9565 radio, MAC, DMA, WPA2 and native AirPort code added since then has
not been built into a new authorized kext or tested on the Dell.
The normal target now includes a native PCI owner with serialized power, BAR access, RTC reset and EEPROM acquisition. RF calibration, hardware queues and native Wi-Fi registration are still required for scanning and networking. Portable modules have offline host regressions; those do not
verify kernel loading, native AirPort or real device operation. The development goal is genuine
macOS Wi-Fi support, not an Ethernet device disguised as AirPort.

## Clean OpenCore baseline and later SimpleATH configuration

The owner's November 10, 2026 USB diagnostic baseline is deliberately free
of experimental Wi-Fi/Ethernet injections. On the USB EFI, `Kernel -> Add`
contains neither `SimpleATH.kext` nor the old experimental
`RealtekRTL8100.kext`. Both bundles were removed from the USB EFI; no
SimpleATH injection is configured. The old AR9565
PCI `168c:0036` to `168c:0030` device-ID/`IOName` spoof was also removed.
`Kernel -> Block`, `Kernel -> Patch`, and `Kernel -> Force` are empty. No
El Capitan `IO80211ElCap.kext`, `corecaptureElCap.kext`,
`AirPortAtheros40.kext`, `IO80211FamilyLegacy.kext`, or injected legacy
`IOSkywalkFamily.kext` is present on this USB. Native Apple networking
components must not be blocked or downgraded for SimpleATH.

The USB **still contains** generic non-network boot support, including Lilu,
VirtualSMC, battery/graphics and input drivers. `AMFIPass.kext` and the
`-amfipassbeta` boot argument are also temporarily retained: AMFIPass is an
OCLP/root-patch helper, **not a SimpleATH dependency**, and existing macOS
root patches may still depend on it. Do not remove it or tighten SIP/AMFI
until the system's actual root-patch requirements are known.

### Does native SimpleATH require OCLP Legacy Wireless root patches?

**No legacy Atheros/El Capitan injection is specified or required by the
current SimpleATH source.** Its `src/Info.plist` directly requests the Tahoe
Apple providers `com.apple.iokit.IO80211Family` (minimum `1200.13.1`),
`com.apple.iokit.IOSkywalkFamily` (`1.0`),
`com.apple.iokit.IONetworkingFamily` (`3.2`) and
`com.apple.driver.corecapture` (`1.0`), *not*
`IO80211FamilyLegacy`, `IO80211ElCap`, `AirPortAtheros40` or
`corecaptureElCap`. These dependencies must actually be available on the
installed macOS build. OpenCore injection succeeding with existing root
patches does **not** prove the driver can start after a root-patch rollback;
that remains untested.

OCLP **Post-Install Root Patches** modify macOS's system volume and are
separate from the USB's `EFI/OC/config.plist`. If OCLP was used **only** for
legacy Wi-Fi, revert its root patches through OCLP after reaching a stable
macOS boot. If OCLP also provides graphics or other indispensable hardware
support, **do not revert all root patches blindly**: OCLP's rollback may
remove those too. Plan a recovery path and restore only the needed non-Wi-Fi
patch categories before discarding AMFIPass or changing SIP settings.
See OCLP's [post-install guide][o1] and
[patch rollback guide][o2].

[o1]: https://dortania.github.io/OpenCore-Legacy-Patcher/POST-INSTALL.html
[o2]: https://dortania.github.io/OpenCore-Legacy-Patcher/UNINSTALL.html

### Re-enable SimpleATH after a confirmed working baseline

1. First boot macOS with this clean OpenCore configuration. Run
   `USB/debug/SimpleATH-debug.command` from the USB data partition and
   inspect the adjacent `SimpleATH-debug-*.log` if diagnostics are needed.
2. Ensure the new native Intel x86_64 `SimpleATH.kext` build is in
   `EFI/OC/Kexts/SimpleATH.kext`. Keep the **original** AR9565 PCI identity,
   vendor `168c`, device `0036`; do **not** restore the legacy `0030` spoof.
3. Add **only this kext** to `Kernel -> Add` in `EFI/OC/config.plist`, after
   the existing base kext entries. The entry is:

   ```xml
   <dict>
       <key>Arch</key><string>Any</string>
       <key>BundlePath</key><string>SimpleATH.kext</string>
       <key>Comment</key><string>SimpleATH native Tahoe AR9565 test</string>
       <key>Enabled</key><true/>
       <key>ExecutablePath</key><string>Contents/MacOS/SimpleATH</string>
       <key>MaxKernel</key><string></string>
       <key>MinKernel</key><string>25.0.0</string>
       <key>PlistPath</key><string>Contents/Info.plist</string>
   </dict>
   ```

4. Do **not** restore `RealtekRTL8100.kext`, ElCapitan/legacy AirPort or
   CoreCapture, a replacement `IOSkywalkFamily.kext`, or an Apple Skywalk
   blocking/patch entry. Leave the existing non-network ACPI, graphics,
   SMC and input configuration alone. Use `ocvalidate` against the **exact**
   OpenCore version before the next authorized hardware experiment.
5. For debugging, `simpleathdbg=1` may be added to boot arguments, with
   normal verbose kernel logging if needed. Restore the clean baseline
   if a subsequent boot freezes. A successful load does not yet prove the
   radio, scan, WPA2 or AirDrop paths are functional.

This recipe is a **future** test plan, not an instruction to auto-enable the
kext now. Only the owner can confirm macOS boots reliably on this EFI and
whether its installed OCLP root patches can be safely removed.

## Canonical references and research

Use `.references/` at the repository root for all retained source research.
Populate it with `python3 -B tools/references/download.py`; use `--offline`
to verify existing sources. Search ignored references explicitly with
`rg --hidden --no-ignore -g '!**/.git/**' -n 'symbol|register|error' .references/`
and enumerate files with `rg --files --hidden --no-ignore .references/`.
Whenever a behavior, API or missing implementation is unclear, search these
sources and the web for the evidence needed (prefer upstream source, published
specifications and official documentation). Record exact revisions, source
hashes, adaptation scope, destinations and licenses in the single
`.references/ledger.jsonl`. Preserve upstream notices; downloaded code is not
proof of implementation or runtime success.

Linux is retained in `.references/linux/`, MacKernelSDK in
`.references/MacKernelSDK/`, and the other pinned repositories in
`.references/<repository>/<revision>/`. Research and SDK consumers must use
these canonical paths. Only `.references/ledger.jsonl` is tracked; bulk
sources, receipt caches and downloaded libraries stay ignored. Every typed
TODO names the specific files useful for its implementation.

## Author's Notes

It’s just for fun—we’ll see if it works or not.

## Development protocol

SimpleATH uses ten coordinating agents with a **direct-to-main,
NO-PULL-REQUESTS** workflow. The agents coordinate concurrent file
ownership in their **existing agent chat**; no agent branches or PRs.
See [AGENTS.md](AGENTS.md) and [TODO.md](TODO.md).

**Every engineering task except the FINAL TODO is deliberately
theoretical/source-only. Nothing in those tasks is allowed to depend
on formal or informal verification on physical hardware.** Agents
research public Linux ath9k code, available KDK/SDK exports,
documented macOS interfaces, published standards and other publicly
available driver sources. They implement and harden the driver and
its fail-closed behavior without requiring Dell diagnostics,
EEPROM dumps, RF measurements or user testing.

**FIRST IMPLEMENTATION, THEN CORRECTION.** The owner's 2026-11-09 order is:
implement the complete production driver 100%; then resolve all lint/check
failures to zero without weakening rules; then harden edge cases indefinitely
and finish the remaining TODOs while testing the notebook. The owner shares
logs here, and agents use them to implement real fixes. Continuous hardening
must never become an indefinite testing hold. As of 2026-11-10, strict CI,
authorized kext builds and release publication use separate tag triggers.

**Owner acceptance criterion: implement the whole system before testing it.**
The first testable driver must contain every required source path, connected
end to end, with the expectation that the complete workflow works. Do not
perfect one isolated component while leaving the rest unimplemented: a partial
driver cannot exercise the interactions and complexity the owner wants to test.
A failed launch, a kernel crash or a broken workflow during owner-authorized
testing is actionable debugging evidence, not a reason to defer implementation
or wait for indefinite hardening. Collect the logs, fix the actual failure and
repeat. This accepts first-run uncertainty; it does not authorize deliberate
faults, invented readiness or describing missing functionality as complete.

Agents should divide the work accordingly: the integration agent implements
and connects the runtime paths; collaborating agents resolve relevant
Clang-Tidy and other validator findings without interrupting implementation
or weakening checks. Build authorization is separate from CI success;
validation failures still produce visible warnings and reports.

Before notebook testing, all required AR9565 source must be complete,
integrated on main and reviewed, with no known missing implementation or
passive-only substitute, and validation must reach zero failures. Continuous
hardening and remaining maintenance TODOs may stay open during testing. The owner can then request the first
GitHub compilation of that exact commit through one expressly authorized
`build-v*` tag. Reaching this milestone never authorizes a build by itself.
The objective is fully functional Wi-Fi; source review cannot guarantee
first-run success. The final TODO stays open until the owner explicitly
asks to close it, including after otherwise successful experiments.

Agents finish missing runtime implementations, reach zero validation failures,
then continue hardening alongside authorized notebook testing.
Complete the AR9565 Linux ledger and reference-retirement TODO before removing
the local .references/linux/ tree. Existing notices preserve third-party attribution.

Source-level completeness is not empirical proof. Unknown hardware
values, regulatory conditions and private macOS ABI differences
must be recorded and handled safely rather than guessed or
misrepresented as verified.

## Architecture and current source

- **PCI and device identity:** native AR9565 ownership, live identity/D0 checks,
  BAR mapping, ordered active MMIO, RTC bootstrap and EEPROM acquisition in
  `SimpleATH::start`, with gated sleep/resume/termination and startup errors.
- **EEPROM, OTP and calibration:** bounded parsing, revision-specific
  definitions and generated register recipes derived from ath9k.
- **RF/PHY and regulatory rules:** static channel, calibration and
  transmit-power policy source with explicit missing prerequisites.
- **AR9003 DMA:** RX/TX descriptors, rate/power controls, safe buffer
  ownership and completion metadata, not a live packet engine.
- **802.11 MAC:** scan/BSS snapshots, authentication and association,
  EAPOL, data framing and link loss/reconnection logic.
- **WPA2:** portable PMK/PTK/HMAC/AES source and callback adapters;
  keycache integration and cryptographic review remain unfinished.
- **Native Tahoe AirPort:** research and interface contracts for
  IO80211FamilyLegacy/Skywalk; a verified native network service is
  not yet available.

Supporting design references include [AR9565 bring-up](docs/design/AR9565-BRINGUP.md),
[MAC/DMA source](docs/design/WIFI-MAC-AND-DMA.md),
[WPA2 cryptography](docs/design/WPA2-CRYPTO-SOURCE.md),
[Wi-Fi engine](docs/design/WIFI-ENGINE-SOURCE.md),
[Tahoe ABI evidence](docs/design/TAHOE-25G332-KDK.md),
[native IO80211 research](docs/design/TAHOE-NATIVE-IO80211-REFERENCE.md)
and [recovery status](docs/design/STATUS-AND-RECOVERY.md).

The target QCA9565/Dell Wireless 1707 is a **combined Wi-Fi and Bluetooth
4.0 chip**, not an assumed separate Bluetooth chipset. Qualcomm documents
the combined silicon, and Dell lists both functions for the Inspiron 5567:
[Qualcomm QCA9565](https://www.qualcomm.com/networking-infrastructure/products/qca9565),
[Dell DW1707/QCA9565 driver](https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=g66t8).

The functions still have separate host transports and software ownership:
PCIe WLAN, and USB Bluetooth HCI with its firmware/transport integration.
A working WLAN path does not by itself implement Bluetooth. Likewise,
AirDrop requires BLE discovery and Apple's peer-to-peer Wi-Fi/AWDL path,
not only association with an access point:
[Apple AirDrop security](https://support.apple.com/en-ie/guide/security-pdf/sec2261183f4/web).
Implement and integrate those required paths; shared silicon is neither
proof of automatic support nor evidence that support is impossible.
Bluetooth/coexistence and AirDrop remain required project goals, with
observed notebook results recorded in the owner-controlled final test cycle.

## Runtime diagnostics and crash symbols

The authorized build workflow selects the optimized Release configuration,
preserves `SimpleATH.kext.dSYM` symbols, and verifies that the kernel and
dSYM UUID/architecture match. Builds are independent of CI and archive
both binary and symbols on success. Runtime diagnostics use the driver:

- `simpleathdbg=1` or `-simpleathdbg` enables detailed startup state logs.
- `simpleathdbg=0` forces normal logging, including essential failures.
- With no override, a valid OpenCore `DBG` or `NPT` identifier exposed through
  its `opencore-version` NVRAM property selects detailed logging. Release,
  hidden, missing or malformed metadata selects normal logging.

This reads exported boot metadata without mounting EFI or opening OpenCore's
`config.plist`. It detects OpenCore's build type, not its `Misc/Debug/Target`
logging bitmask. Selection never changes driver features, RF authorization,
compiler optimizations or readiness. `SimpleATHDiagnosticsDetailed` and
`SimpleATHDiagnosticsSource` report the decision in the driver's registry.
Source: [OpenCore build identifiers](https://github.com/acidanthera/OpenCorePkg/blob/master/Include/Acidanthera/Library/OcMainLib.h)
and [OpenCore exported NVRAM configuration](https://github.com/acidanthera/OpenCorePkg/blob/master/Docs/Configuration.tex).

## Manual macOS debugging

Open `tools/debug/SimpleATH-debug.command` in Finder, or run it in Terminal:

```sh
./tools/debug/SimpleATH-debug.command
```

The launcher uses Python 3.9+ from the macOS development setup. Administrator
access is mandatory: the collector relaunches through `sudo` and cannot
collect as an ordinary user. It always creates a new private
`SimpleATH-debug-YYYYMMDD-HHMMSS-*.log` **beside the tool**, even when launched
from another directory. The sudo caller owns the log. Reproduce the problem,
then run it and share that log in this chat. For a longer history:

```sh
./tools/debug/SimpleATH-debug.command --minutes 30 --timeout 60
```

The merged report includes OS/kernel/build identity, a restricted NVRAM
boot/SIP/OpenCore-key inventory, loaded kexts, available driver file hashes,
PCI/USB and AirPort/Bluetooth registry entries, hardware profiles,
interfaces/routing/DNS, AWDL, power state and recent crash reports. It also
collects the requested recent Wi-Fi/Bluetooth/AirDrop logs, related 24-hour
messages, the last 2 hours of kernel logs and 24-hour boot/panic signals.
Commands have deadlines and output limits; missing commands/devices, errors
and truncation remain explicit. The separate `SimpleATH-Collect.command` has
been merged into this tool and is no longer needed.
Logs can contain device/network identifiers and stay excluded from Git.
The collector does not install/load drivers, change settings, scan radio
channels, export pairing/password keys or capture network packets. A finished
report means evidence was collected, not that the driver passed its tests.

The pending run/log-review task is part of the single owner-controlled final
acceptance TODO. Bluetooth USB/BLE and AirDrop/AWDL source implementation are
also explicit production TODOs; both must be integrated before source closure.

## Build for macOS testing

Kernel artifacts are compiled **only** by an explicitly owner-authorized
`build-vYYYY.MMDD.HHmm` tag (for example, `build-v2026.1110.1555`). The
zero-padded date/time is expressed in `America/Mexico_City`. Build tags run
**only** the Intel macOS Xcode build; they never run CI or publish a release.
The workflow checks the exact CalVer tag, tests native Apple kernel/C
headers and fails immediately when required headers are unavailable. The
`.references/MacKernelSDK` download is for offline research only and cannot
supply CI or build headers. Never reuse a tag, trigger a build without
owner authorization or include uncommitted changes in a tagged snapshot.

The unsigned bundle is `build/Products/Release/SimpleATH.kext`. It now runs
PCI claim/map, physical silicon inspection, MAC quiescence, RTC bootstrap and
EEPROM discovery when loaded on the target. `SimpleATHStartupStage` reports
progress; failures log the exact stage and detail code. `BoardAcquired` means
reset and board acquisition succeeded; it does not mean Wi-Fi can yet scan or
connect. Remaining RF/calibration, queue/interrupt and AirPort integration
stays open in TODO.md.

**CI and release are separate actions.** `ci` and `ci-*` tags run the full
strict macOS validator, without compiling the kext. `release-v*` tags first
run that same strict validator; **only if every check succeeds** does a
separate job publish the GitHub release for the tagged commit. Build tags
never cause CI or release publication. No finding is advisory or converted
to success. The `-simpleathoff` boot argument still disables matching.

## Tooling: explicitly NOT a Jig repository

**SimpleATH is an explicit exception to the Jig rule and does not use
Jig.** Existing .jig/ material is left as-is, inactive. There is
no mandatory hexagonal architecture, Jig check, Jig hook or Jig CI gate.

The only dedicated local source validator is a **small Python
standard-library orchestrator** that calls system-installed linters and
uses the existing rules in the repository root:

- C, Objective-C and C++: Clang Format using .clang-format.
- C, Objective-C and C++: mandatory Clang-Tidy using .clang-tidy,
  requiring an existing compile_commands.json.
- Python: Ruff lint + Ruff format using ruff.toml and BasedPyright
  using pyrightconfig.json.

    python3 -B tools/validate.py
    python3 -B tools/validate.py --no-cache

The tracked `compile_commands.json` now supplies explicit **host-side,
source-only** Clang-Tidy parse commands for existing C++/Objective-C++
translation units in `src/`, `tests/` and `tools/`. Source entries use the
project's C++14 dialect; offline test/tool entries use C++17. It was not
captured from an Xcode kext compilation and does not establish native Tahoe
header, ABI or runtime compatibility. The JSON records this checkout's
absolute root path, as Clang-Tidy silently skips unmatched relative entries.
The validator checks for a matching command first and reports missing/stale
entries as unsuccessful skips, never an apparent Tidy pass.
After moving or cloning the repository, refresh those paths with:

    python3 -B tools/generate_compile_commands.py

To use the pinned open-source kernel compatibility headers for static
analysis on Fedora (without compiling a kext), run:

    python3 -B tools/bootstrap_sdk.py
    python3 -B tools/generate_compile_commands.py
    python3 -B tools/validate.py --no-cache

The SDK stays in the ignored `.references/MacKernelSDK` directory. On Linux,
the generator sets an x86_64 Darwin parse target and detects an available
LLVM libc++ header configuration. Genuine missing declarations remain
Clang-Tidy failures; no Linux-only skip exists. The user-space
CoreWLAN probe still needs Apple frameworks and is not fabricated on Fedora.

This generator only inventories source paths and writes JSON; it never invokes
a compiler, builds a kext or fabricates missing headers. On a Linux host
without Apple's SDK/KDK, platform-specific source still has unresolved
includes. Clang-Tidy now **runs** and reports actual source findings; a
failing lint check is not a successful native verification.

**Incremental cache:** .cache/validate/cache.json holds separate results
per file and linter. Unchanged files are not rechecked; changes to source,
root rule files, or installed linter version invalidate the cache.
Use --no-cache when changes to imported headers/modules may affect an
unchanged file. The latest structured agent/CLI report is always written
to .cache/validate/report.json after a completed run; JSON is emitted on
stdout on every run. Read the `"scope": "repository"` marker and the CLI
exit status before interpreting a pass count. An exclusive advisory lock on
`.cache/validate/run.lock` serializes concurrent validator instances so no
agent can replace another's cache or report with an out-of-order write.
Every run checks **all repository sources** under `src/`, `tools/` and
`tests/`, including tracked and untracked files, excluding the Linux reference
tree. Legacy positional file arguments are accepted but ignored; they can
never produce a misleading partial report. The report declares
`"scope": "repository"`. Both JSON stdout and
`.cache/validate/report.json` show **only failed and skipped checks**,
including cached findings; successful checks are omitted from the result rows
but included in the complete pass/fail/cached/skipped summary. Diagnostics are
bounded per check; a cached failure stays a failure. All five source tools are
listed in `tools`, including unavailable tools; missing compilation commands
are reported as skipped checks rather than passing silently.

By owner instruction, Clang-Tidy, offline host tests and JSON output are
**mandatory**. `--no-tidy`, `--no-tests`, and `--no-json` are rejected before
any cache or report writes. Missing Clang-Tidy or `compile_commands.json`
remains an explicit skipped check that fails validation, never a fabricated
pass. `--no-cache` forces a fresh full-repository analysis; the resulting
per-file tool outcomes still populate the shared cache. Positive `--tidy`,
`--tests`, and `--json` flags remain accepted for compatibility.

Offline host tests use root `tests/`: Python standard-library unittest and
C++/Objective-C++ host-only compilation/execution in temporary directories.
No kext compilation, device test or tool installation is authorized. Host
results are never cached, and file arguments cannot narrow checks. See
[tests/README.md](tests/README.md) for supported test fixtures and errors.
These tests exercise synthetic data/fakes, never actual PCI/RF or kernel
objects. The local `.references/linux/` reference tree is ignored by Git and by this
validator; legacy path arguments never override whole-repo discovery.

The script never formats files in place, builds a kext, generates a
compilation database, installs software or touches hardware. Existing lint
failures and missing requested checks remain failures, not a green report.
The runner uses the project's Python 3.14 tool environment.

## Builds, CI and hardware testing

The GitHub Actions workflows are **tag-only** and do not run on ordinary
`main` pushes, pull requests or manual workflow dispatch. All macOS runner
jobs require **public** repository visibility to avoid private runner charges:

- `ci` / `ci-*`: strict Clang-Format, Clang-Tidy, Ruff, BasedPyright and
  offline host tests on macOS Tahoe Intel; any failure or skip fails CI.
- `build-vYYYY.MMDD.HHmm`: Xcode unsigned kext build **only**. It is not
  dependent on any CI job, and does not publish a GitHub release.
- `release-v*`: strict macOS CI first; publish a GitHub release only when
  the complete CI job passes. A failed/skipped CI job never publishes.

CI uses Python 3.15, `uv` and pinned precompiled macOS x86_64 wheels without
Homebrew or source builds. `tools/validate.py --no-cache --stdout-only`
prints all failure/skip findings and counts in the GitHub Actions log,
without writing `.cache/validate/report.json` or validator cache state.
Local runs retain their normal on-disk reports and optional cache.

Both Clang-Tidy in macOS CI and the Xcode build use **native Apple SDK/KDK
headers only**. Kernel sources use C/XNU types (`<stddef.h>`, `<stdint.h>`,
`<string.h>`) without depending on hosted `libc++`; the sole placement-new
adapter uses IOKit-owned storage and never allocates. A freestanding Clang
syntax regression and source scan guard against reintroducing C++ library
headers into the kernel target. The downloaded `.references/MacKernelSDK`
remains available for offline research and Linux-only static exploration,
never as an include/library path in CI or build. Native Xcode compilation
checks the presence of kernel and C headers before starting; missing Apple
headers fail clearly instead of silently using reference substitutes. The
header checks do not prove Tahoe ABI compatibility; builds remain unsigned
and are never installed automatically.

These rules do **not** authorize creating tags, compiling the kext, or
physical testing. All EFI/OpenCore/USB/SSD and PCI/RF activity still requires
separate owner approval. A successful build does not prove working AirPort.

## Upstream source references

Run `python3 -B tools/references/download.py` to download the complete pinned
AirPort_RTW89, AirportItlwm-BE200 and NullMoth source trees into
`.references/<repository>/<revision>/`, the full MacKernelSDK into
`.references/MacKernelSDK/`, and all 422 retained Linux Wi-Fi/Bluetooth
reference files into `.references/linux/`. Missing Linux files are restored
from their per-file immutable revisions and SHA-256 values, preserving the
existing mixed-version snapshot and implementation assessments. No upstream
code is executed.
`--offline` checks existing copies without network access. The tracked
`.references/ledger.jsonl` records hashes, license observations, reuse
status and destination files; repeated runs preserve existing assessments.
Only the unified ledger is included in Git; there is no separate Linux ledger.
If missing, its inventory is restored from the local tracked checkout (or
Git HEAD); `--references PATH` can populate a separate reference directory.
`--repo linux` or `--repo MacKernelSDK` selects an individual download.
Source copies retain upstream notices.
Fetching references does not implement or verify the driver.

## License and attribution

This is the owner's public personal development and research project.
No repository-wide license is granted for independently authored SimpleATH
code. Public source availability is not a blanket permission to reuse it.

Third-party components retain their own licenses, copyrights and conditions;
GPL-2.0 components remain GPL-2.0, and permissive imports keep their original
notices. [licenses/GPL-2.0.txt](licenses/GPL-2.0.txt) is the retained third-party
GPLv2 text, not a license for the whole repository. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for exact scopes.

Removing a project-wide license does not waive upstream terms or the GPL
obligations of a distributed combined derivative. No license of upstream
NullMoth code is changed by this policy.
