# SimpleATH

**Experimental, source-first native Wi-Fi kernel extension for Intel macOS
Tahoe, targeting the Qualcomm Atheros AR9565 / QCA9565 (PCI 168c:0036)
in the Dell Inspiron 5567.**

**Not yet a functional, physically verified Wi-Fi driver.** The last
authorized binary was a passive device-matching prototype; the substantial
AR9565 radio, MAC, DMA, WPA2 and native AirPort code added since then has
not been compiled or tested on the Dell. The development goal is genuine
macOS Wi-Fi support, not an Ethernet device disguised as AirPort.

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

**Order of operations:** finish ALL source-only TODOs, then
continue theoretical source hardening **indefinitely**. No deadline,
scheduled release or automatic transition to experiments exists.
Only when the owner explicitly decides the time is right will
the last TODO begin. **The owner personally tests the Dell and
shares logs/diagnostics in this ChatGPT conversation**; the agents
then coordinate real-bug fixes in their own chat and commit them
directly to main. This owner-led loop repeats until the outcome
is satisfactory.

When only the final acceptance TODO remains, all required AR9565 source
must be complete, integrated on main and reviewed, with no known source
blocker or passive-only substitute. The owner can then request the first
GitHub compilation of that exact commit through one expressly authorized
`build-v*` tag. Reaching this milestone never authorizes a build by itself.
The objective is fully functional Wi-Fi; source review cannot guarantee
first-run success. The final TODO stays open until the owner explicitly
asks to close it, including after otherwise successful experiments.

Without a new owner instruction, agents continue whole-source theoretical
hardening and web research indefinitely, repairing concrete defects and
reopening source TODOs when needed. Complete the AR9565 Linux ledger and
the dedicated reference-retirement TODO before removing the local linux/
tree. Existing inline notices and THIRD_PARTY_NOTICES.md are sufficient;
no additional reference archive or preservation infrastructure is required.

Source-level completeness is not empirical proof. Unknown hardware
values, regulatory conditions and private macOS ABI differences
must be recorded and handled safely rather than guessed or
misrepresented as verified.

## Architecture and current source

- **PCI and device identity:** guarded AR9565 register/session source,
  power/ownership and mapped-DMA transport contracts.
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

Bluetooth may be a separate chipset on the Dell; **AirDrop also depends
on Bluetooth and macOS Continuity compatibility**. Neither Bluetooth
nor AirDrop can be guaranteed solely by writing an AR9565 Wi-Fi kext.
Both remain goals of the owner-controlled final experimental cycle.

## Tooling: explicitly NOT a Jig repository

**SimpleATH is an explicit exception to the Jig rule and does not use
Jig.** Existing .jig/ material is left as-is, inactive. There is
no mandatory hexagonal architecture, Jig check, Jig hook or Jig CI gate.

The only dedicated local source validator is a **small Python
standard-library orchestrator** that calls system-installed linters and
uses the existing rules in the repository root:

- C, Objective-C and C++: Clang Format using .clang-format.
- C, Objective-C and C++ optionally: Clang-Tidy using .clang-tidy,
  **only** with an existing compile_commands.json.
- Python: Ruff lint + Ruff format using ruff.toml and BasedPyright
  using pyrightconfig.json.

    python3 tools/validate.py
    python3 tools/validate.py tools/validate.py
    python3 tools/validate.py --json tools/validate.py
    python3 tools/validate.py --no-cache src/wifi/Frames.cpp
    python3 tools/validate.py --tidy src/wifi/Frames.cpp

**Incremental cache:** .cache/validate/cache.json holds separate results
per file and linter. Unchanged files are not rechecked; changes to source,
root rule files, or installed linter version invalidate the cache.
Use --no-cache when changes to imported headers/modules may affect an
unchanged file. The latest structured agent/CLI report is always written
to .cache/validate/report.json; --json emits the same report on stdout.
Pass/fail/cached/skipped counts and bounded diagnostics are explicit;
a cached failure stays a failure.

The script never formats files in place, builds a kext, generates a
compilation database, installs software, runs test suites or touches
hardware. Existing lint failures are reported rather than hidden.

## Builds, CI and hardware testing

**Not authorized during source-only development.** Do not produce
another kext, run an Xcode build or test suite, trigger CI, push
build-v* tags, modify OpenCore/EFI/USB/SSD, or interact with live
PCI/RF hardware. The GitHub Actions build remains tag-only, and
ordinary main pushes never trigger a kext build.

When the owner *later* activates the final TODO, compilation,
artifact inspection, EFI installation and physical tests require
their own explicit authorizations. Preserve the known bootable
OpenCore recovery configuration. A macOS boot, IORegistry match or
successfully injected passive kext is not working wireless networking.

## License and attribution

New authored SimpleATH source is AGPL-3.0-only. Referenced Linux
ath9k source and imported tables retain their original permissive
file-specific license notices; historical SimpleBCM reference
material retains its original attribution. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
