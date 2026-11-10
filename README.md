# SimpleATH

**Experimental, source-first native Wi-Fi kernel extension for Intel macOS
Tahoe, targeting the Qualcomm Atheros AR9565 / QCA9565 (PCI 168c:0036)
in the Dell Inspiron 5567.**

**Not yet a functional, physically verified Wi-Fi driver.** The last
authorized binary was a passive device-matching prototype; the substantial
AR9565 radio, MAC, DMA, WPA2 and native AirPort code added since then has
not been built into a new authorized kext or tested on the Dell.
A few portable modules now have offline host regressions; those do not
verify kernel loading, native AirPort or real device operation. The development goal is genuine
macOS Wi-Fi support, not an Ethernet device disguised as AirPort.

## Author's Notes

Go to hell if you hate AI because of "ethical concerns" or any other bullshit.

This is an experiment for a Hackintosh (which is incredibly stupid, considering
you could just buy a Mac).

It’s just for fun—we’ll see if it works or not.

I used some "**G**arbage & **P**oop **L**overs" license—I absolutely loathe it.
I preferred having access to Linux source code to use for this project.

GitHub lists this repository as **public**. Standard GitHub-hosted runners
(including `macos-26-intel`) are free for public repositories; larger
runners and excess artifact storage can cost money. The workflows stay
restricted to public visibility and use one-day artifact retention. Details:
https://docs.github.com/en/actions/concepts/billing-and-usage

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

The SDK stays in the ignored `.research/MacKernelSDK` directory. On Linux,
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
objects. The local `linux/` reference tree is ignored by Git and by this
validator; legacy path arguments never override whole-repo discovery.

The script never formats files in place, builds a kext, generates a
compilation database, installs software or touches hardware. Existing lint
failures and missing requested checks remain failures, not a green report.
The runner uses the project's Python 3.14 tool environment.

## Builds, CI and hardware testing

The GitHub Actions workflows are **tag-only** and do not run on ordinary
`main` pushes, pull requests or manual workflow dispatch. They also require
**public** repository visibility, to avoid chargeable private-runner usage:

- `ci` or `ci-*`: run the complete macOS-mode validator and offline host tests
  on the standard Intel Tahoe runner. **No kext is built.**
- `build-v*`: invoke that same validator on the exact tag commit first. Only
  a fully successful validation starts the separate x86_64 Xcode kext build.
  Failure or skipped validation checks prevent the build entirely.

The CI uses the newest compatible GitHub Actions major versions, current
Homebrew LLVM/Ruff/BasedPyright and Python 3.15. It refreshes the Clang-Tidy
compilation database for the hosted checkout and uses the project's pinned
MacKernelSDK compatibility headers. That SDK is not a verified exact Tahoe
KDK, and a successful static check cannot establish native ABI correctness.
The strict validator does not support `--linux` or treat missing Apple
headers as successes. Build artifacts are unsigned and are not installed.

This setup does **not** itself authorize or create any tag, run a CI job,
compile the kext locally, or begin physical testing. Release-build tags and
all EFI/OpenCore/USB/SSD or PCI/RF work require separate explicit owner
approval. A successful build does not prove the driver provides working
Wi-Fi or AirPort on the target machine.

## License and attribution

New authored SimpleATH source is AGPL-3.0-only. Referenced Linux
ath9k source and imported tables retain their original permissive
file-specific license notices; historical SimpleBCM reference
material retains its original attribution. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
