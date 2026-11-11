# SimpleATH

**Experimental native wireless driver project for Qualcomm Atheros AR9565 /
QCA9565 (PCI `168c:0036`) on Intel macOS Tahoe.**

SimpleATH explores native PCIe Wi-Fi, USB Bluetooth, BLE and Apple peer-to-peer
wireless integration, without substituting an Ethernet device for AirPort.
The repository includes driver code, generated hardware tables, ABI research,
offline tests and development utilities.

> **Development status:** Not a verified working Wi-Fi/Bluetooth/AirDrop driver.
> Portable host tests and source-level checks do not establish kernel boot,
> hardware transmit/receive, association, AirPort, BLE or AirDrop functionality.
> The current source has not been validated as a new device-tested kext release.

## Scope and compatibility


- **Area:** WLAN hardware
  - **Target:** Qualcomm Atheros AR9565 / QCA9565, PCI `168c:0036`
  - **Current evidence:** Hardware/PHY, MAC, DMA and NVM source; offline
    coverage

- **Area:** Operating system
  - **Target:** Intel `x86_64` macOS Tahoe
  - **Current evidence:** Native ABI research; exact-build compatibility
    unverified

- **Area:** Bluetooth
  - **Target:** AR3012-family USB HCI and firmware
  - **Current evidence:** Firmware resources and host-side control code;
    attachment unverified

- **Area:** Apple integration
  - **Target:** Native AirPort, BLE and AWDL/AirDrop paths
  - **Current evidence:** Integration source exists; full end-to-end operation
    unverified


A chipset match alone does not establish compatibility with a particular
computer, macOS build, kernel collection or firmware configuration.

## Repository layout

- `src/` — C++ driver, platform adapters, radios, protocol modules and Xcode
  project.
- `tools/` — source verification, native ABI inspection, generation and build
  utilities.
- `tests/` — Python and portable native regression tests.
- `docs/` — architecture, research, evidence and outstanding development work.
- `src/firmware/` — independently licensed Atheros/Qualcomm Bluetooth binaries
and
  manifests.
- `docs/provenance/files.json` — file-level copyright, license and
source-of-origin
  inventory.

## Getting started

Clone the repository and review its design documentation before changing code:

```sh
git clone https://github.com/albertovillaosorno/SimpleATH.git
cd SimpleATH
python3 -B -m unittest discover -s tests -p 'test_*.py'
python3 -B tools/public_contract.py all
```

The Python regression suite is primarily offline. Some tests or native checks
require platform-specific development tools. For strict source validation on a
configured macOS runner:

```sh
python3 -B tools/generate_compile_commands.py
python3 -B tools/validate.py --no-cache
```

See [build documentation](docs/Build.md) for the current Xcode, CI, macOS SDK
and dependency requirements. **Do not interpret an offline check or build
artifact as evidence of safe boot or functioning radio hardware.** Manual
kernel installation and device testing require a suitable recovery plan.

## Development and verification

The [roadmap](TODO.md) and [design records](docs/design/) distinguish source
implementations, measured evidence and known unknowns. Report failures with
reproducible steps, macOS build information, toolchain version and sanitized
logs. Do not include device identifiers, personal paths, credentials, keys,
full memory dumps or other sensitive diagnostics in public issues.

The project uses structured commit subjects, a signed-off author trailer,
file-level provenance, and `Boundary-Contract` source headers. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License and third-party attribution

Original SimpleATH material **owned by Alberto Villa Osorno** is offered under
**MIT only**. MIT code may be incorporated into GPL-2.0 projects subject to
the GPL terms of that combined distribution. This MIT grant does **not** apply
to all files.
Certain inherited SimpleBCM files lack a verified upstream license grant and
are explicitly marked `LicenseRef-SimpleBCM-All-Rights-Reserved`; they are not
represented as MIT code.
Atheros-derived code, Bluetooth firmware and other upstream components retain
their individual terms. Consult [LICENSE-MIT](LICENSE-MIT),
[LICENSE-GPL](LICENSE-GPL), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
and the [file provenance inventory](docs/provenance/files.json) before reuse.

**Not affiliated with or endorsed by Apple, Qualcomm, Atheros or Dell.**
