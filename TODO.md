# SimpleATH — ten-agent execution roadmap

**Target:** Qualcomm Atheros AR9565/QCA9565 (PCI 168c:0036),
Dell Inspiron 5567, macOS Tahoe 26.7.2 build 25G332 (Intel).
**Current reality:** an experimental, bootable passive probe and
unvalidated source modules. Wi-Fi, Bluetooth and AirDrop are NOT yet
verified working from SimpleATH. Completion means real hardware evidence,
not merely compilation or an IORegistry property.

Ten agents may work in parallel ONLY in separate worktrees/branches.
See AGENTS.md for the exclusive file ownership matrix. The integration
owner merges work in dependency order and resolves changes to shared
files. Mark boxes only against real evidence; provide PR, source hash,
dependency assumptions and acceptance outcome.

**Owner authorization still pending:** no new kext compilation, test
suite, CI, build-v* tag, EFI/USB/SSD changes, RF or hardware experiments.
Local tooling changes never authorize the above.

## Workstreams to dispatch (one per agent)

- [ ] **A1 / Tahoe ABI:** complete exact-target dependency graph:
  IOPCIFamily, IO80211Family/Legacy, IOSkywalkFamily, networking and
  kernel KPI exports, vtable layouts and Apple80211 selectors. Review
  25G332 KDK; old missing-symbol names are now recorded in PCI exports.
  Document what still requires runtime and import verification.

- [ ] **A2 / PCI owner:** complete a separately gated native IOPCIDevice
  adapter for real PCI identity, exclusive open/close, D0, mapped BAR0,
  strictly ordered MMIO, PCI command save/restore and rollback. Preserve
  passive V1, require ABI verification before linking new imports.

- [ ] **A3 / NVM:** complete safe EEPROM/OTP word acquisition, revision
  and dictionary selection, block checksum, real MAC, antenna diversity,
  calibration validity and regulatory domain. Reject corrupt data and
  OpenCore-spoofed identity; no guessed physical reads or board defaults.

- [ ] **A4 / PHY and regulatory:** implement revision-correct RF reset,
  PLL/channel setup, radio sleep/wake, noise/ANI, gain tables,
  temperature calibration, RF-kill, BT coexistence and constrained
  TX power. Never enable TX before verified board and country limits.

- [ ] **A5 / EDMA and interrupts:** integrate real 32-bit-safe
  IOMMU/DMA mappings, AR9003 descriptor queues, TX/RX completion,
  interrupts, serialization, error recovery, drain and memory lifetime.
  Portable descriptor codecs alone do not move packets.

- [ ] **A6 / MAC scanning and association:** complete channel dwell,
  beacon/probe caching, accurate RSN/rates/capabilities, snapshot
  iteration for macOS, authentication, association, retries,
  regulatory channel selection and real state transitions.

- [ ] **A7 / WPA2 and CCMP:** review PBKDF2/HMAC/PTK/AES primitives,
  implement secure OS entropy integration, WPA2 MIC and four-way
  handshake, actual hardware PTK/GTK keycache, group rekey, CCMP
  packet numbers and replay enforcement. Future vector tests need
  separate owner authorization and must not be reported as executed.

- [ ] **A8 / native AirPort interface:** implement correct IO80211
  controller/interface, Apple80211 scanning, connect/disconnect,
  RSSI/noise, WLAN power, BSD packet ownership, genuine Wi-Fi menu
  and Tahoe service events. Research independent restored
  IO80211FamilyLegacy precedent without copying Realtek source or
  assuming its ABI is the Dell's. Do not pass off Ethernet as AirPort.

- [ ] **A9 / end-to-end integration:** connect PCI, calibrated RF,
  EDMA, MAC, WPA2, DataPath and WifiEngine to native TX/RX,
  IP packet delivery, timing, recovery, power transitions and sleep.
  Complete fail-closed unwind from every failure. No fake success flags.

- [ ] **A10 / project coordination:** preserve locally configured
  Clang, Ruff, Pyright and EditorConfig rules without downloads;
  maintain ten isolated agent branches, source provenance, CI/build
  permission gates, release readiness, TODO tracking, ownership
  and GitHub metadata. Treat Jig as deferred until a version can
  enforce code quality **without mandatory hexagonal structure**.
  Do not rewrite the Atheros driver into Jig's forced paths.

## Separate future release gates (all unchecked)

- [ ] Owner explicitly approves compiling ONE named source revision on
  Intel macOS/Xcode. Only then build, inspect relocations/imports,
  Info.plist, binary hash and exact compatibility. No CI/tag by default.
- [ ] Owner separately approves offline tests and cryptographic vectors.
  Never mark tested on source/static review alone.
- [ ] Owner separately approves installing ONE reviewed binary/hash
  on a disposable EFI. Preserve the boot-proven 13-kext recovery,
  all backups and the untouched SSD.
- [ ] Owner separately approves staged hardware checks on the Dell:
  injection, exclusive PCI, EEPROM read, RX scan, legal/calibrated
  radio TX, WPA2 and network IP, sleep/reconnect, Bluetooth coexistence.
  A successful boot or kext injection is NOT proof of Wi-Fi.

## FINAL TODO — owner-authorized on-device acceptance, LAST ITEM

- [ ] **Demonstrate stable, fully working Wi-Fi, Bluetooth and AirDrop
  on the Dell under macOS Tahoe.** Measure actual native Wi-Fi scans,
  WPA2-PSK association/key rekey, encrypted traffic, DHCP, DNS,
  TCP/UDP, sustained throughput, packet loss, reconnect, RF power,
  stability, kernel logs and sleep/wake across repeated sessions.
  Identify and separately test the Dell's physical **Bluetooth**
  chipset: pairing, peripherals/audio, reconnection, coexistence
  and sleep. Then demonstrate genuine **AirDrop** discovery and
  transfers BOTH ways with a compatible Apple device, including
  permissions, Handoff/Continuity and Wi-Fi/Bluetooth interaction.
  AirDrop is conditional on hardware and macOS Continuity support;
  an AR9565 Wi-Fi driver alone cannot guarantee it. Record exact
  devices, versions, evidence, issues and safe rollback. This box
  stays unchecked until these real tests pass with explicit owner
  permission. If a hardware feature is unsupported, report the
  limitation rather than claiming 100% completion.
