<!--
  Native-Universal.md
  SimpleATH

  Based on the original SimpleBCM native ABI documentation by laobamac.
  Copyright (c) 2026 laobamac. All rights reserved.
-->

# Native Skywalk adaptation

**Implementation status:** This document explains the original SimpleBCM Broadcom compatibility architecture retained as a reference for a future Atheros backend. None of the legacy payload mapping, native Skywalk bridge, or Broadcom control-plane forwarding described below is linked into the current minimal SimpleATH bootstrap.

In the upstream implementation, SimpleBCM selects a compatibility profile by the Darwin major version rather than restricting loading by minor version, build number, or UUID. Before loading a payload, it verifies the native class sizes and virtual-method layouts it actually needs. The source distribution includes three payload variants: Legacy, original AirPort, and Tahoe AirPort. A boot maps and registers only Legacy and the AirPort version selected for the running OS. The old IOSkywalkFamily is used solely as an offline ABI reference and is not embedded in the driver.

## Build references

| System | Build | IOSkywalkFamily UUID | IO80211Family UUID |
| --- | --- | --- | --- |
| Sonoma 14.8.8 | 23J620 | 9F5908B5-BA4B-37E3-AC31-62E1D45F1589 | EC4BA672-6E08-3AD2-B882-01690A960FF4 |
| Sequoia 15.8 | 24H23 | 70DFAA8E-E369-3417-B6FD-B19FB6D5D49B | 13D3592A-A6BE-35E7-984C-0ACD90A76356 |
| Tahoe 26.7.2 | 25G332 | A6EDB8DB-175B-3A49-8919-5769FCDB6BED | 4C2B4969-2B92-3646-9512-C1769BE0F9A4 |

These versions and UUIDs pin build references; they are **not** a runtime allowlist. `Resources/NativeABI` contains symbols, virtual tables, and required instruction fragments extracted from these systems and read after SHA-256 verification. Reference definitions are in `Tools/system_profiles.py`; the generators are `Tools/native_abi.py`, `Tools/native_payload.py`, and `Tools/embed.py`. At runtime, the full upstream adapter checks the metaclasses and symbol addresses for 15 native classes and interfaces, as well as the packet-pool and user-client virtual-table layouts.

## Object layout and call forwarding

| Native layout property | Sonoma | Sequoia | Tahoe |
| --- | ---: | ---: | ---: |
| IOSkywalkNetworkInterface size | 208 | 208 | 224 |
| IOSkywalkEthernetInterface size | 272 | 272 | 288 |
| Ethernet extension pointer offset | 264 | 264 | 280 |
| Ethernet virtual-table slot count | 353 | 352 | 353 |
| IOSkywalkPacketBufferPool size | 184 | 184 | 192 |
| IOSkywalkNetworkBSDClient size | 328 | 328 | 336 |
| IO80211API/AsyncEventUserClient size | 224 | 224 | 224 |

Legacy stores the controller at `this+0x118`, whereas the native Tahoe Ethernet superclass stores an extension pointer at that same location. `NativeSkywalk.cpp` preserves the old layout with a 272-byte `BCMLegacyInterface` and separately constructs a native Ethernet object. Native derived objects are allocated with 296 bytes, storing context at offset 288. Method forwarding switches the receiver object and temporarily retains the legacy object while callbacks execute.

Interface callbacks are generated from the complete virtual table for each OS. On Sonoma, the logical-link registration entry is found through the native Ethernet virtual table. On Sequoia and Tahoe, the loader pattern-matches a registration wrapper within the native code segment and checks the Ethernet deregistration entry it calls. The signature must match uniquely, tolerating relocated addresses without fixed function offsets.

Packets and queues use native Skywalk objects without introducing per-packet adapter objects or extra packet-data copies. Packet virtual calls and constructor virtual tables account for additional slots. Packet-pool allocation, metaclass sizes, and release behavior are selected by system profile: Sonoma and Sequoia use `Pool::release`; Tahoe uses `OSObject::release` and `Pool::taggedRelease`. `TxSubmission` uses the callback overload with a constant packet array, preserves the original flags, and passes `UINT32_MAX` for the newly added argument.

## Class names and control interfaces

Conflicting Legacy and native IO80211Family metaclass names are rewritten in payload C strings without changing the allocated string lengths or C++ symbol resolution. The old controller registers under `AirPortDriver` so that SystemConfiguration classifies it as a wireless controller.

`NativeUserClient.cpp` uses native API/AsyncEvent user-client constructors and metaclasses, forwarding instance methods to `BCM80211UserClient`. System processes continue receiving native user-client types, and privilege checks remain with the original control implementation. `WirelessABI.hpp` handles differences among the three OS versions in selectors, association structures, scan results, and event formats.

## Power management and payloads

The native IOSkywalkNetworkBSDClient power parent is attached to the wireless controller's actual IOPCIDevice provider via `joinPMtree`. The network IOService provider relationship remains unchanged. Interface context retains the PCI provider and releases it when startup fails or the interface stops. The original AirPort power table is not rewritten.

The original payloads are pinned to specific commits and SHA-256 checksums by `Tools/bootstrap.py`. The two AirPort variants share one base payload and identical relocation, symbol, and entry tables. Tahoe-specific differences are stored as offsets, lengths, and replacement bytes. At startup, the driver restores those bytes only within the selected payload's separate mapping; it checks diff boundaries before writing and verifies the complete payload before relocating it. The base payload stays read-only and adds no processing to the transmit or receive path.

Generation modifies only mapping copies in the build directory. Runtime modifications are limited to owned payload memory and instance virtual tables. The original `Tools/build.py` verifies payload reconstruction, native exports, inherited virtual tables, relocations, forwarding calling conventions, and control-plane codecs; see [Build.md](Build.md) for its build environment.

**For SimpleATH:** these Broadcom-oriented mechanisms are design references only. Implementing a real AR9565 driver requires hardware-specific PCI probing, initialization, firmware/register handling, and a validated native wireless data/control interface. Simply renaming the Broadcom classes or matching `pci168c,36` is not sufficient.
