# Third-party notices

The following external projects supply retained references or attributed source.
They are not relicensed by this file or by the SimpleATH GPL-2.0 license.

## Linux kernel (ath9k, mac80211, cfg80211, PCI and Bluetooth)

Source: https://github.com/torvalds/linux

Copyright belongs to the respective Linux kernel contributors.
The Linux kernel is provided under GPL-2.0-only with the Linux syscall
exception where applicable; individual source files have their own SPDX
identifiers and may carry different or dual licenses. The project retains
original source-level notices. The `linux/` directory is reference material;
Linux kernel modules cannot be directly linked into the macOS kext.

## SimpleBCM

Source: https://github.com/laobamac/SimpleBCM

Copyright (c) 2026 laobamac. All rights reserved in the original upstream
copyright notices and source material. The prior loader architecture and ABI
references informed this research, but the current stage-one SimpleATH kext
contains no embedded SimpleBCM payload or Broadcom runtime.

SimpleATH's newly authored glue and diagnostic code is GPL-2.0-only.


## AirPort_RTW89

Source: https://github.com/FranciumOS-org/AirPort_RTW89
Reviewed revision: `90b6cfc5a69c271688fad188857cfaeb58053dc5` (2026-11-10).

The project's own frontend, native glue and compatibility implementations
carry `SPDX-License-Identifier: GPL-2.0`. Its Linux rtw89 files are
GPL-2.0 OR BSD-3-Clause; vendored hostap is BSD-3-Clause, and Mbed TLS has
its own Apache-2.0 OR GPL-2.0-or-later terms. Copyright remains with each
upstream author. Preserve upstream headers and license texts for any copied
or adapted implementation, and identify the destination scope here.

Current use: source-level comparison of native scan/join ownership, lifecycle,
EAPOL routing and the split between hardware owner and AirPort frontend.
No RTW89 source body or firmware is currently redistributed in SimpleATH.
The restored IO80211FamilyLegacy backend is not substituted for the exact
25G332 modern IO80211/InfraProtocol target. Its README does not claim working
AirDrop/AWDL/Continuity.

## AirportMtkWlan / OpenIntelWireless-derived native architecture

Source: https://github.com/Arxusion/AirportMtkWlan
Reviewed revision: `37aa87eecf9fd2246c0f4ef9879416afa396a105`.

GPLv2 upstream material was consulted for the modern InfraProtocol/WCL
architecture and request/event behavior. No upstream implementation bodies,
private headers or Apple binaries are redistributed. SimpleATH's native
class declarations and factory imports are independently checked against
the matching KDK. Upstream copyrights and licenses are unchanged.

## NullMoth NVIDIA driver for macOS

Source: https://github.com/nullmoth/nvidia-macos-driver
Reviewed revision: `7412cdde81447f78da0ebb64216dc258d8beaedb` (2026-11-10).

The repository's kernel extensions, plugin, build and package code use
PolyForm Noncommercial 1.0.0, Copyright (c) 2026 NullMoth Systems
(https://nullmothsystems.com). The translator and Mesa changes have separate
licenses described upstream. Its noncommercial restriction is not replaced
by SimpleATH's GPL-2.0-only license. Current use is architectural research
only; no NullMoth code, firmware, binaries or headers are redistributed.
