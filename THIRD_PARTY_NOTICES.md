# Third-party notices

The following are the only two external source projects used as references.
They are not relicensed by this file or by the SimpleATH AGPL-3.0 license.

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

SimpleATH's newly authored glue and diagnostic code is AGPL-3.0-only.
