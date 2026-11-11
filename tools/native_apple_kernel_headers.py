# Copyright:
#   - Copyright © 2026 Alberto Villa Osorno
# SPDX-License-Identifier:
#   - MIT
# Confidential:
#   - false
# License-File:
#   - LICENSE-MIT
# Provenance:
#   - SimpleATH original; independently developed or locally authored
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for native apple kernel headers.
# - Must-Not:
#   - Read unrelated user files, hide failures, or bypass explicit tool inputs.
# - Allows:
#   - Inputs: explicit command-line, repository, or fixture inputs.
#   - Outputs: deterministic reports, generated artifacts, or error codes.
#   - Side effects: bounded local source-analysis or developer-command activity.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Host-side tooling for native apple kernel headers.
# - Description:
#   - Implements or verifies the native_apple_kernel_headers source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for native apple kernel headers.
"""Construct freestanding Tahoe syntax probes from native Apple SDK paths.

Keep Kernel.framework system declarations before macOS userspace headers.
The 2026-11-10 probe failure had _strings.h's userspace ffs/fls and
MacTypes.h's Debugger competing with native libkern/IOKit declarations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

KERNEL_HEADERS = "System/Library/Frameworks/Kernel.framework/Headers"
USER_HEADERS = "usr/include"
BUILTIN_HEADERS = "include"
IOKIT_HEADER = "IOKit/network/IONetworkController.h"
CLANG_CXX = "clang++"


def native_kernel_syntax_command(
    sdk: Path, resource: Path, sources: Path
) -> list[str]:
    """Build one syntax-only command; never link a kernel extension.

    Args:
        sdk: Absolute directory returned by xcrun --show-sdk-path.
        resource: Directory returned by xcrun clang++ -print-resource-dir.
        sources: Repository src directory containing Tahoe declarations.

    Returns:
        Clang invocation that resolves XNU headers before macOS userspace.

    Raises:
        FileNotFoundError: An Apple or Clang native header is absent.

    """
    sdk = sdk.resolve()
    resource = resource.resolve()
    sources = sources.resolve()
    kernel = sdk / KERNEL_HEADERS
    userspace = sdk / USER_HEADERS
    builtin = resource / BUILTIN_HEADERS
    for path in (
        kernel / IOKIT_HEADER,
        userspace,
        builtin / "stddef.h",
        builtin / "stdint.h",
    ):
        if not path.exists():
            msg = f"Missing native Apple/Clang SDK input: {path}"
            raise FileNotFoundError(msg)
    return [
        "xcrun",
        CLANG_CXX,
        "-std=c++14",
        "-target",
        "x86_64-apple-macos14.0",
        "-mkernel",
        "-DKERNEL=1",
        "-D__IO80211_TARGET=10",
        "-fno-rtti",
        "-fno-exceptions",
        "-fno-builtin",
        "-nostdinc",
        "-isysroot",
        str(sdk),
        "-I",
        str(sources),
        "-isystem",
        str(builtin),
        # Preserve this order. Kernel sys/cdefs.h must be chosen before
        # userspace sys/cdefs.h or native libkern and IOKit cannot coexist.
        "-isystem",
        str(kernel),
        "-isystem",
        str(userspace),
        "-fsyntax-only",
        "-x",
        "c++",
        "-",
    ]
