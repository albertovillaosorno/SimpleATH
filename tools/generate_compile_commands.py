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
#   - Host-side tooling for generate compile commands.
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
#   - Host-side tooling for generate compile commands.
# - Description:
#   - Implements or verifies the generate_compile_commands source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for generate compile commands.
"""Write host-only Clang-Tidy parse commands without compiling a kext.

These commands are source-analysis fixtures, not captured Xcode build actions.
Native macOS analysis uses Apple headers. Linux may use optional downloaded
research headers without claiming Tahoe ABI verification.
"""

import json
import os
from pathlib import Path
import shutil
import sys
from typing import TypedDict

OBJCXX_SUFFIX = ".mm"
CXX_LANGUAGE = "c++"
DARWIN_TARGET = "x86_64-apple-macosx14.0"
DARWIN_PLATFORM = "darwin"
TAHOE_IOCTL_SOURCES = (
    "src/platform/tahoe/SimpleATHTahoeController.cpp",
    "src/platform/tahoe/SimpleATHInfraProtocol.cpp",
)


def _host_alias(root: Path, name: str, destination: Path) -> str:
    """Map host-only SDK directories via untracked checkout-relative links.

    No absolute home, SDK or toolchain paths are written into Git.
    """
    relative = Path(".cache/clang-tidy") / name
    alias = root / relative
    alias.parent.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve()
    if alias.is_symlink() and alias.resolve() != destination:
        alias.unlink()
    if alias.exists() and not alias.is_symlink():
        message = f"Host SDK alias is not a symlink: {relative}"
        raise ValueError(message)
    if not alias.is_symlink():
        alias.symlink_to(destination, target_is_directory=True)
    return relative.as_posix()


def _native_macos_flags(root: Path) -> list[str]:
    """Use only Apple SDK headers when analyzing macOS kernel sources.

    Returns:
        Native parse flags, never a downloaded research SDK path.

    """
    sdk = os.environ.get("SDKROOT")
    if not sdk:
        return ["-DKERNEL=1"]
    alias = _host_alias(root, "sdkroot", Path(sdk))
    return [
        "-DKERNEL=1",
        "-isysroot",
        alias,
        "-isystem",
        f"{alias}/System/Library/Frameworks/Kernel.framework/Headers",
    ]


def _reference_parse_flags(root: Path) -> list[str]:
    """Use optional Linux-host research headers without building a kext.

    Returns:
        Source-only Linux cross-parse flags when references are available.

    """
    headers = root / ".references/MacKernelSDK/Headers"
    if not (headers / "IOKit/IOLib.h").is_file():
        return []
    flags: list[str] = ["-DKERNEL=1"]
    if sys.platform.startswith("linux"):
        flags.extend(("-target", DARWIN_TARGET))
        compiler = shutil.which("clang++")
        if compiler is not None:
            toolchain = Path(compiler).resolve().parent.parent / "include"
            library = toolchain / "c++/v1"
            sites = sorted(toolchain.glob("*/c++/v1/__config_site"))
            if library.is_dir() and len(sites) == 1:
                flags.extend(("-isystem", _host_alias(root, "libcxx", library)))
                flags.extend((
                    "-isystem",
                    _host_alias(root, "libcxx-site", sites[0].parent),
                ))
    flags.extend(("-isystem", ".references/MacKernelSDK/Headers"))
    return flags


def _kernel_parse_flags(root: Path) -> list[str]:
    """Select native Apple or Linux-only research parse inputs.

    Returns:
        Clang-Tidy parse flags for the current host platform.

    """
    if sys.platform == DARWIN_PLATFORM:
        return _native_macos_flags(root)
    return _reference_parse_flags(root)


class CompileCommand(TypedDict):
    """One explicitly scoped Clang compilation database entry."""

    directory: str
    file: str
    arguments: list[str]


def source_commands(root: Path) -> list[CompileCommand]:
    """Enumerate source, fixture and tool translation units without binaries.

    Returns:
        Stable checkout-relative Clang parse commands for existing source files.

    """
    root = root.resolve()
    found: list[Path] = []
    for folder in ("src", "tests", "tools"):
        for suffix in ("*.cpp", "*.mm"):
            found.extend(
                path
                for path in (root / folder).rglob(suffix)
                if path.is_file() and not path.is_symlink()
            )
    result: list[CompileCommand] = []
    kernel_flags = _kernel_parse_flags(root)
    for path in sorted(found):
        relative = path.relative_to(root).as_posix()
        standard = (
            "c++17" if relative.startswith(("tests/", "tools/")) else "c++14"
        )
        language = (
            "objective-c++" if path.suffix == OBJCXX_SUFFIX else CXX_LANGUAGE
        )
        result.append({
            "directory": ".",  # Repository root; portable across checkouts.
            "file": relative,
            "arguments": [
                "clang++",
                f"-std={standard}",
                "-I",
                "src",
                *(
                    kernel_flags
                    if relative.startswith("src/") and language == CXX_LANGUAGE
                    else ()
                ),
                *(
                    ("-D__IO80211_TARGET=10",)
                    if relative in TAHOE_IOCTL_SOURCES
                    else ()
                ),
                "-x",
                language,
                "-fsyntax-only",
                relative,
            ],
        })
    return result


def write_database(root: Path) -> Path:
    """Replace only the local source-analysis compilation database.

    Returns:
        The written compilation database path for this checkout.

    """
    resolved = root.resolve()
    destination = resolved / "compile_commands.json"
    payload = json.dumps(source_commands(resolved), indent=2) + "\n"
    _ = destination.write_text(payload, encoding="utf-8")
    return destination


def main() -> None:
    """Write portable relative paths; host SDK aliases stay ignored."""
    _ = write_database(Path(__file__).resolve().parent.parent)


if __name__ == "__main__":
    main()
