# Copyright (c) 2026 SimpleATH contributors.
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


def _native_macos_flags() -> list[str]:
    """Use only Apple SDK headers when analyzing macOS kernel sources.

    Returns:
        Native parse flags, never a downloaded research SDK path.

    """
    sdk = os.environ.get("SDKROOT")
    if not sdk:
        return ["-DKERNEL=1"]
    kernel = Path(sdk) / "System/Library/Frameworks/Kernel.framework/Headers"
    return ["-DKERNEL=1", "-isysroot", sdk, "-isystem", str(kernel)]


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
                flags.extend(("-isystem", str(library)))
                flags.extend(("-isystem", str(sites[0].parent)))
    flags.extend(("-isystem", str(headers)))
    return flags


def _kernel_parse_flags(root: Path) -> list[str]:
    """Select native Apple or Linux-only research parse inputs.

    Returns:
        Clang-Tidy parse flags for the current host platform.

    """
    if sys.platform == DARWIN_PLATFORM:
        return _native_macos_flags()
    return _reference_parse_flags(root)


class CompileCommand(TypedDict):
    """One explicitly scoped Clang compilation database entry."""

    directory: str
    file: str
    arguments: list[str]


def source_commands(root: Path) -> list[CompileCommand]:
    """Enumerate source, fixture and tool translation units without binaries.

    Returns:
        Stable absolute-root Clang parse commands for existing source files.

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
            "directory": str(root),
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
    """Refresh absolute checkout paths after moving or cloning the source."""
    _ = write_database(Path(__file__).resolve().parent.parent)


if __name__ == "__main__":
    main()
