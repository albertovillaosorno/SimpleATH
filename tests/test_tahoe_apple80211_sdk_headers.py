# Copyright (c) 2026 SimpleATH contributors.
"""Regress the 2026-11-10 missing Apple80211 private-header build failure.

Native Tahoe SDK 26.5 does not supply IOKit/80211/apple80211_var.h or
apple80211_ioctl.h. This test validates the absence of such includes and
compiles the repository-owned fixed payload adapter as freestanding C++.
"""

from pathlib import Path
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src"
ADAPTER = SOURCE / "platform/tahoe/TahoeApple80211Values.hpp"
PRIVATE_INCLUDE_PREFIX = r'(?m)^\s*#\s*(?:include|import)\s*[<"]IOKit/80211/'
PRIVATE_HEADER = re.compile(
    PRIVATE_INCLUDE_PREFIX + r'apple80211_(?:var|ioctl)\.h[>"]'
)


class Apple80211PrivateSdkHeaderRegression(unittest.TestCase):
    """Keep Xcode kernel sources independent of omitted private headers."""

    @staticmethod
    def test_native_target_never_imports_private_apple80211_headers() -> None:
        """Reproduce the exact unavailable-header failure as a source gate."""
        names = {".c", ".cpp", ".h", ".hpp", ".mm"}
        for path in SOURCE.rglob("*"):
            if path.suffix not in names or not path.is_file():
                continue
            source = path.read_text(encoding="utf-8")
            assert PRIVATE_HEADER.search(source) is None, (
                f"Unavailable Apple80211 private SDK header in {path}"
            )

    @staticmethod
    def test_local_value_adapter_compiles_without_apple_private_sdk() -> None:
        """Compile native value envelopes using only Clang C headers."""
        clang = shutil.which("clang++")
        assert clang is not None, "Clang C++ compiler is required"
        resource = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
            [clang, "-print-resource-dir"],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=20,
        )
        assert resource.returncode == 0, resource.stderr
        builtin = Path(resource.stdout.strip()) / "include"
        assert (builtin / "stdint.h").is_file()
        source = '#include "platform/tahoe/TahoeApple80211Values.hpp"\n'
        command = [
            clang,
            "-std=c++14",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            "-nostdinc",
            "-isystem",
            str(builtin),
            "-I",
            str(SOURCE),
            "-fsyntax-only",
            "-x",
            "c++",
            "-",
        ]
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
            command,
            input=source,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=20,
        )
        assert ADAPTER.is_file()
        assert result.returncode == 0, result.stderr


if __name__ == "__main__":
    _ = unittest.main()
