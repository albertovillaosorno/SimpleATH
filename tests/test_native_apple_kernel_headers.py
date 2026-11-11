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
#   - Offline regression cases for native apple kernel headers.
# - Must-Not:
#   - Require physical hardware, mutate installed drivers, or suppress failures.
# - Allows:
#   - Inputs: isolated fixtures and reproducible source-under-test inputs.
#   - Outputs: assertions and observable regression verdicts.
#   - Side effects: test-local temporary files and bounded subprocesses only.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Offline regression cases for native apple kernel headers.
# - Description:
#   - Implements or verifies the test_native_apple_kernel_headers source
#     boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for native apple kernel headers.
"""Prevent accidentally mixing macOS userspace and XNU header variants."""

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import tempfile
import unittest

from tools.native_apple_kernel_headers import KERNEL_HEADERS
from tools.native_apple_kernel_headers import native_kernel_syntax_command

CLANG = "clang++"
ISYSTEM_FLAG = "-isystem"
NOSTDINC_FLAG = "-nostdinc"
RESEARCH_MARKER = ".references/"
EXPECTED_HEADER_CONFLICT = "conflicting types for 'ffs'"


def _write(path: Path, content: str) -> None:
    """Create a host-only synthetic SDK header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")


class NativeAppleKernelHeaderIsolation(unittest.TestCase):
    """The real macOS SDK probe must not prefer userspace sys headers."""

    @staticmethod
    def test_kernel_include_root_precedes_user_include_root() -> None:
        """Order real sys/cdefs and libkern before SDK usr/include."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "MacOSX.sdk"
            kernel = sdk / KERNEL_HEADERS
            userspace = sdk / "usr/include"
            resource = root / "clang"
            builtin = resource / "include"
            source = root / "src"
            _write(kernel / "IOKit/network/IONetworkController.h", "// native")
            _write(builtin / "stddef.h", "// compiler")
            _write(builtin / "stdint.h", "// compiler")
            userspace.mkdir(parents=True)
            source.mkdir()
            flags = native_kernel_syntax_command(sdk, resource, source)
            include_roots = [
                flags[i + 1]
                for i, item in enumerate(flags)
                if item == ISYSTEM_FLAG
            ]
            assert include_roots == [str(builtin), str(kernel), str(userspace)]
            assert NOSTDINC_FLAG in flags
            assert flags[-4:] == ["-fsyntax-only", "-x", "c++", "-"]
            assert RESEARCH_MARKER not in " ".join(flags)

    @staticmethod
    def test_reversed_header_order_reproduces_ffs_collision() -> None:
        """A synthetic native-vs-userland declaration collision must fail."""
        compiler = shutil.which(CLANG)
        assert compiler is not None, "Clang compiler is required"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel = root / "Kernel.framework/Headers"
            userspace = root / "usr/include"
            _write(kernel / "sys/cdefs.h", "#define USING_XNU_CDEFS 1\n")
            _write(userspace / "sys/cdefs.h", "#define USING_USER_CDEFS 1\n")
            _write(
                kernel / "libkern/libkern.h",
                """\
#include <sys/cdefs.h>
extern "C" int ffs(unsigned int);
""",
            )
            _write(
                userspace / "_strings.h",
                'extern "C" int ffs(int);\n',
            )
            source = """\
#include <libkern/libkern.h>
#ifdef USING_USER_CDEFS
#include <_strings.h>
#endif
"""
            options = [
                compiler,
                "-std=c++14",
                "-nostdinc",
                "-fsyntax-only",
                "-x",
                "c++",
                "-",
            ]
            good = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
                [
                    *options[:-4],
                    "-isystem",
                    str(kernel),
                    "-isystem",
                    str(userspace),
                    *options[-4:],
                ],
                input=source,
                capture_output=True,
                check=False,
                text=True,
                shell=False,
                timeout=20,
            )
            assert good.returncode == 0, good.stderr
            bad = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
                [
                    *options[:-4],
                    "-isystem",
                    str(userspace),
                    "-isystem",
                    str(kernel),
                    *options[-4:],
                ],
                input=source,
                capture_output=True,
                check=False,
                text=True,
                shell=False,
                timeout=20,
            )
            assert bad.returncode != 0
            assert EXPECTED_HEADER_CONFLICT in bad.stderr

    @staticmethod
    def test_missing_native_sdk_fails_closed() -> None:
        """Never silently substitute downloaded or userspace-only headers."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rejected = False
            try:
                _ = native_kernel_syntax_command(
                    root / "missing-sdk", root / "compiler", root
                )
            except FileNotFoundError:
                rejected = True
            assert rejected, "Missing Apple SDK headers were accepted"
