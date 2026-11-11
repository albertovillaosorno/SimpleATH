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
#   - Offline regression cases for kernel headers.
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
#   - Offline regression cases for kernel headers.
# - Description:
#   - Implements or verifies the test_kernel_headers source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for kernel headers.
"""Prevent libc++ headers and namespace APIs from leaking into the kext."""

from pathlib import Path
import re
import shutil

# Reviewed boundary: isolated compiler syntax checks, never kernel linking.
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "src"
PLACEMENT_HEADER = SOURCES / "platform/KernelPlacementNew.hpp"
FORBIDDEN_CXX_HEADERS = frozenset({
    "cstddef",
    "cstdint",
    "cstring",
    "iterator",
    "new",
    "memory",
    "string",
    "vector",
    "algorithm",
    "array",
    "type_traits",
    "utility",
    "unordered_map",
    "map",
    "set",
    "list",
    "functional",
    "optional",
})
INCLUDE = re.compile(r"^\s*#\s*include\s*<([^>]+)>")
ACTIVE_STD = re.compile(r"\bstd::[a-zA-Z_]")
HOST_PLACEMENT_HEADER = "new"
NATIVE_STD_NEXT = "std::next"
POWER_SOURCE_UNITS = (
    "hardware/Ar9565Power.cpp",
    "hardware/Ar9565Eeprom.cpp",
    "hardware/Ar9565Core.cpp",
    "hardware/Ar9565InitCatalog.cpp",
)
FREESTANDING_CXX_STANDARDS = ("c++14", "c++17")


def _check_native_includes(path: Path) -> None:
    """Reject hosted C++ headers and namespaces in one native file."""
    content = path.read_text(encoding="utf-8")
    for number, line in enumerate(content.splitlines(), 1):
        match = INCLUDE.match(line)
        if match and match.group(1) in FORBIDDEN_CXX_HEADERS:
            # The sole host fallback is preprocessor-excluded from kernel.
            assert path == PLACEMENT_HEADER, f"{path}:{number}: libc++"
            assert match.group(1) == HOST_PLACEMENT_HEADER
        if line.lstrip().startswith("//"):
            continue
        assert ACTIVE_STD.search(line) is None, (
            f"{path}:{number}: std:: API in native target"
        )


class KernelHeaderPolicy(unittest.TestCase):
    """Every native compilation unit must use XNU/compiler headers only."""

    @staticmethod
    def test_native_sources_have_no_libcxx_dependency() -> None:
        """Use C/XNU primitive types instead of hosted C++ library APIs."""
        for path in sorted(SOURCES.rglob("*")):
            if path.suffix in {".cpp", ".hpp", ".h", ".mm"}:
                _check_native_includes(path)

    @staticmethod
    def test_placement_shim_is_kernel_only_and_never_allocates() -> None:
        """The DMA object's lifetime uses caller-owned IOKit storage."""
        content = PLACEMENT_HEADER.read_text(encoding="utf-8")
        for required in (
            "#if defined(__APPLE__) && defined(KERNEL)",
            "inline void *operator new(size_t, void *storage) noexcept",
            "return storage;",
            "#else",
            "#include <new>",
        ):
            assert required in content
        native = (SOURCES / "platform/Ar9565NativeQueues.cpp").read_text()
        for required in (
            '#include "KernelPlacementNew.hpp"',
            "new(storage) NativeQueueMemory",
            "IOMalloc(sizeof(NativeQueueMemory))",
        ):
            assert required in native

    @staticmethod
    def test_native_capture_preserves_explicit_length_guard() -> None:
        """Byte copying must remain bounded without std::next."""
        content = (SOURCES / "hardware/Ar9565NvmReader.cpp").read_text()
        for required in (
            "byteOffset(destination, bytesAcquired)",
            "bytesAcquired >= word.byteCount",
            "publishCapturedWord(destination, publishSpec,",
            "byteOffset(storage, length - sizeof(header))",
            "__builtin_memcmp(header, capturedHeader, sizeof(header))",
        ):
            assert required in content
        assert NATIVE_STD_NEXT not in content


class FreestandingKernelHeaders(unittest.TestCase):
    """Exercise the kernel-only placement path with no libc++ include root."""

    @staticmethod
    def test_native_placement_compiles_without_standard_cpp_headers() -> None:
        """Compile a synthetic object lifetime with freestanding Clang.

        The test uses only the compiler resource headers and links nothing.
        """
        compiler = shutil.which("clang++")
        assert compiler is not None
        resource = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
            [compiler, "-print-resource-dir"],
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        source = """\
#include "platform/KernelPlacementNew.hpp"
#include <stdint.h>
static_assert(sizeof(uint8_t) == 1, "kernel byte must be one octet");
struct Object { int first; int second; };
static_assert(noexcept(::operator new(sizeof(Object),
                                      static_cast<void *>(nullptr))),
              "placement construction must not throw");
void construct() {
    alignas(Object) char storage[sizeof(Object)];
    (void)new (static_cast<void *>(storage)) Object{1, 2};
}
"""
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
            [
                compiler,
                "-std=c++14",
                "-DKERNEL",
                "-D__APPLE__",
                "-nostdinc",
                "-isystem",
                str(Path(resource) / "include"),
                "-I",
                str(SOURCES),
                "-x",
                "c++",
                "-fsyntax-only",
                "-",
            ],
            input=source,
            shell=False,
            text=True,
            capture_output=True,
            check=False,
            timeout=20,
        )
        assert result.returncode == 0, result.stderr

    @staticmethod
    def test_tx_power_units_compile_without_hosted_headers() -> None:
        """Reject any future libc++/userspace dependency in AR9565 power.

        Compile each actual C++ translation unit, not a mock header or a
        freshly copied production implementation. This is a host syntax-only
        regression, never an Apple kext build or device/hardware test.
        """
        compiler = shutil.which("clang++")
        assert compiler is not None, "Clang compiler is required"
        resource = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
            [compiler, "-print-resource-dir"],
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        builtin = Path(resource) / "include"
        assert (builtin / "stddef.h").is_file()
        for standard in FREESTANDING_CXX_STANDARDS:
            for unit in POWER_SOURCE_UNITS:
                result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
                    [
                        compiler,
                        f"-std={standard}",
                        "-ffreestanding",
                        "-fno-exceptions",
                        "-fno-rtti",
                        "-nostdinc",
                        "-isystem",
                        str(builtin),
                        "-I",
                        str(SOURCES),
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-fsyntax-only",
                        str(SOURCES / unit),
                    ],
                    shell=False,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                assert result.returncode == 0, (
                    f"{unit} {standard}: unsupported kernel header dependency\n"
                    f"{result.stderr}"
                )
