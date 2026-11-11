# Copyright (c) 2026 SimpleATH contributors.
"""Regress native SDK OSMetaClass allocation-operator build failures."""

from pathlib import Path
import platform
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import unittest

from tools.native_apple_kernel_headers import native_kernel_syntax_command

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src"
CLASSES = (
    ("SimpleATH", "SimpleATH.cpp"),
    ("SimpleATHUsbBluetooth", "platform/bluetooth/SimpleATHUsbBluetooth.hpp"),
    (
        "SimpleATHUsbHciTransport",
        "platform/bluetooth/SimpleATHUsbBluetooth.hpp",
    ),
    ("SimpleATHTahoeController", "platform/tahoe/SimpleATHTahoeController.hpp"),
    ("SimpleATHInfraProtocol", "platform/tahoe/SimpleATHInfraProtocol.hpp"),
)
NATIVE_UNITS = (
    "SimpleATH.cpp",
    "platform/bluetooth/SimpleATHUsbBluetooth.cpp",
    "platform/tahoe/SimpleATHTahoeController.cpp",
    "platform/tahoe/SimpleATHInfraProtocol.cpp",
)
NEW_DECLARATION = "void *operator new(size_t size);"
DELETE_DECLARATION = "void operator delete(void *memory, size_t size);"
HOST_STANDARDS = ("c++14", "c++17")


def _class_body(source: str, classname: str) -> str:
    """Isolate one metaclass owner even in multi-class headers.

    Args:
        source: C++ declarations from one header.
        classname: Exact OSObject subclass name.

    Returns:
        The single subclass declaration body.

    """
    start = source.index(f"class {classname} final")
    end = source.index("\n};", start)
    return source[start:end]


def _compile_fixture(
    declarations: str, standard: str
) -> subprocess.CompletedProcess[str]:
    """Expand the two native allocator definitions without a hosted C++ SDK.

    Args:
        declarations: Actual declaration lines from an owned driver class.
        standard: Supported kernel C++ language version.

    Returns:
        Host compiler diagnostics; never links or generates a kext.

    """
    clang = shutil.which("clang++")
    assert clang is not None, "Clang is required for host syntax regression"
    source = f"""\
using size_t = __SIZE_TYPE__;
extern void *allocate(size_t);
extern void deallocate(void *, size_t);
class SyntheticDriver {{
public:
{declarations}
}};
void *SyntheticDriver::operator new(size_t bytes) {{ return allocate(bytes); }}
void SyntheticDriver::operator delete(void *data, size_t bytes) {{
    deallocate(data, bytes);
}}
"""
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
        [
            clang,
            f"-std={standard}",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-rtti",
            "-nostdinc",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsyntax-only",
            "-x",
            "c++",
            "-",
        ],
        input=source,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        timeout=25,
        cwd=ROOT,
    )


def _xcrun_text(*args: str) -> str:
    """Read the installed Apple toolchain path for a native-only probe.

    Args:
        args: Exact xcrun arguments, without an implicit shell.

    Returns:
        The path produced by the selected tool.

    """
    xcrun = shutil.which("xcrun")
    assert xcrun is not None, "Native Apple SDK requires xcrun"
    result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
        [xcrun, *args],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        timeout=30,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


class NativeMetaclassAllocation(unittest.TestCase):
    """Keep every expanded class consistent with modern native XNU macros."""

    @staticmethod
    def test_driver_allocator_declarations_match_sdk_operator_methods() -> None:
        """Every actual macro consumer declares both matching signatures."""
        for classname, path in CLASSES:
            content = _class_body(
                (SOURCE / path).read_text(encoding="utf-8"), classname
            )
            assert f"class {classname} final" in content
            assert content.count(NEW_DECLARATION) == 1, classname
            assert content.count(DELETE_DECLARATION) == 1, classname
            implementation = SOURCE / path.replace(".hpp", ".cpp")
            assert f"OSDefineDefaultStructors({classname}," in (
                implementation.read_text(encoding="utf-8")
            )

    @staticmethod
    def test_freestanding_allocator_macro_definitions_compile() -> None:
        """Reproduce Tahoe operator new/delete expansion under C++14/17."""
        for classname, path in CLASSES:
            content = _class_body(
                (SOURCE / path).read_text(encoding="utf-8"), classname
            )
            declarations = "\n".join(
                line.strip()
                for line in content.splitlines()
                if line.strip().startswith((
                    "void *operator new(",
                    "void operator delete(",
                ))
            )
            assert NEW_DECLARATION in content, classname
            assert DELETE_DECLARATION in content, classname
            for standard in HOST_STANDARDS:
                result = _compile_fixture(declarations, standard)
                assert result.returncode == 0, (
                    f"{classname} {standard}: {result.stderr}"
                )

    @staticmethod
    def test_missing_allocators_reproduce_xcode_failure() -> None:
        """The old hand-expanded class contract must fail native Clang."""
        for standard in HOST_STANDARDS:
            result = _compile_fixture("", standard)
            assert result.returncode != 0
            assert "operator new" in result.stderr
            assert "operator delete" in result.stderr

    @staticmethod
    def test_native_sdk_compiles_real_metaclass_translation_units() -> None:
        """On macOS, use native XNU headers to catch future macro drift.

        Linux checks the portable failure fixture; there is no non-Apple SDK
        fallback and no kext build or link occurs here.
        """
        if platform.system() != "Darwin":
            return
        sdk = Path(_xcrun_text("--sdk", "macosx", "--show-sdk-path"))
        resource = Path(_xcrun_text("clang++", "-print-resource-dir"))
        command = native_kernel_syntax_command(sdk, resource, SOURCE)
        assert command[-1] == "-"
        for unit in NATIVE_UNITS:
            result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
                [*command[:-1], str(SOURCE / unit)],
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=45,
                cwd=ROOT,
            )
            assert result.returncode == 0, (
                f"Native Apple kernel C++ syntax failed for {unit}:\n"
                f"{result.stderr}"
            )


if __name__ == "__main__":
    _ = unittest.main()
