# Copyright (c) 2026 Alberto Villa Osorno.
"""Exercise native patch routing with isolated, synthetic kernel shims."""

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - Fixed host-only commands.
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/fixtures/patcher_route/route_test.cpp.in"
HEADERS = {
    "IOKit/IOLib.h": (
        '#pragma once\nextern "C" void IOLog(const char *, ...);\n'
    ),
    "mach/mach_types.h": "#pragma once\n",
    "libkern/copyio.h": (
        "#pragma once\n"
        "#include <cstddef>\n#include <cstdint>\n"
        'extern "C" int copyin(uintptr_t, void *, size_t);\n'
        'extern "C" int copyout(const void *, uintptr_t, size_t);\n'
    ),
    "sys/systm.h": (
        "#pragma once\n"
        "#include <cstddef>\n#include <cstdint>\n#include <climits>\n"
        "#include <cstring>\n"
        'extern "C" int copyin(uintptr_t, void *, size_t);\n'
        'extern "C" int copyout(const void *, uintptr_t, size_t);\n'
    ),
}


class PatcherRoutingHostTests(unittest.TestCase):
    """Check route preflight without loading or compiling any macOS kext."""

    @staticmethod
    def test_invalid_batch_never_patches_earlier_route() -> None:
        """Later failures must leave every original hook and stub untouched."""
        compiler = shutil.which("clang++")
        assert compiler is not None, "Offline host test requires clang++"
        with tempfile.TemporaryDirectory(
            prefix="simpleath-patcher-test-"
        ) as name:
            temporary = Path(name)
            include = temporary / "include"
            for relative, content in HEADERS.items():
                header = include / relative
                header.parent.mkdir(parents=True, exist_ok=True)
                _ = header.write_text(content, encoding="utf-8")
            test_source = temporary / "route_test.cpp"
            _ = test_source.write_bytes(FIXTURE.read_bytes())
            for standard in ("c++14", "c++17"):
                executable = temporary / f"route-{standard}"
                compiled = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
                    [
                        compiler,
                        f"-std={standard}",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-I",
                        str(include),
                        "-I",
                        str(ROOT / "src"),
                        str(test_source),
                        str(ROOT / "src/Patcher.cpp"),
                        str(ROOT / "src/Relocate.cpp"),
                        "-o",
                        str(executable),
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                assert compiled.returncode == 0, compiled.stderr
                run = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
                    [str(executable)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                assert run.returncode == 0, (
                    f"{standard}: {run.stdout} {run.stderr} "
                    f"(exit {run.returncode})"
                )
