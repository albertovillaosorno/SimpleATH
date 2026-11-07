# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Opt-in offline forwarding ABI fixture with checked result counts."""

from __future__ import annotations

from pathlib import Path
import shutil

# Only an explicitly requested local compiler and generated fixture are run.
import subprocess  # ruff: ignore[suspicious-subprocess-import]
from typing import TYPE_CHECKING

if __package__:
    from tools.abi_types import integer
    from tools.abi_types import json_object
else:
    from abi_types import integer
    from abi_types import json_object

if TYPE_CHECKING:
    from tools.abi_types import JsonValue

HOST_SOURCE_FILE = Path(__file__).with_name("forwarding_validation_host.cpp")
MAX_FORWARDERS = 2048
MAX_ASSEMBLY_BYTES = 4 * 1024 * 1024
DECLARATIONS = "// ATH_DECLARATIONS_PLACEHOLDER"
FORWARDERS = "ATH_FORWARDERS_PLACEHOLDER"
CALLBACKS = "ATH_CALLBACKS_PLACEHOLDER"


def render_fixture(method_count: int) -> str:
    """Render a bounded source fixture without launching any process.

    Returns:
        Complete C++ source with every exact placeholder replaced.

    Raises:
        ValueError: The count or checked fixture placeholders are invalid.

    """
    if not 0 < method_count <= MAX_FORWARDERS:
        message = "Forwarding method count is outside the supported range"
        raise ValueError(message)
    source = HOST_SOURCE_FILE.read_text(encoding="utf-8")
    for marker in (DECLARATIONS, FORWARDERS, CALLBACKS):
        if source.count(marker) != 1:
            message = (
                "Forwarding C++ fixture placeholder is missing or repeated"
            )
            raise ValueError(message)
    declarations: list[str] = []
    old_entries: list[str] = []
    new_entries: list[str] = []
    for index in range(method_count):
        declarations.extend((
            f'extern "C" void athSkyForward{index}();',
            f'extern "C" void athSkyCallback{index}();',
        ))
        old_entries.append(f"reinterpret_cast<uintptr_t>(athSkyForward{index})")
        new_entries.append(
            f"reinterpret_cast<uintptr_t>(athSkyCallback{index})"
        )
    return (
        source
        .replace(DECLARATIONS, "\n".join(declarations))
        .replace(FORWARDERS, ",".join(old_entries))
        .replace(CALLBACKS, ",".join(new_entries))
    )


def checked_counts(output: str, method_count: int) -> dict[str, JsonValue]:
    """Require all three numeric fixture counters to match executed calls.

    Returns:
        The validated JSON report, including its exact fixture counters.

    Raises:
        ValueError: The report is malformed, incomplete or inconsistent.

    """
    result = json_object(output)
    calls = integer(result.get("forwardingCalls"))
    retained = integer(result.get("retainedReceivers"))
    released = integer(result.get("releasedReceivers"))
    if calls != 6 * method_count or retained != 2 * method_count:
        message = "Forwarding fixture did not exercise every ABI call"
        raise ValueError(message)
    if released != retained:
        message = "Forwarding fixture leaked retained receivers"
        raise ValueError(message)
    return result


def run_probe(
    folder: Path, forwarders: str, method_count: int
) -> dict[str, JsonValue]:
    """Compile/run the generated Darwin assembly only on explicit invocation.

    Returns:
        Validated fixture result counters.

    Raises:
        ValueError: The local generated assembly or fixture is invalid.
        FileNotFoundError: The authorized toolchain is unavailable.

    """
    if not folder.is_dir() or not forwarders:
        message = "Forwarding fixture needs an existing directory and assembly"
        raise ValueError(message)
    if len(forwarders.encode("utf-8")) > MAX_ASSEMBLY_BYTES:
        message = "Forwarding fixture assembly exceeds the source limit"
        raise ValueError(message)
    source = render_fixture(method_count)
    xcrun = shutil.which("xcrun")
    if xcrun is None:
        message = "macOS xcrun is required for forwarding ABI verification"
        raise FileNotFoundError(message)
    assembly = folder / "Forwarding.S"
    host = folder / "ForwardingValidation.cpp"
    executable = folder / "forwarding"
    _ = assembly.write_text(
        ".section __TEXT,__text\n" + forwarders, encoding="utf-8"
    )
    _ = host.write_text(source, encoding="utf-8")
    _ = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
        [
            xcrun,
            "clang++",
            "-std=c++14",
            "-O1",
            "-UNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            str(host),
            str(assembly),
            "-o",
            str(executable),
        ],
        check=True,
        shell=False,
        timeout=120,
    )
    output = subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]
        [str(executable)], text=True, shell=False, timeout=60
    )
    return checked_counts(output, method_count)
