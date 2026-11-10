#
#  verify.py
#  SimpleATH
#
#  Created by laobamac on 2026/9/5.
#  Copyright © 2026 laobamac. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
"""Run the opt-in macOS ABI verification fixture with checked outputs."""

from __future__ import annotations

import json
from pathlib import Path
import shutil

# Only known local command paths run in this explicit verification entrypoint.
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import sys
import tempfile
from typing import TYPE_CHECKING

if __package__:
    from tools.abi_types import json_object
else:
    from abi_types import json_object

if TYPE_CHECKING:
    from tools.abi_types import JsonValue

ROOT = Path(__file__).resolve().parent.parent
HOST_SOURCE_FILE = Path(__file__).with_name("abi_validation_host.cpp")


def verify_abi(folder: Path) -> dict[str, JsonValue]:
    """Compile and execute the explicit macOS ABI host fixture.

    This is an opt-in legacy verification tool. Merely importing the module
    never invokes the compiler; the caller must authorize the platform build.

    Returns:
        JSON-compatible mapping emitted by the fixture.

    Raises:
        FileNotFoundError: The macOS xcrun tool or fixture file is missing.

    """
    folder = folder.resolve()
    source = folder / "ABIValidation.cpp"
    executable = folder / "ABIValidation"
    _ = source.write_text(
        HOST_SOURCE_FILE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    xcrun = shutil.which("xcrun")
    if xcrun is None:
        message = "macOS xcrun is required for ABI fixture verification"
        raise FileNotFoundError(message)
    _ = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
        [
            xcrun,
            "clang++",
            "-std=c++14",
            "-O1",
            "-g",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-mmacosx-version-min=14.0",
            "-I",
            str(ROOT / "SimpleATH"),
            str(source),
            "-framework",
            "IOKit",
            "-framework",
            "CoreFoundation",
            "-lobjc",
            "-o",
            str(executable),
        ],
        check=True,
        shell=False,
    )
    output = subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]
        [str(executable)], text=True, timeout=60, shell=False
    )
    return json_object(output)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="SimpleATH-ABI-") as folder:
        _ = sys.stdout.write(
            json.dumps(verify_abi(Path(folder)), indent=2) + "\n"
        )
