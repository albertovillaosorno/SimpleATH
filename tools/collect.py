#!/usr/bin/env python3
# Copyright:
#   - Copyright © 2026 laobamac. All rights reserved.
# SPDX-License-Identifier:
#   - LicenseRef-SimpleBCM-All-Rights-Reserved
# Confidential:
#   - false
# License-File:
#   - LICENSE-SIMPLEBCM
# Provenance:
#   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
#   - Originally authored by laobamac on 2026/9/11.
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for collect.
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
#   - Host-side tooling for collect.
# - Description:
#   - Implements or verifies the collect source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for collect.

"""Capture explicitly requested macOS Wi-Fi diagnostics into a local folder."""

import argparse
from datetime import UTC
from datetime import datetime
import json
from pathlib import Path
import re
import shutil

# Diagnostics invoke fixed macOS utilities without a shell.
import subprocess
import sys
from typing import NotRequired
from typing import TYPE_CHECKING
from typing import TypeIs
from typing import TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable

IDENTIFIERS = [
    "dev.alberto.SimpleATH",
    "as.vit9696.Lilu",
    "as.lvs1974.AirportBrcmFixup",
    "com.apple.iokit.IO80211Family",
    "com.apple.iokit.IOSkywalkFamily",
    "com.apple.iokit.IO80211FamilyLegacy",
    "com.apple.driver.AirPort.BrcmNIC",
]
_LOG_WIFI_PREDICATE = (
    '(process == "airportd" OR process == "wifip2pd" AND '
    '(subsystem == "com.apple.awdl" OR eventMessage CONTAINS "IOCTL" OR '
    'eventMessage CONTAINS "parse event")) OR (process == "sharingd" '
    'AND category CONTAINS "AirDrop") OR (process == "mDNSResponder" '
    'AND (eventMessage CONTAINS "awdl0" OR eventMessage CONTAINS "airdrop"))'
)
_LOG_KERNEL_PREDICATE = (
    'process == "kernel" AND (eventMessage CONTAINS "SimpleATH" OR '
    'eventMessage CONTAINS "IO80211APIUserClient" OR '
    'eventMessage CONTAINS "IOSkywalkFamily" OR '
    'eventMessage CONTAINS "IO80211FamilyLegacy" OR '
    'eventMessage CONTAINS "AirPort.BrcmNIC")'
)
_INTERFACE_PATTERN = re.compile(r"en\d+", re.ASCII)


class _Arguments(argparse.Namespace):
    output: Path = Path()
    interface: list[str] | None = None


class _CommandResult(TypedDict):
    command: list[str]
    exit: NotRequired[int]
    stdout: NotRequired[str]
    stderr: NotRequired[str]
    error: NotRequired[str]


def capture(command: list[str]) -> _CommandResult:
    """Capture one macOS command as data, including nonzero exit status.

    Returns:
        The command vector and captured output or launch failure.

    """
    executable = (
        shutil.which(command[0])
        if not Path(command[0]).is_absolute()
        else command[0]
    )
    if executable is None:
        return {
            "command": command,
            "error": f"Executable not found: {command[0]}",
        }
    try:
        # Command tokens are fixed here; only validated enN names are appended.
        # No shell, intentional diagnostics collection.
        result = subprocess.run(
            [executable, *command[1:]],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": command, "error": str(error)}
    else:
        return {
            "command": command,
            "exit": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }


def _is_sequence(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _arguments() -> tuple[Path, list[str] | None]:
    parser = argparse.ArgumentParser()
    timestamp = datetime.now(tz=UTC).astimezone().strftime("%Y%m%d-%H%M%S")
    _ = parser.add_argument(
        "--output",
        type=Path,
        default=Path.cwd() / f"SimpleATH-diagnostics-{timestamp}",
    )
    _ = parser.add_argument(
        "--interface",
        action="append",
        help="Wireless BSD interface; defaults to athprobe discovery",
    )
    args = parser.parse_args(namespace=_Arguments())
    return args.output, args.interface


def _diagnostic_commands() -> list[list[str]]:
    commands = [
        ["sw_vers"],
        ["sysctl", "-n", "kern.osversion", "kern.osrelease"],
        ["ioreg", "-r", "-c", "SimpleATH", "-l"],
        ["ioreg", "-r", "-c", "IO80211APIUserClient", "-l"],
        ["ioreg", "-r", "-c", "ATHLegacyInterface", "-l"],
        ["ioreg", "-r", "-c", "ATHNativeInterface", "-l"],
        ["ioreg", "-p", "IOPower", "-r", "-c", "AirPort_BrcmNIC", "-l"],
        [
            "ioreg",
            "-p",
            "IOPower",
            "-r",
            "-c",
            "IOSkywalkNetworkBSDClient",
            "-l",
        ],
        ["ioreg", "-r", "-c", "IO80211AsyncEventUserClient", "-l"],
        ["networksetup", "-listallhardwareports"],
        ["networksetup", "-listnetworkserviceorder"],
        ["scutil", "--nwi"],
        ["scutil", "--dns"],
        ["scutil", "--proxy"],
        ["route", "-n", "get", "default"],
        ["ifconfig", "-a"],
        ["ifconfig", "awdl0"],
        ["netstat", "-I", "awdl0", "-b", "-n"],
        [
            "/usr/bin/log",
            "show",
            "--last",
            "5m",
            "--style",
            "compact",
            "--info",
            "--debug",
            "--predicate",
            _LOG_WIFI_PREDICATE,
        ],
        [
            "/usr/bin/log",
            "show",
            "--last",
            "boot",
            "--style",
            "compact",
            "--info",
            "--debug",
            "--predicate",
            _LOG_KERNEL_PREDICATE,
        ],
    ]
    commands.append(
        ["kmutil", "showloaded", "--list-only"]
        + [
            arg
            for identifier in IDENTIFIERS
            for arg in ("--optional-identifier", identifier)
        ]
    )
    return commands


def _probe_candidates() -> list[Path]:
    folder = Path(__file__).resolve().parent
    return [
        folder / "athprobe",
        folder.parent / "athprobe",
        *[
            folder.parent
            / "build/DerivedData/Build/Products"
            / config
            / "athprobe"
            for config in ("Release", "Debug")
        ],
    ]


def _is_object_dict(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _is_mapping(value: object) -> TypeIs[dict[str, object]]:
    return _is_object_dict(value) and all(isinstance(k, str) for k in value)


def _decode_json(value: str, decoder: Callable[[str], object]) -> object:
    return decoder(value)


def _extract_names(interfaces: object) -> list[str]:
    if not _is_sequence(interfaces):
        return []
    names: list[str] = []
    for item in interfaces:
        if _is_mapping(item):
            name = item.get("name")
            if isinstance(name, str):
                names.append(name)
    return names


def _probe_interfaces(stdout: str) -> list[str]:
    try:
        payload = _decode_json(stdout, json.loads)
    except json.JSONDecodeError:
        return []
    if not _is_mapping(payload):
        return []
    return _extract_names(payload.get("interfaces"))


def _interfaces(
    requested: list[str] | None, results: list[_CommandResult]
) -> list[str]:
    names = requested or []
    probe = next((path for path in _probe_candidates() if path.is_file()), None)
    if probe is not None:
        result = capture([str(probe)])
        results.append(result)
        if not requested and result.get("exit") == 0:
            stdout = result.get("stdout")
            if stdout is not None:
                names = _probe_interfaces(stdout)
    return sorted({
        name for name in names if _INTERFACE_PATTERN.fullmatch(name)
    })


def main() -> None:
    """Write diagnostics only after direct invocation on the owner's Mac."""
    output, requested = _arguments()
    output.mkdir(parents=True, exist_ok=False)
    results: list[_CommandResult] = []
    commands = _diagnostic_commands()
    for name in _interfaces(requested, results):
        commands.extend([
            ["ipconfig", "getpacket", name],
            ["netstat", "-I", name, "-b", "-n"],
        ])
    results.extend(capture(command) for command in commands)
    report = {
        "copyright": "Copyright © 2026 laobamac. All rights reserved.",
        "results": results,
    }
    _ = (output / "diagnostics.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    )
    _ = sys.stdout.write(f"{output.resolve()}\n")


if __name__ == "__main__":
    main()
