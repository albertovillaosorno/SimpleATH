#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Collect manual macOS Wi-Fi, Bluetooth and AirDrop diagnostics beside this file.

Requires Python 3.9+ and administrator access; relaunches itself with sudo.
No driver installation, configuration changes, radio scans or packet capture.
"""

from __future__ import annotations

import argparse
from datetime import datetime
from datetime import timezone
import hashlib
import os
from pathlib import Path
import pwd
import platform
import select
import shlex
import signal
import stat
import subprocess
import sys
import time
from typing import BinaryIO
from typing import NamedTuple

VERSION = "1.0"
SECTION_LIMIT = 8 * 1024 * 1024
REPORT_LIMIT = 128 * 1024 * 1024
CHUNK = 65536
PANIC_LIMIT = 2 * 1024 * 1024
PANIC_COUNT = 6
DRIVER_HASH_LIMIT = 64 * 1024 * 1024
PREDICATE = (
    '(process == "kernel" AND (eventMessage CONTAINS[c] "SimpleATH" OR '
    'eventMessage CONTAINS[c] "AR9565" OR '
    'eventMessage CONTAINS[c] "IO80211" OR '
    'eventMessage CONTAINS[c] "Skywalk" OR '
    'eventMessage CONTAINS[c] "Bluetooth")) OR '
    'process IN {"airportd", "wifid", "wifip2pd", "bluetoothd", '
    '"sharingd", "useractivityd"} OR '
    'subsystem BEGINSWITH[c] "com.apple.wifi" OR '
    'subsystem BEGINSWITH[c] "com.apple.awdl"'
)


class Probe(NamedTuple):
    """One fixed, shell-free diagnostic command."""

    title: str
    argv: tuple[str, ...]


class Options(argparse.Namespace):
    """Validated manual collection options."""

    minutes: int = 15
    timeout: int = 30


def arguments() -> Options:
    """Read bounded time limits; report placement is always beside the tool."""
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--minutes",
        type=int,
        default=15,
        help="Unified log history, 1..1440 minutes (default: 15)",
    )
    _ = parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-command deadline, 5..180 seconds (default: 30)",
    )
    options = parser.parse_args(namespace=Options())
    if not 1 <= options.minutes <= 1440:
        parser.error("--minutes must be between 1 and 1440")
    if not 5 <= options.timeout <= 180:
        parser.error("--timeout must be between 5 and 180")
    return options


def require_macos_root(script: Path) -> None:
    """Refuse other platforms and re-execute through sudo before collection."""
    if platform.system() != "Darwin":
        raise RuntimeError(
            "Run this tool on the target Mac; macOS is required."
        )
    if os.geteuid() != 0:
        _ = sys.stdout.write(
            "Administrator access is required. Relaunching with sudo.\n"
        )
        _ = sys.stdout.flush()
        os.execv(
            "/usr/bin/sudo",
            ("sudo", "--", sys.executable, str(script), *sys.argv[1:]),
        )


def open_report(script: Path) -> tuple[Path, BinaryIO]:
    """Create a new private log adjacent to the real script, never overwrite."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%fZ")
    path = script.parent / f"SimpleATH-debug-{stamp}-{os.getpid()}.log"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        if os.environ.get("SUDO_UID", "").isdecimal():
            uid = int(os.environ["SUDO_UID"])
            os.fchown(descriptor, uid, pwd.getpwuid(uid).pw_gid)
        return path, os.fdopen(descriptor, "wb", buffering=0)
    except BaseException:
        os.close(descriptor)
        raise


class Report:
    """A bounded stream with explicit command outcomes and progress."""

    def __init__(self, output: BinaryIO) -> None:
        self.output: BinaryIO = output
        self.bytes: int = 0
        self.counts: dict[str, int] = {}

    def write(self, data: bytes) -> None:
        """Append bytes, refusing unbounded reports instead of filling storage."""
        if self.bytes + len(data) > REPORT_LIMIT:
            raise RuntimeError(
                "Report size limit reached; partial log preserved"
            )
        _ = self.output.write(data)
        self.bytes += len(data)

    def line(self, text: str) -> None:
        """Encode a line consistently, including raw output that was not UTF-8."""
        self.write((text + "\n").encode("utf-8", errors="replace"))

    def outcome(self, state: str, detail: str) -> None:
        """Record failures as data; they are never relabeled as a driver pass."""
        self.counts[state] = self.counts.get(state, 0) + 1
        self.line(f"\n[RESULT {state}] {detail}\n")


def stop_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate only this collector's isolated command and its children."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        _ = process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        _ = process.wait(timeout=5)


def stream_command(
    process: subprocess.Popen[bytes], report: Report, timeout: int
) -> str:
    """Stream bounded output until EOF, timeout or the per-section size cap."""
    if process.stdout is None:
        raise RuntimeError("Command output pipe was not created")
    deadline = time.monotonic() + timeout
    size = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            return "timeout"
        block = os.read(
            process.stdout.fileno(), min(CHUNK, SECTION_LIMIT - size + 1)
        )
        if not block:
            return "captured"
        if size + len(block) > SECTION_LIMIT:
            report.write(block[: SECTION_LIMIT - size])
            return "truncated"
        report.write(block)
        size += len(block)


def capture(probe: Probe, report: Report, timeout: int) -> None:
    """Run an absolute command without a shell, retaining its real exit status."""
    divider = "=" * 72
    report.line(f"\n{divider}\n{probe.title}\n$ {shlex.join(probe.argv)}\n")
    _ = sys.stdout.write(f"Collecting: {probe.title}\n")
    _ = sys.stdout.flush()
    try:
        process = subprocess.Popen(
            probe.argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as error:
        report.outcome(
            "missing"
            if isinstance(error, FileNotFoundError)
            else "collection-error",
            str(error),
        )
        return
    try:
        state = stream_command(process, report, timeout)
        if state != "captured":
            stop_group(process)
        code = process.wait(timeout=2)
        report.outcome(
            state if state != "captured" or code == 0 else "command-failed",
            f"exit={code}; deadline={timeout}s; pid={process.pid}",
        )
    except (OSError, subprocess.SubprocessError) as error:
        report.outcome("collection-error", str(error))
    finally:
        # Popen.__exit__ performs an unbounded wait. A broken driver can leave
        # a query uninterruptible; keep collection bounded and record its PID.
        if process.returncode is None:
            try:
                stop_group(process)
            except (OSError, subprocess.SubprocessError) as error:
                report.outcome(
                    "termination-incomplete", f"pid={process.pid}: {error}"
                )
        if process.stdout is not None:
            process.stdout.close()


def system_probes() -> list[Probe]:
    """Describe OS, protection, loaded drivers, networking and power evidence."""
    return [
        Probe("macOS version", ("/usr/bin/sw_vers",)),
        Probe("Kernel identity", ("/usr/bin/uname", "-a")),
        Probe(
            "Hardware and kernel versions",
            (
                "/usr/sbin/sysctl",
                "hw.model",
                "hw.machine",
                "hw.ncpu",
                "hw.memsize",
                "kern.osversion",
                "kern.osrelease",
                "machdep.cpu.brand_string",
            ),
        ),
        Probe("System integrity protection", ("/usr/bin/csrutil", "status")),
        Probe(
            "Authenticated root status",
            ("/usr/bin/csrutil", "authenticated-root", "status"),
        ),
        Probe("Kernel boot arguments", ("/usr/sbin/nvram", "boot-args")),
        Probe(
            "Loaded kernel extensions",
            ("/usr/bin/kmutil", "showloaded", "--list-only"),
        ),
        Probe(
            "Network hardware ports",
            ("/usr/sbin/networksetup", "-listallhardwareports"),
        ),
        Probe(
            "Network service order",
            ("/usr/sbin/networksetup", "-listnetworkserviceorder"),
        ),
        Probe("Network interfaces and counters", ("/sbin/ifconfig", "-a")),
        Probe("Routing tables", ("/usr/sbin/netstat", "-rn")),
        Probe("Network reachability state", ("/usr/sbin/scutil", "--nwi")),
        Probe("DNS configuration", ("/usr/sbin/scutil", "--dns")),
        Probe("AWDL interface", ("/sbin/ifconfig", "awdl0")),
        Probe("Low-latency Wi-Fi interface", ("/sbin/ifconfig", "llw0")),
        Probe("Wi-Fi diagnostics", ("/usr/bin/wdutil", "info")),
        Probe("Power settings", ("/usr/bin/pmset", "-g", "custom")),
        Probe("Power assertions", ("/usr/bin/pmset", "-g", "assertions")),
        Probe(
            "Relevant process inventory",
            ("/bin/ps", "-axo", "pid,ppid,uid,etime,comm"),
        ),
    ]


def device_probes(timeout: int) -> list[Probe]:
    """Collect real PCI/USB, Wi-Fi and Bluetooth registry/profile evidence."""
    classes = (
        "SimpleATH",
        "IOPCIDevice",
        "IO80211Controller",
        "IO80211SkywalkInterface",
        "IO80211Interface",
        "IOSkywalkNetworkInterface",
        "IOUSBHostDevice",
        "IOBluetoothHCIController",
        "IOBluetoothHostControllerUSBTransport",
    )
    probes = [
        Probe(
            f"IORegistry: {name}",
            ("/usr/sbin/ioreg", "-r", "-l", "-w0", "-c", name),
        )
        for name in classes
    ]
    for kind in (
        "SPHardwareDataType",
        "SPSoftwareDataType",
        "SPPCIDataType",
        "SPAirPortDataType",
        "SPBluetoothDataType",
        "SPUSBDataType",
    ):
        probes.append(
            Probe(
                f"System profile: {kind}",
                (
                    "/usr/sbin/system_profiler",
                    "-detailLevel",
                    "full",
                    "-timeout",
                    str(timeout),
                    kind,
                ),
            )
        )
    return probes


def recent_reports(report: Report) -> None:
    """Copy bounded recent driver/network crash reports without following links."""
    directory = Path("/Library/Logs/DiagnosticReports")
    patterns = (
        "Kernel*",
        "panic*",
        "SimpleATH*",
        "bluetoothd*",
        "airportd*",
        "wifid*",
        "sharingd*",
    )
    paths = {
        p
        for pattern in patterns
        for p in directory.glob(pattern)
        if not p.is_symlink() and p.is_file()
    }
    ranked: list[tuple[float, Path]] = []
    for path in paths:
        try:
            ranked.append((path.stat().st_mtime, path))
        except OSError as error:
            report.outcome("collection-error", str(error))
    for _, path in sorted(ranked, reverse=True)[:PANIC_COUNT]:
        report.line(f"\nRecent diagnostic report: {path}\n")
        try:
            descriptor = os.open(
                path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            )
            with os.fdopen(descriptor, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise OSError("Diagnostic report is not a regular file")
                data = source.read(PANIC_LIMIT + 1)
            report.write(data[:PANIC_LIMIT])
            report.outcome(
                "truncated" if len(data) > PANIC_LIMIT else "captured",
                str(path),
            )
        except OSError as error:
            report.outcome("collection-error", str(error))


def hash_driver_file(path: Path) -> str:
    """Hash a bounded regular driver file without opening a device or FIFO."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > DRIVER_HASH_LIMIT:
            message = "Driver hash source is not a bounded regular file"
            raise OSError(message)
        digest = hashlib.sha256()
        size = 0
        for block in iter(lambda: source.read(CHUNK), b""):
            size += len(block)
            if size > DRIVER_HASH_LIMIT:
                message = "Driver grew beyond the hash limit"
                raise OSError(message)
            digest.update(block)
        return digest.hexdigest()


def driver_files(report: Report) -> None:
    """Hash installed bundles; file presence does not establish loading."""
    for root in (
        Path("/Library/Extensions"),
        Path("/System/Library/Extensions"),
    ):
        for relative in ("Contents/Info.plist", "Contents/MacOS/SimpleATH"):
            path = root / "SimpleATH.kext" / relative
            report.line(f"\nInstalled driver file (not loading proof): {path}")
            try:
                report.line(f"SHA256 {hash_driver_file(path)}")
            except OSError as error:
                report.line(f"Unavailable: {error}")


def collect(report: Report, options: Options) -> None:
    """Gather read-only snapshots and filtered recent unified logs."""
    for probe in system_probes() + device_probes(options.timeout):
        capture(probe, report, options.timeout)
    driver_files(report)
    recent_reports(report)
    capture(
        Probe(
            "Recent Wi-Fi/Bluetooth/AirDrop/kernel logs",
            (
                "/usr/bin/log",
                "show",
                "--style",
                "compact",
                "--last",
                f"{options.minutes}m",
                "--info",
                "--predicate",
                PREDICATE,
            ),
        ),
        report,
        options.timeout,
    )


def main() -> int:
    """Collect only on manual execution; preserve partial reports on failure."""
    script = Path(__file__).resolve(strict=True)
    options = arguments()
    try:
        require_macos_root(script)
        path, output = open_report(script)
        _ = sys.stdout.write(f"Log: {path}\n")
        with output:
            report = Report(output)
            report.line(
                f"SimpleATH manual debug {VERSION}\nUTC: {datetime.now(timezone.utc).isoformat()}\nEffective UID: {os.geteuid()}\nTool SHA256: {hashlib.sha256(script.read_bytes()).hexdigest()}"
            )
            report.line(
                "Read-only collection. Missing devices and failed commands are evidence, not passes. No passwords, keychain exports, Bluetooth link keys or packet capture are requested."
            )
            try:
                collect(report, options)
            except (OSError, RuntimeError, KeyboardInterrupt) as error:
                report.line(f"\nCOLLECTION INCOMPLETE: {error}\n")
                raise
            report.line(
                f"\nCOLLECTION FINISHED. Outcomes: {report.counts}\nThis report does not certify driver functionality.\n"
            )
        _ = sys.stdout.write(f"Finished. Send this log in the chat: {path}\n")
        return 0
    except (OSError, RuntimeError, KeyboardInterrupt) as error:
        _ = sys.stderr.write(
            f"SimpleATH debug: {error}\nAny existing partial log remains beside the script.\n"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
