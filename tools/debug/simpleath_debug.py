#!/usr/bin/env python3
# Copyright (c) 2026 SimpleATH contributors.
"""Collect manual macOS Wi-Fi, BT and AirDrop evidence next to this file.

Requires Python 3.9+ and administrator access; relaunches itself with sudo.
No driver installation, configuration changes, radio scans or packet capture.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import hashlib
import os
from pathlib import Path
import platform
import pwd
import shlex
import signal
import stat
import sys
import time
from typing import BinaryIO
from typing import NamedTuple

VERSION = "1.0"
MAX_HISTORY_MINUTES = 1440
MIN_COMMAND_TIMEOUT = 5
MAX_COMMAND_TIMEOUT = 180
SUPPORTED_KERNEL = "Darwin"
UTC_OFFSET = timezone(timedelta(0))
CAPTURED = "captured"
TIMED_OUT = "timeout"
TRUNCATED = "truncated"
SUDO_PATH = "/usr/bin/sudo"
SAFETY_NOTICE = (
    "Read-only collection. Missing devices and failed commands are",
    "evidence, not passes. No passwords, keychain exports, Bluetooth",
    "link keys or packet capture are requested.",
)
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
    """Read bounded time limits; report placement is beside the tool.

    Returns:
        Validated time bounds for the diagnostics collector.

    """
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
    if not 1 <= options.minutes <= MAX_HISTORY_MINUTES:
        parser.error("--minutes must be between 1 and 1440")
    if not MIN_COMMAND_TIMEOUT <= options.timeout <= MAX_COMMAND_TIMEOUT:
        parser.error("--timeout must be between 5 and 180")
    return options


class UnsupportedHostError(RuntimeError):
    """Reject collection on unsupported operating systems."""

    def __init__(self) -> None:
        """Explain why macOS is mandatory for this diagnostic utility."""
        super().__init__("Run this tool on the target Mac; macOS is required.")


def require_macos_root(script: Path) -> None:
    """Refuse other platforms and re-execute through sudo before collection.

    Raises:
        UnsupportedHostError: The current host is not macOS.
        SystemExit: The privileged child has finished; use its exit status.

    """
    if platform.system() != SUPPORTED_KERNEL:
        raise UnsupportedHostError
    if os.geteuid() != 0:
        _ = sys.stdout.write(
            "Administrator access is required. Relaunching with sudo.\n"
        )
        _ = sys.stdout.flush()
        arguments = ("sudo", "--", sys.executable, str(script), *sys.argv[1:])
        child = os.posix_spawn(SUDO_PATH, arguments, os.environ.copy())
        _, wait_status = os.waitpid(child, 0)
        raise SystemExit(os.waitstatus_to_exitcode(wait_status))


def open_report(script: Path) -> tuple[Path, BinaryIO]:
    """Create a private log next to the script without overwriting.

    Returns:
        The new report path and its privately opened binary stream.

    """
    stamp = datetime.now(UTC_OFFSET).strftime("%Y%m%d-%H%M%S-%fZ")
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
        """Initialize counters and a retained report stream."""
        self.output: BinaryIO = output
        self.bytes: int = 0
        self.counts: dict[str, int] = {}

    def write(self, data: bytes) -> None:
        """Write bytes without exhausting storage.

        Raises:
            ReportLimitExceededError: The report cannot fit the provided bytes.

        """
        if self.bytes + len(data) > REPORT_LIMIT:
            raise ReportLimitExceededError
        _ = self.output.write(data)
        self.bytes += len(data)

    def line(self, text: str) -> None:
        """Encode text consistently, replacing invalid UTF-8 bytes."""
        self.write((text + "\n").encode("utf-8", errors="replace"))

    def outcome(self, state: str, detail: str) -> None:
        """Record a factual outcome without relabeling failure as success."""
        self.counts[state] = self.counts.get(state, 0) + 1
        self.line(f"\n[RESULT {state}] {detail}\n")


async def stop_group(process: asyncio.subprocess.Process) -> None:
    """Terminate only this collector's isolated process group, boundedly."""
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        _ = await asyncio.wait_for(process.wait(), timeout=2)
    except TimeoutError:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        _ = await asyncio.wait_for(process.wait(), timeout=5)


class ReportLimitExceededError(RuntimeError):
    """An attempted write would exceed the bounded diagnostic report."""

    def __init__(self) -> None:
        """Explain why a partially collected report remains incomplete."""
        super().__init__("Report size limit reached; partial log preserved")


class MissingOutputPipeError(RuntimeError):
    """Signal a missing diagnostic command output channel."""


def _bounded_read_size(consumed: int) -> int:
    """Read at most one byte beyond the per-command output allowance.

    Returns:
        Positive byte limit for the next asynchronous pipe read.

    """
    return min(CHUNK, SECTION_LIMIT - consumed + 1)


async def _read_until_deadline(
    reader: asyncio.StreamReader, consumed: int, deadline: float
) -> bytes | None:
    """Read one bounded block, returning None if the deadline expires.

    Returns:
        Received bytes, EOF as empty bytes, or None on timeout.

    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        return await asyncio.wait_for(
            reader.read(_bounded_read_size(consumed)), timeout=remaining
        )
    except TimeoutError:
        return None


def _append_section_block(report: Report, block: bytes, consumed: int) -> int:
    """Append verified bytes, reporting -1 when a section was truncated.

    Returns:
        New consumed-byte count or -1 when the section cap is reached.

    """
    if consumed + len(block) > SECTION_LIMIT:
        report.write(block[: SECTION_LIMIT - consumed])
        return -1
    report.write(block)
    return consumed + len(block)


def _required_stdout(
    process: asyncio.subprocess.Process,
) -> asyncio.StreamReader:
    """Get a checked output reader for the owned diagnostic child.

    Returns:
        An attached asynchronous stdout reader.

    Raises:
        MissingOutputPipeError: The child's stdout was not piped.

    """
    if process.stdout is None:
        raise MissingOutputPipeError
    return process.stdout


async def stream_command(
    process: asyncio.subprocess.Process,
    report: Report,
    duration_seconds: int,
) -> str:
    """Read bounded stdout until EOF, deadline or the section size limit.

    Returns:
        Captured, timed-out or truncated command state.

    """
    reader = _required_stdout(process)
    deadline = time.monotonic() + duration_seconds
    consumed = 0
    state = CAPTURED
    while True:
        block = await _read_until_deadline(reader, consumed, deadline)
        if block is None:
            state = TIMED_OUT
            break
        if not block:
            break
        consumed = _append_section_block(report, block, consumed)
        if consumed < 0:
            state = TRUNCATED
            break
    return state


async def _finish_process(
    process: asyncio.subprocess.Process, report: Report
) -> None:
    """Revoke any outstanding diagnostic child before closing its event loop."""
    if process.returncode is None:
        try:
            await stop_group(process)
        except (OSError, RuntimeError, TimeoutError) as error:
            report.outcome(
                "termination-incomplete", f"pid={process.pid}: {error}"
            )


async def _capture_async(
    probe: Probe, report: Report, duration_seconds: int
) -> None:
    """Execute a fixed argv in its own process group with bounded output."""
    try:
        process = await asyncio.create_subprocess_exec(
            *probe.argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
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
        state = await stream_command(process, report, duration_seconds)
        if state != CAPTURED:
            await stop_group(process)
        code = await asyncio.wait_for(process.wait(), timeout=2)
        report.outcome(
            state if state != CAPTURED or code == 0 else "command-failed",
            f"exit={code}; deadline={duration_seconds}s; pid={process.pid}",
        )
    except (OSError, RuntimeError, TimeoutError) as error:
        report.outcome("collection-error", str(error))
    finally:
        await _finish_process(process, report)


def capture(probe: Probe, report: Report, timeout: int) -> None:
    """Collect from a fixed argv, with no shell and a bounded process group."""
    divider = "=" * 72
    report.line(f"\n{divider}\n{probe.title}\n$ {shlex.join(probe.argv)}\n")
    _ = sys.stdout.write(f"Collecting: {probe.title}\n")
    _ = sys.stdout.flush()
    asyncio.run(_capture_async(probe, report, timeout))


def system_probes() -> list[Probe]:
    """List read-only OS, driver, networking and power probes.

    Returns:
        Fixed argument vectors for the system inventory.

    """
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
    """List PCI, USB, Wi-Fi and Bluetooth registry/profile probes.

    Returns:
        Fixed argument vectors with a bounded profiler timeout.

    """
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
    kinds = (
        "SPHardwareDataType",
        "SPSoftwareDataType",
        "SPPCIDataType",
        "SPAirPortDataType",
        "SPBluetoothDataType",
        "SPUSBDataType",
    )
    probes.extend(
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
        for kind in kinds
    )
    return probes


class InvalidDiagnosticReportError(OSError):
    """A report-like path is not a regular, bounded file."""

    def __init__(self) -> None:
        """Describe the unsupported log object type."""
        super().__init__("Diagnostic report is not a regular file")


def _read_recent_report(path: Path) -> bytes:
    """Open a bounded report without following a symlink or device node.

    Returns:
        At most one byte beyond the diagnostic section limit.

    Raises:
        InvalidDiagnosticReportError: The opened path is not a regular file.

    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise InvalidDiagnosticReportError
        return source.read(PANIC_LIMIT + 1)


def _record_recent_report(report: Report, path: Path) -> None:
    """Capture a single recent diagnostic file and its factual status."""
    report.line(f"\nRecent diagnostic report: {path}\n")
    try:
        data = _read_recent_report(path)
    except OSError as error:
        report.outcome("collection-error", str(error))
    else:
        report.write(data[:PANIC_LIMIT])
        report.outcome(
            TRUNCATED if len(data) > PANIC_LIMIT else CAPTURED,
            str(path),
        )


def recent_reports(report: Report) -> None:
    """Collect bounded crash reports without following links or devices."""
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
        _record_recent_report(report, path)


def hash_driver_file(path: Path) -> str:
    """Hash a bounded driver file without opening a device or FIFO.

    Returns:
        SHA-256 digest in lowercase hexadecimal.

    Raises:
        OSError: The source is not a bounded, regular driver file.

    """
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


def _collect_with_failure_record(report: Report, options: Options) -> None:
    """Mark an incomplete report before surfacing the original error.

    Raises:
        OSError: An underlying diagnostic read failed.
        RuntimeError: The report exceeded its bounded capacity.
        KeyboardInterrupt: The owner interrupted the collection.

    """
    try:
        collect(report, options)
    except (OSError, RuntimeError, KeyboardInterrupt) as error:
        report.line(f"\nCOLLECTION INCOMPLETE: {error}\n")
        raise


def _write_report(report: Report, options: Options, script: Path) -> None:
    """Write an evidence-only header, probes and explicit final outcome."""
    report.line(
        "\n".join((
            f"SimpleATH manual debug {VERSION}",
            f"UTC: {datetime.now(UTC_OFFSET).isoformat()}",
            f"Effective UID: {os.geteuid()}",
            f"Tool SHA256: {hashlib.sha256(script.read_bytes()).hexdigest()}",
        ))
    )
    report.line(" ".join(SAFETY_NOTICE))
    _collect_with_failure_record(report, options)
    report.line(
        "\n".join((
            "",
            f"COLLECTION FINISHED. Outcomes: {report.counts}",
            "This report does not certify driver functionality.",
            "",
        ))
    )


def _collect_to_file(script: Path, options: Options) -> Path:
    """Open a private report and collect without losing partial evidence.

    Returns:
        Absolute path of the newly created manual diagnostic report.

    """
    path, output = open_report(script)
    _ = sys.stdout.write(f"Log: {path}\n")
    with output:
        _write_report(Report(output), options, script)
    return path


def main() -> int:
    """Run only when requested on macOS and report the actual exit status.

    Returns:
        Zero when all probes finish, or one on an incomplete collection.

    """
    script = Path(__file__).resolve(strict=True)
    options = arguments()
    try:
        require_macos_root(script)
        path = _collect_to_file(script, options)
    except (OSError, RuntimeError, KeyboardInterrupt) as error:
        _ = sys.stderr.write(
            "\n".join((
                f"SimpleATH debug: {error}",
                "Any existing partial log remains beside the script.",
                "",
            ))
        )
        return 1
    else:
        _ = sys.stdout.write(f"Finished. Send this log in the chat: {path}\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
