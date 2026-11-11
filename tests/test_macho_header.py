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
#   - Offline regression cases for macho header.
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
#   - Offline regression cases for macho header.
# - Description:
#   - Implements or verifies the test_macho_header source boundary.
# - Usage:
#   - Executed by offline host test discovery or the native test harness.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Offline regression cases for macho header.
"""Synthetic, bounded Mach-O header and load-command parsing tests."""

from contextlib import redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import struct
import tempfile
from unittest import TestCase
from unittest import mock

from tools import macho
from tools.macho import Image
from tools.macho import MAX_MACHO_BYTES

HEADER_BYTES = 32
FAT_TABLE_BYTES = 40
FAT_CPU = 0x1000007
UUID_COMMAND = 0x1B
SEGMENT_COMMAND = 0x19
SYMTAB_COMMAND = 2
UUID_BYTES = bytes(range(16))
SAMPLE_NAME = b"\0_sample\0"
SOURCE_CHANGED = "source changed"
FAKE_XCRUN = "/mock/xcrun"


def _thin(commands: tuple[bytes, ...] = (), payload: bytes = b"") -> bytes:
    """Build a minimal, nonexecutable x86_64 Mach-O image.

    Returns:
        Thin 64-bit header and supplied load commands/data.

    """
    header = bytearray(HEADER_BYTES)
    header[:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into(
        "<II", header, 16, len(commands), sum(len(c) for c in commands)
    )
    return bytes(header) + b"".join(commands) + payload


def _parse(data: bytes) -> Image:
    """Parse a synthetic image from a disposable private filesystem path.

    Returns:
        A validated image whose input bytes never come from a system KDK.

    """
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "synthetic.macho"
        _ = path.write_bytes(data)
        return Image(path)


def _rejects(data: bytes, expected: str) -> bool:
    """Confirm an invalid image fails at its expected parser boundary.

    Returns:
        True if ValueError contains the expected diagnostic.

    """
    try:
        _ = _parse(data)
    except ValueError as error:
        return expected in str(error)
    return False


def _uuid_command() -> bytes:
    """Make a correctly sized LC_UUID entry.

    Returns:
        A 24-byte load command.

    """
    return struct.pack("<II", UUID_COMMAND, 24) + UUID_BYTES


def _fat32(
    *,
    second_cpu: int = 0x100000C,
    first_offset: int = 48,
    second_offset: int = 80,
    second_alignment: int = 2,
) -> bytes:
    """Construct a two-architecture fat container for integrity tests.

    Returns:
        Two synthetic nonexecuting 64-bit headers in a FAT32 table.

    """
    thin = _thin()
    first = struct.pack(">IIIII", FAT_CPU, 3, first_offset, len(thin), 2)
    second = struct.pack(
        ">IIIII", second_cpu, 3, second_offset, len(thin), second_alignment
    )
    return (
        b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + first + second + thin * 2
    )


def _bad_indirect_stubs() -> bytes:
    """Make a well-bounded symbol-stub section with a zero stub stride.

    Returns:
        Mach-O metadata that must be refused before dividing by the stride.

    """
    header_size = 32
    segment_size = 152
    dynamic_size = 80
    indirect_offset = header_size + segment_size + dynamic_size
    segment = struct.pack(
        "<II16sQQQQiiII",
        SEGMENT_COMMAND,
        segment_size,
        b"__TEXT",
        0x1000,
        8,
        0,
        0,
        0,
        0,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__stubs",
        b"__TEXT",
        0x1000,
        8,
        0,
        0,
        0,
        0,
        8,
        0,
        0,
        0,
    )
    dynamic = struct.pack(
        "<II18I",
        0xB,
        dynamic_size,
        *([0] * 12),
        indirect_offset,
        1,
        *([0] * 4),
    )
    return _thin((segment + section, dynamic), b"\0" * 4)


def _symbol_image() -> bytes:
    """Construct one bound symbol table and NUL-terminated name.

    Returns:
        A valid thin image with a single known symbol.

    """
    command_bytes = 24
    symbol_offset = HEADER_BYTES + command_bytes
    string_offset = symbol_offset + 16
    command = struct.pack(
        "<IIIIII",
        SYMTAB_COMMAND,
        command_bytes,
        symbol_offset,
        1,
        string_offset,
        len(SAMPLE_NAME),
    )
    symbol = struct.pack("<IBBHQ", 1, 0xF, 1, 0, 0x1000)
    return _thin((command,), symbol + SAMPLE_NAME)


class MachoLoadCommandSafety(TestCase):
    """Refuse incomplete metadata before slicing or interpreting payloads."""

    @staticmethod
    def test_thin_uuid_and_symtab_round_trip() -> None:
        """Preserve UUID and exported symbols from synthetic valid metadata."""
        uuid = _parse(_thin((_uuid_command(),)))
        assert uuid.uuid == UUID_BYTES.hex()
        image = _parse(_symbol_image())
        assert image.symbols == {"_sample": 0x1000}

    @staticmethod
    def test_nonregular_linked_and_large_inputs_fail_closed() -> None:
        """Reject links, pipes and declared huge files without parsing."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.macho"
            original = root / "original.macho"
            _ = original.write_bytes(_thin())
            source.symlink_to(original)
            assert _unsafe_input_rejected(source)
            source.unlink()
            os.mkfifo(source)
            assert _unsafe_input_rejected(source)
            source.unlink()
            with source.open("wb") as stream:
                _ = stream.truncate(MAX_MACHO_BYTES + 1)
            assert _unsafe_input_rejected(source)

    @staticmethod
    def test_fat64_slice_round_trip() -> None:
        """Select a present x86_64 slice with exact bounded metadata."""
        thin = _thin((_uuid_command(),))
        architecture = struct.pack(
            ">IIQQII", FAT_CPU, 3, FAT_TABLE_BYTES, len(thin), 2, 0
        )
        fat = b"\xca\xfe\xba\xbf" + struct.pack(">I", 1)
        source = fat + architecture + thin
        image = _parse(source)
        assert image.uuid == UUID_BYTES.hex()
        assert image.data == thin
        assert image.source_sha256 == hashlib.sha256(source).hexdigest()

    @staticmethod
    def test_truncated_fat64_and_slice_bounds_rejected() -> None:
        """Refuse a missing architecture table or a truncated target slice."""
        truncated = b"\xca\xfe\xba\xbf" + struct.pack(">I", 1)
        assert _rejects(truncated, "fat architecture table")
        architecture = struct.pack(
            ">IIQQII", FAT_CPU, 3, FAT_TABLE_BYTES, 1000, 2, 0
        )
        assert _rejects(truncated + architecture, "fat slice bounds")

    @staticmethod
    def test_short_or_overlong_command_area_rejected() -> None:
        """Reject missing command bytes and declared sizes beyond the file."""
        assert _rejects(
            _thin((struct.pack("<II", UUID_COMMAND, 24),)),
            "load command bounds",
        )
        short = bytearray(_thin())
        struct.pack_into("<II", short, 16, 1, 4096)
        assert _rejects(bytes(short), "command area")
        assert _rejects(
            _thin((struct.pack("<II", UUID_COMMAND, 4),)), "load command bounds"
        )

    @staticmethod
    def test_truncated_uuid_and_segment_commands_rejected() -> None:
        """Enforce fixed field layout before reading UUID or segment data."""
        assert _rejects(_thin((struct.pack("<II", UUID_COMMAND, 8),)), "UUID")
        assert _rejects(
            _thin((struct.pack("<II", SEGMENT_COMMAND, 8),)), "segment"
        )

    @staticmethod
    def test_symbol_table_string_bounds_rejected() -> None:
        """Avoid symbol-name reads that leave declared string storage."""
        image = bytearray(_symbol_image())
        struct.pack_into("<I", image, HEADER_BYTES + 8 + 12, 65536)
        assert _rejects(bytes(image), "symbol table exceeds")

    @staticmethod
    def test_missing_symbol_terminator_rejected() -> None:
        """Reject unterminated symbol names within the table's strsize."""
        image = bytearray(_symbol_image())
        image[-1] = ord("x")
        assert _rejects(bytes(image), "Unterminated Mach-O symbol")

    @staticmethod
    def test_disassembly_command_uses_fixed_shell_free_argv() -> None:
        """Never invoke a shell or use an unqualified xcrun process name."""
        calls: list[list[str]] = []

        class _Output:
            stdout: str = "synthetic disassembly"

        def fake_run(argv: list[str], **options: object) -> _Output:
            calls.append(argv)
            assert options.get("shell") is False
            assert options.get("check") is True
            return _Output()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.macho"
            _ = path.write_bytes(_symbol_image())
            image = Image(path)
            with (
                mock.patch(
                    "tools.macho.shutil.which", return_value="/mock/xcrun"
                ),
                mock.patch("tools.macho.subprocess.run", side_effect=fake_run),
            ):
                _ = image.disassemble("^_sample$")
        assert len(calls) == 1
        assert calls[0][:2] == ["/mock/xcrun", "llvm-objdump"]

    @staticmethod
    def test_truncated_or_oversized_leb_rejected() -> None:
        """Bound malformed LEB128 decoding without hanging the parser."""
        assert all(_leb_rejected(data) for data in (b"\x80", b"\x80" * 16))


def _disassembly_change_rejected(image: Image) -> bool:
    """Detect stale source-path evidence without launching a real disassembler.

    Returns:
        True when the source snapshot mismatch is rejected.

    """
    try:
        _ = image.disassemble("^_sample$")
    except ValueError as error:
        return SOURCE_CHANGED in str(error)
    return False


class MachoFatAndStubSafety(TestCase):
    """Reject malformed fat selection and dynamic stub metadata."""

    @staticmethod
    def test_fat_architectures_are_unique_disjoint_and_aligned() -> None:
        """Reject ambiguity, overlap and offsets into the fat index table."""
        assert _parse(_fat32()).data == _thin()
        malformed = (
            (_fat32(second_cpu=FAT_CPU), "Ambiguous x86_64"),
            (_fat32(second_offset=64), "Overlapping Mach-O"),
            (_fat32(second_offset=81), "alignment"),
            (_fat32(first_offset=44), "fat slice bounds"),
            (_fat32(first_offset=0), "fat slice bounds"),
        )
        for data, reason in malformed:
            assert _rejects(data, reason), reason

    @staticmethod
    def test_load_commands_reject_duplicates_and_unparsed_tail() -> None:
        """Never use conflicting metadata or unaccounted command bytes."""
        uuid = _uuid_command()
        assert _rejects(_thin((uuid, uuid)), "Duplicate Mach-O UUID")
        symbol = struct.pack("<IIIIII", SYMTAB_COMMAND, 24, 0, 0, 0, 0)
        assert _rejects(
            _thin((symbol, symbol)), "Duplicate Mach-O symbol table"
        )
        invalid_count = bytearray(_thin((uuid,)))
        struct.pack_into("<I", invalid_count, 16, 0)
        assert _rejects(bytes(invalid_count), "command bytes/count disagree")

    @staticmethod
    def test_completed_leb_values_stay_within_signed_and_unsigned_64_bits() -> (
        None
    ):
        """Reject 70-bit values even when the final byte ends the stream."""
        assert Image.leb(b"\xff" * 9 + b"\x01", 0) == ((1 << 64) - 1, 10)
        assert Image.leb(b"\x80" * 9 + b"\x7f", 0, signed=True) == (
            -(1 << 63),
            10,
        )
        for payload in (b"\x80" * 9 + b"\x02", b"\xff" * 9 + b"\x02"):
            assert _leb_rejected(payload)
            assert _leb_rejected(payload, signed=True)

    @staticmethod
    def test_stub_section_requires_nonzero_stride() -> None:
        """Reject zero-sized stubs before dividing by the stride."""
        assert _rejects(
            _bad_indirect_stubs(), "indirect symbol index or stride"
        )


class MachoSnapshotHashSafety(TestCase):
    """Use hashes of bounded source bytes, never later path reopens."""

    @staticmethod
    def test_disassembler_rejects_changed_snapshot_before_subprocess() -> None:
        """Refuse an input replaced after the initial checked Mach-O read."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "original.macho"
            source = _symbol_image()
            _ = path.write_bytes(source)
            image = Image(path)
            _ = path.write_bytes(source + b"tampered")
            with (
                mock.patch(
                    "tools.macho.shutil.which", return_value="/mock/xcrun"
                ),
                mock.patch("tools.macho.subprocess.run") as launch,
            ):
                assert _disassembly_change_rejected(image)
            launch.assert_not_called()

    @staticmethod
    def test_disassembler_rejects_source_change_during_subprocess() -> None:
        """Do not return disassembly evidence if a source changes in flight."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "original.macho"
            source = _symbol_image()
            _ = path.write_bytes(source)
            image = Image(path)

            class _Output:
                stdout: str = "synthetic disassembly"

            def fake_run(argv: list[str], **kwargs: object) -> _Output:
                assert argv[0] == FAKE_XCRUN
                assert kwargs.get("shell") is False
                _ = path.write_bytes(source + b"tampered")
                return _Output()

            with (
                mock.patch(
                    "tools.macho.shutil.which", return_value="/mock/xcrun"
                ),
                mock.patch(
                    "tools.macho.subprocess.run", side_effect=fake_run
                ) as launch,
            ):
                assert _disassembly_change_rejected(image)
            launch.assert_called_once()

    @staticmethod
    def test_cli_hash_uses_verified_bytes_without_path_reread() -> None:
        """Print only the snapshot hash; never reopen the path for reporting."""
        contents = _thin((_uuid_command(),))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.macho"
            _ = path.write_bytes(contents)
            output = io.StringIO()
            with (
                mock.patch.object(
                    Path,
                    "read_bytes",
                    side_effect=AssertionError("unsafe second read"),
                ),
                mock.patch("sys.argv", ["macho.py", str(path)]),
                redirect_stdout(output),
            ):
                macho.main()
        assert "SHA256=" + hashlib.sha256(contents).hexdigest() in (
            output.getvalue()
        )


def _unsafe_input_rejected(path: Path) -> bool:
    """Check that unsafe path types fail before Mach-O parsing.

    Returns:
        True if input is refused for safety.

    """
    try:
        _ = Image(path)
    except OSError, ValueError:
        return True
    return False


def _leb_rejected(data: bytes, *, signed: bool = False) -> bool:
    """Check a malformed signed/unsigned LEB128 stream.

    Returns:
        True when the decoder refuses the supplied incomplete input.

    """
    try:
        _ = Image.leb(data, 0, signed=signed)
    except ValueError:
        return True
    return False
