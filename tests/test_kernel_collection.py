# Copyright (c) 2026 SimpleATH contributors.
"""Exercise bounded offline Mach-O kernel image parsing with synthetic bytes."""

from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
from unittest import TestCase
from unittest import mock

from tools import kernel_collection as kc
from tools import native_references as references

VIRTUAL = 0x1000
EMPTY = b""
N_STRX = 1
SECTION_WORD_SIZE = 4


def _segment(
    *,
    address: int = VIRTUAL,
    length: int = 64,
    file_offset: int = 0,
    file_size: int = kc.HEADER_SIZE,
) -> bytes:
    return struct.pack(
        "<II16sQQQQiiII",
        kc.SEGMENT_COMMAND,
        kc.SEGMENT_SIZE,
        b"__TEXT",
        address,
        length,
        file_offset,
        file_size,
        7,
        5,
        0,
        0,
    )


def _image(commands: list[bytes], extra: bytes = b"") -> bytes:
    header = bytearray(kc.HEADER_SIZE)
    header[:4] = kc.MAGIC_64_LE
    struct.pack_into("<I", header, 4, kc.CPU_X86_64)
    struct.pack_into("<II", header, 16, len(commands), sum(map(len, commands)))
    return bytes(header) + b"".join(commands) + extra


def _rejected(data: bytes) -> bool:
    try:
        _ = kc.KernelImage(data)
    except ValueError, struct.error, UnicodeError:
        return True
    return False


def _read_rejected(image: kc.KernelImage, address: int, size: int) -> bool:
    try:
        _ = image.read(address, size)
    except ValueError:
        return True
    return False


def _section(
    *, address: int = VIRTUAL, size: int = 4, offset: int = 0, flags: int = 0
) -> bytes:
    return struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text",
        b"__TEXT",
        address,
        size,
        offset,
        0,
        0,
        0,
        flags,
        0,
        0,
        0,
    )


def _section_image(section: bytes) -> bytes:
    segment = bytearray(_segment())
    struct.pack_into("<I", segment, 4, kc.SEGMENT_SIZE + kc.SECTION_SIZE)
    struct.pack_into("<I", segment, 64, 1)
    return _image([bytes(segment) + section])


class _SyntheticSnapshot:
    """Implement the minimal checked JSON-reader surface without I/O."""

    def __init__(self, path: Path) -> None:
        """Record the selected synthetic path."""
        self.path: Path = path

    @staticmethod
    def pointer(address: int) -> int:
        """Preserve synthetic pointer addresses.

        Returns:
            The supplied address without dereferencing a real image.

        """
        return address

    @staticmethod
    def version() -> str:
        """Return an offline marker.

        Returns:
            A synthetic kernel version label.

        """
        return "synthetic"

    def close(self) -> None:
        """No file or mapped memory is owned."""


def _json_rejected(source: Path) -> bool:
    """Check that invalid factory results fail before binary initialization.

    Returns:
        True if the invalid JSON factory was rejected.

    """
    try:
        _ = kc.KernelCollection(source)
    except ValueError:
        return True
    return False


class KernelImageBounds(TestCase):
    """Reject malformed load commands, sections, names and virtual ranges."""

    @staticmethod
    def test_mapped_bytes_and_unbacked_virtual_bytes() -> None:
        """Return file-backed metadata and never expose truncated zero-fill."""
        image = kc.KernelImage(_image([_segment()]))
        assert image.base == VIRTUAL
        assert image.read(VIRTUAL, 4) == kc.MAGIC_64_LE
        assert image.read(VIRTUAL, 0) == EMPTY
        assert _read_rejected(image, VIRTUAL + kc.HEADER_SIZE, 1)
        assert _read_rejected(image, -1, 1)
        assert _read_rejected(image, VIRTUAL, -1)
        assert _read_rejected(image, kc.MAX_U64, 2)
        assert _read_rejected(image, VIRTUAL + 1, 128)

    @staticmethod
    def test_reject_truncated_or_malformed_load_commands() -> None:
        """Require every declared command to lie within its own table."""
        valid = _segment()
        assert _rejected(b"")
        assert _rejected(_image([]))
        assert _rejected(_image([valid[:-1]]))
        assert _rejected(_image([b"\0" * kc.COMMAND_SIZE]))
        invalid_size = struct.pack("<II", kc.SEGMENT_COMMAND, 1)
        assert _rejected(_image([invalid_size]))
        oversize = struct.pack("<II", kc.SEGMENT_COMMAND, 1000)
        assert _rejected(_image([oversize]))
        invalid_count = bytearray(_segment())
        struct.pack_into("<I", invalid_count, 64, 1)
        assert _rejected(_image([bytes(invalid_count)]))
        assert _rejected(_image([_segment(file_offset=1000)]))
        assert _rejected(_image([_segment(file_size=1000)]))

    @staticmethod
    def test_reject_bad_cpu_magic_and_command_sizes() -> None:
        """Check the architecture and declared command count/size bounds."""
        valid = bytearray(_image([_segment()]))
        valid[0] = 0
        assert _rejected(bytes(valid))
        valid[0] = kc.MAGIC_64_LE[0]
        struct.pack_into("<I", valid, 4, 0)
        assert _rejected(bytes(valid))
        struct.pack_into("<I", valid, 4, kc.CPU_X86_64)
        struct.pack_into("<I", valid, 16, 100)
        assert _rejected(bytes(valid))
        struct.pack_into("<I", valid, 16, 1)
        struct.pack_into("<I", valid, 20, 0)
        assert _rejected(bytes(valid))

    @staticmethod
    def test_binary_collection_opens_and_closes_its_mapped_fileset() -> None:
        """Keep the existing collection API on a synthetic nested Mach-O."""
        name = b"com.apple.kernel\0"
        inner_offset = 256
        entry = (
            struct.pack(
                "<IIQQII",
                kc.FILESET_COMMAND,
                kc.FILESET_SIZE + len(name),
                VIRTUAL,
                inner_offset,
                kc.FILESET_SIZE,
                0,
            )
            + name
        )
        root = _image([_segment(), entry])
        assert len(root) < inner_offset
        nested = _image([_segment(file_offset=inner_offset)])
        source = root + bytes(inner_offset - len(root)) + nested
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "synthetic.kc"
            _ = archive.write_bytes(source)
            collection = kc.KernelCollection(archive)
            assert isinstance(collection, kc.KernelCollection)
            assert collection.root.entries[kc.KERNEL_NAME] == (
                VIRTUAL,
                inner_offset,
            )
            assert collection.kernel.base == VIRTUAL
            assert collection.fixup_base == VIRTUAL
            collection.close()
            assert collection.data.closed

    @staticmethod
    def test_pinned_json_dispatch_uses_checked_reference_collection() -> None:
        """A committed checksum-matching snapshot stays a JSON reader."""
        source = references.DIRECTORY / "Tahoe.json"
        collection = kc.KernelCollection(source)
        assert isinstance(collection, references.ReferenceCollection)
        assert (
            collection.version()
            == references.load_reference(source)["kernelVersion"]
        )
        collection.close()

    @staticmethod
    def test_json_factory_accepts_only_checked_snapshot_operations() -> None:
        """Dispatch JSON snapshots without opening them as Mach-O files."""
        source = Path("/synthetic/check.json")
        snapshot = _SyntheticSnapshot(source)
        factory = mock.Mock(return_value=snapshot)
        module = SimpleNamespace(ReferenceCollection=factory)
        with mock.patch("importlib.import_module", return_value=module):
            result = kc.KernelCollection(source)
        assert result is snapshot
        factory.assert_called_once_with(source)

        malformed = SimpleNamespace(
            ReferenceCollection=mock.Mock(return_value=object())
        )
        with mock.patch("importlib.import_module", return_value=malformed):
            assert _json_rejected(source)

    @staticmethod
    def test_sections_must_fit_virtual_and_file_extents() -> None:
        """Enforce file-backed section bounds and permit validated zero-fill."""
        image = kc.KernelImage(_section_image(_section()))
        assert image.sections == [("__TEXT", "__text", VIRTUAL, 4, 0)]
        assert _rejected(_section_image(_section(address=VIRTUAL - 1)))
        assert _rejected(_section_image(_section(address=VIRTUAL + 61)))
        assert _rejected(_section_image(_section(offset=999)))
        zero_fill = kc.KernelImage(
            _section_image(_section(address=VIRTUAL + 32, offset=999, flags=1))
        )
        assert zero_fill.sections[0][3] == SECTION_WORD_SIZE

    @staticmethod
    def test_symbols_reject_unbounded_offsets_and_nonterminated_names() -> None:
        """Accept only checked symbol entries with bounded names."""
        segment = _segment()
        table_start = kc.HEADER_SIZE + len(segment) + kc.SYMTAB_SIZE
        strings_start = table_start + kc.SYMBOL_SIZE
        text = b"\0entry\0"
        symtab = struct.pack(
            "<IIIIII",
            kc.SYMTAB_COMMAND,
            kc.SYMTAB_SIZE,
            table_start,
            1,
            strings_start,
            len(text),
        )
        entry = struct.pack("<IBBHQ", N_STRX, 0x0F, 1, 0, VIRTUAL)
        data = _image([segment, symtab], entry + text)
        image = kc.KernelImage(data)
        assert image.symbols == {"entry": VIRTUAL}
        assert image.exports == {"entry"}
        assert _rejected(_image([segment, symtab], entry + b"\0entry!"))
        corrupted = struct.pack("<IBBHQ", 128, 0x0F, 1, 0, VIRTUAL)
        assert _rejected(_image([segment, symtab], corrupted + text))
        invalid_table = struct.pack(
            "<IIIIII", kc.SYMTAB_COMMAND, kc.SYMTAB_SIZE, 1000, 1, 0, 1
        )
        assert _rejected(_image([segment, invalid_table]))

    @staticmethod
    def test_fileset_entry_name_offset_must_be_bounded() -> None:
        """Reject invalid fileset offsets and unterminated names."""
        header = struct.pack(
            "<IIQQII", kc.FILESET_COMMAND, kc.FILESET_SIZE, 0, 800, 0, 0
        )
        assert _rejected(_image([_segment(), header]))
        body = struct.pack(
            "<IIQQII", kc.FILESET_COMMAND, kc.FILESET_SIZE, 0, 0, 800, 0
        )
        assert _rejected(_image([_segment(), body]))
        u = struct.pack(
            "<IIQQII", kc.FILESET_COMMAND, kc.FILESET_SIZE + 6, 0, 0, 32, 0
        )
        assert _rejected(_image([_segment(), u + b"abcxyz"]))
