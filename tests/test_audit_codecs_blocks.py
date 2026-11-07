# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Pure disassembly inventory tests, never invoking xcrun or audit output."""

from pathlib import Path
import tempfile
from unittest import TestCase
from unittest import mock

from tools import audit_codecs
from tools.abi_types import json_object
from tools.audit_codecs import analyze_scalar_handler
from tools.audit_codecs import disassembly_blocks
from tools.audit_codecs import verify_copy_counts
from tools.macho import Image

CAPABILITY_NAME = "_getCapability"
SCAN_LENGTH_CHECK = "0x48c"
EXPECTED_BLOCK_COUNT = 2
COPY_TOTAL = 18
BACKEND_EXPECTED = 16
SCALAR_ADDRESS = 0x1234
SCALAR_REQUEST = 7
SCALAR_SYMBOL = "_safeScalar"
SAMPLE_DISASSEMBLY = (
    "1234 <_getCapability>:\n"
    "    1234: movl $0xc, %eax\n\n"
    "1456 <_getScan>:\n"
    "    1456: cmpl $0x48c, 0x18(%rbx)\n"
)


def _duplicate_rejected(text: str) -> bool:
    """Ensure duplicate handler addresses cannot silently shadow evidence.

    Returns:
        True when a duplicate block raises ValueError.

    """
    try:
        _ = disassembly_blocks(text)
    except ValueError:
        return True
    return False


class CodecDisassemblyBlockInventory(TestCase):
    """Keep source evidence indexing exact and fail closed."""

    @staticmethod
    def test_known_disassembly_blocks_are_indexed() -> None:
        """Retain symbol blocks and original source lines by entry address."""
        blocks = disassembly_blocks(SAMPLE_DISASSEMBLY)
        assert set(blocks) == {0x1234, 0x1456}
        assert CAPABILITY_NAME in blocks[0x1234]
        assert SCAN_LENGTH_CHECK in blocks[0x1456]

    @staticmethod
    def test_unrelated_text_is_ignored() -> None:
        """Do not interpret diagnostic banners as evidence of a handler."""
        blocks = disassembly_blocks(
            "warning: synthetic\n\n" + SAMPLE_DISASSEMBLY
        )
        assert len(blocks) == EXPECTED_BLOCK_COUNT

    @staticmethod
    def test_duplicate_address_is_rejected() -> None:
        """Do not allow a second symbol to overwrite the first block."""
        duplicate = "1234 <_replacement>:\n  movq %rax, %rbx\n"
        assert _duplicate_rejected(SAMPLE_DISASSEMBLY + "\n" + duplicate)

    @staticmethod
    def test_empty_or_uppercase_heading_is_not_a_valid_block() -> None:
        """Only accept exact expected lowercase hexadecimal heading shape."""
        assert disassembly_blocks("") == {}
        assert disassembly_blocks("ABCD <_symbol>:\n  ret\n") == {}


def _fake_image() -> Image:
    """Build only the symbol-lookup fields of an offline Image.

    Returns:
        A synthetic image that never reads an on-disk Mach-O.

    """
    image = object.__new__(Image)
    image.binds = {SCALAR_ADDRESS: SCALAR_SYMBOL}
    image.addresses = []
    image.keys = []
    return image


def _rejects_scalar(block: str) -> bool:
    """Check that unsafe scalar request memory layouts are fatal.

    Returns:
        True when the scalar request is rejected before emitting evidence.

    """
    try:
        _ = analyze_scalar_handler(
            _fake_image(), SCALAR_REQUEST, SCALAR_ADDRESS, block=block
        )
    except RuntimeError:
        return True
    return False


def _rejects_copy_counts(copies: list[dict[str, str]]) -> bool:
    """Check invalid copy relocation totals are fatal.

    Returns:
        True when the supplied counts are rejected.

    """
    try:
        verify_copy_counts(copies)
    except RuntimeError:
        return True
    return False


class CodecScalarAndCopyGuards(TestCase):
    """Exercise fail-closed guards without KDK or disassembler access."""

    @staticmethod
    def test_valid_scalar_store_is_admitted() -> None:
        """Emit request, address and source symbol for a guarded scalar."""
        entry = analyze_scalar_handler(
            _fake_image(),
            SCALAR_REQUEST,
            SCALAR_ADDRESS,
            block="movl %eax, 0x14(%r8)",
        )
        assert entry is not None
        assert entry["request"] == SCALAR_REQUEST
        assert entry["symbol"] == SCALAR_SYMBOL

    @staticmethod
    def test_scalar_pointer_dereference_is_rejected() -> None:
        """Never mistake a handler accessing data pointers for a scalar."""
        assembly = "movl %eax, 0x14(%r8)\nmovl 0x20(%r8), %eax"
        assert _rejects_scalar(assembly)

    @staticmethod
    def test_unverified_scalar_register_is_rejected() -> None:
        """Require a proven apple80211req alias for an indirect store."""
        assert _rejects_scalar("movl %eax, 0x14(%rbx)")

    @staticmethod
    def test_alias_must_precede_store() -> None:
        """A later register copy cannot justify an earlier scalar store."""
        assert _rejects_scalar("movl %eax, 0x14(%rbx)\nmovq %r8, %rbx")
        assert not _rejects_scalar("movq %r8, %rbx\nmovl %eax, 0x14(%rbx)")

    @staticmethod
    def test_every_scalar_store_requires_a_verified_destination() -> None:
        """Reject a second store to an unverified output register."""
        assert _rejects_scalar("movl %eax, 0x14(%r8)\nmovl %ecx, 0x14(%rbx)")

    @staticmethod
    def test_unknown_copy_image_is_not_pinned_abi_evidence() -> None:
        """Pairwise totals alone must not admit an unknown relocation owner."""
        copies = [{"image": "Legacy"}] * 15
        copies += [{"image": "AirPort"}, {"image": "AirPortOriginal"}]
        copies.append({"image": "UnexpectedBackend"})
        assert len(copies) == COPY_TOTAL
        assert _rejects_copy_counts(copies)

    @staticmethod
    def test_copy_relocations_require_exact_backend_counts() -> None:
        """Accept only the legacy and two backend totals from pinned ABI."""
        copies = [{"image": "Legacy"}] * (COPY_TOTAL - 2 * 2)
        copies += [{"image": "AirPort"}, {"image": "AirPort"}]
        copies += [{"image": "AirPortOriginal"}, {"image": "AirPortOriginal"}]
        assert len(copies) == COPY_TOTAL
        assert verify_copy_counts(copies) is None
        assert _rejects_copy_counts(copies[:-1])
        shifted = [dict(entry) for entry in copies]
        shifted[-1]["image"] = "AirPort"
        assert _rejects_copy_counts(shifted)
        assert (
            sum(e["image"] in {"Legacy", "AirPort"} for e in copies)
            == BACKEND_EXPECTED
        )


class PinnedCodecSnapshotHash(TestCase):
    """Keep codec evidence tied to already inspected bounded source bytes."""

    @staticmethod
    def test_report_does_not_reopen_original_image_path() -> None:
        """Persist the Image snapshot fingerprint without reading it again."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            image = _fake_image()
            image.path = root / "missing-image"
            image.source_sha256 = "pinned-fixture-checksum"
            with (
                mock.patch.object(audit_codecs, "ROOT", root),
                mock.patch.object(
                    audit_codecs,
                    "_load_legacy_handlers",
                    return_value=(image, (), {}),
                ),
                mock.patch.object(
                    audit_codecs, "_scalar_gets", return_value=[]
                ),
                mock.patch.object(audit_codecs, "_copy_sites", return_value=[]),
                mock.patch.object(audit_codecs, "_verify_get_layout"),
                mock.patch.object(audit_codecs, "_verify_set_layout"),
            ):
                audit_codecs.main()
            payload = json_object(
                (root / "docs/Control-Codecs.json").read_bytes()
            )
            assert payload["legacySHA256"] == image.source_sha256
