# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Pure disassembly inventory tests, never invoking xcrun or audit output."""

from unittest import TestCase

from tools.audit_codecs import disassembly_blocks

CAPABILITY_NAME = "_getCapability"
SCAN_LENGTH_CHECK = "0x48c"
EXPECTED_BLOCK_COUNT = 2
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
