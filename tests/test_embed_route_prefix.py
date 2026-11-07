# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Synthetic disassembly parsing without executing the native Xcode tool."""

from pathlib import Path
import sys
from unittest import TestCase

# The legacy CLI uses script-relative imports; never invoke its entrypoint.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from embed import checked_route_prefix

NAME = "__ZSomeRoute"
BASE = 0x1000
MINIMUM = 14
MAXIMUM = 32
CONTIGUOUS = (
    "1000: 48 89 e5  pushq %rbp\n"
    "1003: 48 83 ec  subq %rsp\n"
    "1006: 48 89 45  movq %rax\n"
    "1009: 48 8b 45  movq %rdi\n"
    "100c: 90 90  nop"
)
REJECT_RELATIVE = "Non-relocatable"
REJECT_GAP = "Non-contiguous"
REJECT_SIZE = "Invalid"


def _error(text: str) -> str:
    """Return a rejected synthetic prefix's safety diagnostic.

    Returns:
        The rejection message, or empty string for an accepted prefix.

    """
    try:
        _ = checked_route_prefix(text, NAME, BASE)
    except RuntimeError as error:
        return str(error)
    return ""


class RoutePrefixSafetyTests(TestCase):
    """No relocation of unsafe control flow or incomplete instructions."""

    @staticmethod
    def test_minimal_contiguous_prefix() -> None:
        """Accumulate instruction widths and stop at the first 14 bytes."""
        assert checked_route_prefix(CONTIGUOUS, NAME, BASE) == MINIMUM
        assert (
            checked_route_prefix(CONTIGUOUS + "\n100e: eb 00  jmp", NAME, BASE)
            == MINIMUM
        )

    @staticmethod
    def test_displacement_or_control_flow_rejected() -> None:
        """Reject RIP-relative operations and all control-transfer opcodes."""
        for instruction in (
            "movq %rip, %rax",
            "callq target",
            "jmp label",
            "retq",
            "loop target",
        ):
            assert REJECT_RELATIVE in _error(
                "1000: 48 89 e5  " + instruction + "\n" + CONTIGUOUS
            )

    @staticmethod
    def test_gapped_or_absent_instructions_rejected() -> None:
        """Do not accept missing bytes or discontiguous address records."""
        assert REJECT_GAP in _error("1001: 90  nop")
        assert REJECT_SIZE in _error("some disassembler title\n1000: 90  nop")
        assert REJECT_SIZE in _error("no instructions at all")

    @staticmethod
    def test_complete_oversized_instruction_rejected() -> None:
        """Never split a disassembled instruction to reach the minimum."""
        oversized = "1000: " + ("90 " * (MAXIMUM + 1)) + " nop"
        assert REJECT_SIZE in _error(oversized)
