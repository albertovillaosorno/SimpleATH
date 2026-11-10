# Copyright (c) 2026 SimpleATH contributors.
"""Pure synthetic regression for pinned profile codegen and guard choices."""

from pathlib import Path
from unittest import TestCase

from tools import macho

# These pure internals are intentionally tested without invoking the generator.
from tools.profiles import _ProfileImage  # pyright: ignore[reportPrivateUsage]  # ruff: ignore[import-private-name] - Synthetic byte model only.
from tools.profiles import _copy_sites  # pyright: ignore[reportPrivateUsage]  # ruff: ignore[import-private-name] - Check safety gate directly.
from tools.profiles import _guard_mismatch  # pyright: ignore[reportPrivateUsage]  # ruff: ignore[import-private-name] - Test mask behavior directly.
from tools.profiles import _profile_header  # pyright: ignore[reportPrivateUsage]  # ruff: ignore[import-private-name] - Check C++ layout directly.
from tools.profiles import _profile_lines  # pyright: ignore[reportPrivateUsage]  # ruff: ignore[import-private-name] - Synthetic codegen only.

ADDRESS = 0x1000
GUARD_BYTES = 32
CHANGED_AT = 4
ORIGINAL = bytes(range(GUARD_BYTES))
CHANGED = ORIGINAL[:CHANGED_AT] + bytes([255]) + ORIGINAL[CHANGED_AT + 1 :]
EXPECTED_HEADER = (
    "struct ByteGuard { uint32_t offset; uint8_t bytes[32]; "
    "uint8_t mask[32]; };"
)
EXPECTED_FAILURE = "Unexpected copy callsite count"


def _fake_image(data: bytes) -> macho.Image:
    """Create a synthetic mapped-data view without reading a real binary.

    Returns:
        A byte-backed Image usable by the pure guard helpers.

    """
    image = object.__new__(macho.Image)
    image.data = data
    image.segments = [("SYNTH", ADDRESS, len(data), 0, len(data))]
    image.uuid = "synthetic"
    return image


class ProfileOutputRegression(TestCase):
    """Keep output lines and guarded offsets stable across parser refactors."""

    @staticmethod
    def test_initializer_spelling_matches_original_byteguard_layout() -> None:
        """Emit the original C++ nested hex and masked bytes, not reprs."""
        image = _fake_image(ORIGINAL)
        profile = _ProfileImage(
            "Skywalk",
            Path("/synthetic"),
            image,
            [],
            [(ADDRESS, "test")],
            [],
            [],
        )
        lines = _profile_lines(profile)
        literal = ", ".join(f"0x{value:02X}" for value in ORIGINAL)
        mask = ", ".join("0xFF" for _ in range(GUARD_BYTES))
        assert lines == [
            "static const ByteGuard kSkywalkGuards[] = {",
            f"    {{0x{ADDRESS:X}, {{{literal}}}, {{{mask}}}}},",
            "};",
            "",
        ]

    @staticmethod
    def test_differing_backend_byte_must_not_be_relaxed_except_relocation() -> (
        None
    ):
        """Ignore differences only at bytes covered by either relocation."""
        original = _fake_image(ORIGINAL)
        changed = _fake_image(CHANGED)
        assert _guard_mismatch(original, changed, [], address=ADDRESS)
        assert not _guard_mismatch(
            original,
            changed,
            [(ADDRESS + CHANGED_AT, 1, "_symbol", 0)],
            address=ADDRESS,
        )
        assert _guard_mismatch(
            original,
            changed,
            [(ADDRESS + CHANGED_AT + 1, 1, "_symbol", 0)],
            address=ADDRESS,
        )

    @staticmethod
    def test_copy_sites_require_expected_count() -> None:
        """Refuse a foreign copy-site set before its bytes are inspected."""
        rejected = False
        try:
            _ = _copy_sites(_fake_image(ORIGINAL), [], "AirPort", guards=[])
        except RuntimeError as error:
            rejected = str(error) == EXPECTED_FAILURE
        assert rejected

    @staticmethod
    def test_generated_header_prologue_keeps_exact_c_layout() -> None:
        """Preserve C++ declaration bytes in the array of generated lines."""
        lines = _profile_header()
        assert EXPECTED_HEADER in lines
