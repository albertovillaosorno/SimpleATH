# Copyright (c) 2026 SimpleATH contributors.
"""Preflight bounded class-name edits in legacy ABI research payloads."""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from collections.abc import Mapping


def _check_range(size: int, start: int, length: int) -> None:
    """Reject an invalid CString range before reading any image bytes.

    Raises:
        ValueError: The section is not wholly inside the image.

    """
    if start < 0 or length < 0:
        message = "CString section is outside the image"
        raise ValueError(message)
    if start > size or length > size - start:
        message = "CString section is outside the image"
        raise ValueError(message)


def _check_sections(size: int, spans: list[tuple[int, int]]) -> None:
    """Validate disjoint CString ranges against one image length.

    Raises:
        ValueError: A range crosses its image or another range.

    """
    for start, length in spans:
        _check_range(size, start, length)
    ordered = sorted(spans)
    for (previous_start, previous_size), (start, _) in pairwise(ordered):
        if start < previous_start + previous_size:
            message = "Overlapping CString sections"
            raise ValueError(message)


def _replacement(
    name: str, size: int, replacements: Mapping[str, str]
) -> bytes:
    """Encode one replacement while preserving original class storage.

    Returns:
        The zero-padded class bytes, excluding the existing terminator.

    Raises:
        ValueError: Replacement is not ASCII, has NUL or is too long.

    """
    try:
        data = replacements[name].encode("ascii")
    except UnicodeEncodeError as error:
        message = "Non-ASCII replacement for class string: " + name
        raise ValueError(message) from error
    if 0 in data or len(data) > size:
        message = "Invalid replacement for class string: " + name
        raise ValueError(message)
    return data.ljust(size, b"\0")


def _collect_edits(
    data: bytearray,
    spans: list[tuple[int, int]],
    replacements: Mapping[str, str],
) -> tuple[list[tuple[int, int, bytes]], dict[str, list[int]]]:
    """Gather replacement positions without changing the input.

    Returns:
        Planned edits and original name-to-offset mapping.

    Raises:
        ValueError: A CString is not terminated or replacement is invalid.

    """
    edits: list[tuple[int, int, bytes]] = []
    found: dict[str, list[int]] = {}
    for start, size in spans:
        limit = start + size
        position = start
        while position < limit:
            end = data.find(0, position, limit)
            if end < 0:
                message = "Unterminated CString in image section"
                raise ValueError(message)
            raw = bytes(data[position:end])
            name = raw.decode("ascii", errors="replace")
            if name in replacements:
                replacement = _replacement(name, len(raw), replacements)
                edits.append((position, end, replacement))
                found.setdefault(name, []).append(position)
            position = end + 1
    return edits, found


def rename_class_cstrings(
    data: bytearray,
    sections: Iterable[tuple[int, int]],
    replacements: Mapping[str, str],
    *,
    require_all: bool,
) -> dict[str, list[int]]:
    """Rename exact class strings without mutating a rejected image.

    Args:
        data: Image bytes addressed by virtual offset.
        sections: CString start and byte count, in image section order.
        replacements: Old class names and bounded replacement names.
        require_all: Reject an image missing any expected class name.

    Returns:
        Original names mapped to their encountered image offsets.

    Raises:
        ValueError: A span, terminator, replacement or required class is bad.

    """
    spans = list(sections)
    _check_sections(len(data), spans)
    edits, found = _collect_edits(data, spans, replacements)
    if require_all and set(found) != set(replacements):
        missing = set(replacements) - set(found)
        message = f"Class strings missing: {missing}"
        raise ValueError(message)
    for position, end, replacement in edits:
        data[position:end] = replacement
    return found
