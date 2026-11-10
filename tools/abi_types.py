# Copyright (c) 2026 SimpleATH contributors.
"""Checked scalar and JSON boundaries for offline ABI inspection tools."""

import json
import math
import plistlib
import struct
from typing import Never
from typing import TYPE_CHECKING
from typing import TypeIs

if TYPE_CHECKING:
    from collections.abc import Buffer
    from collections.abc import Callable
    import mmap

type JsonValue = (
    bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None
)
JSON_DEPTH_LIMIT = 64
JSON_INPUT_LIMIT = 128 * 1024 * 1024


def invalid(message: str) -> Never:
    """Reject malformed input.

    Raises:
        ValueError: Always, with the supplied diagnostic.

    """
    raise ValueError(message)


def integer(value: object) -> int:
    """Return a checked integer, excluding boolean values.

    Returns:
        The supplied integer.

    """
    if not isinstance(value, int) or isinstance(value, bool):
        invalid("Expected an integer")
    return value


def string(value: object) -> str:
    """Return a checked string.

    Returns:
        The supplied string.

    """
    if not isinstance(value, str):
        invalid("Expected a string")
    return value


def json_value(value: object, depth: int = 0) -> JsonValue:
    """Validate a JSON value without accepting unknown object types.

    Returns:
        Recursively checked JSON data.

    """
    if depth > JSON_DEPTH_LIMIT:
        invalid("JSON nesting exceeds the inspection limit")
    if isinstance(value, float) and not math.isfinite(value):
        invalid("JSON numbers must be finite")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return _json_container(value, depth)


def _is_list(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _is_dict(value: object) -> TypeIs[dict[object, object]]:
    return isinstance(value, dict)


def _json_container(value: object, depth: int) -> JsonValue:
    if _is_list(value):
        return [json_value(item, depth + 1) for item in value]
    if _is_dict(value):
        return {
            string(key): json_value(item, depth + 1)
            for key, item in value.items()
        }
    invalid("Expected a JSON scalar, array or object")


def mapping(value: object) -> dict[str, JsonValue]:
    """Validate a JSON object and its nested contents.

    Returns:
        A checked string-keyed JSON dictionary.

    """
    result = json_value(value)
    if not isinstance(result, dict):
        invalid("Expected a JSON object")
    return result


def sequence(value: object) -> list[JsonValue]:
    """Validate a JSON array and its nested contents.

    Returns:
        A checked JSON array.

    """
    result = json_value(value)
    if not isinstance(result, list):
        invalid("Expected a JSON array")
    return result


def json_object(data: str | bytes) -> dict[str, JsonValue]:
    """Decode bounded JSON text and require an object root.

    Returns:
        A recursively checked dictionary.

    """
    if len(data) > JSON_INPUT_LIMIT:
        invalid("JSON input exceeds the inspection limit")
    return mapping(_decode(data, json.loads))


def _decode(
    data: str | bytes, decoder: Callable[[str | bytes], object]
) -> object:
    return decoder(data)


def plist_object(data: bytes) -> dict[str, JsonValue]:
    """Decode plist metadata that contains JSON-compatible values.

    Returns:
        A checked dictionary; binary/data/date plist values are rejected.

    """
    return mapping(_decode_bytes(data, plistlib.loads))


def unpack_values(
    data: bytes | mmap.mmap, format_string: str, offset: int = 0
) -> tuple[int | bytes, ...]:
    """Unpack the integer and byte-string fields used by Mach-O records.

    Returns:
        Checked scalar fields in the supplied struct format.

    """
    values = _unpack(data, format_string, offset, decoder=struct.unpack_from)
    return tuple(_binary_scalar(item) for item in values)


def unpack_integers(
    data: bytes | mmap.mmap, format_string: str, offset: int = 0
) -> tuple[int, ...]:
    """Unpack and check a record containing integer fields only.

    Returns:
        Checked integer fields.

    """
    return tuple(
        integer(item) for item in unpack_values(data, format_string, offset)
    )


def _unpack(
    data: Buffer,
    format_string: str,
    offset: int,
    *,
    decoder: Callable[[str, Buffer, int], tuple[object, ...]],
) -> tuple[object, ...]:
    return decoder(format_string, data, offset)


def _binary_scalar(value: object) -> int | bytes:
    if isinstance(value, bytes):
        return value
    return integer(value)


def byte_string(value: object) -> bytes:
    """Require a byte string from a parsed binary record.

    Returns:
        The checked byte string.

    """
    if not isinstance(value, bytes):
        invalid("Expected a byte string")
    return value


def _decode_bytes(data: bytes, decoder: Callable[[bytes], object]) -> object:
    return decoder(data)
