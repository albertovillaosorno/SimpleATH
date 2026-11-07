#!/usr/bin/env python3
# Copyright (c) 2026 SimpleATH contributors.
"""Generate AR9565 2.4 GHz register presets from pinned Linux ath9k sources.

These files are C++ data only. They MUST NOT be used for hardware writes before
PCI transport, EEPROM/regulatory calibration and reset have been implemented.
The input tables carry a permissive Qualcomm/Atheros license, copied verbatim
into each generated file; they are not claimed as newly authored AGPL code.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
from typing import Final

ROOT = Path(__file__).resolve().parent.parent
ATH9K = ROOT / "linux/drivers/net/wireless/ath/ath9k"
OUTPUT = ROOT / "src/hardware/generated/Ar9565InitTables.hpp"
SOURCES = {
    "ar9565_1p0": ATH9K / "ar9565_1p0_initvals.h",
    "ar9565_1p1": ATH9K / "ar9565_1p1_initvals.h",
    "ar9331_1p1": ATH9K / "ar9330_1p1_initvals.h",
    "ar9300_2p2": ATH9K / "ar9003_2p2_initvals.h",
}
# Linux ordering for five-column tables: address, 5G HT20, 5G HT40,
# 2G HT40, 2G HT20. Two-column tables have one value for all modes.
TABLES = (
    ("socPreamble", "ar9565_1p0_soc_preamble"),
    ("macCore", "ar9565_1p0_mac_core"),
    ("basebandCore", "ar9565_1p0_baseband_core"),
    ("radioCore", "ar9565_1p0_radio_core"),
    ("rxGain", "ar9565_1p0_Common_rx_gain_table"),
    ("commonWoXlnaRxGainTable", "ar9565_1p0_common_wo_xlna_rx_gain_table"),
    ("txGainLowOb", "ar9565_1p0_modes_low_ob_db_tx_gain_table"),
    ("txGainHighOb", "ar9565_1p0_modes_high_ob_db_tx_gain_table"),
    ("txGainHighPower", "ar9565_1p0_modes_high_power_tx_gain_table"),
    ("socPostamble", "ar9565_1p0_soc_postamble"),
    ("macPostamble", "ar9331_1p1_mac_postamble"),
    ("basebandPostamble", "ar9565_1p0_baseband_postamble"),
    ("radioPostamble10", "ar9565_1p0_radio_postamble"),
    ("radioPostamble11", "ar9565_1p1_radio_postamble"),
    ("japan2484Txfir", "ar9300_2p2_baseband_core_txfir_coeff_japan_2484"),
)
ARRAY = re.compile(
    r"static\s+const\s+u32\s+([a-zA-Z0-9_]+)\s*\[\]\s*\[(\d+)\]\s*=\s*\{(.*?)\};",
    re.DOTALL,
)
ROW = re.compile(r"\{\s*(0x[0-9a-fA-F]+(?:\s*,\s*0x[0-9a-fA-F]+)*)\s*\}")
VALID_INPUT_WIDTHS = {2, 3, 5}
VALID_CHANNEL_WIDTHS = {2, 5}
DUAL_COLUMN_WIDTH: Final = 2
LEGAL_NOTICE: Final = "Permission to use, copy, modify, and/or distribute"


def _rows(name: str, width: int, body: str) -> list[tuple[int, ...]]:
    cleaned = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    cleaned = re.sub(r"//[^\n]*", "", cleaned)
    rows: list[tuple[int, ...]] = []
    for match in ROW.finditer(cleaned):
        fields = tuple(
            int(part.strip(), 16) for part in match.group(1).split(",")
        )
        if len(fields) != width:
            message = f"Bad column count for {name}"
            raise RuntimeError(message)
        rows.append(fields)
    if not rows or cleaned.replace(",", "").strip().count("{") != len(rows):
        message = f"Unparsed table rows: {name}"
        raise RuntimeError(message)
    return rows


def _parse_source(
    key: str,
    path: Path,
    arrays: dict[str, list[tuple[int, ...]]],
    *,
    sources: dict[str, str],
) -> None:
    for match in ARRAY.finditer(path.read_text(encoding="utf-8")):
        name, width, body = match.groups()
        numeric_width = int(width)
        if numeric_width not in VALID_INPUT_WIDTHS:
            message = f"Unexpected table width: {key} {name}"
            raise RuntimeError(message)
        rows = _rows(name, numeric_width, body)
        if name in arrays:
            message = f"Duplicate table: {name}"
            raise RuntimeError(message)
        arrays[name] = rows
        sources[name] = key


def parse_tables() -> tuple[dict[str, list[tuple[int, ...]]], dict[str, str]]:
    """Parse the named ath9k tables into validated per-row integer arrays.

    Returns:
        Extracted tables and their exact source identifier for attribution.

    """
    arrays: dict[str, list[tuple[int, ...]]] = {}
    sources: dict[str, str] = {}
    for key, path in SOURCES.items():
        _parse_source(key, path, arrays, sources=sources)
    return arrays, sources


def _preamble() -> list[str]:
    legal = SOURCES["ar9565_1p0"].read_text().split("*/", 1)[0] + "*/"
    # Unlike an assert, this remains a hard gate under optimized Python.
    if LEGAL_NOTICE not in legal:
        message = "Required upstream license notice was not found"
        raise RuntimeError(message)
    lines = [
        "// Generated from Linux ath9k register tables; do not edit by hand.",
        "// Sources are pinned by the following SHA-256 hashes:",
    ]
    for path in SOURCES.values():
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"// {path.relative_to(ROOT)}: {checksum}")
    lines.extend([
        legal,
        "#ifndef SIMPLEATH_AR9565_INIT_TABLES_HPP",
        "#define SIMPLEATH_AR9565_INIT_TABLES_HPP",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "namespace simpleath { namespace ini {",
        "struct RegisterValue { uint32_t offset; uint32_t value; };",
        "struct TableView { const RegisterValue *rows; size_t count; };",
    ])
    return lines


def _emit_mode(
    label: str,
    rows: list[tuple[int, ...]],
    mode: str,
    *,
    column: int,
) -> list[str]:
    selected = 1 if len(rows[0]) == DUAL_COLUMN_WIDTH else column
    symbol = f"k{label[0].upper()}{label[1:]}{mode}"
    lines = [
        f"static const RegisterValue {symbol}[] __attribute__((unused)) = {{"
    ]
    lines.extend(
        f"    {{0x{row[0]:08x}u, 0x{row[selected]:08x}u}}," for row in rows
    )
    contents = f"{{{symbol}, sizeof({symbol}) / sizeof({symbol}[0])}};"
    declaration = (
        f"static const TableView {symbol}View __attribute__((unused)) = "
    )
    lines.extend(["};", declaration + contents])
    return lines


def _emit_tables(
    arrays: dict[str, list[tuple[int, ...]]],
    source_map: dict[str, str],
    lines: list[str],
) -> int:
    count = 0
    for label, name in TABLES:
        rows = arrays[name]
        if len(rows[0]) not in VALID_CHANNEL_WIDTHS:
            message = f"Unsupported channel layout in {name}"
            raise RuntimeError(message)
        # HT20/HT40 variants and revision-specific radio postambles are
        # deliberately separate. The generic AR9300 alias is not compatible.
        for mode, column in (("Ht20", 4), ("Ht40", 3)):
            lines.extend(_emit_mode(label, rows, mode, column=column))
            count += len(rows)
        lines.append(f"// Original Linux array: {name} ({source_map[name]}).")
    return count


def _validate_expected(arrays: dict[str, list[tuple[int, ...]]]) -> None:
    expected = {name for _, name in TABLES}
    if not expected.issubset(arrays):
        message = f"Missing Linux tables: {sorted(expected - set(arrays))}"
        raise RuntimeError(message)


def main() -> None:
    """Write source data from fixed Linux reference paths when requested."""
    arrays, source_map = parse_tables()
    _validate_expected(arrays)
    lines = _preamble()
    count = _emit_tables(arrays, source_map, lines)
    lines.extend([
        "} } // namespace simpleath::ini",
        "#endif // SIMPLEATH_AR9565_INIT_TABLES_HPP",
        "",
    ])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    _ = OUTPUT.write_text("\n".join(lines))
    info = (
        f"Generated {OUTPUT.relative_to(ROOT)}, {count} 2G register entries, "
    )
    info += f"{OUTPUT.stat().st_size} bytes, from {len(TABLES)} Linux tables.\n"
    _ = sys.stdout.write(info)
    _ = sys.stdout.write(
        "No PCI/MMIO writes performed, no kernel extension compiled.\n"
    )


if __name__ == "__main__":
    main()
