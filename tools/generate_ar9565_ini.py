#!/usr/bin/env python3
"""Generate AR9565 2.4 GHz register presets from pinned Linux ath9k sources.

These files are C++ data only. They MUST NOT be used for hardware writes before
PCI transport, EEPROM/regulatory calibration and reset have been implemented.
The input tables carry a permissive Qualcomm/Atheros license, copied verbatim
into each generated file; they are not claimed as newly authored AGPL code.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

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
    re.S,
)
ROW = re.compile(r"\{\s*(0x[0-9a-fA-F]+(?:\s*,\s*0x[0-9a-fA-F]+)*)\s*\}")


def parse_tables() -> tuple[dict[str, list[tuple[int, ...]]], dict[str, str]]:
    arrays = {}
    sources = {}
    for key, path in SOURCES.items():
        text = path.read_text()
        for match in ARRAY.finditer(text):
            name, width, body = match.groups()
            width_int = int(width)
            if width_int not in (2, 3, 5):
                raise RuntimeError(f"Unexpected table width: {key} {name}")
            cleaned = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
            cleaned = re.sub(r"//[^\n]*", "", cleaned)
            rows = []
            for row in ROW.finditer(cleaned):
                fields = tuple(int(token.strip(), 16) for token in row.group(1).split(","))
                if len(fields) != width_int:
                    raise RuntimeError(f"Bad column count for {name}")
                rows.append(fields)
            if not rows or cleaned.replace(",", "").strip().count("{") != len(rows):
                raise RuntimeError(f"Unparsed table rows: {name}")
            if name in arrays:
                raise RuntimeError(f"Duplicate table: {name}")
            arrays[name] = rows
            sources[name] = key
    return arrays, sources


def main() -> None:
    arrays, source_map = parse_tables()
    expected = {name for _, name in TABLES}
    if not expected.issubset(arrays):
        raise RuntimeError(f"Missing Linux tables: {sorted(expected - set(arrays))}")
    # Legal provenance from upstream, without replacing its original notice.
    legal = SOURCES["ar9565_1p0"].read_text().split("*/", 1)[0] + "*/"
    assert "Permission to use, copy, modify, and/or distribute" in legal
    lines = [
        "// Generated from Linux ath9k register tables; do not edit by hand.",
        "// Sources are pinned by the following SHA-256 hashes:",
    ]
    for key, path in SOURCES.items():
        lines.append(f"// {path.relative_to(ROOT)}: {hashlib.sha256(path.read_bytes()).hexdigest()}")
    lines += [
        legal,
        "#ifndef SIMPLEATH_AR9565_INIT_TABLES_HPP",
        "#define SIMPLEATH_AR9565_INIT_TABLES_HPP",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "namespace simpleath { namespace ini {",
        "struct RegisterValue { uint32_t offset; uint32_t value; };",
        "struct TableView { const RegisterValue *rows; size_t count; };",
    ]
    count = 0
    for label, name in TABLES:
        rows = arrays[name]
        if len(rows[0]) not in (2, 5):
            raise RuntimeError(f"Unsupported channel layout in {name}")
        # Produce BOTH HT20 and HT40 variants for every register bank.
        # Keep a separate revision-specific radio postamble, not a generic
        # AR9300 alias which would be wrong for the AR9565 1.1.
        for mode, col in (("Ht20", 4), ("Ht40", 3)):
            selected = 1 if len(rows[0]) == 2 else col
            symbol = f"k{label[0].upper()}{label[1:]}{mode}"
            lines.append(f"static const RegisterValue {symbol}[] __attribute__((unused)) = {{")
            for row in rows:
                lines.append(f"    {{0x{row[0]:08x}u, 0x{row[selected]:08x}u}},")
            lines.append("};")
            lines.append(
                f"static const TableView {symbol}View __attribute__((unused)) = {{{symbol}, "
                f"sizeof({symbol}) / sizeof({symbol}[0])}};"
            )
            count += len(rows)
        lines.append(f"// Original Linux array: {name} ({source_map[name]}).")
    lines += [
        "} } // namespace simpleath::ini",
        "#endif // SIMPLEATH_AR9565_INIT_TABLES_HPP",
        "",
    ]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines))
    print(f"Generated {OUTPUT.relative_to(ROOT)}, {count} 2G register entries, "
          f"{OUTPUT.stat().st_size} bytes, from {len(TABLES)} Linux tables.")
    print("No PCI/MMIO writes performed, no kernel extension compiled.")


if __name__ == "__main__":
    main()
