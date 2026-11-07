#!/usr/bin/env python3
#
#  audit_codecs.py
#  SimpleATH
#
#  Created by laobamac on 2026/9/18.
#  Copyright © 2026 laobamac. All rights reserved.
#

"""Audit legacy Apple80211 codec call sites against pinned binary evidence."""

import hashlib
import json
import re
import struct

from macho import Image
from profiles import IMAGES
from profiles import ROOT
from profiles import SCALAR_GET_REQUESTS
from profiles import relocations


def main():
    image = Image(IMAGES["Legacy"])
    table = struct.unpack(
        "<417Q", image.read(image.symbols["_gGetHandlerTable"], 417 * 8)
    )
    assembly = image.disassemble(r"^__ZL.*get.*P17IO80211Controller")
    blocks = {}
    for block in assembly.split("\n\n"):
        match = re.match(r"([0-9a-f]+) <([^>]+)>:", block)
        if match:
            blocks[int(match[1], 16)] = block
    if not (set(table) - {0}) <= blocks.keys():
        raise RuntimeError(
            "The GET handler table contains entries that were not disassembled"
        )
    scalar = []
    for request, address in enumerate(table, 1):
        if not address:
            continue
        block = blocks[address]
        stores = [
            line.strip()
            for line in block.splitlines()
            if re.search(
                r"\bmov[lqw]\s+[^\n]*, 0x14\(%r(?:bx|1[2345]|8)\)", line
            )
        ]
        if "copyOut" in block or not stores:
            continue
        if re.search(r"0x20\(%r(?:bx|1[2345]|8)\)", block):
            raise RuntimeError(
                "A scalar GET handler accesses a data pointer; inspect it again"
            )
        register_match = re.search(r"0x14\(%(r\w+)\)", stores[0])
        if register_match is None:
            raise RuntimeError("Scalar output target register not found")
        register = register_match[1]
        if register != "r8" and not re.search(
            r"movq\s+%r8, %" + register + r"\b", block
        ):
            raise RuntimeError(
                "The scalar output target was not confirmed to be apple80211req"
            )
        scalar.append({
            "request": request,
            "symbol": image.name(address),
            "address": hex(address),
            "stores": stores,
        })
    if [entry["request"] for entry in scalar] != SCALAR_GET_REQUESTS:
        raise RuntimeError(
            "The scalar GET mapping does not match the actual machine code"
        )
    copies = []
    for label in ["Legacy", "AirPort", "AirPortOriginal"]:
        binary = Image(IMAGES[label])
        for address, _, symbol, kind in relocations(binary):
            if symbol in ("_copyin", "_copyout") and kind == 2:
                copies.append({
                    "image": label,
                    "address": hex(address - 1),
                    "symbol": binary.name(address - 1),
                    "operation": symbol,
                })
    if len(copies) != 18:
        raise RuntimeError("Unexpected total copy callsite count")
    for backend in ["AirPort", "AirPortOriginal"]:
        if (
            len([
                entry
                for entry in copies
                if entry["image"] in ("Legacy", backend)
            ])
            != 16
        ):
            raise RuntimeError("Unexpected backend copy callsite count")
    if table[10] not in blocks or table[11] not in blocks:
        raise RuntimeError("Required scan and capability GET handlers absent")
    scan = blocks[table[10]]
    if not re.search(r"cmpl\s+\$0x48c, 0x18\(%rbx\)", scan):
        raise RuntimeError(
            "The legacy scan-result structure length check has changed"
        )
    capabilities = blocks[table[11]]
    if not re.search(r"cmpl\s+\$0xc, %eax", capabilities) or not re.search(
        r"leaq\s+-0x24\(%rbp\), %rsi", capabilities
    ):
        raise RuntimeError("The legacy capability bitmap structure has changed")
    set_entries = {
        request: struct.unpack(
            "<Q",
            image.read(
                image.symbols["_gSetHandlerTable"] + (request - 1) * 8, 8
            ),
        )[0]
        for request in [20, 216]
    }
    set_assembly = image.disassemble(
        r"^__ZL19setAssociateRequest|^__ZL14setRoamProfile"
    )
    if (
        set_entries != {20: 0x84430, 216: 0x8B211}
        or not re.search(r"movl\s+\$0x224, %ecx", set_assembly)
        or not re.search(r"cmpl\s+\$0x7c, 0x18\(%r8\)", set_assembly)
    ):
        raise RuntimeError(
            "The legacy association or roaming profile structure has changed"
        )
    report = {
        "copyright": "Copyright © 2026 laobamac. All rights reserved.",
        "legacySHA256": hashlib.sha256(image.path.read_bytes()).hexdigest(),
        "getTableCapacity": 417,
        "populatedGetEntries": sum(bool(x) for x in table),
        "uniqueGetCodecs": len(set(table) - {0}),
        "scalarGetRequests": scalar,
        "adaptedCopySites": copies,
        "associateTransfer": {
            "request": 20,
            "legacySize": 0x224,
            "nativeSize": {"Sonoma": 0x358, "Sequoia": 0x384, "Tahoe": 0x38C},
            "legacyCodec": "0x84430",
            "nativeProducer": {"Sequoia": "0xa053", "Tahoe": "0xa094"},
            "driverConsumer": "0x42b8e",
            "extendedLayoutSystems": ["Sequoia", "Tahoe"],
            "authLower": {
                "legacyOffset": 6,
                "legacyWidth": 2,
                "nativeOffset": 8,
                "nativeWidth": 4,
            },
            "authUpper": {
                "legacyOffset": 8,
                "legacyWidth": 2,
                "nativeOffset": 12,
                "nativeWidth": 4,
            },
            "ssidLength": {"legacyOffset": 0xC, "nativeOffset": 0x10},
            "key": {"legacyOffset": 0x38, "nativeOffset": 0x3C},
            "rsnLength": {"legacyOffset": 0xCC, "nativeOffset": 0xD0},
            "pmkLength": {"legacyOffset": 0x1D4, "nativeOffset": 0x1D8},
            "bssidCount": {
                "legacyOffset": 0x202,
                "nativeOffset": 0x206,
                "legacyMaximum": 3,
                "nativeMaximum": 10,
            },
            "scopeLength": {"legacyOffset": 0x218, "nativeOffset": 0x244},
        },
        "roamProfileTransfer": {
            "request": 216,
            "legacyBandSize": 0x7C,
            "nativeBandSize": 0x80,
            "aggregateSystems": ["Sequoia", "Tahoe"],
            "sonomaTransfer": "Single 0x7C-byte Legacy band, passed through unchanged",
            "nativeAllBandsSize": 0x180,
            "nativeValidOffset": 12,
            "legacyRecordsOffset": 12,
            "nativeRecordsOffset": 16,
            "legacySetCodec": "0x8b211",
            "legacyGetCodec": "0x806fb",
            "nativeBandParser": {"Sequoia": "0x33d0a", "Tahoe": "0x37432"},
            "bands": [2, 4],
        },
        "capabilityTransfer": {
            "request": 12,
            "legacySize": 12,
            "nativeSize": {"Sonoma": 16, "Sequoia": 19, "Tahoe": 21},
            "legacyCodec": "0x78cb7",
            "nativeBindSizeInstruction": {
                "Sequoia": "0x2672a",
                "Tahoe": "0x26a29",
            },
            "scanCompletionCapability": 46,
            "nativeScanWaitTest": "0x4259",
            "scope": "Native-sized output for all endpoints; only Classic advertises bridge scan completion events; other hardware bits are preserved.",
        },
        "scanResultTransfer": {
            "request": 11,
            "legacySize": 0x48C,
            "nativeSize": {"Sonoma": 0x4CC, "Sequoia": 0x8D8, "Tahoe": 0x8E0},
            "commonHeaderSize": 0x8C,
            "ieLengthOffset": 0x8A,
            "legacyIECapacity": 0x400,
            "nativeIECapacity": {"Sequoia": 0x800, "Tahoe": 0x800},
            "legacyCodec": "0x78a33",
            "nativeCallerSizeInstruction": "0x4333",
            "nativeParser": "0x6d4f",
            "nativeControllerSizeInstruction": "0x7ff8007d28a9",
        },
        "nativeCaller": {
            "imageUUID": "A7A35846-4067-3182-B70E-F7477FBC32BD",
            "symbol": "Apple80211RawGet",
            "instructionOffset": "0x6984",
            "behavior": "If req_data is NULL, the native caller supplies &req_val and length 4 as IOUC output.",
        },
    }
    report["sonoma"] = {
        "OSBuild": "23J620",
        "kernel": "23.6.0",
        "airPortBackend": "Original",
        "nativeIO80211UUID": "0a93a0f4c12532fe918856f7c24ddc41",
        "nativeIO80211FamilyUUID": "ec4ba6726e083ad2b88201690a960ff4",
        "scanResultSizeInstruction": "0x4baa",
        "capabilitySizeInstruction": "0x20e10",
        "associateSizeInstruction": "0xa5fe",
        "associateTransfer": {
            "nativeSize": 0x358,
            "legacyPrefixSize": 0x224,
            "prefixUnchanged": True,
            "authLowerOffset": 6,
            "authUpperOffset": 8,
            "authWidth": 2,
            "ssidLengthOffset": 0xC,
            "keyOffset": 0x38,
            "rsnLengthOffset": 0xCC,
            "pmkLengthOffset": 0x1D4,
            "bssidCountOffset": 0x202,
            "bssidMaximum": 3,
            "authWriteInstructions": ["0xa99c", "0xa9be"],
        },
        "scanMultipleSize": 0x14E0,
        "roamProfileSize": 0x7C,
        "selectorCount": 7,
        "commandPacketSize": 0x3C30,
        "largeCommandPacketSize": 0x3C030,
        "eventHeaderSize": 0x30,
        "driverAvailableSize": 0xB8,
        "associationDonePolicy": "Preserve Legacy empty event; no synthetic JoinStatus",
        "associationDoneConsumer": {
            "symbol": "__eventRead",
            "eventDispatch": "0x22376",
            "resultRequest21": "0x224d7",
            "getterCall": "0x224e5",
            "emptyPayloadCallback": ["0x22502", "0x22517"],
        },
        "validation": "Native binary analysis and host-executed codec vectors",
        "upstreamWireless": "https://github.com/dortania/OpenCore-Legacy-Patcher/blob/8da38565fa1551a8e5ce8613ea835d04dd97e089/opencore_legacy_patcher/efi_builder/networking/wireless.py",
    }
    destination = ROOT / "docs/Control-Codecs.json"
    content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if not destination.exists() or destination.read_text() != content:
        destination.write_text(content)
    print(
        f"GET handler table verified: {report["populatedGetEntries"]} entries / {report["uniqueGetCodecs"]} unique codec entry points, {len(scalar)} scalar results, and 16 guarded copy sites per backend."
    )


if __name__ == "__main__":
    main()
