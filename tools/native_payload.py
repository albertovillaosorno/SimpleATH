#!/usr/bin/env python3
#
#  native_payload.py
#  SimpleATH
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

import bisect
import json
from collections.abc import Callable
from collections.abc import Mapping
from collections.abc import Sequence
import re
import struct

from native_abi import Mach
from native_abi import NATIVE_CLASSES
from native_abi import NativeModel
from native_abi import class_size
from native_abi import insns
from native_abi import method_key
from native_abi import table
from native_abi import vtable_name
from native_payload_strings import rename_class_cstrings
from system_profiles import SYSTEMS

API_SYMBOLS = [
    "__ZN26IOSkywalkEthernetInterfaceC2EPK11OSMetaClass",
    "__ZN26IOSkywalkEthernetInterfaceD2Ev",
    "__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary",
    "__ZN26IOSkywalkEthernetInterface4freeEv",
    "__ZTV26IOSkywalkEthernetInterface",
    "__ZTV22IOSkywalkNetworkPacket",
    "__ZTV25IOSkywalkPacketBufferPool",
    "__ZN26IOSkywalkEthernetInterface25registerEthernetInterfaceEPKNS_16RegistrationInfoEPP20IOSkywalkPacketQueuejP25IOSkywalkPacketBufferPoolS7_j",
    "__ZN26IOSkywalkEthernetInterface25registerEthernetInterfaceEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j",
    "__ZN25IOSkywalkNetworkInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j",
    "__ZN26IOSkywalkEthernetInterface27deregisterEthernetInterfaceEj",
    "__ZN26IOSkywalkTxSubmissionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PjEPFjS3_S4_PKP15IOSkywalkPacketjPvESC_jj",
    "__ZN26IOSkywalkTxSubmissionQueue16packetSubmissionEb",
    "__ZN26IOSkywalkTxSubmissionQueue14requestDequeueEPvj",
    "_OSObject_typed_operator_new",
    "_OSObject_typed_operator_delete",
    "__ZN25IOSkywalkNetworkInterface10joinPMtreeEP9IOService",
]

CLIENT_CLASSES = ("IO80211APIUserClient", "IO80211AsyncEventUserClient")
CLIENT_SUFFIXES = ("C2EPK11OSMetaClass", "D2Ev", "4freeEv", "10gMetaClassE")

INTERFACE_CLASSES = (
    "IOSkywalkInterface",
    "IOSkywalkNetworkInterface",
    "IOSkywalkEthernetInterface",
)
PACKET_CLASS = "AirPort_Brcm43xxSkywalkPacket"
POOL_CLASS = "AirPort_Brcm43xxSkywalkPacketBufferPool"

# Source-only offsets pinned to the retained original AirPort image. They
# must be checked against the disassembled function and encoded slot before
# generating any replacement; no device or kernel access occurs here.
PACKET_CALL_SITES: tuple[tuple[int, int, str], ...] = (
    (0x25BF6, 0x1D0, "__ZN15AirPort_BrcmNIC11llTxDequeue"),
    (0x25D43, 0x1E8, "__ZN15AirPort_BrcmNIC11llTxEnqueue"),
    (0x25E70, 0x1D8, "__ZN15AirPort_BrcmNIC11llRxEnqueue"),
    (
        0x26658,
        0x1E0,
        "__ZN34AirPort_Brcm43xxLLSkywalkInterface11logTxPacket",
    ),
    (
        0x266CE,
        0x1E0,
        "__ZN34AirPort_Brcm43xxLLSkywalkInterface11inputPacket",
    ),
    (0x287EF, 0x1F0, "__ZN15AirPort_BrcmNIC14llTxCompletion"),
    (0x2884B, 0x1F0, "__ZN15AirPort_BrcmNIC14llTxCompletion"),
)
PATCH_INSTRUCTION_BYTES = 6
PATCH_NATIVE_SLOT_DELTA = 24
PATCH_OPCODE = 0xFF
PATCH_MODRM_MASK = 0xF8
PATCH_MODRM = 0x90


def _matches_patch_instruction(function: str, prefix: str, raw: bytes) -> bool:
    """Check the named x86 virtual dispatch instruction shape.

    Returns:
        True only for the expected complete indirect call encoding.

    """
    if not function.startswith(prefix) or len(raw) != PATCH_INSTRUCTION_BYTES:
        return False
    return raw[0] == PATCH_OPCODE and raw[1] & PATCH_MODRM_MASK == PATCH_MODRM


def checked_packet_call_patches(
    functions: list[tuple[int, str]], read: Callable[[int, int], bytes]
) -> list[tuple[int, int, int]]:
    """Verify the complete packet virtual-call catalog without execution.

    Returns:
        Patch offset, old slot and translated native slot triples.

    Raises:
        ValueError: Missing functions, truncated code or unexpected slots.

    """
    addresses = [address for address, _ in functions]
    result: list[tuple[int, int, int]] = []
    if addresses != sorted(addresses) or len(addresses) != len(set(addresses)):
        message = "Unsorted or duplicate packet function addresses"
        raise ValueError(message)
    for address, slot, prefix in PACKET_CALL_SITES:
        index = bisect.bisect_right(addresses, address)
        if index == 0:
            message = f"Missing packet dispatch function: {address:#x}"
            raise ValueError(message)
        # A valid six-byte encoding cannot run into the next function.
        # Otherwise a forged instruction at this pinned address could make
        # the patcher overwrite a neighbor's instruction prefix.
        if index < len(addresses) and (
            address + PATCH_INSTRUCTION_BYTES > addresses[index]
        ):
            message = f"Packet dispatch crosses function boundary: {address:#x}"
            raise ValueError(message)
        function = functions[index - 1][1]
        raw = read(address, PATCH_INSTRUCTION_BYTES)
        if not _matches_patch_instruction(function, prefix, raw):
            message = f"Unrecognized packet virtual call: {address:#x}"
            raise ValueError(message)
        if struct.unpack("<I", raw[2:])[0] != slot:
            message = f"Packet virtual slot mismatch: {address:#x}"
            raise ValueError(message)
        result.append((address + 2, slot, slot + PATCH_NATIVE_SLOT_DELTA))
    return result


def interface_method(name: str) -> bool:
    """Return whether a mangled method belongs to a Skywalk interface.

    Returns:
        True only for one of the declared interface classes.

    """
    return any(
        name.startswith((
            "__ZN" + str(len(cls)) + cls,
            "__ZNK" + str(len(cls)) + cls,
        ))
        for cls in INTERFACE_CLASSES
    )


def normalized(name: str) -> str:
    """Normalize the known ether_addr_t mangling alias.

    Returns:
        Canonical symbol name used by the compatibility map.

    """
    return name.replace("12ether_addr_t", "10ether_addr")


def checked_client_profile_rows(
    client_symbols: Sequence[Sequence[str]],
    client_tables: Sequence[Sequence[str]],
    native_index: Mapping[str, int],
) -> list[tuple[int, ...]]:
    """Encode all declared user clients without silently dropping a table.

    Returns:
        Native import indices followed by each client's vtable slot count.

    Raises:
        ValueError: A client profile is absent from either parallel catalog.
        KeyError: A required client symbol has no native import index.

    """
    if len(client_symbols) != len(CLIENT_CLASSES) or len(client_tables) != len(
        CLIENT_CLASSES
    ):
        message = "Incomplete native user-client profile catalog"
        raise ValueError(message)
    return [
        (*[native_index[name] for name in symbols], len(vtable))
        for symbols, vtable in zip(client_symbols, client_tables, strict=True)
    ]


class SkywalkPlan:
    def __init__(self, system="Tahoe"):
        self.model = NativeModel(system)
        self.system = system
        self.profile = SYSTEMS[system]
        if self.model.native.uuid != self.profile["skywalk"]:
            raise ValueError(
                "The native Skywalk implementation has no verified profile"
            )
        self.old = self.model.old
        self.native = self.model.native
        self.legacy = self.model.images["Legacy"]
        self.air = self.model.images["BrcmTahoe"]
        self.wireless = Mach(self.native.path, "com.apple.iokit.IO80211Family")
        if self.wireless.uuid != self.profile["wireless"]:
            raise ValueError("Unsupported native IO80211Family")
        self.link_symbol = (
            API_SYMBOLS[8]
            if self.profile["kernel"] != 23
            else "__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j"
        )
        if self.link_symbol not in self.native.defined():
            raise ValueError(
                "Missing native Ethernet logical-link registration method"
            )
        ethernet = self.model.new_tables["IOSkywalkEthernetInterface"]
        self.link_slot = (
            ethernet.index(self.link_symbol)
            if self.link_symbol in ethernet
            else 0xFFFFFFFF
        )
        self.api_symbols = list(API_SYMBOLS)
        self.api_symbols[8] = API_SYMBOLS[0]
        self.client_symbols = []
        self.client_tables = []
        for cls in CLIENT_CLASSES:
            if class_size(self.wireless, cls) != 224:
                raise ValueError("Unsupported native user-client layout")
            symbols = [
                "__ZN" + str(len(cls)) + cls + suffix
                for suffix in CLIENT_SUFFIXES
            ]
            symbols.append(vtable_name(cls))
            if not set(symbols) <= self.wireless.defined():
                raise ValueError("Native user-client exports missing")
            self.client_symbols.append(symbols)
            self.client_tables.append(
                table(self.wireless, cls, self.model.kernel)
            )

        def classes(image):
            return {
                match[2]
                for name in image.defined()
                if (match := re.fullmatch(r"__ZN(\d+)(.*)10gMetaClassE", name))
                and len(match[2]) == int(match[1])
            }

        collisions = (classes(self.legacy) | classes(self.air)) & classes(
            self.wireless
        )
        self.namespace = {}
        for name in sorted(collisions):
            if name == "IO80211Controller":
                replacement = "AirPortDriver"
            elif name.startswith("IO"):
                replacement = "SB" + name[2:]
            elif name.startswith("Log"):
                replacement = "ATH" + name[3:]
            else:
                raise ValueError("Unknown class collision: " + name)
            self.namespace[name] = replacement
        if len(self.namespace) != 42:
            raise ValueError("Changed legacy/native class collision set")
        if "AirPortDriver" in classes(self.wireless) | classes(
            self.model.kernel
        ):
            raise ValueError(
                "Wireless controller compatibility name is already in use"
            )
        self.compat = {}
        ethernet = self.model.old_tables["IOSkywalkEthernetInterface"]
        public_callbacks = {
            ethernet[offset // 8] for offset in (0x428, 0x430, 0x780)
        }
        needed = set(ethernet)
        for image in (self.legacy, self.air):
            needed.update(
                normalized(name)
                for name in image.undef()
                if interface_method(name)
            )
        needed = sorted(
            name
            for name in needed
            if interface_method(name) or name in public_callbacks
        )
        self.methods = needed
        self.method_index = {name: index for index, name in enumerate(needed)}
        old_slots = {method_key(name): i for i, name in enumerate(ethernet)}
        self.method_slots = [
            old_slots.get(method_key(name), 0xFFFFFFFF) for name in needed
        ]
        for name, i in self.method_index.items():
            if interface_method(name):
                self.compat[name] = f"_athSkyForward{i}"
        self.compat.update({
            "__ath_interface_start": "_athLegacySkywalkStart",
            "__ZN25IOSkywalkNetworkInterface10joinPMtreeEP9IOService": "_athLegacyJoinPowerTree",
            "__ZN26IOSkywalkEthernetInterfaceC2EPK11OSMetaClass": "__ZN18ATHLegacyInterfaceC2EPK11OSMetaClass",
            "__ZN26IOSkywalkEthernetInterfaceD2Ev": "__ZN18ATHLegacyInterfaceD2Ev",
            "__ZN26IOSkywalkEthernetInterfaceD1Ev": "__ZN18ATHLegacyInterfaceD1Ev",
            "__ZN26IOSkywalkEthernetInterfaceD0Ev": "__ZN18ATHLegacyInterfaceD0Ev",
            "__ZNK26IOSkywalkEthernetInterface12getMetaClassEv": "__ZNK18ATHLegacyInterface12getMetaClassEv",
            "__ZN26IOSkywalkEthernetInterface10gMetaClassE": "__ZN18ATHLegacyInterface10gMetaClassE",
            "__ZTV26IOSkywalkEthernetInterface": "_athLegacySkywalkVtable",
            "__ZTV22IOSkywalkNetworkPacket": "_athPacketCompatibilityVtable",
            "__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary": "_athLegacySkywalkInit",
            "__ZN26IOSkywalkEthernetInterface4freeEv": "_athLegacySkywalkFree",
            "__ZN25IOSkywalkNetworkInterface4stopEP9IOService": "_athLegacySkywalkStop",
            "__ZN18IOSkywalkInterface13willTerminateEP9IOServicej": "_athLegacyWillTerminate",
            "__ZN18IOSkywalkInterface12didTerminateEP9IOServicejPb": "_athLegacyDidTerminate",
            "__ZN26IOSkywalkEthernetInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient": "_athLegacySkywalkUserClient",
            API_SYMBOLS[7]: "_athRegisterLegacyEthernet",
            API_SYMBOLS[10]: "_athDeregisterLegacyEthernet",
            "__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j": "_athRegisterLegacyEthernetLink",
            API_SYMBOLS[9]: "_athRegisterLegacyNetworkLink",
            "__ZN25IOSkywalkNetworkInterface22handleDoorbellForQueueEP20IOSkywalkPacketQueuej": "_athLegacyDoorbell",
            "__ZN26IOSkywalkTxSubmissionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PjEPFjS3_S4_PKP15IOSkywalkPacketjPvESC_j": "_athLegacyTxWithPool",
            "__ZNK25IOSkywalkPacketBufferPool7releaseEv": "_athLegacyPoolRelease",
            "_OSObject_typed_operator_new": "_athLegacyTypedNew",
            "_OSObject_typed_operator_delete": "_athLegacyTypedDelete",
        })
        for image in (self.legacy, self.air):
            for name in image.undef():
                if normalized(name) in self.compat:
                    self.compat[name] = self.compat[normalized(name)]
        self.compat_names = sorted(self.compat)
        self.compat_index = {
            name: index for index, name in enumerate(self.compat_names)
        }
        self.native_names = set(self.api_symbols)
        self.native_names.update(
            name for group in self.client_symbols for name in group
        )
        self.native_names.update(
            name
            for name in needed
            if name in self.native.defined()
            and name
            != "__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j"
        )
        self.native_names.update(
            name for name in ethernet if not interface_method(name)
        )
        self.callbacks = []
        native_slots = {
            method_key(name): i
            for i, name in enumerate(
                self.model.new_tables["IOSkywalkEthernetInterface"]
            )
        }
        for label, cls in [
            ("Legacy", "IO80211SkywalkInterface"),
            ("Legacy", "IO80211InfraInterface"),
            ("BrcmTahoe", "AirPort_Brcm43xxLLSkywalkInterface"),
        ]:
            old = self.model.old_tables[cls]
            rows = []
            for index, name in enumerate(old[: len(ethernet)]):
                if index * 8 < 0x850 and index * 8 not in (
                    0x428,
                    0x430,
                    0x770,
                    0x780,
                ):
                    continue
                base = ethernet[index]
                if index * 8 != 0x770 and normalized(name) == normalized(base):
                    continue
                if method_key(name) not in native_slots:
                    raise ValueError(
                        f"Native callback has no equivalent: {name}"
                    )
                if base not in self.method_index:
                    raise ValueError(
                        f"Callback does not originate in Skywalk: {name}"
                    )
                rows.append((
                    native_slots[method_key(name)],
                    self.method_index[base],
                ))
            self.callbacks.append((
                0 if label == "Legacy" else 1,
                self.model.images[label].names[vtable_name(cls)][4],
                rows,
            ))
        self.packet_calls = self.packet_call_patches()
        self.vptr_sites = self.packet_vptr_sites()
        self.pool_meta = [0x24E2E, 0x24F0C, 0x64AD0]
        for address in self.pool_meta:
            if self.air.read(address - 1, 5) != bytes.fromhex("b9b8000000"):
                raise ValueError(
                    "Unrecognized packet pool class-size initializer"
                )
        self.pool_type = self.air.names[
            "__ZL43AirPort_Brcm43xxSkywalkPacketBufferPool_ktv"
        ][4]
        self.power_template = self.air.names["__ZL20power_state_template"][4]
        self.power_states = [
            struct.unpack(
                "<12Q", self.air.read(self.power_template + i * 96, 96)
            )
            for i in range(3)
        ]
        if [state[:4] for state in self.power_states] != [
            (1, 0, 0, 0),
            (1, 0x400, 0x400, 0x400),
            (1, 0xF000, 0, 2),
        ]:
            raise ValueError("Unrecognized Broadcom power domain")

    def packet_call_patches(self) -> list[tuple[int, int, int]]:
        """Check each pinned packet dispatch site against the image bytes.

        Returns:
            Offset, old virtual slot and native slot for each verified call.

        """
        return checked_packet_call_patches(self.air.funcs(), self.air.read)

    def packet_vptr_sites(self):
        destination = self.air.names[vtable_name(PACKET_CLASS)][4] + 16
        section = next(s for s in self.air.sects if s[0] == "__text")
        start, length = section[2:4]
        data = self.air.read(start, length)
        rows = []
        offset = 0
        while True:
            offset = data.find(b"\x48\x8d\x05", offset)
            if offset < 0:
                break
            if offset + 7 <= len(data):
                delta = struct.unpack_from("<i", data, offset + 3)[0]
                if start + offset + 7 + delta == destination:
                    rows.append(start + offset)
            offset += 1
        if not rows:
            raise ValueError("Packet vtable construction sites were not found")
        return rows

    def namespace_payload(self, label, data, image=None):
        image = image or (self.legacy if label == "Legacy" else self.air)
        sections = [
            (section[2], section[3])
            for section in image.sects
            if section[0] == "__cstring"
        ]
        return rename_class_cstrings(
            data, sections, self.namespace, require_all=label == "Legacy"
        )

    def resolve(self, name):
        return self.compat_index.get(name)

    def emit(self, native_index):
        cpp = []
        assembly = []
        api = [native_index[name] for name in self.api_symbols]
        cpp.append(
            "const uint32_t skyAPIImports[] = {"
            + ",".join(map(str, api))
            + "};"
        )
        self.emit_rows(
            cpp,
            "NativeClientProfile",
            "nativeClientProfiles",
            checked_client_profile_rows(
                self.client_symbols, self.client_tables, native_index
            ),
        )
        cpp.append(
            "const uint32_t compatibilityImportCount = "
            + str(len(self.compat_names))
            + ";"
        )
        cpp.append(
            "const char *const compatibilityImportNames[] = {"
            + ",".join(json.dumps(name) for name in self.compat_names)
            + "};"
        )
        method_rows = [
            (native_index.get(name, 0xFFFFFFFF), self.method_slots[i])
            for i, name in enumerate(self.methods)
        ]
        self.emit_rows(cpp, "SkyMethod", "skyMethods", method_rows)
        cpp.append(f"const uint32_t skyMethodCount = {len(method_rows)};")
        old = self.model.old_tables["IOSkywalkEthernetInterface"]
        entries = [
            (self.compat_index[name], 1)
            if name in self.compat_index
            else (native_index[name], 0)
            for name in old
        ]
        entries[0x5C0 // 8] = (self.compat_index["__ath_interface_start"], 1)
        self.emit_rows(cpp, "SkyEntry", "skyLegacyEntries", entries)
        cpp.append(f"const uint32_t skyLegacySlotCount = {len(entries)};")
        packet_base = self.model.old_views["IOSkywalkNetworkPacket"]
        if any(row[0] != "native" for row in packet_base):
            raise ValueError("A native packet base method is missing")
        self.emit_rows(
            cpp,
            "SkyEntry",
            "skyPacketEntries",
            [(row[2] // 8, 3) for row in packet_base],
        )
        cpp.append(f"const uint32_t skyPacketSlotCount = {len(packet_base)};")
        subclass = self.model.tables[PACKET_CLASS]
        packet_entries = []
        for source, name, target in subclass:
            if source == "native" and name == "IOSkywalkNetworkPacket":
                packet_entries.append((target // 8, 3))
            elif source == "BrcmTahoe":
                packet_entries.append((target, 4))
            else:
                raise ValueError(
                    f"Unsupported native packet entry: {source}, {name}"
                )
        self.emit_rows(
            cpp, "SkyEntry", "skyPacketSubclassEntries", packet_entries
        )
        cpp.append(
            f"const uint32_t skyPacketSubclassSlotCount = {len(packet_entries)};"
        )
        cpp.append(f"const uint32_t skyClassCount = {len(self.callbacks)};")
        self.emit_rows(cpp, "SkyPatch", "skyPacketCalls", self.packet_calls)
        cpp.append(
            f"const uint32_t skyPacketCallCount = {len(self.packet_calls)};"
        )
        cpp.append(
            "const uint32_t skyPacketVptrSites[] = {"
            + ",".join(map(str, self.vptr_sites))
            + "};"
        )
        cpp.append(
            f"const uint32_t skyPacketVptrSiteCount = {len(self.vptr_sites)};"
        )
        cpp.append(
            "const uint32_t skyPoolMetaSizeSites[] = {"
            + ",".join(map(str, self.pool_meta))
            + "};"
        )
        cpp.append(
            f"const uint32_t skyPoolMetaSizeSiteCount = {len(self.pool_meta)};"
        )
        cpp.append(f"const uint32_t skyPoolTypeView = {self.pool_type};")
        cpp.append(
            f"const uint32_t skyPoolVtable = {self.air.names[vtable_name(POOL_CLASS)][4]};"
        )
        cpp.append(
            f"const uint32_t skyPacketVtable = {self.air.names[vtable_name(PACKET_CLASS)][4]};"
        )
        assembly += [
            ".section __DATA_CONST,__const",
            ".p2align 3",
            ".globl _athCompatibilityImports",
            "_athCompatibilityImports:",
        ]
        assembly += [".quad " + self.compat[name] for name in self.compat_names]
        for array, prefix in [
            ("athSkyForwarders", "athSkyForward"),
            ("athSkyCallbacks", "athSkyCallback"),
        ]:
            assembly += [".p2align 3", ".globl _" + array, "_" + array + ":"]
            assembly += [
                f".quad _{prefix}{i}" for i in range(len(self.methods))
            ]
        assembly += [".section __TEXT,__text"]
        for prefix, resolver in [
            ("athSkyForward", "athResolveOldSkywalk"),
            ("athSkyCallback", "athResolveNativeSkywalk"),
        ]:
            for i in range(len(self.methods)):
                assembly += [
                    ".p2align 4",
                    f".globl _{prefix}{i}",
                    f"_{prefix}{i}:",
                    "pushq %rax",
                    "pushq %rdi",
                    "pushq %rsi",
                    "pushq %rdx",
                    "pushq %rcx",
                    "pushq %r8",
                    "pushq %r9",
                    ("movl $" + str(i) + ", %esi"),
                    f"callq _{resolver}",
                    "movq %rax, %r11",
                ]
                if prefix == "athSkyCallback":
                    assembly += ["movq %rdx, %r10", "andq $-2, %rdx"]
                assembly += [
                    "movq %rdx, 40(%rsp)",
                    "popq %r9",
                    "popq %r8",
                    "popq %rcx",
                    "popq %rdx",
                    "popq %rsi",
                    "popq %rdi",
                    "popq %rax",
                ]
                if prefix == "athSkyCallback":
                    assembly += [
                        "pushq %r10",
                        "callq *%r11",
                        "pushq %rax",
                        "pushq %rdx",
                        "movq 16(%rsp), %rdi",
                        "callq _athReleaseNativeReceiver",
                        "popq %rdx",
                        "popq %rax",
                        "addq $8, %rsp",
                        "retq",
                    ]
                else:
                    assembly += ["jmpq *%r11"]
        return cpp, assembly

    @staticmethod
    def emit_rows(cpp, kind, name, rows):
        cpp.append(
            f"const {kind} {name}[] = {{"
            + ",".join("{" + ",".join(map(str, row)) + "}" for row in rows)
            + "};"
        )

    def manifest(self):
        return {
            "system": self.system,
            "kernel": self.profile["kernel"],
            "build": self.profile["build"],
            "nativeUUID": self.native.uuid,
            "wirelessUUID": self.wireless.uuid,
            "ethernetSize": self.profile["ethernetSize"],
            "poolSize": self.profile["poolSize"],
            "nativeSlotCount": len(
                self.model.new_tables["IOSkywalkEthernetInterface"]
            ),
            "ethernetLinkSymbol": self.link_symbol,
            "ethernetLinkSlot": self.link_slot,
            "airPortPayloadIndex": 2 if self.profile["kernel"] == 25 else 1,
            "classNamespace": self.namespace,
            "wirelessControllerIdentity": "AirPortDriver",
            "userClientStrategy": "native-class-with-delegated-control",
            "interfaceStrategy": "native-interface-adapter",
            "packetStrategy": "native-packets-with-preserved-private-fields",
            "queueStrategy": "native-array-callbacks",
            "packetCallPatches": self.packet_calls,
            "packetVptrSites": self.vptr_sites,
            "poolMetaSizeSite": self.pool_meta,
            "compatibilityImports": self.compat_names,
            "compatibilityTargets": [
                self.compat[name] for name in self.compat_names
            ],
            "powerDomain": {
                "strategy": "pci-provider",
                "template": self.power_template,
                "airPortTablePreserved": True,
                "joinPMtreeSlot": 0x7A0,
            },
            "hardwareValidation": "not-run-by-build",
        }


def checked_system_profile_names(names: Sequence[str]) -> None:
    """Require the complete pinned native profile catalog in stable order.

    Raises:
        ValueError: A profile is missing, duplicated, reordered or unknown.

    """
    if tuple(names) != tuple(SYSTEMS):
        message = "Incomplete or reordered native system profile catalog"
        raise ValueError(message)


def prepare_native_guards(plans: Sequence[SkywalkPlan]) -> set[str]:
    """Validate common native classes across all pinned system profiles.

    Returns:
        Exports needed to resolve checked native vtables and references.

    Raises:
        ValueError: A required system profile is absent or reordered.

    """
    checked_system_profile_names([plan.system for plan in plans])
    common = set.intersection(
        *(
            p.native.defined() | p.model.kernel.defined() | p.wireless.defined()
            for p in plans
        )
    )
    imports = set()
    for plan in plans:
        plan.vtable_guards = []
        plan.class_guards = []
        plan.unchecked_overrides = []
        for cls in (*NATIVE_CLASSES, *CLIENT_CLASSES):
            image = plan.wireless if cls in CLIENT_CLASSES else plan.native
            meta = "__ZN" + str(len(cls)) + cls + "10gMetaClassE"
            if meta not in common:
                raise ValueError("Missing common native metaclass: " + cls)
            plan.class_guards.append((meta, class_size(image, cls)))
            imports.add(meta)
        for cls in (
            "IOSkywalkEthernetInterface",
            "IOSkywalkNetworkPacket",
            "IOSkywalkPacketBufferPool",
            *CLIENT_CLASSES,
        ):
            image = plan.wireless if cls in CLIENT_CLASSES else plan.native
            parent = vtable_name(cls)
            imports.add(parent)
            for slot, method in enumerate(table(image, cls, plan.model.kernel)):
                if method in common:
                    plan.vtable_guards.append((parent, (slot + 2) * 8, method))
                    imports.add(method)
                else:
                    plan.unchecked_overrides.append((cls, slot, method))
        allowed = {
            "__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j",
            "__ZNK25IOSkywalkPacketBufferPool7releaseEv",
            "__ZNK25IOSkywalkPacketBufferPool13taggedReleaseEPKv",
            "__ZN25IOSkywalkNetworkInterface13willTerminateEP9IOServicej",
            "__ZN25IOSkywalkNetworkInterface17setRxFlowSteeringEjP31ifnet_traffic_descriptor_commonj",
        }
        if any(
            method not in allowed for _, _, method in plan.unchecked_overrides
        ):
            raise ValueError("Unrecognized native vtable override")
        plan.link_bytes, plan.link_mask, plan.link_references = b"", b"", []
        if plan.link_slot != 0xFFFFFFFF:
            continue
        address, data = plan.native.funcbytes(plan.link_symbol)
        mask = bytearray([255] * len(data))
        for pc, length, instruction, raw in insns(data, address):
            if raw[0] not in (0xE8, 0xE9):
                if "%rip" in instruction:
                    raise ValueError(
                        "Unexpected RIP-relative access in logical-link wrapper"
                    )
                continue
            if length != 5:
                raise ValueError(
                    "Unexpected branch encoding in logical-link wrapper"
                )
            offset = pc - address + 1
            mask[offset : offset + 4] = b"\0" * 4
            target = pc + length + struct.unpack_from("<i", raw, 1)[0]
            names = set(plan.native.byaddr.get(target, [])) & common
            if names:
                name = sorted(names)[0]
                plan.link_references.append((offset, name))
                imports.add(name)
        if [name for _, name in plan.link_references] != [API_SYMBOLS[10]]:
            raise ValueError(
                "Logical-link wrapper must reference native Ethernet deregistration"
            )
        plan.link_bytes, plan.link_mask = data, bytes(mask)
    return imports


def emit_system_profiles(
    plans: Sequence[SkywalkPlan], native_index: Mapping[str, int]
) -> list[str]:
    """Emit native source profile rows after validating required inputs.

    Returns:
        Generated C++ declarations for all checked reference profiles.

    Raises:
        ValueError: A required system profile is absent or reordered.

    """
    checked_system_profile_names([plan.system for plan in plans])
    lines: list[str] = []
    rows = []
    for index, plan in enumerate(plans):
        classes = []
        for number, (image, address, callbacks) in enumerate(plan.callbacks):
            name = f"system{index}Callbacks{number}"
            plan.emit_rows(lines, "SkyCallback", name, callbacks)
            classes.append(f"{{{image},{address},{name},{len(callbacks)}}}")
        name = f"system{index}Classes"
        lines.append(
            "static const SkyClass "
            + name
            + "[] = {"
            + ",".join(classes)
            + "};"
        )
        profile = plan.profile
        guards = f"system{index}VtableGuards"
        plan.emit_rows(
            lines,
            "NativeVtableGuard",
            guards,
            [
                (native_index[p], o, native_index[m])
                for p, o, m in plan.vtable_guards
            ],
        )
        sizes = f"system{index}ClassGuards"
        plan.emit_rows(
            lines,
            "NativeClassGuard",
            sizes,
            [(native_index[m], s) for m, s in plan.class_guards],
        )
        pattern = "{nullptr,nullptr,0,nullptr,0}"
        if plan.link_bytes:
            data, mask, refs = [
                f"system{index}Link{suffix}"
                for suffix in ("Bytes", "Mask", "References")
            ]
            for symbol, values in (
                (data, plan.link_bytes),
                (mask, plan.link_mask),
            ):
                lines.append(
                    f"static const uint8_t {symbol}[] = "
                    + "{"
                    + ",".join(map(str, values))
                    + "};"
                )
            plan.emit_rows(
                lines,
                "NativeCodeReference",
                refs,
                [(o, native_index[m]) for o, m in plan.link_references],
            )
            pattern = (
                "{"
                + f"{data},{mask},{len(plan.link_bytes)},{refs},{len(plan.link_references)}"
                + "}"
            )
        fields = [
            str(profile["kernel"]),
            json.dumps(plan.system),
            str(profile["ethernetSize"]),
            str(profile["poolSize"]),
            str(profile["ethernetSlots"]),
            str(2 if profile["kernel"] == 25 else 1),
            str(plan.link_slot) + "U",
            pattern,
            guards,
            str(len(plan.vtable_guards)),
            sizes,
            str(len(plan.class_guards)),
            name,
        ]
        rows.append("{" + ",".join(fields) + "}")
    lines.append(
        "const NativeSystemProfile nativeSystems[] = {" + ",".join(rows) + "};"
    )
    lines.append(f"const uint32_t nativeSystemCount = {len(plans)};")
    return lines
