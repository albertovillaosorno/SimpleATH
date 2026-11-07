#!/usr/bin/env python3
#
#  native_payload.py
#  SimpleATH
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#
"""Source-only native Skywalk compatibility metadata and patch guards."""

from __future__ import annotations

import bisect
from dataclasses import dataclass
import json
import re
import struct
from typing import TYPE_CHECKING
from typing import final

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Mapping
    from collections.abc import Sequence


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

# Stable compatibility-profile and native-dispatch invariants.
SONOMA_KERNEL = 23
TAHOE_KERNEL = 25
USER_CLIENT_LAYOUT_BYTES = 224
EXPECTED_CLASS_COLLISIONS = 42
NO_NATIVE_SLOT = 0xFFFFFFFF
CONTROLLER_CLASS = "IO80211Controller"
CONTROLLER_ALIAS = "AirPortDriver"
LEGACY_SOURCE = "Legacy"
BRCM_TAHOE_SOURCE = "BrcmTahoe"
NATIVE_SOURCE = "native"
NATIVE_PACKET_CLASS = "IOSkywalkNetworkPacket"
TEXT_SECTION = "__text"
CSTRING_SECTION = "__cstring"
CALLBACK_PREFIX = "athSkyCallback"
CALLBACK_START_OFFSET = 0x850
CALLBACK_OVERRIDE_OFFSET = 0x770
BRANCH_OPCODES = frozenset({0xE8, 0xE9})
BRANCH_LENGTH = 5
RIP_REGISTER = "%rip"
ETHERNET_LOGICAL_LINK_SYMBOL = (
    "__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLink"
    "EPKNS_16RegistrationInfoEP20IOSkywalkLogicalLink"
    "P25IOSkywalkPacketBufferPoolS6_j"
)


def _rip_lea_sites(start: int, data: bytes, destination: int) -> list[int]:
    """Find complete x86 RIP-relative LEA instructions targeting a vtable.

    Returns:
        Verified source image instruction offsets.

    """
    rows: list[int] = []
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
    return rows


def _require_mach_image(image: object) -> Mach:
    """Refuse metadata-only snapshots for operations needing Mach-O tables.

    Returns:
        Concrete bounded Mach-O image with function and section catalogs.

    Raises:
        ValueError: The reference contains only JSON summary metadata.

    """
    if isinstance(image, Mach):
        return image
    message = "Native packet generation requires concrete Mach-O source images"
    raise ValueError(message)


def _renamed_collision(name: str) -> str:
    """Return the pinned alias for a known conflicting native class.

    Returns:
        The renamed legacy class identifier.

    Raises:
        ValueError: A class collision is outside the documented families.

    """
    if name == CONTROLLER_CLASS:
        return CONTROLLER_ALIAS
    if name.startswith("IO"):
        return "SB" + name[2:]
    if name.startswith("Log"):
        return "ATH" + name[3:]
    message = "Unknown class collision: " + name
    raise ValueError(message)


def _matches_patch_instruction(function: str, prefix: str, raw: bytes) -> bool:
    """Check the named x86 virtual dispatch instruction shape.

    Returns:
        True only for the expected complete indirect call encoding.

    """
    if not function.startswith(prefix) or len(raw) != PATCH_INSTRUCTION_BYTES:
        return False
    return raw[0] == PATCH_OPCODE and raw[1] & PATCH_MODRM_MASK == PATCH_MODRM


def _packet_function_at_site(
    address: int,
    functions: list[tuple[int, str]],
    addresses: list[int],
) -> str:
    """Return the containing function only for a complete patch location.

    Returns:
        Name of the function owning the entire six-byte instruction.

    Raises:
        ValueError: No matching function or instruction crosses its boundary.

    """
    index = bisect.bisect_right(addresses, address)
    if index == 0:
        message = f"Missing packet dispatch function: {address:#x}"
        raise ValueError(message)
    if index < len(addresses) and (
        address + PATCH_INSTRUCTION_BYTES > addresses[index]
    ):
        message = f"Packet dispatch crosses function boundary: {address:#x}"
        raise ValueError(message)
    return functions[index - 1][1]


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
    if addresses != sorted(addresses) or len(addresses) != len(set(addresses)):
        message = "Unsorted or duplicate packet function addresses"
        raise ValueError(message)
    result: list[tuple[int, int, int]] = []
    for address, slot, prefix in PACKET_CALL_SITES:
        function = _packet_function_at_site(address, functions, addresses)
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


def native_client_symbols(cls: str) -> list[str]:
    """Generate the exact native constructor/destructor/meta/vtable names.

    Returns:
        The five required mangled symbol names for one user-client class.

    """
    prefix = "__ZN" + str(len(cls)) + cls
    return [
        *(prefix + suffix for suffix in CLIENT_SUFFIXES),
        "__ZTV" + str(len(cls)) + cls,
    ]


def _checked_client_row(
    cls: str,
    symbols: Sequence[str],
    vtable: Sequence[str],
    *,
    native_index: Mapping[str, int],
) -> tuple[int, ...]:
    """Validate one client profile and encode its complete import row.

    Returns:
        Required native indices and the source vtable slot count.

    Raises:
        ValueError: Client symbols or its vtable are malformed.
        KeyError: A required native class symbol is unresolved.

    """
    if list(symbols) != native_client_symbols(cls) or not vtable:
        message = "Malformed native user-client symbol or vtable catalog"
        raise ValueError(message)
    for name in symbols:
        if name not in native_index:
            raise KeyError(name)
    return (*[native_index[name] for name in symbols], len(vtable))


def checked_client_profile_rows(
    client_symbols: Sequence[Sequence[str]],
    client_tables: Sequence[Sequence[str]],
    native_index: Mapping[str, int],
) -> list[tuple[int, ...]]:
    """Encode all declared user clients without silently dropping a table.

    Returns:
        Native import indices followed by each client's vtable slot count.

    Raises:
        ValueError: A client profile is absent or malformed.

    """
    if len(client_symbols) != len(CLIENT_CLASSES) or len(client_tables) != len(
        CLIENT_CLASSES
    ):
        message = "Incomplete native user-client profile catalog"
        raise ValueError(message)
    return [
        _checked_client_row(cls, symbols, vtable, native_index=native_index)
        for cls, symbols, vtable in zip(
            CLIENT_CLASSES, client_symbols, client_tables, strict=True
        )
    ]


@final
class SkywalkPlan:
    """Derive a pinned native compatibility plan from offline source images."""

    # Populated only after the checked multi-profile guard preflight.
    vtable_guards: list[tuple[str, int, str]]
    class_guards: list[tuple[str, int]]
    unchecked_overrides: list[tuple[str, int, str]]
    link_bytes: bytes
    link_mask: bytes
    link_references: list[tuple[int, str]]
    link_symbol: str
    link_slot: int
    api_symbols: list[str]
    compat_names: list[str]
    compat_index: dict[str, int]
    native_names: set[str]

    def __init__(self, system: str = "Tahoe") -> None:
        """Load source-only native ABI profiles without touching hardware."""
        self._init_sources(system)
        self.link_symbol, self.link_slot, self.api_symbols = self._init_link()
        self._init_clients()
        self._init_namespace()
        self.compat: dict[str, str] = {}
        self.methods: list[str] = []
        self.method_index: dict[str, int] = {}
        self.method_slots = []
        (
            self.compat_names,
            self.compat_index,
            self.native_names,
        ) = self._init_compatibility()
        self._init_callbacks()
        self._init_packet_power()

    def _init_sources(self, system: str) -> None:
        """Resolve the exact reference image, family and link contracts.

        Raises:
            ValueError: A reference identity or required export mismatches.

        """
        self.model = NativeModel(system)
        self.vtable_guards = []
        self.class_guards = []
        self.unchecked_overrides = []
        self.link_bytes = b""
        self.link_mask = b""
        self.link_references = []
        self.guards_ready = False
        self.system = system
        self.profile = SYSTEMS[system]
        if self.model.native.uuid != self.profile["skywalk"]:
            message = (
                "The native Skywalk implementation has no verified profile"
            )
            raise ValueError(message)
        self.old = self.model.old
        self.native = self.model.native
        self.legacy = _require_mach_image(self.model.images[LEGACY_SOURCE])
        self.air = _require_mach_image(self.model.images[BRCM_TAHOE_SOURCE])
        self.wireless = Mach(self.native.path, "com.apple.iokit.IO80211Family")
        if self.wireless.uuid != self.profile["wireless"]:
            message = "Unsupported native IO80211Family"
            raise ValueError(message)

    def _init_link(self) -> tuple[str, int, list[str]]:
        """Check the exact native registration path and import indices.

        Returns:
            Link symbol, checked native vtable slot and import catalog.

        Raises:
            ValueError: The required native logical-link symbol is absent.

        """
        link_symbol = (
            API_SYMBOLS[8]
            if self.profile["kernel"] != SONOMA_KERNEL
            else ETHERNET_LOGICAL_LINK_SYMBOL
        )
        if link_symbol not in self.native.defined():
            message = "Missing native Ethernet logical-link registration method"
            raise ValueError(message)
        ethernet: list[str] = self.model.new_tables[
            "IOSkywalkEthernetInterface"
        ]
        link_slot = (
            ethernet.index(link_symbol)
            if link_symbol in ethernet
            else NO_NATIVE_SLOT
        )
        api_symbols = list(API_SYMBOLS)
        api_symbols[8] = API_SYMBOLS[0]
        return link_symbol, link_slot, api_symbols

    def _init_clients(self) -> None:
        """Require exact, complete native user-client class layouts.

        Raises:
            ValueError: A required class layout or export is missing.

        """
        self.client_symbols: list[list[str]] = []
        self.client_tables: list[list[str]] = []
        for cls in CLIENT_CLASSES:
            if class_size(self.wireless, cls) != USER_CLIENT_LAYOUT_BYTES:
                message = "Unsupported native user-client layout"
                raise ValueError(message)
            symbols = native_client_symbols(cls)
            if not set(symbols) <= self.wireless.defined():
                message = "Native user-client exports missing"
                raise ValueError(message)
            self.client_symbols.append(symbols)
            self.client_tables.append(
                table(self.wireless, cls, self.model.kernel)
            )

    def _init_namespace(self) -> None:
        """Map only the pinned conflicting legacy class identifiers.

        Raises:
            ValueError: An unknown or changed class collision is found.

        """

        def classes(names: set[str]) -> set[str]:
            return {
                match[2]
                for name in names
                if (match := re.fullmatch(r"__ZN(\d+)(.*)10gMetaClassE", name))
                and len(match[2]) == int(match[1])
            }

        collisions = (
            classes(self.legacy.defined()) | classes(self.air.defined())
        ) & classes(self.wireless.defined())
        self.namespace: dict[str, str] = {}
        for name in sorted(collisions):
            self.namespace[name] = _renamed_collision(name)
        if len(self.namespace) != EXPECTED_CLASS_COLLISIONS:
            message = "Changed legacy/native class collision set"
            raise ValueError(message)
        if CONTROLLER_ALIAS in classes(self.wireless.defined()) | classes(
            self.model.kernel.defined()
        ):
            message = "Wireless controller compatibility name is already in use"
            raise ValueError(message)

    def _init_compatibility(
        self,
    ) -> tuple[list[str], dict[str, int], set[str]]:
        """Derive legacy forwarders and native imports from checked names.

        Returns:
            Ordered names, compatibility indices and resolved imports.

        """
        ethernet: list[str] = self.model.old_tables[
            "IOSkywalkEthernetInterface"
        ]
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
            old_slots.get(method_key(name), NO_NATIVE_SLOT) for name in needed
        ]
        for name, i in self.method_index.items():
            if interface_method(name):
                self.compat[name] = f"_athSkyForward{i}"
        return self._init_compatibility_routes(needed, ethernet)

    def _init_compatibility_routes(
        self, needed: list[str], ethernet: list[str]
    ) -> tuple[list[str], dict[str, int], set[str]]:
        """Add exact native aliases and finalize source-level import names.

        Returns:
            Complete compatibility names, indices and native imports.

        """
        self.compat.update({
            "__ath_interface_start": "_athLegacySkywalkStart",
            "__ZN25IOSkywalkNetworkInterface10joinPMtreeEP9IOService": (
                "_athLegacyJoinPowerTree"
            ),
            "__ZN26IOSkywalkEthernetInterfaceC2EPK11OSMetaClass": (
                "__ZN18ATHLegacyInterfaceC2EPK11OSMetaClass"
            ),
            "__ZN26IOSkywalkEthernetInterfaceD2Ev": (
                "__ZN18ATHLegacyInterfaceD2Ev"
            ),
            "__ZN26IOSkywalkEthernetInterfaceD1Ev": (
                "__ZN18ATHLegacyInterfaceD1Ev"
            ),
            "__ZN26IOSkywalkEthernetInterfaceD0Ev": (
                "__ZN18ATHLegacyInterfaceD0Ev"
            ),
            "__ZNK26IOSkywalkEthernetInterface12getMetaClassEv": (
                "__ZNK18ATHLegacyInterface12getMetaClassEv"
            ),
            "__ZN26IOSkywalkEthernetInterface10gMetaClassE": (
                "__ZN18ATHLegacyInterface10gMetaClassE"
            ),
            "__ZTV26IOSkywalkEthernetInterface": "_athLegacySkywalkVtable",
            "__ZTV22IOSkywalkNetworkPacket": "_athPacketCompatibilityVtable",
            "__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary": (
                "_athLegacySkywalkInit"
            ),
            "__ZN26IOSkywalkEthernetInterface4freeEv": "_athLegacySkywalkFree",
            "__ZN25IOSkywalkNetworkInterface4stopEP9IOService": (
                "_athLegacySkywalkStop"
            ),
            "__ZN18IOSkywalkInterface13willTerminateEP9IOServicej": (
                "_athLegacyWillTerminate"
            ),
            "__ZN18IOSkywalkInterface12didTerminateEP9IOServicejPb": (
                "_athLegacyDidTerminate"
            ),
            (
                "__ZN26IOSkywalkEthernetInterface13newUserClientE"
                "P4taskPvjP12OSDictionaryPP12IOUserClient"
            ): ("_athLegacySkywalkUserClient"),
            API_SYMBOLS[7]: "_athRegisterLegacyEthernet",
            API_SYMBOLS[10]: "_athDeregisterLegacyEthernet",
            ETHERNET_LOGICAL_LINK_SYMBOL: "_athRegisterLegacyEthernetLink",
            API_SYMBOLS[9]: "_athRegisterLegacyNetworkLink",
            (
                "__ZN25IOSkywalkNetworkInterface22handleDoorbellF"
                "orQueueEP20IOSkywalkPacketQueuej"
            ): ("_athLegacyDoorbell"),
            (
                "__ZN26IOSkywalkTxSubmissionQueue8withPoolEP25IOS"
                "kywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PjEPF"
                "jS3_S4_PKP15IOSkywalkPacketjPvESC_j"
            ): ("_athLegacyTxWithPool"),
            "__ZNK25IOSkywalkPacketBufferPool7releaseEv": (
                "_athLegacyPoolRelease"
            ),
            "_OSObject_typed_operator_new": "_athLegacyTypedNew",
            "_OSObject_typed_operator_delete": "_athLegacyTypedDelete",
        })
        for image in (self.legacy, self.air):
            for name in image.undef():
                if normalized(name) in self.compat:
                    self.compat[name] = self.compat[normalized(name)]
        compat_names = sorted(self.compat)
        compat_index = {name: index for index, name in enumerate(compat_names)}
        native_names = set(self.api_symbols)
        native_names.update(
            name for group in self.client_symbols for name in group
        )
        native_names.update(
            name
            for name in needed
            if name in self.native.defined()
            and name != ETHERNET_LOGICAL_LINK_SYMBOL
        )
        native_names.update(
            name for name in ethernet if not interface_method(name)
        )
        return compat_names, compat_index, native_names

    def _init_callbacks(self) -> None:
        """Derive verified reverse-callback slots from source vtables."""
        ethernet: list[str] = self.model.old_tables[
            "IOSkywalkEthernetInterface"
        ]
        self.callbacks: list[tuple[int, int, list[tuple[int, int]]]] = []
        native_slots = {
            method_key(name): i
            for i, name in enumerate(
                self.model.new_tables["IOSkywalkEthernetInterface"]
            )
        }
        for label, cls in [
            (LEGACY_SOURCE, "IO80211SkywalkInterface"),
            (LEGACY_SOURCE, "IO80211InfraInterface"),
            (BRCM_TAHOE_SOURCE, "AirPort_Brcm43xxLLSkywalkInterface"),
        ]:
            old: list[str] = self.model.old_tables[cls]
            rows = self._callback_rows(old, ethernet, native_slots)
            self.callbacks.append((
                0 if label == LEGACY_SOURCE else 1,
                self.model.images[label].names[vtable_name(cls)][4],
                rows,
            ))

    def _callback_rows(
        self,
        old: list[str],
        ethernet: list[str],
        native_slots: dict[str, int],
    ) -> list[tuple[int, int]]:
        """Map changed callback slots to verified native and old indices.

        Returns:
            Source-to-native slot translation pairs.

        """
        rows: list[tuple[int, int]] = []
        for index, name in enumerate(old[: len(ethernet)]):
            entry = self._callback_entry(
                (index * 8, name, ethernet[index]), native_slots
            )
            if entry is not None:
                rows.append(entry)
        return rows

    def _callback_entry(
        self,
        candidate: tuple[int, str, str],
        native_slots: Mapping[str, int],
    ) -> tuple[int, int] | None:
        """Accept an explicitly changed callback with a matching native slot.

        Returns:
            Native and old-method indices, or None for inherited slots.

        Raises:
            ValueError: An override has no native equivalent or origin.

        """
        offset, name, base = candidate
        if offset < CALLBACK_START_OFFSET and offset not in {
            0x428,
            0x430,
            0x770,
            0x780,
        }:
            return None
        if offset != CALLBACK_OVERRIDE_OFFSET and normalized(
            name
        ) == normalized(base):
            return None
        if method_key(name) not in native_slots:
            message = f"Native callback has no equivalent: {name}"
            raise ValueError(message)
        if base not in self.method_index:
            message = f"Callback does not originate in Skywalk: {name}"
            raise ValueError(message)
        return native_slots[method_key(name)], self.method_index[base]

    def _init_packet_power(self) -> None:
        """Preflight packet constructor and power-state source patterns.

        Raises:
            ValueError: A pinned binary layout or power record mismatches.

        """
        self.packet_calls = self.packet_call_patches()
        self.vptr_sites = self.packet_vptr_sites()
        self.pool_meta: list[int] = [0x24E2E, 0x24F0C, 0x64AD0]
        for address in self.pool_meta:
            if self.air.read(address - 1, 5) != bytes.fromhex("b9b8000000"):
                message = "Unrecognized packet pool class-size initializer"
                raise ValueError(message)
        self.pool_type = self.air.names[
            "__ZL43AirPort_Brcm43xxSkywalkPacketBufferPool_ktv"
        ][4]
        self.power_template = self.air.names["__ZL20power_state_template"][4]
        self.power_states: list[tuple[int, ...]] = [
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
            message = "Unrecognized Broadcom power domain"
            raise ValueError(message)

    def packet_call_patches(self) -> list[tuple[int, int, int]]:
        """Check each pinned packet dispatch site against the image bytes.

        Returns:
            Offset, old virtual slot and native slot for each verified call.

        """
        return checked_packet_call_patches(self.air.funcs(), self.air.read)

    def packet_vptr_sites(self) -> list[int]:
        """Find verified packet vtable construction instructions.

        Returns:
            Virtual addresses of matching RIP-relative LEA instructions.

        Raises:
            ValueError: The pinned construction instruction is absent.

        """
        destination = self.air.names[vtable_name(PACKET_CLASS)][4] + 16
        section = next(s for s in self.air.sects if s[0] == TEXT_SECTION)
        start, length = section[2:4]
        data = self.air.read(start, length)
        rows = _rip_lea_sites(start, data, destination)
        if not rows:
            message = "Packet vtable construction sites were not found"
            raise ValueError(message)
        return rows

    def namespace_payload(
        self, label: str, data: bytearray, image: Mach | None = None
    ) -> dict[str, list[int]]:
        """Rename known class strings in an offline expanded source image.

        Returns:
            Source class names and the virtual offsets of rewritten strings.

        """
        image = image or (self.legacy if label == LEGACY_SOURCE else self.air)
        sections = [
            (section[2], section[3])
            for section in image.sects
            if section[0] == CSTRING_SECTION
        ]
        return rename_class_cstrings(
            data, sections, self.namespace, require_all=label == LEGACY_SOURCE
        )

    def resolve(self, name: str) -> int | None:
        """Resolve a known native compatibility symbol index.

        Returns:
            The import index, or None for an unmatched name.

        """
        return self.compat_index.get(name)

    def emit(
        self, native_index: Mapping[str, int]
    ) -> tuple[list[str], list[str]]:
        """Emit checked C++ tables and native x86_64 forwarding stubs.

        Returns:
            Generated C++ and assembly sources in their pinned order.

        Raises:
            ValueError: Native preflight has not marked this profile ready.

        """
        if not self.guards_ready:
            message = "Native ABI guards were not prepared"
            raise ValueError(message)
        return self._emit_cpp(native_index), self._emit_assembly()

    def _emit_cpp(self, native_index: Mapping[str, int]) -> list[str]:
        """Encode import, vtable and packet tables in source declaration order.

        Returns:
            C++ declarations for the selected compatibility profile.

        """
        cpp: list[str] = []
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
            rows=checked_client_profile_rows(
                self.client_symbols, self.client_tables, native_index
            ),
        )
        cpp.extend((
            "const uint32_t compatibilityImportCount = "
            + str(len(self.compat_names))
            + ";",
            "const char *const compatibilityImportNames[] = {"
            + ",".join(json.dumps(name) for name in self.compat_names)
            + "};",
        ))
        method_rows = [
            (native_index.get(name, NO_NATIVE_SLOT), self.method_slots[i])
            for i, name in enumerate(self.methods)
        ]
        self.emit_rows(cpp, "SkyMethod", "skyMethods", rows=method_rows)
        cpp.append(f"const uint32_t skyMethodCount = {len(method_rows)};")
        old = self.model.old_tables["IOSkywalkEthernetInterface"]
        entries = [
            (self.compat_index[name], 1)
            if name in self.compat_index
            else (native_index[name], 0)
            for name in old
        ]
        entries[0x5C0 // 8] = (self.compat_index["__ath_interface_start"], 1)
        self.emit_rows(cpp, "SkyEntry", "skyLegacyEntries", rows=entries)
        cpp.append(f"const uint32_t skyLegacySlotCount = {len(entries)};")
        self._emit_packet_tables(cpp)
        self._emit_patch_tables(cpp)
        return cpp

    def _emit_packet_tables(self, cpp: list[str]) -> None:
        """Encode only the checked packet-parent and subclass inheritance.

        Raises:
            ValueError: The source model contains an unknown packet entry.

        """
        packet_base = self.model.old_views[NATIVE_PACKET_CLASS]
        if any(row[0] != NATIVE_SOURCE for row in packet_base):
            message = "A native packet base method is missing"
            raise ValueError(message)
        self.emit_rows(
            cpp,
            "SkyEntry",
            "skyPacketEntries",
            rows=[(row[2] // 8, 3) for row in packet_base],
        )
        cpp.append(f"const uint32_t skyPacketSlotCount = {len(packet_base)};")
        subclass = self.model.tables[PACKET_CLASS]
        packet_entries: list[tuple[int, int]] = []
        for source, name, target in subclass:
            if source == NATIVE_SOURCE and name == NATIVE_PACKET_CLASS:
                packet_entries.append((target // 8, 3))
            elif source == BRCM_TAHOE_SOURCE:
                packet_entries.append((target, 4))
            else:
                message = f"Unsupported native packet entry: {source}, {name}"
                raise ValueError(message)
        self.emit_rows(
            cpp, "SkyEntry", "skyPacketSubclassEntries", rows=packet_entries
        )
        subclass_count = len(packet_entries)
        cpp.append(
            f"const uint32_t skyPacketSubclassSlotCount = {subclass_count};"
        )

    def _emit_patch_tables(self, cpp: list[str]) -> None:
        """Encode packet call sites and owner metadata without device access."""
        cpp.append(f"const uint32_t skyClassCount = {len(self.callbacks)};")
        self.emit_rows(
            cpp, "SkyPatch", "skyPacketCalls", rows=self.packet_calls
        )
        pool_vtable = self.air.names[vtable_name(POOL_CLASS)][4]
        packet_vtable = self.air.names[vtable_name(PACKET_CLASS)][4]
        vptr_count = len(self.vptr_sites)
        cpp.extend((
            f"const uint32_t skyPacketCallCount = {len(self.packet_calls)};",
            "const uint32_t skyPacketVptrSites[] = {"
            + ",".join(map(str, self.vptr_sites))
            + "};",
            f"const uint32_t skyPacketVptrSiteCount = {vptr_count};",
            "const uint32_t skyPoolMetaSizeSites[] = {"
            + ",".join(map(str, self.pool_meta))
            + "};",
            f"const uint32_t skyPoolMetaSizeSiteCount = {len(self.pool_meta)};",
            f"const uint32_t skyPoolTypeView = {self.pool_type};",
            f"const uint32_t skyPoolVtable = {pool_vtable};",
            f"const uint32_t skyPacketVtable = {packet_vtable};",
        ))

    def _emit_assembly(self) -> list[str]:
        """Generate the ABI forwarding tables and exact dispatch stubs.

        Returns:
            Assembly definitions for pinned import and callback arrays.

        """
        assembly: list[str] = []
        assembly += [
            ".section __DATA_CONST,__const",
            ".p2align 3",
            ".globl _athCompatibilityImports",
            "_athCompatibilityImports:",
        ]
        assembly += [".quad " + self.compat[name] for name in self.compat_names]
        for array, prefix in [
            ("athSkyForwarders", "athSkyForward"),
            ("athSkyCallbacks", CALLBACK_PREFIX),
        ]:
            assembly += [".p2align 3", ".globl _" + array, "_" + array + ":"]
            assembly += [
                f".quad _{prefix}{i}" for i in range(len(self.methods))
            ]
        assembly += [".section __TEXT,__text"]
        for prefix, resolver in [
            ("athSkyForward", "athResolveOldSkywalk"),
            (CALLBACK_PREFIX, "athResolveNativeSkywalk"),
        ]:
            self._emit_forwarding_stubs(assembly, prefix, resolver)
        return assembly

    def _emit_forwarding_stubs(
        self, assembly: list[str], prefix: str, resolver: str
    ) -> None:
        """Append complete register-preserving trampolines for one direction."""
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
            if prefix == CALLBACK_PREFIX:
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
            if prefix == CALLBACK_PREFIX:
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

    @staticmethod
    def emit_rows(
        cpp: list[str], kind: str, name: str, *, rows: Sequence[Sequence[int]]
    ) -> None:
        """Append one native ABI integer table to generated C++ source."""
        cpp.append(
            f"const {kind} {name}[] = {{"
            + ",".join("{" + ",".join(map(str, row)) + "}" for row in rows)
            + "};"
        )

    def manifest(self) -> dict[str, object]:
        """Return native compatibility evidence without hardware access.

        Returns:
            The structured source-only compatibility manifest.

        """
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
            "airPortPayloadIndex": 2
            if self.profile["kernel"] == TAHOE_KERNEL
            else 1,
            "classNamespace": self.namespace,
            "wirelessControllerIdentity": CONTROLLER_ALIAS,
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


def _guard_class_sizes(
    plan: SkywalkPlan, common: set[str], imports: set[str]
) -> None:
    """Check every native metaclass and its declared object size.

    Raises:
        ValueError: A required metaclass is missing from a pinned profile.

    """
    for cls in (*NATIVE_CLASSES, *CLIENT_CLASSES):
        image = plan.wireless if cls in CLIENT_CLASSES else plan.native
        meta = "__ZN" + str(len(cls)) + cls + "10gMetaClassE"
        if meta not in common:
            message = "Missing common native metaclass: " + cls
            raise ValueError(message)
        plan.class_guards.append((meta, class_size(image, cls)))
        imports.add(meta)


def _guard_native_vtables(
    plan: SkywalkPlan, common: set[str], imports: set[str]
) -> None:
    """Resolve strictly known superclass vtable entries.

    Raises:
        ValueError: An unknown unchecked override was introduced.

    """
    for cls in (
        "IOSkywalkEthernetInterface",
        NATIVE_PACKET_CLASS,
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
        ETHERNET_LOGICAL_LINK_SYMBOL,
        "__ZNK25IOSkywalkPacketBufferPool7releaseEv",
        "__ZNK25IOSkywalkPacketBufferPool13taggedReleaseEPKv",
        "__ZN25IOSkywalkNetworkInterface13willTerminateEP9IOServicej",
        (
            "__ZN25IOSkywalkNetworkInterface17setRxFlowSteeringEj"
            "P31ifnet_traffic_descriptor_commonj"
        ),
    }
    if any(method not in allowed for _, _, method in plan.unchecked_overrides):
        message = "Unrecognized native vtable override"
        raise ValueError(message)


@dataclass
class LinkGuardContext:
    """Mutable import and mask output for one bounded source instruction."""

    address: int
    data: bytes
    common: set[str]
    imports: set[str]
    mask: bytearray
    references: list[tuple[int, str]]
    byaddr: Mapping[int, list[str]]


def _require_link_instruction_span(
    context: LinkGuardContext,
    pc: int,
    *,
    length: int,
    raw: bytes,
) -> None:
    """Reject truncated, empty, or out-of-image disassembly instruction spans.

    Raises:
        ValueError: An instruction does not fit its mapped source body.

    """
    if length <= 0 or len(raw) != length:
        message = "Out-of-bounds native logical-link instruction"
        raise ValueError(message)
    if pc < context.address or pc + length > context.address + len(
        context.data
    ):
        message = "Out-of-bounds native logical-link instruction"
        raise ValueError(message)


def checked_link_instruction(
    context: LinkGuardContext, instruction: tuple[int, int, str, bytes]
) -> None:
    """Record only complete, bounded direct branches from an ABI wrapper.

    Raises:
        ValueError: Instruction spans or branch opcodes are inconsistent.

    """
    pc, length, mnemonic, raw = instruction
    _require_link_instruction_span(context, pc, length=length, raw=raw)
    if raw[0] not in BRANCH_OPCODES:
        if RIP_REGISTER in mnemonic:
            message = "Unexpected RIP-relative access in logical-link wrapper"
            raise ValueError(message)
        return
    if length != BRANCH_LENGTH:
        message = "Unexpected branch encoding in logical-link wrapper"
        raise ValueError(message)
    offset = pc - context.address + 1
    context.mask[offset : offset + 4] = b"\0" * 4
    target = pc + length + struct.unpack_from("<i", raw, 1)[0]
    names = set(context.byaddr.get(target, [])) & context.common
    if names:
        name = min(names)
        context.references.append((offset, name))
        context.imports.add(name)


def _guard_link_source(
    plan: SkywalkPlan, common: set[str], imports: set[str]
) -> None:
    """Verify the exact binary wrapper and record masked relocatable code.

    Raises:
        ValueError: The wrapper references a different native method.

    """
    plan.link_bytes, plan.link_mask, plan.link_references = b"", b"", []
    if plan.link_slot != NO_NATIVE_SLOT:
        return
    address, data = plan.native.funcbytes(plan.link_symbol)
    mask = bytearray([255] * len(data))
    context = LinkGuardContext(
        address=address,
        data=data,
        common=common,
        imports=imports,
        mask=mask,
        references=plan.link_references,
        byaddr=plan.native.byaddr,
    )
    for instruction in insns(data, address):
        checked_link_instruction(context, instruction)
    if [name for _, name in plan.link_references] != [API_SYMBOLS[10]]:
        message = (
            "Logical-link wrapper must reference native Ethernet deregistration"
        )
        raise ValueError(message)
    plan.link_bytes, plan.link_mask = data, bytes(mask)


def prepare_native_guards(plans: Sequence[SkywalkPlan]) -> set[str]:
    """Validate common native classes across all pinned system profiles.

    Returns:
        Exports needed to resolve checked native vtables and references.

    """
    checked_system_profile_names([plan.system for plan in plans])
    # A failed retry must not leave a previously prepared profile marked ready.
    for plan in plans:
        plan.guards_ready = False
    first = plans[0]
    common: set[str] = (
        first.native.defined()
        | first.model.kernel.defined()
        | first.wireless.defined()
    )
    for plan in plans[1:]:
        common.intersection_update(
            plan.native.defined()
            | plan.model.kernel.defined()
            | plan.wireless.defined()
        )
    imports: set[str] = set()
    for plan in plans:
        plan.vtable_guards = []
        plan.class_guards = []
        plan.unchecked_overrides = []
        _guard_class_sizes(plan, common, imports)
        _guard_native_vtables(plan, common, imports)
        _guard_link_source(plan, common, imports)
    # Publish readiness only after every pinned system passes the preflight.
    for plan in plans:
        plan.guards_ready = True
    return imports


def _emit_profile_classes(
    plan: SkywalkPlan, lines: list[str], index: int
) -> str:
    """Write the verified callback tables before their class descriptor.

    Returns:
        Source declaration name of the class catalog.

    """
    classes: list[str] = []
    for number, (image, address, callbacks) in enumerate(plan.callbacks):
        name = f"system{index}Callbacks{number}"
        plan.emit_rows(lines, "SkyCallback", name, rows=callbacks)
        classes.append(f"{{{image},{address},{name},{len(callbacks)}}}")
    name = f"system{index}Classes"
    lines.append(
        "static const SkyClass " + name + "[] = {" + ",".join(classes) + "};"
    )
    return name


def _emit_profile_guards(
    plan: SkywalkPlan,
    lines: list[str],
    index: int,
    *,
    native_index: Mapping[str, int],
) -> tuple[str, str]:
    """Write native vtable/class ABI requirements in the pinned order.

    Returns:
        Source names of vtable and class guard arrays.

    """
    guards = f"system{index}VtableGuards"
    plan.emit_rows(
        lines,
        "NativeVtableGuard",
        guards,
        rows=[
            (native_index[parent], offset, native_index[method])
            for parent, offset, method in plan.vtable_guards
        ],
    )
    sizes = f"system{index}ClassGuards"
    plan.emit_rows(
        lines,
        "NativeClassGuard",
        sizes,
        rows=[(native_index[meta], size) for meta, size in plan.class_guards],
    )
    return guards, sizes


def _emit_profile_link(
    plan: SkywalkPlan,
    lines: list[str],
    index: int,
    *,
    native_index: Mapping[str, int],
) -> str:
    """Write branch-masked source wrapper only when required by this ABI.

    Returns:
        C++ initializer for the optional reference-code descriptor.

    """
    if not plan.link_bytes:
        return "{nullptr,nullptr,0,nullptr,0}"
    data, mask, refs = (
        f"system{index}Link{suffix}"
        for suffix in ("Bytes", "Mask", "References")
    )
    for symbol, values in ((data, plan.link_bytes), (mask, plan.link_mask)):
        items = ",".join(map(str, values))
        lines.append(f"static const uint8_t {symbol}[] = {{{items}}};")
    plan.emit_rows(
        lines,
        "NativeCodeReference",
        refs,
        rows=[
            (offset, native_index[name])
            for offset, name in plan.link_references
        ],
    )
    return (
        f"{{{data},{mask},{len(plan.link_bytes)},{refs},"
        f"{len(plan.link_references)}}}"
    )


def _emit_one_system_profile(
    plan: SkywalkPlan,
    lines: list[str],
    index: int,
    *,
    native_index: Mapping[str, int],
) -> str:
    """Write one complete source-only ABI descriptor in declaration order.

    Returns:
        C++ aggregate row referring to its checked child tables.

    """
    name = _emit_profile_classes(plan, lines, index)
    guards, sizes = _emit_profile_guards(
        plan, lines, index, native_index=native_index
    )
    pattern = _emit_profile_link(plan, lines, index, native_index=native_index)
    profile = plan.profile
    fields = [
        str(profile["kernel"]),
        json.dumps(plan.system),
        str(profile["ethernetSize"]),
        str(profile["poolSize"]),
        str(profile["ethernetSlots"]),
        str(2 if profile["kernel"] == TAHOE_KERNEL else 1),
        str(plan.link_slot) + "U",
        pattern,
        guards,
        str(len(plan.vtable_guards)),
        sizes,
        str(len(plan.class_guards)),
        name,
    ]
    return "{" + ",".join(fields) + "}"


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
    if not all(plan.guards_ready for plan in plans):
        message = "Native ABI guards were not prepared"
        raise ValueError(message)
    lines: list[str] = []
    rows = [
        _emit_one_system_profile(plan, lines, index, native_index=native_index)
        for index, plan in enumerate(plans)
    ]
    lines.extend((
        "const NativeSystemProfile nativeSystems[] = {" + ",".join(rows) + "};",
        f"const uint32_t nativeSystemCount = {len(plans)};",
    ))
    return lines
