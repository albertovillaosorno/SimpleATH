# SPDX-License-Identifier: AGPL-3.0-only
"""Inspect a legacy native ABI product and opt-in forwarding fixture.

This is a build-time offline verifier; importing it never invokes compilers.
"""

#
#  verify_native.py
#  SimpleATH
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

from __future__ import annotations

import bisect
from pathlib import Path
import re
import struct
from typing import TYPE_CHECKING
from typing import TypedDict
from typing import final

from bootstrap import ROOT
from native_abi import Mach
from native_abi import class_size
from native_abi import insns
from native_abi import method_key
from native_abi import table
from native_abi import verify_model
from native_forwarding_probe import run_probe
from native_payload import CLIENT_CLASSES
from native_payload import PACKET_CLASS
from native_payload import SkywalkPlan
from profiles import IMAGES

if __package__:
    from tools.abi_types import integer
    from tools.abi_types import json_object
    from tools.abi_types import mapping
    from tools.abi_types import sequence
    from tools.abi_types import string
    from tools.native_invariants import read_native_artifact
    from tools.native_invariants import reconstruct_payload_image
    from tools.native_invariants import require
else:
    from abi_types import integer
    from abi_types import json_object
    from abi_types import mapping
    from abi_types import sequence
    from abi_types import string
    from native_invariants import read_native_artifact
    from native_invariants import reconstruct_payload_image
    from native_invariants import require


if TYPE_CHECKING:
    from tools.abi_types import JsonValue
    from tools.native_references import ReferenceImage


# Public ABI invariants, not host measurements: keep values explicit and named.
CSTRING_SECTION = "__cstring"
TEXT_SECTION = "__text"
NATIVE_CONTROLLER_NAME = "AirPortDriver"
NO_LOGICAL_LINK_SLOT = 0xFFFFFFFF
TAHOE_KERNEL_MAJOR = 25
LEGACY_POOL_RELEASE = "_athLegacyPoolRelease"
RUNTIME_CLASS_COUNT = 15
MIN_RUNTIME_VTABLE_COUNT = 1060
ORIGINAL_CONTROLLER_NAME = b"IO80211Controller\0"
RIP_RELATIVE_LEA = b"\x48\x8d\x35"
LEGACY_CONTROLLER_SIZE = 1048
REQUIRED_POWER_CAPABILITY = 2
MIN_AIRPORT_CLASS_SIZE = 6816
POWER_TREE_METHOD = "joinPMtree(IOService*)"
LEGACY_POWER_JOIN = "_athLegacyJoinPowerTree"
POWER_PROVIDER_STRATEGY = "pci-provider"
ATH_USER_CLIENT_META = "__ZN18ATH80211UserClient10gMetaClassE"
API_USER_CLIENT_META = "__ZN20IO80211APIUserClient10gMetaClassE"
LEGACY_FACADE_SIZE = 272
NATIVE_CLIENT_TABLE_SLOTS = 300
NATIVE_CLIENT_SIZE = 224
METACLASS_SLOT_BYTES = 0x38
RELEASE_RECEIVER_OFFSET = "216("
INSTANCE_CONSTRUCTED_CALL = "meta->instanceConstructed()"
MAX_REGISTERED_CALLBACK_PARAMETERS = 5
POINTER_MARKER = "*"
SKYWALK_PACKET_CONSTRUCTOR = "AirPort_Brcm43xxSkywalkPacket"
X86_RELATIVE_LEA_BYTES = 7
OS_META_CLASS_CONSTRUCTOR = "__ZN11OSMetaClassC2EPKcPKS_j"
CLASS_GUARD_FIELDS = 2


class _PayloadRecord(TypedDict):
    """Required fields for one reconstructed native payload."""

    label: str
    size: int
    namespacedClassStrings: dict[str, list[int]]
    powerDomainPatches: list[JsonValue]


class _SystemProfile(TypedDict):
    """Required native identity and layout fields for a kernel profile."""

    system: str
    nativeUUID: str
    wirelessUUID: str
    ethernetSize: int
    poolSize: int
    ethernetLinkSlot: int
    airPortPayloadIndex: int


class _PowerDomain(TypedDict):
    """Declared power-domain topology from the generated manifest."""

    strategy: str
    airPortTablePreserved: bool


class _NativeAdapter(TypedDict):
    """Required native adapter settings for offline identity validation."""

    wirelessControllerIdentity: str
    powerDomain: _PowerDomain


class _RuntimeGuards(TypedDict):
    """Required runtime class and vtable inventories per kernel version."""

    classes: list[tuple[str, int]]
    vtables: list[JsonValue]


class _VerifierManifest(TypedDict):
    """Validated subset of a generated embedding manifest."""

    payloads: list[_PayloadRecord]
    nativeAdapter: _NativeAdapter
    systemProfiles: list[_SystemProfile]
    nativeRuntimeGuards: dict[str, _RuntimeGuards]


def _read_payload(value: JsonValue) -> _PayloadRecord:
    """Require a payload's bounded size, label and class offset catalog.

    Returns:
        Typed fields required for the integrity comparisons.

    """
    record = mapping(value)
    return {
        "label": string(record["label"]),
        "size": integer(record["size"]),
        "namespacedClassStrings": {
            name: [integer(offset) for offset in sequence(offsets)]
            for name, offsets in mapping(
                record["namespacedClassStrings"]
            ).items()
        },
        "powerDomainPatches": sequence(record["powerDomainPatches"]),
    }


def _read_profile(value: JsonValue) -> _SystemProfile:
    """Require all profile IDs, layout sizes and slot indices.

    Returns:
        Typed source profile fields.

    """
    record = mapping(value)
    return {
        "system": string(record["system"]),
        "nativeUUID": string(record["nativeUUID"]),
        "wirelessUUID": string(record["wirelessUUID"]),
        "ethernetSize": integer(record["ethernetSize"]),
        "poolSize": integer(record["poolSize"]),
        "ethernetLinkSlot": integer(record["ethernetLinkSlot"]),
        "airPortPayloadIndex": integer(record["airPortPayloadIndex"]),
    }


def _read_native_adapter(value: JsonValue) -> _NativeAdapter:
    """Require the selected wireless identity and preserved power topology.

    Returns:
        Typed adapter identity and power policy metadata.

    Raises:
        TypeError: The power preservation flag is not boolean.

    """
    record = mapping(value)
    power = mapping(record["powerDomain"])
    preserved = power["airPortTablePreserved"]
    if not isinstance(preserved, bool):
        message = "Native adapter power table flag must be a boolean"
        raise TypeError(message)
    return {
        "wirelessControllerIdentity": string(
            record["wirelessControllerIdentity"]
        ),
        "powerDomain": {
            "strategy": string(power["strategy"]),
            "airPortTablePreserved": preserved,
        },
    }


def _read_runtime_guards(value: JsonValue) -> _RuntimeGuards:
    """Require exact class/name pairs and a bounded vtable inventory.

    Returns:
        Typed runtime guard rows.

    Raises:
        ValueError: A class guard has the wrong arity.

    """
    record = mapping(value)
    classes: list[tuple[str, int]] = []
    for entry in sequence(record["classes"]):
        row = sequence(entry)
        if len(row) != CLASS_GUARD_FIELDS:
            message = "Native runtime class guard must have two fields"
            raise ValueError(message)
        classes.append((string(row[0]), integer(row[1])))
    return {"classes": classes, "vtables": sequence(record["vtables"])}


def _read_manifest(source: bytes) -> _VerifierManifest:
    """Parse the exact required manifest fields without unknown JSON values.

    Returns:
        Checked source metadata for every offline ABI stage.

    """
    record = json_object(source)
    return {
        "payloads": [
            _read_payload(payload) for payload in sequence(record["payloads"])
        ],
        "nativeAdapter": _read_native_adapter(record["nativeAdapter"]),
        "systemProfiles": [
            _read_profile(profile)
            for profile in sequence(record["systemProfiles"])
        ],
        "nativeRuntimeGuards": {
            system: _read_runtime_guards(value)
            for system, value in mapping(record["nativeRuntimeGuards"]).items()
        },
    }


def _binary_image(image: Mach | ReferenceImage) -> Mach:
    """Require a concrete Mach-O binary before inspecting byte-only fields.

    Returns:
        A parsed binary with on-disk segments and executable metadata.

    Raises:
        TypeError: A JSON-only reference cannot prove executable bytes.

    """
    if not isinstance(image, Mach):
        message = "Native ABI byte checks require a concrete Mach-O image"
        raise TypeError(message)
    return image


@final
class _NativeVerifier:
    """Run ordered fail-closed native ABI checks on offline artifacts."""

    def __init__(
        self, temporary: str | Path, binary: str | Path, system: str
    ) -> None:
        """Load the selected profile and verified local manifest."""
        self.temporary = temporary
        self.binary = binary
        self.system = system
        self.plan = SkywalkPlan(system)
        self.checks: list[str] = [
            string(item) for item in verify_model(self.plan.model)
        ]
        self.manifest = _read_manifest(
            read_native_artifact(ROOT / "build/Embedded/manifest.json")
        )

    def _check_payloads(self) -> bytes:
        """Verify namespaced payloads and read the original legacy image.

        Returns:
            Bounded original bytes for the controller identity comparison.

        """
        for payload in self.manifest["payloads"]:
            label = payload["label"]
            image = _binary_image(Mach(IMAGES[label]))
            segments = [
                (address, fileoff, length)
                for _, address, _, fileoff, length in image.segs
            ]
            original = reconstruct_payload_image(
                payload["size"], segments, image.b, base=image.base
            )
            original_size = len(original)
            renamed = self.plan.namespace_payload(label, original, image)
            require(
                (len(original) == original_size),
                "namespaced payload integrity #01",
            )
            require(
                (renamed == payload["namespacedClassStrings"]),
                "namespaced payload integrity #02",
            )
            generated = read_native_artifact(
                ROOT / "build/Embedded" / f"{label}.bin"
            )
            for section in image.sects:
                if section[0] == CSTRING_SECTION:
                    start, length = section[2:4]
                    require(
                        (
                            generated[start : start + length]
                            == bytes(original[start : start + length])
                        ),
                        "namespaced payload integrity #03",
                    )
                    require(
                        (
                            not set(
                                generated[start : start + length].split(b"\0")
                            ).intersection(
                                name.encode() for name in self.plan.namespace
                            )
                        ),
                        "namespaced payload integrity #04",
                    )
        self.checks.append(
            "42 legacy class names isolated in both payload CString sections"
        )
        return read_native_artifact(ROOT / "build/Embedded/Legacy.bin")

    def _check_profile(self) -> None:
        """Verify the profile source invariants.

        Raises:
            ValueError: The runtime metaclass name is malformed.

        """
        require(
            (
                self.plan.namespace["IO80211Controller"]
                == NATIVE_CONTROLLER_NAME
            ),
            "native profile and runtime guards #05",
        )
        require(
            (
                self.manifest["nativeAdapter"]["wirelessControllerIdentity"]
                == NATIVE_CONTROLLER_NAME
            ),
            "native profile and runtime guards #06",
        )
        profile = next(
            p
            for p in self.manifest["systemProfiles"]
            if p["system"] == self.system
        )
        require(
            (profile["nativeUUID"] == self.plan.native.uuid),
            "native profile and runtime guards #07",
        )
        require(
            (profile["wirelessUUID"] == self.plan.wireless.uuid),
            "native profile and runtime guards #08",
        )
        require(
            (
                profile["ethernetSize"]
                == class_size(self.plan.native, "IOSkywalkEthernetInterface")
            ),
            "native profile and runtime guards #09",
        )
        require(
            (
                profile["poolSize"]
                == class_size(self.plan.native, "IOSkywalkPacketBufferPool")
            ),
            "native profile and runtime guards #10",
        )
        require(
            (profile["ethernetLinkSlot"] == self.plan.link_slot),
            "native profile and runtime guards #11",
        )
        if self.plan.link_slot != NO_LOGICAL_LINK_SLOT:
            require(
                (
                    self.plan.model.new_tables["IOSkywalkEthernetInterface"][
                        self.plan.link_slot
                    ]
                    == self.plan.link_symbol
                ),
                "native profile and runtime guards #12",
            )
        require(
            (
                profile["airPortPayloadIndex"]
                == (
                    2
                    if self.plan.profile["kernel"] == TAHOE_KERNEL_MAJOR
                    else 1
                )
            ),
            "native profile and runtime guards #13",
        )
        require(
            (
                self.plan.compat["__ZNK25IOSkywalkPacketBufferPool7releaseEv"]
                == LEGACY_POOL_RELEASE
            ),
            "native profile and runtime guards #14",
        )
        guards = self.manifest["nativeRuntimeGuards"][self.system]
        for meta, size in guards["classes"]:
            match = re.fullmatch(r"__ZN\d+(.+)10gMetaClassE", meta)
            if match is None:
                message = "Unrecognized native runtime metaclass guard"
                raise ValueError(message)
            cls = match[1]
            image = (
                self.plan.wireless
                if cls in CLIENT_CLASSES
                else self.plan.native
            )
            require(
                (class_size(image, cls) == size),
                "native profile and runtime guards #15",
            )
        require(
            (len(guards["classes"]) == RUNTIME_CLASS_COUNT),
            "native profile and runtime guards #16",
        )
        require(
            (len(guards["vtables"]) >= MIN_RUNTIME_VTABLE_COUNT),
            "native profile and runtime guards #17",
        )
        self.checks.append(
            "Major version selects layouts/link without build or UUID gate"
        )

    def _check_controller(self, generated_legacy: bytes) -> None:
        """Verify the controller source invariants."""
        controller_name = 0x127239
        require(
            (
                self.plan.legacy.read(controller_name, 18)
                == ORIGINAL_CONTROLLER_NAME
            ),
            "legacy controller identity #18",
        )
        require(
            (
                generated_legacy[controller_name : controller_name + 18]
                == b"AirPortDriver" + b"\0" * 5
            ),
            "legacy controller identity #19",
        )
        for site in (0x8D629, 0x8D707, 0x94019):
            raw = self.plan.legacy.read(site, 7)
            require(
                (raw[:3] == RIP_RELATIVE_LEA), "legacy controller identity #20"
            )
            require(
                (
                    site + 7 + struct.unpack_from("<i", raw, 3)[0]
                    == controller_name
                ),
                "legacy controller identity #21",
            )
        require(
            (
                class_size(self.plan.legacy, "IO80211Controller")
                == LEGACY_CONTROLLER_SIZE
            ),
            "legacy controller identity #22",
        )
        self.checks.append(
            "Controller metaclasses/init use AirPortDriver; layout intact"
        )

    def _check_power(self) -> None:
        """Verify the power source invariants."""
        generated = read_native_artifact(
            ROOT
            / "build/Embedded"
            / (
                "AirPort.bin"
                if self.plan.profile["kernel"] == TAHOE_KERNEL_MAJOR
                else "AirPortOriginal.bin"
            )
        )
        original_power = self.plan.air.read(self.plan.power_template, 288)
        require(
            (
                generated[
                    self.plan.power_template : self.plan.power_template + 288
                ]
                == original_power
            ),
            "power domain layout #23",
        )
        native_states = self.plan.native.read(
            self.plan.native.names["__ZL13myPowerStates"][4], 192
        )
        required = struct.unpack_from("<Q", native_states, 96 + 24)[0]
        require(
            (required == REQUIRED_POWER_CAPABILITY), "power domain layout #24"
        )
        states = [
            struct.unpack_from("<12Q", original_power, i * 96) for i in range(3)
        ]
        require(
            ([state[2] for state in states] == [0, 0x400, 0]),
            "power domain layout #25",
        )
        require(
            (not any((state[2] & required) == required for state in states)),
            "power domain layout #26",
        )
        require(
            (
                all(
                    not payload["powerDomainPatches"]
                    for payload in self.manifest["payloads"]
                )
            ),
            "power domain layout #27",
        )
        require(
            (
                class_size(self.plan.air, "AirPort_BrcmNIC")
                > MIN_AIRPORT_CLASS_SIZE
            ),
            "power domain layout #28",
        )
        require(
            (
                method_key(
                    self.plan.model.new_tables["IOSkywalkEthernetInterface"][
                        0x7A0 // 8
                    ]
                )
                == POWER_TREE_METHOD
            ),
            "power domain layout #29",
        )
        require(
            (
                self.plan.compat[
                    "__ZN25IOSkywalkNetworkInterface10joinPMtreeEP9IOService"
                ]
                == LEGACY_POWER_JOIN
            ),
            "power domain layout #30",
        )
        topology = self.manifest["nativeAdapter"]["powerDomain"]
        require(
            (topology["strategy"] == POWER_PROVIDER_STRATEGY),
            "power domain layout #31",
        )
        require((topology["airPortTablePreserved"]), "power domain layout #32")
        self.checks.append(
            "Broadcom power table preserved; native joins use joinPMtree"
        )

    def _check_facade(self) -> Mach | ReferenceImage:
        """Verify the native facade and retain its image for client checks.

        Returns:
            Open parsed Mach-O product for later client validation.

        """
        product = Mach(self.binary)
        require(
            (ATH_USER_CLIENT_META in product.names),
            "native user client facade #33",
        )
        require(
            (API_USER_CLIENT_META not in product.defined()),
            "native user client facade #34",
        )
        require(
            (class_size(product, "ATHLegacyInterface") == LEGACY_FACADE_SIZE),
            "native user client facade #35",
        )
        base = table(
            self.plan.model.kernel, "IOService", self.plan.model.kernel
        )
        legacy = table(product, "ATHLegacyInterface")
        require((len(base) == len(legacy)), "native user client facade #36")
        for index, name in enumerate(legacy):
            require(
                (method_key(name) == method_key(base[index])),
                "native user client facade #37",
            )
        self.checks.append(
            "Legacy facade matches IOService slots and 272-byte allocation"
        )

        return product

    def _check_clients(self, product: Mach | ReferenceImage) -> None:
        """Verify the clients source invariants."""
        source = (ROOT / "src/NativeUserClient.cpp").read_text()
        override_slots = {0, 8} | {
            int(value, 16)
            for value in re.findall(r"view\[2 \+ (0x[0-9a-f]+) / 8\]", source)
        }
        expected = {
            0x90: "free()",
            0x5C0: "start(IOService*)",
            0x5C8: "stop(IOService*)",
            0x850: "externalMethod(",
            0x858: "registerNotificationPort(",
            0x8E0: "initWithTask(",
            0x8F0: "clientClose()",
            0x8F8: "clientDied()",
            0x900: "getService()",
            0x908: "registerNotificationPort(",
            0x920: "clientMemoryForType(",
        }
        # Never silently skip an expected client when a table is absent.
        for cls, native_table in zip(
            CLIENT_CLASSES, self.plan.client_tables, strict=True
        ):
            require(
                (len(native_table) == NATIVE_CLIENT_TABLE_SLOTS),
                "native client vtable coverage #38",
            )
            require(
                (class_size(self.plan.wireless, cls) == NATIVE_CLIENT_SIZE),
                "native client vtable coverage #39",
            )
            for offset, prefix in expected.items():
                require(
                    (method_key(native_table[offset // 8]).startswith(prefix)),
                    "native client vtable coverage #40",
                )
            for index, name in enumerate(native_table):
                if cls in name and index * 8 != METACLASS_SLOT_BYTES:
                    require(
                        (index * 8 in override_slots),
                        f"native client vtable coverage #41: {name}",
                    )
            address, code = self.plan.wireless.funcbytes(
                "__ZN" + str(len(cls)) + cls + "4freeEv"
            )
            decoded = list(insns(code, address))
            require(
                (
                    any(
                        RELEASE_RECEIVER_OFFSET in text
                        for _, _, text, _ in decoded
                    )
                ),
                "native client vtable coverage #42",
            )
        require(
            (METACLASS_SLOT_BYTES not in override_slots),
            "native client vtable coverage #43",
        )
        require(
            (INSTANCE_CONSTRUCTED_CALL in source),
            "native client vtable coverage #44",
        )
        self.checks.append(
            "Native client slots/size/overrides/metaclass identity verified"
        )
        product.close()

    def _check_callbacks(self) -> None:
        """Verify supported callback registers and ABI slot ranges.

        Raises:
            AssertionError: A callback exceeds the supported register ABI.

        """
        allowed = {
            "bool",
            "unsigned int",
            "int",
            "unsigned long",
            "unsigned long long",
        }
        for _, _, bindings in self.plan.callbacks:
            for native_slot, index in bindings:
                signature = method_key(self.plan.methods[index])
                arguments = signature[
                    signature.index("(") + 1 : signature.rindex(")")
                ]
                parameters = arguments.split(", ") if arguments else []
                if len(parameters) > MAX_REGISTERED_CALLBACK_PARAMETERS or any(
                    POINTER_MARKER not in p and p not in allowed
                    for p in parameters
                ):
                    raise AssertionError(
                        "Callback requires a different calling convention: "
                        + signature
                    )
                require(
                    (
                        native_slot
                        < len(
                            self.plan.model.new_tables[
                                "IOSkywalkEthernetInterface"
                            ]
                        )
                    ),
                    "callback calling convention #45",
                )
        self.checks.append(
            "All native callbacks fit the verified six-register ABI"
        )

    def _check_packet_calls(self) -> None:
        """Verify the packet calls source invariants."""
        new_slots = {
            method_key(name): i * 8
            for i, name in enumerate(self.plan.model.new_tables[PACKET_CLASS])
        }
        for offset, old_slot, new_slot in self.plan.packet_calls:
            name = self.plan.model.old_tables[PACKET_CLASS][old_slot // 8]
            require(
                (new_slots[method_key(name)] == new_slot),
                "callback calling convention #46",
            )
            require(
                (
                    struct.unpack("<I", self.plan.air.read(offset, 4))[0]
                    == old_slot
                ),
                "packet call identity #47",
            )
        self.checks.append("Every packet call preserves its method identity")

    def _check_constructors(self) -> None:
        """Verify the constructors source invariants."""
        air = _binary_image(self.plan.air)
        functions = air.funcs()
        starts = [address for address, _ in functions]
        for address in self.plan.vptr_sites:
            start, name = functions[bisect.bisect_right(starts, address) - 1]
            require(
                (SKYWALK_PACKET_CONSTRUCTOR in name),
                "packet constructor vptr #48",
            )
            decoded = list(insns(air.read(start, address + 7 - start), start))
            require((decoded[-1][0] == address), "packet constructor vptr #49")
            require(
                (decoded[-1][1] == X86_RELATIVE_LEA_BYTES),
                "packet constructor vptr #50",
            )
        self.checks.append(
            "All packet vptr replacements are complete constructor instructions"
        )
        expected_sizes = []
        for address, relocation in air.relocs().items():
            if relocation[0] == OS_META_CLASS_CONSTRUCTOR and air.read(
                address - 6, 5
            ) == bytes.fromhex("b9b8000000"):
                expected_sizes.append(address - 5)
        require(
            (sorted(expected_sizes) == sorted(self.plan.pool_meta)),
            "pool metaclass coverage #51",
        )
        self.checks.append(
            "Pool metaclass constructors and global initializer both covered"
        )

    def _check_forwarding(self) -> dict[str, JsonValue]:
        """Verify forwarding artifacts through the offline host probe.

        Returns:
            Structured probe counters for the verified forwarding calls.

        """
        old = _binary_image(self.plan.old)
        forwarders = (
            read_native_artifact(ROOT / "build/Embedded/Payloads.S")
            .decode("utf-8")
            .split(".section __TEXT,__text", 1)[1]
        )
        forwarding = run_probe(
            Path(self.temporary), forwarders, len(self.plan.methods)
        )
        blob = read_native_artifact(Path(self.binary))
        old_code = next(
            section for section in old.sects if section[0] == TEXT_SECTION
        )
        require(
            (old.read(old_code[2], min(old_code[3], 4096)) not in blob),
            "legacy executable text isolation #52",
        )
        self.checks.append(
            "The old IOSkywalk executable text is absent from the product"
        )

        return forwarding

    def run(self) -> dict[str, object]:
        """Check every source invariant and return the offline evidence.

        Returns:
            The complete source verification report.

        """
        generated_legacy = self._check_payloads()
        self._check_profile()
        self._check_controller(generated_legacy)
        self._check_power()
        product = self._check_facade()
        self._check_clients(product)
        self._check_callbacks()
        self._check_packet_calls()
        self._check_constructors()
        forwarding = self._check_forwarding()
        result: dict[str, object] = {
            "checks": self.checks,
            "forwarding": forwarding,
            "packetCallSites": len(self.plan.packet_calls),
            "packetConstructors": len(self.plan.vptr_sites),
            "poolSizeSites": len(self.plan.pool_meta),
            "nativeInterfaceCallbacks": [
                len(row[2]) for row in self.plan.callbacks
            ],
            "kernelExecution": False,
            "hardwareValidation": "not-run-by-build",
        }
        self.plan.wireless.close()
        self.plan.model.close()
        return result


def verify_native(
    temporary: str | Path, binary: str | Path, system: str = "Tahoe"
) -> dict[str, object]:
    """Verify native ABI invariants without executing kernel or device code.

    Returns:
        A structured report of checked ABI invariants and offline evidence.

    """
    return _NativeVerifier(temporary, binary, system).run()
