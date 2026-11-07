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

import bisect
import json
from pathlib import Path
import re
import struct

from bootstrap import ROOT
from native_abi import Mach
from native_abi import class_size
from native_abi import insns
from native_abi import method_key
from native_abi import table
from native_abi import verify_model
from native_payload import CLIENT_CLASSES
from native_payload import PACKET_CLASS
from native_payload import SkywalkPlan
from profiles import IMAGES
from native_forwarding_probe import run_probe

if __package__:
    from tools.native_invariants import read_native_artifact
    from tools.native_invariants import require
else:
    from native_invariants import read_native_artifact
    from native_invariants import require


def verify_native(temporary, binary, system="Tahoe"):
    plan = SkywalkPlan(system)
    checks = verify_model(plan.model)
    manifest = json.loads((ROOT / "build/Embedded/manifest.json").read_text())
    for payload in manifest["payloads"]:
        label = payload["label"]
        image = Mach(IMAGES[label])
        original = bytearray(payload["size"])
        for _, address, _, fileoff, length in image.segs:
            original[address : address + length] = image.b[
                image.base + fileoff : image.base + fileoff + length
            ]
        original_size = len(original)
        renamed = plan.namespace_payload(label, original, image)
        require(
            (len(original) == original_size), "namespaced payload integrity #01"
        )
        require(
            (renamed == payload["namespacedClassStrings"]),
            "namespaced payload integrity #02",
        )
        generated = (ROOT / ("build/Embedded/" + label + ".bin")).read_bytes()
        for section in image.sects:
            if section[0] == "__cstring":
                start, length = section[2:4]
                require(
                    (
                        generated[start : start + length]
                        == original[start : start + length]
                    ),
                    "namespaced payload integrity #03",
                )
                strings = set(generated[start : start + length].split(b"\0"))
                require(
                    (
                        not strings.intersection(
                            name.encode() for name in plan.namespace
                        )
                    ),
                    "namespaced payload integrity #04",
                )
    checks.append(
        "All 42 shared legacy class names are isolated in both payload CString sections"
    )
    generated_legacy = (ROOT / "build/Embedded/Legacy.bin").read_bytes()
    require(
        (plan.namespace["IO80211Controller"] == "AirPortDriver"),
        "native profile and runtime guards #05",
    )
    require(
        (
            manifest["nativeAdapter"]["wirelessControllerIdentity"]
            == "AirPortDriver"
        ),
        "native profile and runtime guards #06",
    )
    profile = next(
        p for p in manifest["systemProfiles"] if p["system"] == system
    )
    require(
        (profile["nativeUUID"] == plan.native.uuid),
        "native profile and runtime guards #07",
    )
    require(
        (profile["wirelessUUID"] == plan.wireless.uuid),
        "native profile and runtime guards #08",
    )
    require(
        (
            profile["ethernetSize"]
            == class_size(plan.native, "IOSkywalkEthernetInterface")
        ),
        "native profile and runtime guards #09",
    )
    require(
        (
            profile["poolSize"]
            == class_size(plan.native, "IOSkywalkPacketBufferPool")
        ),
        "native profile and runtime guards #10",
    )
    require(
        (profile["ethernetLinkSlot"] == plan.link_slot),
        "native profile and runtime guards #11",
    )
    if plan.link_slot != 0xFFFFFFFF:
        require(
            (
                plan.model.new_tables["IOSkywalkEthernetInterface"][
                    plan.link_slot
                ]
                == plan.link_symbol
            ),
            "native profile and runtime guards #12",
        )
    require(
        (
            profile["airPortPayloadIndex"]
            == (2 if plan.profile["kernel"] == 25 else 1)
        ),
        "native profile and runtime guards #13",
    )
    require(
        (
            plan.compat["__ZNK25IOSkywalkPacketBufferPool7releaseEv"]
            == "_athLegacyPoolRelease"
        ),
        "native profile and runtime guards #14",
    )
    guards = manifest["nativeRuntimeGuards"][system]
    for meta, size in guards["classes"]:
        cls = re.fullmatch(r"__ZN\d+(.+)10gMetaClassE", meta)[1]
        image = plan.wireless if cls in CLIENT_CLASSES else plan.native
        require(
            (class_size(image, cls) == size),
            "native profile and runtime guards #15",
        )
    require(
        (len(guards["classes"]) == 15), "native profile and runtime guards #16"
    )
    require(
        (len(guards["vtables"]) >= 1060),
        "native profile and runtime guards #17",
    )
    checks.append(
        "Major-version profile selects native layouts and a logical-link entry without a build or UUID gate"
    )
    controller_name = 0x127239
    require(
        (plan.legacy.read(controller_name, 18) == b"IO80211Controller\0"),
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
        raw = plan.legacy.read(site, 7)
        require((raw[:3] == b"\x48\x8d\x35"), "legacy controller identity #20")
        require(
            (site + 7 + struct.unpack_from("<i", raw, 3)[0] == controller_name),
            "legacy controller identity #21",
        )
    require(
        (class_size(plan.legacy, "IO80211Controller") == 1048),
        "legacy controller identity #22",
    )
    checks.append(
        "Both controller metaclass constructors and the module initializer use AirPortDriver with unchanged storage and class size"
    )
    generated = (
        ROOT
        / (
            "build/Embedded/"
            + ("AirPort" if plan.profile["kernel"] == 25 else "AirPortOriginal")
            + ".bin"
        )
    ).read_bytes()
    original_power = plan.air.read(plan.power_template, 288)
    require(
        (
            generated[plan.power_template : plan.power_template + 288]
            == original_power
        ),
        "power domain layout #23",
    )
    native_states = plan.native.read(
        plan.native.names["__ZL13myPowerStates"][4], 192
    )
    required = struct.unpack_from("<Q", native_states, 96 + 24)[0]
    require((required == 2), "power domain layout #24")
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
                for payload in manifest["payloads"]
            )
        ),
        "power domain layout #27",
    )
    require(
        (class_size(plan.air, "AirPort_BrcmNIC") > 6816),
        "power domain layout #28",
    )
    require(
        (
            method_key(
                plan.model.new_tables["IOSkywalkEthernetInterface"][0x7A0 // 8]
            )
            == "joinPMtree(IOService*)"
        ),
        "power domain layout #29",
    )
    require(
        (
            plan.compat[
                "__ZN25IOSkywalkNetworkInterface10joinPMtreeEP9IOService"
            ]
            == "_athLegacyJoinPowerTree"
        ),
        "power domain layout #30",
    )
    topology = manifest["nativeAdapter"]["powerDomain"]
    require((topology["strategy"] == "pci-provider"), "power domain layout #31")
    require((topology["airPortTablePreserved"]), "power domain layout #32")
    checks.append(
        "Original Broadcom power table preserved; native power joins use the verified joinPMtree slot"
    )
    product = Mach(binary)
    require(
        ("__ZN18ATH80211UserClient10gMetaClassE" in product.names),
        "native user client facade #33",
    )
    require(
        ("__ZN20IO80211APIUserClient10gMetaClassE" not in product.defined()),
        "native user client facade #34",
    )
    require(
        (class_size(product, "ATHLegacyInterface") == 272),
        "native user client facade #35",
    )
    base = table(plan.model.kernel, "IOService", plan.model.kernel)
    legacy = table(product, "ATHLegacyInterface")
    require((len(base) == len(legacy)), "native user client facade #36")
    for index, name in enumerate(legacy):
        require(
            (method_key(name) == method_key(base[index])),
            "native user client facade #37",
        )
    checks.append(
        "Compiled legacy facade has the native IOService slot layout and 272-byte allocation"
    )
    source = (ROOT / "SimpleATH/NativeUserClient.cpp").read_text()
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
    for cls, native_table in zip(CLIENT_CLASSES, plan.client_tables):
        require((len(native_table) == 300), "native client vtable coverage #38")
        require(
            (class_size(plan.wireless, cls) == 224),
            "native client vtable coverage #39",
        )
        for offset, prefix in expected.items():
            require(
                (method_key(native_table[offset // 8]).startswith(prefix)),
                "native client vtable coverage #40",
            )
        for index, name in enumerate(native_table):
            if cls in name and index * 8 != 0x38:
                require(
                    (index * 8 in override_slots),
                    f"native client vtable coverage #41: {name}",
                )
        address, code = plan.wireless.funcbytes(
            "__ZN" + str(len(cls)) + cls + "4freeEv"
        )
        decoded = list(insns(code, address))
        require(
            (any("216(" in text for _, _, text, _ in decoded)),
            "native client vtable coverage #42",
        )
    require((0x38 not in override_slots), "native client vtable coverage #43")
    require(
        ("meta->instanceConstructed()" in source),
        "native client vtable coverage #44",
    )
    checks.append(
        "Native client slots, sizes, complete override coverage and genuine metaclass identity verified"
    )
    product.close()
    allowed = {
        "bool",
        "unsigned int",
        "int",
        "unsigned long",
        "unsigned long long",
    }
    for _, _, bindings in plan.callbacks:
        for native_slot, index in bindings:
            signature = method_key(plan.methods[index])
            arguments = signature[
                signature.index("(") + 1 : signature.rindex(")")
            ]
            parameters = arguments.split(", ") if arguments else []
            if len(parameters) > 5 or any(
                "*" not in p and p not in allowed for p in parameters
            ):
                raise AssertionError(
                    "Callback requires a different calling convention: "
                    + signature
                )
            require(
                (
                    native_slot
                    < len(plan.model.new_tables["IOSkywalkEthernetInterface"])
                ),
                "callback calling convention #45",
            )
    checks.append("All native callbacks fit the verified six-register ABI")
    new_slots = {
        method_key(name): i * 8
        for i, name in enumerate(plan.model.new_tables[PACKET_CLASS])
    }
    for offset, old_slot, new_slot in plan.packet_calls:
        name = plan.model.old_tables[PACKET_CLASS][old_slot // 8]
        require(
            (new_slots[method_key(name)] == new_slot),
            "callback calling convention #46",
        )
        require(
            (struct.unpack("<I", plan.air.read(offset, 4))[0] == old_slot),
            "packet call identity #47",
        )
    checks.append("Every packet call preserves its method identity")
    functions = plan.air.funcs()
    starts = [address for address, _ in functions]
    for address in plan.vptr_sites:
        start, name = functions[bisect.bisect_right(starts, address) - 1]
        require(
            ("AirPort_Brcm43xxSkywalkPacket" in name),
            "packet constructor vptr #48",
        )
        decoded = list(insns(plan.air.read(start, address + 7 - start), start))
        require((decoded[-1][0] == address), "packet constructor vptr #49")
        require((decoded[-1][1] == 7), "packet constructor vptr #50")
    checks.append(
        "All packet vptr replacements are complete constructor instructions"
    )
    expected_sizes = []
    for address, relocation in plan.air.relocs().items():
        if relocation[0] == "__ZN11OSMetaClassC2EPKcPKS_j" and plan.air.read(
            address - 6, 5
        ) == bytes.fromhex("b9b8000000"):
            expected_sizes.append(address - 5)
    require(
        (sorted(expected_sizes) == sorted(plan.pool_meta)),
        "pool metaclass coverage #51",
    )
    checks.append(
        "Both pool metaclass constructors and the global initializer are covered"
    )
    forwarders = (
        (ROOT / "build/Embedded/Payloads.S")
        .read_text()
        .split(".section __TEXT,__text", 1)[1]
    )
    forwarding = run_probe(Path(temporary), forwarders, len(plan.methods))
    blob = read_native_artifact(Path(binary))
    old_code = next(
        section for section in plan.old.sects if section[0] == "__text"
    )
    require(
        (plan.old.read(old_code[2], min(old_code[3], 4096)) not in blob),
        "legacy executable text isolation #52",
    )
    checks.append(
        "The old IOSkywalk executable text is absent from the product"
    )
    result = {
        "checks": checks,
        "forwarding": forwarding,
        "packetCallSites": len(plan.packet_calls),
        "packetConstructors": len(plan.vptr_sites),
        "poolSizeSites": len(plan.pool_meta),
        "nativeInterfaceCallbacks": [len(row[2]) for row in plan.callbacks],
        "kernelExecution": False,
        "hardwareValidation": "not-run-by-build",
    }
    plan.wireless.close()
    plan.model.close()
    return result
