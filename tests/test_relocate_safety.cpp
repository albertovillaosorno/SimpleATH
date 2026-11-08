// SPDX-License-Identifier: AGPL-3.0-only
// Portable malformed-payload guard tests; no kernel, PCI or kext operations.
#include "Payload.hpp"

#include <cstdint>
#include <cstring>

namespace
{
    bool unchanged(const uint8_t *bytes, size_t count)
    {
        for (size_t index = 0; index < count; ++index)
            if (bytes[index] != 0)
                return false;
        return true;
    }
} // namespace

int main()
{
    uint8_t storage[24] {};
    uint8_t foreignStorage[8] {};
    ath::Relocation relocation {};
    relocation.width = 8;
    relocation.image = 0;
    relocation.target = 4;
    ath::Payload payload {};
    payload.size = 8;
    payload.mappedSize = sizeof(storage);
    payload.stubOffset = 8;
    payload.stubSize = 16;
    payload.relocations = &relocation;
    payload.relocationCount = 1;
    payload.checksum = ath::payloadChecksum(storage, payload.size);
    ath::LinkedImage image {&payload, storage, 0x1000, 0, false, true};
    ath::LinkedImage foreign {nullptr, foreignStorage, 0x2000, 0, false, true};

    // A caller-supplied imported image can own memory but have no payload.
    // Before the guard, accessing that image's symbol bounds dereferences
    // a null payload pointer and crashes the kernel caller.
    if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
        !unchanged(storage, sizeof(storage)))
        return 20;

    // Counted metadata must never be dereferenced when the pointer is null.
    payload.relocations = nullptr;
    if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
        !unchanged(storage, sizeof(storage)))
        return 21;
    payload.relocationCount = 0;
    payload.symbolValueCount = 1;
    if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
        !unchanged(storage, sizeof(storage)))
        return 22;
    payload.symbolValueCount = 0;
    payload.relocations = &relocation;
    payload.relocationCount = 1;

    // Null names and missing symbol tables should produce no result, and a
    // missing payload/mapping may never allocate a stub or touch memory.
    ath::LinkedImage missing {};
    if (ath::findSymbol(image, nullptr) != 0 ||
        ath::findSymbol(missing, "missing") != 0 ||
        ath::allocateStub(missing, 0x3000) != 0)
        return 23;
    payload.symbolCount = 1;
    if (ath::findSymbol(image, "missing") != 0)
        return 24;
    payload.symbolCount = 0;

    // Imported relocation targets and signed addends must not wrap 64-bit
    // kernel virtual addresses to an unrelated mapped address.
    ath::Payload importedPayload {};
    importedPayload.size = sizeof(foreignStorage);
    foreign.payload = &importedPayload;
    foreign.address = UINTPTR_MAX - 2;
    if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
        !unchanged(storage, sizeof(storage)))
        return 25;
    foreign.address = 0x2000;
    relocation.addend = INT64_MIN;
    if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
        !unchanged(storage, sizeof(storage)))
        return 26;
    relocation.image = 255;
    relocation.target = 0;
    relocation.addend = 8;
    const uintptr_t imports[] = {UINTPTR_MAX - 2};
    if (ath::relocateImage(image, nullptr, 0, imports, 1, nullptr, 0) ||
        !unchanged(storage, sizeof(storage)))
        return 27;

    // Keep a positive relocation to ensure the hardened path remains usable.
    relocation.image = 0;
    relocation.target = 4;
    relocation.addend = 0;
    if (!ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0))
        return 28;
    uintptr_t resultingAddress = 0;
    std::memcpy(&resultingAddress, storage, sizeof(resultingAddress));
    if (resultingAddress != 0x2004)
        return 29;

    // Restoration first validates each delta record, then zeroes the mapped
    // destination before applying it. An aliased delta would be erased after
    // validation, silently producing an image different from the payload.
    uint8_t payloadBytes[8] {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t mapped[32] {};
    const uint8_t patch[9] {4, 0, 0, 0, 1, 0, 0, 0, 0x7f};
    ath::Payload restored {};
    restored.bytes = payloadBytes;
    restored.bytesSize = sizeof(payloadBytes);
    restored.size = sizeof(payloadBytes);
    restored.mappedSize = sizeof(mapped);
    restored.stubOffset = sizeof(payloadBytes);
    restored.stubSize = sizeof(mapped) - sizeof(payloadBytes);
    restored.delta = mapped + sizeof(payloadBytes);
    restored.deltaSize = sizeof(patch);
    std::memcpy(mapped + sizeof(payloadBytes), patch, sizeof(patch));
    uint8_t previous[sizeof(mapped)] {};
    std::memcpy(previous, mapped, sizeof(mapped));
    ath::LinkedImage restoredImage {&restored, mapped, 0x3000, 7, false, true};
    if (ath::restorePayload(restoredImage) ||
        std::memcmp(previous, mapped, sizeof(mapped)) != 0)
        return 30;

    // Overlapping base bytes would enter memcpy with undefined behavior;
    // reject them without touching the mapped image or its stub usage.
    restored.delta = nullptr;
    restored.deltaSize = 0;
    restored.bytes = mapped + 1;
    restored.bytesSize = sizeof(payloadBytes);
    if (ath::restorePayload(restoredImage) ||
        std::memcmp(previous, mapped, sizeof(mapped)) != 0 ||
        restoredImage.stubUsed != 7)
        return 31;

    // Independent base/delta storage remains supported and clears old stubs.
    restored.bytes = payloadBytes;
    restored.delta = patch;
    restored.deltaSize = sizeof(patch);
    if (!ath::restorePayload(restoredImage) || mapped[4] != 0x7f ||
        mapped[0] != 1 || mapped[7] != 8 || mapped[8] != 0 ||
        restoredImage.stubUsed != 0)
        return 32;

    // A caller can invoke allocateStub independently of restorePayload.
    // The reserved stub area must never overlap live executable image bytes.
    uint8_t executableAndStubs[32] {};
    uint8_t initialStubBytes[sizeof(executableAndStubs)] {};
    ath::Payload stubPayload {};
    stubPayload.size = 16;
    stubPayload.mappedSize = sizeof(executableAndStubs);
    stubPayload.stubOffset = 8; // Malformed: overlaps the executable prefix.
    stubPayload.stubSize = 16;
    ath::LinkedImage stubImage {
        &stubPayload, executableAndStubs, 0x4000, 0, false, true};
    if (ath::allocateStub(stubImage, 0x12345678) != 0 ||
        stubImage.stubUsed != 0 ||
        std::memcmp(initialStubBytes, executableAndStubs,
                    sizeof(executableAndStubs)) != 0)
        return 33;

    // A valid, disjoint reservation still builds a full 16-byte jump stub.
    stubPayload.stubOffset = 16;
    if (ath::allocateStub(stubImage, 0x12345678) != 0x4010 ||
        stubImage.stubUsed != 16 ||
        std::memcmp(initialStubBytes, executableAndStubs, 16) != 0 ||
        executableAndStubs[16] != 0xff || executableAndStubs[17] != 0x25)
        return 34;
    return 0;
}
