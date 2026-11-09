// SPDX-License-Identifier: AGPL-3.0-only
// Portable malformed-payload guard tests; no kernel, PCI or kext operations.
#include "NativeProfile.hpp"
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

    bool linkPatternBoundaries()
    {
        // The four-byte marker begins at offset 4. The final four bytes encode
        // a signed x86 RIP-relative displacement from the end of the pattern.
        uint8_t text[12] = {0,    0,    0,    0,    0x91, 0x92,
                            0x93, 0x94, 0xfc, 0xff, 0xff, 0xff};
        const uint8_t bytes[8] = {0x91, 0x92, 0x93, 0x94, 0, 0, 0, 0};
        const uint8_t mask[8] = {0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0};
        const ath::NativeCodeReference reference = {4, 0};
        const ath::NativeLinkPattern pattern = {bytes, mask, 8, &reference, 1};
        const uintptr_t validImport[] = {0x1008};
        if (ath::findNativeLink(text, sizeof(text), 0x1000, pattern,
                                validImport, 1) != 0x1004)
            return false;

        // A negative displacement may not wrap below address zero and match an
        // unrelated high import address.
        text[8] = 0xc0;
        const uintptr_t wrappedNegative[] = {UINTPTR_MAX - 51};
        if (ath::findNativeLink(text, sizeof(text), 0, pattern, wrappedNegative,
                                1) != 0)
            return false;

        // Forward RIP-relative targets still resolve normally.
        text[8] = 16;
        text[9] = text[10] = text[11] = 0;
        const uintptr_t forwardImport[] = {0x101c};
        if (ath::findNativeLink(text, sizeof(text), 0x1000, pattern,
                                forwardImport, 1) != 0x1004)
            return false;

        // A positive displacement may not wrap beyond the address space.
        const uintptr_t wrappedPositive[] = {11};
        if (ath::findNativeLink(text, sizeof(text), UINTPTR_MAX - 16, pattern,
                                wrappedPositive, 1) != 0)
            return false;

        // The pattern itself may not straddle the address-space boundary.
        text[8] = text[9] = text[10] = text[11] = 0;
        const uintptr_t wrappedEnd[] = {6};
        if (ath::findNativeLink(text, sizeof(text), UINTPTR_MAX - 5, pattern,
                                wrappedEnd, 1) != 0)
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

    // The direct stub writer is also an entrypoint: a forged mapping can
    // point its writable stub range into the payload descriptor itself.
    // Do not corrupt the descriptors needed for subsequent memory safety.
    ath::Payload selfDescribingPayload {};
    selfDescribingPayload.size = 16;
    selfDescribingPayload.mappedSize = sizeof(selfDescribingPayload);
    selfDescribingPayload.stubOffset = 16;
    selfDescribingPayload.stubSize = 16;
    auto *payloadStorage = reinterpret_cast<uint8_t *>(&selfDescribingPayload);
    uint8_t originalPayload[sizeof(selfDescribingPayload)] {};
    std::memcpy(originalPayload, payloadStorage, sizeof(originalPayload));
    ath::LinkedImage selfDescribingImage {
        &selfDescribingPayload, payloadStorage, 0x7000, 0, false, true};
    if (ath::allocateStub(selfDescribingImage, 0x12345678) != 0 ||
        selfDescribingImage.stubUsed != 0 ||
        std::memcmp(originalPayload, payloadStorage, sizeof(originalPayload)) !=
            0)
        return 38;

    // A second forged mapping can alias the LinkedImage descriptor that
    // carries its own memory pointer, allocation state and target address.
    ath::Payload selfAliasedPayload {};
    selfAliasedPayload.size = 0;
    selfAliasedPayload.mappedSize = sizeof(ath::LinkedImage);
    selfAliasedPayload.stubOffset = 0;
    selfAliasedPayload.stubSize = 16;
    ath::LinkedImage selfAliasedImage {
        &selfAliasedPayload, nullptr, 0x8000, 0, false, true};
    selfAliasedImage.memory = reinterpret_cast<uint8_t *>(&selfAliasedImage);
    uint8_t originalImage[sizeof(selfAliasedImage)] {};
    std::memcpy(originalImage, &selfAliasedImage, sizeof(originalImage));
    if (ath::allocateStub(selfAliasedImage, 0x12345678) != 0 ||
        std::memcmp(originalImage, &selfAliasedImage, sizeof(originalImage)) !=
            0)
        return 39;

    // Relocation metadata can itself live inside a caller-owned mapping.
    // Treat it as immutable input: writing the first relocated pointer must
    // never modify a still-live relocation record or return success.
    ath::Relocation aliasedRelocations[2] {};
    aliasedRelocations[0].offset = 0;
    aliasedRelocations[0].width = 8;
    aliasedRelocations[0].image = 255;
    aliasedRelocations[0].target = 0;
    auto *relocatedBytes = reinterpret_cast<uint8_t *>(aliasedRelocations);
    ath::Payload aliasedPayload {};
    aliasedPayload.size = sizeof(aliasedRelocations[0]);
    aliasedPayload.mappedSize = sizeof(aliasedRelocations);
    aliasedPayload.stubOffset = sizeof(aliasedRelocations[0]);
    aliasedPayload.stubSize = sizeof(aliasedRelocations[0]);
    aliasedPayload.relocations = aliasedRelocations;
    aliasedPayload.relocationCount = 1;
    aliasedPayload.checksum =
        ath::payloadChecksum(relocatedBytes, aliasedPayload.size);
    uint8_t oldRelocations[sizeof(aliasedRelocations)] {};
    std::memcpy(oldRelocations, relocatedBytes, sizeof(oldRelocations));
    ath::LinkedImage aliasImage {
        &aliasedPayload, relocatedBytes, 0x5000, 0, false, true};
    const uintptr_t aliasImports[] {0x5050};
    if (ath::relocateImage(aliasImage, nullptr, 0, aliasImports, 1, nullptr,
                           0) ||
        std::memcmp(oldRelocations, relocatedBytes, sizeof(oldRelocations)) !=
            0)
        return 35;

    // Symbol value offsets have the same alias problem: an offset table in
    // the output mapping may be overwritten by its own relocation operation.
    uint32_t aliasedOffsets[8] {};
    auto *offsetBytes = reinterpret_cast<uint8_t *>(aliasedOffsets);
    ath::Payload offsetPayload {};
    offsetPayload.size = 16;
    offsetPayload.mappedSize = sizeof(aliasedOffsets);
    offsetPayload.stubOffset = 16;
    offsetPayload.stubSize = 16;
    offsetPayload.symbolValues = aliasedOffsets;
    offsetPayload.symbolValueCount = 1;
    offsetPayload.checksum =
        ath::payloadChecksum(offsetBytes, offsetPayload.size);
    uint8_t oldOffsets[sizeof(aliasedOffsets)] {};
    std::memcpy(oldOffsets, offsetBytes, sizeof(oldOffsets));
    ath::LinkedImage offsetImage {&offsetPayload, offsetBytes, 0x6000, 0,
                                  false,          true};
    if (ath::relocateImage(offsetImage, nullptr, 0, nullptr, 0, nullptr, 0) ||
        std::memcmp(oldOffsets, offsetBytes, sizeof(oldOffsets)) != 0)
        return 36;

    if (!linkPatternBoundaries())
        return 37;
    return 0;
}
