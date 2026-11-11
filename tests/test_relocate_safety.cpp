// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Offline regression cases for relocate safety.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for relocate safety.
// - Description:
//   - Implements or verifies the test_relocate_safety source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for relocate safety.

// Portable malformed-payload guard tests; no kernel, PCI or kext operations.
#include "NativeProfile.hpp"
#include "Payload.hpp"

#include <cstdint>
#include <cstring>

namespace
{
    // The regression fixtures intentionally encode exact source bytes,
    // address boundaries and exit codes. Keep these values named so they are
    // distinct from lengths supplied by a caller's untrusted payload.
    constexpr auto kFixtureInt5 = 5;
    constexpr auto kFixtureInt6 = 6;
    constexpr auto kFixtureInt7 = 7;
    constexpr auto kFixtureInt8 = 8;
    constexpr auto kFixtureInt9 = 9;
    constexpr auto kFixtureInt10 = 10;
    constexpr auto kFixtureInt11 = 11;
    constexpr auto kFixtureInt12 = 12;
    constexpr auto kFixtureInt16 = 16;
    constexpr auto kFixtureInt17 = 17;
    constexpr auto kFixtureInt20 = 20;
    constexpr auto kFixtureInt21 = 21;
    constexpr auto kFixtureInt22 = 22;
    constexpr auto kFixtureInt23 = 23;
    constexpr auto kFixtureInt24 = 24;
    constexpr auto kFixtureInt25 = 25;
    constexpr auto kFixtureInt26 = 26;
    constexpr auto kFixtureInt27 = 27;
    constexpr auto kFixtureInt28 = 28;
    constexpr auto kFixtureInt29 = 29;
    constexpr auto kFixtureInt30 = 30;
    constexpr auto kFixtureInt31 = 31;
    constexpr auto kFixtureInt32 = 32;
    constexpr auto kFixtureInt33 = 33;
    constexpr auto kFixtureInt34 = 34;
    constexpr auto kFixtureInt35 = 35;
    constexpr auto kFixtureInt36 = 36;
    constexpr auto kFixtureHex25 = 0x25;
    constexpr auto kFixtureInt37 = 37;
    constexpr auto kFixtureInt38 = 38;
    constexpr auto kFixtureInt39 = 39;
    constexpr auto kFixtureInt40 = 40;
    constexpr auto kFixtureInt41 = 41;
    constexpr auto kFixtureInt42 = 42;
    constexpr auto kFixtureHex7f = 0x7f;
    constexpr auto kFixtureHex91 = 0x91;
    constexpr auto kFixtureHex92 = 0x92;
    constexpr auto kFixtureHex93 = 0x93;
    constexpr auto kFixtureHex94 = 0x94;
    constexpr auto kFixtureHexc0 = 0xc0;
    constexpr auto kFixtureHexf0 = 0xf0;
    constexpr auto kFixtureHexf8 = 0xf8;
    constexpr auto kFixtureHexfc = 0xfc;
    constexpr auto kFixtureHexff = 0xff;
    constexpr auto kFixtureInt255 = 255;
    constexpr auto kFixtureHex1000 = 0x1000;
    constexpr auto kFixtureHex1004 = 0x1004;
    constexpr auto kFixtureHex2000 = 0x2000;
    constexpr auto kFixtureHex2004 = 0x2004;
    constexpr auto kFixtureHex3000 = 0x3000;
    constexpr auto kFixtureHex4000 = 0x4000;
    constexpr auto kFixtureHex4010 = 0x4010;
    constexpr auto kFixtureHex5000 = 0x5000;
    constexpr auto kFixtureHex6000 = 0x6000;
    constexpr auto kFixtureHex7000 = 0x7000;
    constexpr auto kFixtureHex8000 = 0x8000;
    constexpr auto kFixtureHex9000 = 0x9000;
    constexpr auto kFixtureHexa000 = 0xa000;
    constexpr auto kFixtureHexb000 = 0xb000;
    constexpr auto kFixtureHex12345678 = 0x12345678;

    template <typename T, size_t N> T *arrayData(T (&array)[N])
    {
        return &array[0U];
    }

    // The fixture deliberately aliases object bytes: memcpy of the pointer
    // representation preserves the address without a type-punning cast.
    template <typename T> uint8_t *byteView(T &object)
    {
        const T *const original = &object;
        uint8_t *result = nullptr;
        static_assert(sizeof(const T *) == sizeof(uint8_t *),
                      "Host pointer representations must have equal width");
        std::memcpy(static_cast<void *>(&result),
                    static_cast<const void *>(&original), sizeof(result));
        return result;
    }

    bool unchanged(const uint8_t *bytes, size_t count)
    {
        for (size_t index = 0; index < count; ++index)
        {
            uint8_t value = 0U;
            if (!ath::detail::readAt(bytes, index, value) || value != 0U)
            {
                return false;
            }
        }
        return true;
    }

    bool linkPatternBoundaries()
    {
        // The four-byte marker begins at offset 4. The final four bytes encode
        // a signed x86 RIP-relative displacement from the end of the pattern.
        uint8_t text[kFixtureInt12] = {
            0,
            0,
            0,
            0,
            kFixtureHex91,
            kFixtureHex92,
            kFixtureHex93,
            kFixtureHex94,
            kFixtureHexfc,
            kFixtureHexff,
            kFixtureHexff,
            kFixtureHexff,
        };
        const uint8_t bytes[8] = {0x91, 0x92, 0x93, 0x94, 0, 0, 0, 0};
        const uint8_t mask[8] = {0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0};
        const ath::NativeCodeReference reference = {4, 0};
        const ath::NativeLinkPattern pattern = {
            arrayData(bytes), arrayData(mask), 8, &reference, 1,
        };
        const uintptr_t validImport[] = {0x1008};
        if (ath::findNativeLink(arrayData(text), sizeof(text), kFixtureHex1000,
                                pattern, arrayData(validImport),
                                1) != kFixtureHex1004)
        {
            return false;
        }

        // A negative displacement may not wrap below address zero and match an
        // unrelated high import address.
        text[kFixtureInt8] = kFixtureHexc0;
        const uintptr_t wrappedNegative[] = {UINTPTR_MAX - 51};
        if (ath::findNativeLink(arrayData(text), sizeof(text), 0, pattern,
                                arrayData(wrappedNegative), 1) != 0)
        {
            return false;
        }

        // Forward RIP-relative targets still resolve normally.
        text[kFixtureInt8] = kFixtureInt16;
        text[kFixtureInt9] = text[kFixtureInt10] = text[kFixtureInt11] = 0;
        const uintptr_t forwardImport[] = {0x101c};
        if (ath::findNativeLink(arrayData(text), sizeof(text), kFixtureHex1000,
                                pattern, arrayData(forwardImport),
                                1) != kFixtureHex1004)
        {
            return false;
        }

        // A positive displacement may not wrap beyond the address space.
        const uintptr_t wrappedPositive[] = {11};
        if (ath::findNativeLink(arrayData(text), sizeof(text),
                                UINTPTR_MAX - kFixtureInt16, pattern,
                                arrayData(wrappedPositive), 1) != 0)
        {
            return false;
        }

        // The pattern itself may not straddle the address-space boundary.
        text[kFixtureInt8] = text[kFixtureInt9] = text[kFixtureInt10] =
            text[kFixtureInt11] = 0;
        const uintptr_t wrappedEnd[] = {6};
        if (ath::findNativeLink(arrayData(text), sizeof(text),
                                UINTPTR_MAX - kFixtureInt5, pattern,
                                arrayData(wrappedEnd), 1) != 0)
        {
            return false;
        }

        // The first valid match at base zero must not conceal a duplicate.
        uint8_t duplicate[kFixtureInt16] = {
            kFixtureHex91,
            kFixtureHex92,
            kFixtureHex93,
            kFixtureHex94,
            kFixtureHexf8,
            0,
            0,
            0,
            kFixtureHex91,
            kFixtureHex92,
            kFixtureHex93,
            kFixtureHex94,
            kFixtureHexf0,
            0,
            0,
            0,
        };
        const uintptr_t duplicateImport[] = {0x100};
        if (ath::findNativeLink(arrayData(duplicate), sizeof(duplicate), 0,
                                pattern, arrayData(duplicateImport), 1) != 0)
        {
            return false;
        }
        duplicate[0] = 0;
        return ath::findNativeLink(arrayData(duplicate), sizeof(duplicate), 0,
                                   pattern, arrayData(duplicateImport),
                                   1) == kFixtureInt8;
    }
} // namespace

namespace
{
    int relocationGuardCases()
    {
        uint8_t storage[kFixtureInt24] {};
        uint8_t foreignStorage[kFixtureInt8] {};
        ath::Relocation relocation {};
        relocation.width = kFixtureInt8;
        relocation.image = 0;
        relocation.target = 4;
        ath::Payload payload {};
        payload.size = kFixtureInt8;
        payload.mappedSize = sizeof(storage);
        payload.stubOffset = kFixtureInt8;
        payload.stubSize = kFixtureInt16;
        payload.relocations = &relocation;
        payload.relocationCount = 1;
        payload.checksum =
            ath::payloadChecksum(arrayData(storage), payload.size);
        ath::LinkedImage image {
            &payload, arrayData(storage), kFixtureHex1000, 0, false, true,
        };
        ath::LinkedImage foreign {
            nullptr, arrayData(foreignStorage), kFixtureHex2000, 0, false, true,
        };

        // A caller-supplied imported image can own memory but have no payload.
        // Before the guard, accessing that image's symbol bounds dereferences
        // a null payload pointer and crashes the kernel caller.
        if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
            !unchanged(arrayData(storage), sizeof(storage)))
        {
            return kFixtureInt20;
        }

        // Counted metadata must never be dereferenced when the pointer is null.
        payload.relocations = nullptr;
        if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
            !unchanged(arrayData(storage), sizeof(storage)))
        {
            return kFixtureInt21;
        }
        payload.relocationCount = 0;
        payload.symbolValueCount = 1;
        if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
            !unchanged(arrayData(storage), sizeof(storage)))
        {
            return kFixtureInt22;
        }
        payload.symbolValueCount = 0;
        payload.relocations = &relocation;
        payload.relocationCount = 1;

        // Null names and missing symbol tables should produce no result, and a
        // missing payload/mapping may never allocate a stub or touch memory.
        ath::LinkedImage missing {};
        if (ath::findSymbol(image, nullptr) != 0 ||
            ath::findSymbol(missing, "missing") != 0 ||
            ath::allocateStub(missing, kFixtureHex3000) != 0)
        {
            return kFixtureInt23;
        }
        payload.symbolCount = 1;
        if (ath::findSymbol(image, "missing") != 0)
        {
            return kFixtureInt24;
        }
        payload.symbolCount = 0;

        // Imported relocation targets and signed addends must not wrap 64-bit
        // kernel virtual addresses to an unrelated mapped address.
        ath::Payload importedPayload {};
        importedPayload.size = sizeof(foreignStorage);
        foreign.payload = &importedPayload;
        foreign.address = UINTPTR_MAX - 2;
        if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
            !unchanged(arrayData(storage), sizeof(storage)))
        {
            return kFixtureInt25;
        }
        foreign.address = kFixtureHex2000;
        relocation.addend = INT64_MIN;
        if (ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0) ||
            !unchanged(arrayData(storage), sizeof(storage)))
        {
            return kFixtureInt26;
        }
        relocation.image = kFixtureInt255;
        relocation.target = 0;
        relocation.addend = kFixtureInt8;
        const uintptr_t imports[] = {UINTPTR_MAX - 2};
        if (ath::relocateImage(image, nullptr, 0, arrayData(imports), 1,
                               nullptr, 0) ||
            !unchanged(arrayData(storage), sizeof(storage)))
        {
            return kFixtureInt27;
        }

        // Keep a positive relocation to ensure the hardened path remains
        // usable.
        relocation.image = 0;
        relocation.target = 4;
        relocation.addend = 0;
        if (!ath::relocateImage(image, &foreign, 1, nullptr, 0, nullptr, 0))
        {
            return kFixtureInt28;
        }
        uintptr_t resultingAddress = 0;
        std::memcpy(&resultingAddress, arrayData(storage),
                    sizeof(resultingAddress));
        if (resultingAddress != kFixtureHex2004)
        {
            return kFixtureInt29;
        }

        return 0;
    }

    int restorationGuardCases()
    {
        // Restoration first validates each delta record, then zeroes the mapped
        // destination before applying it. An aliased delta would be erased
        // after validation, silently producing an image different from the
        // payload.
        uint8_t payloadBytes[kFixtureInt8] {
            1, 2, 3, 4, kFixtureInt5, kFixtureInt6, kFixtureInt7, kFixtureInt8,
        };
        uint8_t mapped[kFixtureInt32] {};
        const uint8_t patch[9] {4, 0, 0, 0, 1, 0, 0, 0, 0x7f};
        ath::Payload restored {};
        restored.bytes = arrayData(payloadBytes);
        restored.bytesSize = sizeof(payloadBytes);
        restored.size = sizeof(payloadBytes);
        restored.mappedSize = sizeof(mapped);
        restored.stubOffset = sizeof(payloadBytes);
        restored.stubSize = sizeof(mapped) - sizeof(payloadBytes);
        restored.delta = &mapped[sizeof(payloadBytes)];
        restored.deltaSize = sizeof(patch);
        std::memcpy(&mapped[sizeof(payloadBytes)], arrayData(patch),
                    sizeof(patch));
        uint8_t previous[sizeof(mapped)] {};
        std::memcpy(arrayData(previous), arrayData(mapped), sizeof(mapped));
        ath::LinkedImage restoredImage {
            &restored, arrayData(mapped), kFixtureHex3000, kFixtureInt7, false,
            true,
        };
        if (ath::restorePayload(restoredImage) ||
            std::memcmp(arrayData(previous), arrayData(mapped),
                        sizeof(mapped)) != 0)
        {
            return kFixtureInt30;
        }

        // Overlapping base bytes would enter memcpy with undefined behavior;
        // reject them without touching the mapped image or its stub usage.
        restored.delta = nullptr;
        restored.deltaSize = 0;
        restored.bytes = &mapped[1U];
        restored.bytesSize = sizeof(payloadBytes);
        if (ath::restorePayload(restoredImage) ||
            std::memcmp(arrayData(previous), arrayData(mapped),
                        sizeof(mapped)) != 0 ||
            restoredImage.stubUsed != kFixtureInt7)
        {
            return kFixtureInt31;
        }

        // Independent base/delta storage remains supported and clears old
        // stubs.
        restored.bytes = arrayData(payloadBytes);
        restored.delta = arrayData(patch);
        restored.deltaSize = sizeof(patch);
        if (!ath::restorePayload(restoredImage) || mapped[4] != kFixtureHex7f ||
            mapped[0] != 1 || mapped[kFixtureInt7] != kFixtureInt8 ||
            mapped[kFixtureInt8] != 0 || restoredImage.stubUsed != 0)
        {
            return kFixtureInt32;
        }

        // A caller can invoke allocateStub independently of restorePayload.
        // The reserved stub area must never overlap live executable image
        // bytes.
        uint8_t executableAndStubs[kFixtureInt32] {};
        uint8_t initialStubBytes[sizeof(executableAndStubs)] {};
        ath::Payload stubPayload {};
        stubPayload.size = kFixtureInt16;
        stubPayload.mappedSize = sizeof(executableAndStubs);
        stubPayload.stubOffset =
            kFixtureInt8; // Malformed: overlaps the executable prefix.
        stubPayload.stubSize = kFixtureInt16;
        ath::LinkedImage stubImage {
            &stubPayload,    arrayData(executableAndStubs),
            kFixtureHex4000, 0,
            false,           true,
        };
        if (ath::allocateStub(stubImage, kFixtureHex12345678) != 0 ||
            stubImage.stubUsed != 0 ||
            std::memcmp(arrayData(initialStubBytes),
                        arrayData(executableAndStubs),
                        sizeof(executableAndStubs)) != 0)
        {
            return kFixtureInt33;
        }

        // A valid, disjoint reservation still builds a full 16-byte jump stub.
        stubPayload.stubOffset = kFixtureInt16;
        if (ath::allocateStub(stubImage, kFixtureHex12345678) !=
                kFixtureHex4010 ||
            stubImage.stubUsed != kFixtureInt16 ||
            std::memcmp(arrayData(initialStubBytes),
                        arrayData(executableAndStubs), kFixtureInt16) != 0 ||
            executableAndStubs[kFixtureInt16] != kFixtureHexff ||
            executableAndStubs[kFixtureInt17] != kFixtureHex25)
        {
            return kFixtureInt34;
        }

        // The direct stub writer is also an entrypoint: a forged mapping can
        // point its writable stub range into the payload descriptor itself.
        // Do not corrupt the descriptors needed for subsequent memory safety.
        ath::Payload selfDescribingPayload {};
        selfDescribingPayload.size = kFixtureInt16;
        selfDescribingPayload.mappedSize = sizeof(selfDescribingPayload);
        selfDescribingPayload.stubOffset = kFixtureInt16;
        selfDescribingPayload.stubSize = kFixtureInt16;
        auto *payloadStorage = byteView(selfDescribingPayload);
        uint8_t originalPayload[sizeof(selfDescribingPayload)] {};
        std::memcpy(arrayData(originalPayload), payloadStorage,
                    sizeof(originalPayload));
        ath::LinkedImage selfDescribingImage {
            &selfDescribingPayload,
            payloadStorage,
            kFixtureHex7000,
            0,
            false,
            true,
        };
        if (ath::allocateStub(selfDescribingImage, kFixtureHex12345678) != 0 ||
            selfDescribingImage.stubUsed != 0 ||
            std::memcmp(arrayData(originalPayload), payloadStorage,
                        sizeof(originalPayload)) != 0)
        {
            return kFixtureInt38;
        }

        // A second forged mapping can alias the LinkedImage descriptor that
        // carries its own memory pointer, allocation state and target address.
        ath::Payload selfAliasedPayload {};
        selfAliasedPayload.size = 0;
        selfAliasedPayload.mappedSize = sizeof(ath::LinkedImage);
        selfAliasedPayload.stubOffset = 0;
        selfAliasedPayload.stubSize = kFixtureInt16;
        ath::LinkedImage selfAliasedImage {
            &selfAliasedPayload, nullptr, kFixtureHex8000, 0, false, true,
        };
        selfAliasedImage.memory = byteView(selfAliasedImage);
        uint8_t originalImage[sizeof(selfAliasedImage)] {};
        std::memcpy(arrayData(originalImage), byteView(selfAliasedImage),
                    sizeof(originalImage));
        if (ath::allocateStub(selfAliasedImage, kFixtureHex12345678) != 0 ||
            std::memcmp(arrayData(originalImage), byteView(selfAliasedImage),
                        sizeof(originalImage)) != 0)
        {
            return kFixtureInt39;
        }

        return 0;
    }

    int metadataAliasGuardCases()
    {
        // Even if Payload and LinkedImage live elsewhere, standalone stub
        // allocation must preserve immutable relocation and symbol tables.
        ath::Relocation stubRelocations[2] {};
        ath::Payload tablePayload {};
        tablePayload.size = kFixtureInt16;
        tablePayload.mappedSize = sizeof(stubRelocations);
        tablePayload.stubOffset = kFixtureInt16;
        tablePayload.stubSize = kFixtureInt16;
        tablePayload.relocations = arrayData(stubRelocations);
        tablePayload.relocationCount = 2;
        auto *relocationStorage = byteView(stubRelocations);
        uint8_t originalTable[sizeof(stubRelocations)] {};
        ath::LinkedImage tableImage {
            &tablePayload, relocationStorage, kFixtureHex9000, 0, false, true,
        };
        if (ath::allocateStub(tableImage, kFixtureHex12345678) != 0 ||
            tableImage.stubUsed != 0 ||
            std::memcmp(arrayData(originalTable), relocationStorage,
                        sizeof(originalTable)) != 0)
        {
            return kFixtureInt40;
        }

        uint32_t stubSymbolOffsets[kFixtureInt8] {};
        tablePayload.relocations = nullptr;
        tablePayload.relocationCount = 0;
        tablePayload.symbolValues = arrayData(stubSymbolOffsets);
        tablePayload.symbolValueCount = kFixtureInt8;
        tablePayload.mappedSize = sizeof(stubSymbolOffsets);
        tableImage.memory = byteView(stubSymbolOffsets);
        tableImage.address = kFixtureHexa000;
        uint8_t originalSymbolOffsets[sizeof(stubSymbolOffsets)] {};
        if (ath::allocateStub(tableImage, kFixtureHex12345678) != 0 ||
            tableImage.stubUsed != 0 ||
            std::memcmp(arrayData(originalSymbolOffsets),
                        arrayData(stubSymbolOffsets),
                        sizeof(originalSymbolOffsets)) != 0)
        {
            return kFixtureInt41;
        }

        // A stored byte template is also an immutable input to later restores.
        uint8_t stubTemplate[kFixtureInt32] {};
        tablePayload.symbolValues = nullptr;
        tablePayload.symbolValueCount = 0;
        tablePayload.bytes = &stubTemplate[kFixtureInt8];
        tablePayload.bytesSize = sizeof(stubTemplate) - kFixtureInt8;
        tablePayload.mappedSize = sizeof(stubTemplate);
        tableImage.memory = arrayData(stubTemplate);
        tableImage.address = kFixtureHexb000;
        uint8_t originalTemplate[sizeof(stubTemplate)] {};
        if (ath::allocateStub(tableImage, kFixtureHex12345678) != 0 ||
            tableImage.stubUsed != 0 ||
            std::memcmp(arrayData(originalTemplate), arrayData(stubTemplate),
                        sizeof(originalTemplate)) != 0)
        {
            return kFixtureInt42;
        }

        // Relocation metadata can itself live inside a caller-owned mapping.
        // Treat it as immutable input: writing the first relocated pointer must
        // never modify a still-live relocation record or return success.
        ath::Relocation aliasedRelocations[2] {};
        aliasedRelocations[0].offset = 0;
        aliasedRelocations[0].width = kFixtureInt8;
        aliasedRelocations[0].image = kFixtureInt255;
        aliasedRelocations[0].target = 0;
        auto *relocatedBytes = byteView(aliasedRelocations);
        ath::Payload aliasedPayload {};
        aliasedPayload.size = sizeof(aliasedRelocations[0]);
        aliasedPayload.mappedSize = sizeof(aliasedRelocations);
        aliasedPayload.stubOffset = sizeof(aliasedRelocations[0]);
        aliasedPayload.stubSize = sizeof(aliasedRelocations[0]);
        aliasedPayload.relocations = arrayData(aliasedRelocations);
        aliasedPayload.relocationCount = 1;
        aliasedPayload.checksum =
            ath::payloadChecksum(relocatedBytes, aliasedPayload.size);
        uint8_t oldRelocations[sizeof(aliasedRelocations)] {};
        std::memcpy(arrayData(oldRelocations), relocatedBytes,
                    sizeof(oldRelocations));
        ath::LinkedImage aliasImage {
            &aliasedPayload, relocatedBytes, kFixtureHex5000, 0, false, true,
        };
        const uintptr_t aliasImports[] {0x5050};
        if (ath::relocateImage(aliasImage, nullptr, 0, arrayData(aliasImports),
                               1, nullptr, 0) ||
            std::memcmp(arrayData(oldRelocations), relocatedBytes,
                        sizeof(oldRelocations)) != 0)
        {
            return kFixtureInt35;
        }

        // Symbol value offsets have the same alias problem: an offset table in
        // the output mapping may be overwritten by its own relocation
        // operation.
        uint32_t aliasedOffsets[kFixtureInt8] {};
        auto *offsetBytes = byteView(aliasedOffsets);
        ath::Payload offsetPayload {};
        offsetPayload.size = kFixtureInt16;
        offsetPayload.mappedSize = sizeof(aliasedOffsets);
        offsetPayload.stubOffset = kFixtureInt16;
        offsetPayload.stubSize = kFixtureInt16;
        offsetPayload.symbolValues = arrayData(aliasedOffsets);
        offsetPayload.symbolValueCount = 1;
        offsetPayload.checksum =
            ath::payloadChecksum(offsetBytes, offsetPayload.size);
        uint8_t oldOffsets[sizeof(aliasedOffsets)] {};
        std::memcpy(arrayData(oldOffsets), offsetBytes, sizeof(oldOffsets));
        ath::LinkedImage offsetImage {
            &offsetPayload, offsetBytes, kFixtureHex6000, 0, false, true,
        };
        if (ath::relocateImage(offsetImage, nullptr, 0, nullptr, 0, nullptr,
                               0) ||
            std::memcmp(arrayData(oldOffsets), offsetBytes,
                        sizeof(oldOffsets)) != 0)
        {
            return kFixtureInt36;
        }

        return 0;
    }
} // namespace

int main()
{
    const int relocationResult = relocationGuardCases();
    if (relocationResult != 0)
    {
        return relocationResult;
    }
    const int restorationResult = restorationGuardCases();
    if (restorationResult != 0)
    {
        return restorationResult;
    }
    const int metadataResult = metadataAliasGuardCases();
    if (metadataResult != 0)
    {
        return metadataResult;
    }
    if (!linkPatternBoundaries())
    {
        return kFixtureInt37;
    }
    return 0;
}
