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
//   - Offline regression cases for ar9565 core.
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
//   - Offline regression cases for ar9565 core.
// - Description:
//   - Implements or verifies the test_ar9565_core source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for ar9565 core.
// Offline regression of real identity/invalid-output code; no PCI access.
#include "bluetooth/UsbBytes.hpp"
#include "hardware/Ar9565Core.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

namespace
{
    using namespace simpleath;

    constexpr uint8_t kRevisionShift = 12U;
    constexpr uint8_t kMacRevisionShift = 8U;
    constexpr uint32_t kRevisionMask = 0xffU;
    constexpr uint32_t kInvalidRevision = 0xffffffffU;
    constexpr uint32_t kStaleRevision = 0x1234U;
    constexpr uint32_t kBusRegisterLimit = 0x7048U;
    constexpr uint16_t kUnsupportedPciDevice = 0x0030U;
    constexpr uint8_t kJapanChannelNumber = 14U;
    constexpr uint16_t kJapanChannelMhz = 2484U;
    constexpr size_t kMacBytes = 6U;
    constexpr size_t kMacWords = 3U;
    constexpr size_t kAliasWords = 6U;
    constexpr size_t kLastAliasWord = 5U;
    constexpr uint16_t kMacUnicastFirstWord = 0x0211U;
    constexpr uint16_t kMacMulticastFirstWord = 0x0111U;
    constexpr uint16_t kMacSecondWord = 0x2233U;
    constexpr uint16_t kMacThirdWord = 0x4455U;
    constexpr uint16_t kMacFourthWord = 0x6677U;
    constexpr uint16_t kMacFifthWord = 0x8899U;
    constexpr uint16_t kMacSixthWord = 0xaabbU;

    uint32_t expectedReadsBeforeRevocation(uint32_t registerOffset)
    {
        if (registerOffset == kRevisionRegister)
        {
            return 1U;
        }
        if (registerOffset == kRtcStatusRegister)
        {
            return 2U;
        }
        return 3U;
    }

    struct RevokingRead
    {
            Device *owner;
            RegisterBus bus;
            uint32_t revokeAt;
            unsigned reads;
            bool revoke;
            bool reattach;
            bool reattached;
    };

    bool syntheticRead32(void *opaque, uint32_t offset, uint32_t *value)
    {
        auto &context = *static_cast<RevokingRead *>(opaque);
        ++context.reads;
        if (context.revoke && offset == context.revokeAt)
        {
            context.revoke = false;
            // Model a native owner losing its mapping synchronously during
            // an MMIO callback. The callback may also reattach the SAME
            // function/context to a fresh owner generation before returning.
            context.owner->detach();
            if (context.reattach)
            {
                context.reattached =
                    context.owner->matchPci(kPciVendor, kPciDevice, 0, 0) ==
                        Result::Ok &&
                    context.owner->attachReadOnlyBus(context.bus) == Result::Ok;
            }
        }
        if (offset == kRevisionRegister)
        {
            *value = (static_cast<uint32_t>(kMacFamily) << kRevisionShift) |
                     kRevisionMask;
        }
        else if (offset == kRtcStatusRegister)
        {
            *value = kRtcOn;
        }
        else if (offset == kEepromStatusRegister)
        {
            *value = 0;
        }
        else
        {
            return false;
        }
        return true;
    }

    bool rejectSelfReferentialBusDescriptor()
    {
        Device owner;
        if (owner.matchPci(kPciVendor, kPciDevice, 0, 0) != Result::Ok)
        {
            return false;
        }
        // A callback may not borrow the temporary descriptor itself: the
        // provider could alter its function table during the first read.
        RegisterBus descriptor {
            nullptr,
            syntheticRead32,
            nullptr,
            kBusRegisterLimit,
        };
        descriptor.context = &descriptor;
        if (owner.attachReadOnlyBus(descriptor) != Result::BusNotReady ||
            owner.status().stage != Stage::PciMatched ||
            owner.inspect() != Result::WrongState)
        {
            return false;
        }
        // Rejecting bad contexts must not poison a subsequently valid one.
        RevokingRead valid {};
        valid.owner = &owner;
        valid.bus = {
            &valid,
            syntheticRead32,
            nullptr,
            kBusRegisterLimit,
        };
        return owner.attachReadOnlyBus(valid.bus) == Result::Ok &&
               owner.inspect() == Result::Ok &&
               owner.status().stage == Stage::AwaitingResetAndCalibration;
    }

    bool rejectReentrantBusRevocation()
    {
        const uint32_t stages[] {
            kRevisionRegister,
            kRtcStatusRegister,
            kEepromStatusRegister,
        };
        for (const uint32_t revokedAt : stages)
        {
            Device device;
            RevokingRead context {};
            context.owner = &device;
            context.bus = {
                &context,
                syntheticRead32,
                nullptr,
                kBusRegisterLimit,
            };
            context.revokeAt = revokedAt;
            context.revoke = true;
            if (device.matchPci(kPciVendor, kPciDevice, 0, 0) != Result::Ok ||
                device.attachReadOnlyBus(context.bus) != Result::Ok ||
                device.inspect() != Result::WrongState ||
                device.status().stage != Stage::Detached ||
                device.status().silicon.rawSrev != 0 ||
                device.status().eepromAccessible ||
                context.reads != expectedReadsBeforeRevocation(revokedAt))
            {
                return false;
            }

            // Even if a callback detach/reattach cycle restores the identical
            // bus pointers, a stale outer inspection must not publish success
            // or a failure into the replacement owner's state.
            context.revoke = true;
            context.reattach = true;
            context.reattached = false;
            if (device.matchPci(kPciVendor, kPciDevice, 0, 0) != Result::Ok ||
                device.attachReadOnlyBus(context.bus) != Result::Ok ||
                device.inspect() != Result::WrongState || !context.reattached ||
                device.status().stage != Stage::RegisterTransportReady ||
                device.status().lastResult != Result::Ok ||
                device.status().silicon.rawSrev != 0 ||
                device.status().eepromAccessible)
            {
                return false;
            }
            // The new attachment should remain usable on a fresh inspection.
            if (device.inspect() != Result::Ok ||
                device.status().stage != Stage::AwaitingResetAndCalibration ||
                !device.status().eepromAccessible)
            {
                return false;
            }
        }
        return true;
    }

    int checkMacDecoding()
    {
        const std::array<uint16_t, kMacWords> valid {
            kMacUnicastFirstWord,
            kMacSecondWord,
            kMacThirdWord,
        };
        const std::array<uint8_t, kMacBytes> expected {
            0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
        };
        std::array<uint8_t, kMacBytes> mac {};
        if (decodeEepromMac(valid.data(), mac.data()) != Result::Ok)
        {
            return __LINE__;
        }
        for (size_t i = 0; i < mac.size(); ++i)
        {
            if (mac.at(i) != expected.at(i))
            {
                return __LINE__;
            }
        }
        const std::array<uint16_t, kMacWords> invalid {};
        if (decodeEepromMac(invalid.data(), mac.data()) !=
            Result::InvalidMacAddress)
        {
            return __LINE__;
        }
        for (const uint8_t octet : mac)
        {
            if (octet != 0U)
            {
                return __LINE__;
            }
        }

        // In-place EEPROM MAC decoding is allowed after a verified unicast MAC,
        // but failed decoding must not zero immutable raw EEPROM word evidence.
        std::array<uint16_t, kMacWords> invalidAliasWords {
            kMacMulticastFirstWord,
            kMacSecondWord,
            kMacThirdWord,
        };
        // Same-sized object pointers preserve the underlying storage address.
        // The unsigned-byte view is intentional for the alias rejection test.
        auto *const aliasBytes =
            __builtin_bit_cast(uint8_t *, invalidAliasWords.data());
        if (decodeEepromMac(invalidAliasWords.data(), aliasBytes) !=
                Result::InvalidMacAddress ||
            invalidAliasWords.at(0U) != kMacMulticastFirstWord ||
            invalidAliasWords.at(1U) != kMacSecondWord ||
            invalidAliasWords.at(2U) != kMacThirdWord)
        {
            return __LINE__;
        }
        // An output beginning *inside* the words is just as unsafe to erase.
        std::array<uint16_t, kAliasWords> partialAliasWords {
            kMacMulticastFirstWord, kMacSecondWord, kMacThirdWord,
            kMacFourthWord,         kMacFifthWord,  kMacSixthWord,
        };
        auto *const partial = usbByteOffset(
            __builtin_bit_cast(uint8_t *, partialAliasWords.data()), 2U);
        if (decodeEepromMac(partialAliasWords.data(), partial) !=
                Result::InvalidMacAddress ||
            partialAliasWords.at(0U) != kMacMulticastFirstWord ||
            partialAliasWords.at(1U) != kMacSecondWord ||
            partialAliasWords.at(2U) != kMacThirdWord ||
            partialAliasWords.at(3U) != kMacFourthWord ||
            partialAliasWords.at(4U) != kMacFifthWord ||
            partialAliasWords.at(kLastAliasWord) != kMacSixthWord)
        {
            return __LINE__;
        }
        std::array<uint16_t, kMacWords> validAliasWords {
            kMacUnicastFirstWord,
            kMacSecondWord,
            kMacThirdWord,
        };
        auto *const validAliasBytes =
            __builtin_bit_cast(uint8_t *, validAliasWords.data());
        if (decodeEepromMac(validAliasWords.data(), validAliasBytes) !=
            Result::Ok)
        {
            return __LINE__;
        }
        for (size_t i = 0; i < expected.size(); ++i)
        {
            if (*usbByteOffset(validAliasBytes, i) != expected.at(i))
            {
                return __LINE__;
            }
        }
        return 0;
    }
} // namespace

int main()
{
    using namespace simpleath;
    if (!isSupportedPci(kPciVendor, kPciDevice) ||
        isSupportedPci(kPciVendor, kUnsupportedPciDevice))
    {
        return __LINE__;
    }
    for (uint32_t revision = 0; revision < 3; ++revision)
    {
        Silicon silicon {};
        const uint32_t srev =
            (static_cast<uint32_t>(kMacFamily) << kRevisionShift) |
            (revision << kMacRevisionShift) | kRevisionMask;
        if (decodeRevision(srev, silicon) != Result::Ok ||
            silicon.macRevision != revision || !silicon.usesPcie)
        {
            return __LINE__;
        }
    }
    Silicon stale {};
    stale.rawSrev = kStaleRevision;
    if (decodeRevision(kInvalidRevision, stale) == Result::Ok ||
        (stale.rawSrev != 0U))
    {
        return __LINE__;
    }
    Channel channel {};
    if (mapChannel(kJapanChannelNumber, channel) != Result::Ok ||
        channel.centerMhz != kJapanChannelMhz ||
        !channel.requiresJapanAuthorization)
    {
        return __LINE__;
    }
    if (mapChannel(0, channel) != Result::InvalidChannel ||
        (channel.number != 0U) || (channel.centerMhz != 0U) ||
        channel.requiresJapanAuthorization)
    {
        return __LINE__;
    }
    if (const int macResult = checkMacDecoding())
    {
        return macResult;
    }
    if (!rejectReentrantBusRevocation())
    {
        return __LINE__;
    }
    if (!rejectSelfReferentialBusDescriptor())
    {
        return __LINE__;
    }
    return 0;
}
