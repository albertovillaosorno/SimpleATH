// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565Core.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    static constexpr InitStep kCommonPlan[] = {
        InitStep::PowerOnReset,
        InitStep::WakeRtc,
        InitStep::ReadAndValidateEeprom,
        InitStep::ValidateRegulatoryDomain,
        InitStep::ProgramSocPreamble,
        InitStep::ProgramMacCore,
        InitStep::ProgramBasebandCore,
        InitStep::ProgramRadioCore,
        InitStep::ProgramRxGain,
        InitStep::ProgramTxGain,
        InitStep::ProgramSocPostamble,
        InitStep::ProgramMacPostamble,
        InitStep::ProgramBasebandPostamble,
        InitStep::ProgramRadioPostamble,
        InitStep::CalibrateRxIq,
        InitStep::CalibrateTxIq,
        InitStep::ProgramBluetoothCoexistence,
        InitStep::AllocateTxRxDma,
        InitStep::InstallInterrupts,
        InitStep::RegisterNativeWirelessInterface,
    };
    static constexpr uint32_t kMinimumMappedBar = 0x7048;
    static constexpr uint32_t kInvalidRegisterWord = UINT32_MAX;
    static constexpr uint32_t kType2SrevTag = 0xffU;
    static constexpr uint8_t kMaxMacOctetValue = UINT8_MAX;
    static constexpr uint8_t kLast2GChannel = 14;
    static constexpr uint16_t kJapanChannelCenterMhz = 2484;
    static constexpr uint16_t kChannelZeroBaseMhz = 2407;
    static constexpr uint16_t kChannelSpacingMhz = 5;

    // A callback context must not point into its caller-owned descriptor:
    // invoking the provider could overwrite the function pointers we retain.
    // An enclosing PCI session may legitimately start with its Device member,
    // so the callback context itself is not required to avoid the Device.
    // Compare distances without overflowing at address-space boundaries.
    static bool overlapsStorage(const void *first, size_t firstBytes,
                                const void *second, size_t secondBytes)
    {
        if (first == nullptr || second == nullptr || firstBytes == 0 ||
            secondBytes == 0)
        {
            return false;
        }
        uintptr_t left = 0;
        uintptr_t right = 0;
        static_assert(sizeof(uintptr_t) == sizeof(first),
                      "host pointers must have address-sized representations");
        __builtin_memcpy(&left, static_cast<const void *>(&first),
                         sizeof(first));
        __builtin_memcpy(&right, static_cast<const void *>(&second),
                         sizeof(second));
        return left <= right ? right - left < firstBytes
                             : left - right < secondBytes;
    }

    bool isSupportedPci(uint16_t vendor, uint16_t device)
    {
        // Never identify a real AR9300 as AR9565 simply because it has 0030.
        return vendor == kPciVendor && device == kPciDevice;
    }

    Result decodeRevision(uint32_t raw, Silicon &out)
    {
        out = {};
        // ath9k type-2 SREV is used by the AR9003 generation. The lower byte
        // is 0xff, and the version is encoded in bits 18..31, shifted by 12.
        if (raw == kInvalidRegisterWord ||
            (raw & kType2SrevTag) != kType2SrevTag)
        {
            return Result::UnsupportedSilicon;
        }
        const uint32_t family = (raw & 0xfffc0000U) >> 12U;
        const uint32_t revision = (raw & 0x00000f00U) >> 8U;
        if (family != kMacFamily)
        {
            return Result::UnsupportedSilicon;
        }
        if (revision > 2U)
        {
            return Result::UnsupportedRevision;
        }
        Silicon result {};
        result.macFamily = kMacFamily;
        result.macRevision = static_cast<uint8_t>(revision);
        if (revision == 0U)
        {
            result.revision = Revision::V1_0;
        }
        else if (revision == 1U)
        {
            result.revision = Revision::V1_0_1;
        }
        else
        {
            result.revision = Revision::V1_1;
        }
        result.rawSrev = raw;
        result.usesPcie = true;
        out = result;
        return Result::Ok;
    }

    Result mapChannel(uint8_t ieeeChannel, Channel &out)
    {
        // Do not leave the caller's previous authorized-looking channel on an
        // invalid request. This static mapping never grants radio permission.
        out = {};
        if (ieeeChannel == 0 || ieeeChannel > kLast2GChannel)
        {
            return Result::InvalidChannel;
        }
        Channel result {};
        result.number = ieeeChannel;
        result.centerMhz =
            ieeeChannel == kLast2GChannel
                ? kJapanChannelCenterMhz
                : static_cast<uint16_t>(kChannelZeroBaseMhz +
                                        (static_cast<uint16_t>(ieeeChannel) *
                                         kChannelSpacingMhz));
        result.requiresJapanAuthorization = ieeeChannel == kLast2GChannel;
        out = result;
        return Result::Ok;
    }

    bool validatePermanentMac(const uint8_t mac[kPermanentMacBytes])
    {
        if (mac == nullptr)
        {
            return false;
        }
        uint8_t octets[kPermanentMacBytes] {};
        __builtin_memcpy(&octets[0], mac, sizeof(octets));
        if ((octets[0] & 0x01U) != 0)
        {
            return false; // Multicast and broadcast cannot identify a STA.
        }
        bool allZero = true;
        bool allOnes = true;
        for (const uint8_t octet : octets)
        {
            allZero = allZero && octet == 0U;
            allOnes = allOnes && octet == kMaxMacOctetValue;
        }
        return !allZero && !allOnes;
    }

    Result decodeEepromMac(const uint16_t words[3],
                           uint8_t out[kPermanentMacBytes])
    {
        if (out == nullptr)
        {
            return Result::InvalidMacAddress;
        }
        // EEPROM words may share the output's backing bytes on successful
        // decoding. Snapshot all three words before any output write.
        if (words == nullptr)
        {
            __builtin_memset(out, 0, kPermanentMacBytes);
            return Result::InvalidMacAddress;
        }
        uint16_t original[3] {};
        __builtin_memcpy(&original[0], words, sizeof(original));
        constexpr uint32_t kHighMacOctetShift = 8U;
        uint8_t candidate[kPermanentMacBytes] {
            static_cast<uint8_t>(original[0] >> kHighMacOctetShift),
            static_cast<uint8_t>(original[0] & kMaxMacOctetValue),
            static_cast<uint8_t>(original[1] >> kHighMacOctetShift),
            static_cast<uint8_t>(original[1] & kMaxMacOctetValue),
            static_cast<uint8_t>(original[2] >> kHighMacOctetShift),
            static_cast<uint8_t>(original[2] & kMaxMacOctetValue),
        };
        if (!validatePermanentMac(&candidate[0]))
        {
            // Preserve borrowed raw NVM evidence when invalid input aliases
            // output. The ordinary non-overlapping invalid case clears out.
            if (overlapsStorage(words, sizeof(original), out,
                                sizeof(candidate)))
            {
                return Result::InvalidMacAddress;
            }
            __builtin_memset(out, 0, sizeof(candidate));
            return Result::InvalidMacAddress;
        }
        __builtin_memcpy(out, &candidate[0], sizeof(candidate));
        return Result::Ok;
    }

    InitPlan planForRevision(Revision revision)
    {
        const char *source = nullptr;
        switch (revision)
        {
            case Revision::V1_0:
            case Revision::V1_0_1:
                source = "linux/drivers/net/wireless/ath/ath9k/"
                         "ar9565_1p0_initvals.h";
                break;
            case Revision::V1_1:
                source = "linux/drivers/net/wireless/ath/ath9k/"
                         "ar9565_1p1_initvals.h";
                break;
            case Revision::Unknown:
                break;
        }
        const InitPlan plan {
            revision,
            source,
            source != nullptr ? &kCommonPlan[0] : nullptr,
            source != nullptr ? (sizeof(kCommonPlan) / sizeof(kCommonPlan[0]))
                              : 0U,
            false,
        };
        return plan;
    }

    Device::Device() : status_ {}, bus_ {}
    {
        status_.stage = Stage::Detached;
        status_.lastResult = Result::Ok;
    }

    Result Device::fail(Result result)
    {
        status_.lastResult = result;
        return result;
    }

    Result Device::matchPci(uint16_t vendor, uint16_t device,
                            uint16_t subsystemVendor, uint16_t subsystemDevice)
    {
        if (status_.stage != Stage::Detached)
        {
            return fail(Result::WrongState);
        }
        if (!isSupportedPci(vendor, device))
        {
            return fail(Result::UnsupportedPci);
        }
        status_.pci = {vendor, device, subsystemVendor, subsystemDevice, false};
        status_.stage = Stage::PciMatched;
        return fail(Result::Ok);
    }

    Result Device::attachReadOnlyBus(const RegisterBus &bus)
    {
        if (status_.stage != Stage::PciMatched)
        {
            return fail(Result::WrongState);
        }
        if (bus.read32 == nullptr || bus.context == nullptr ||
            bus.barLengthBytes < kMinimumMappedBar ||
            overlapsStorage(&bus, sizeof(bus), this, sizeof(*this)) ||
            overlapsStorage(bus.context, 1, &bus, sizeof(bus)))
        {
            return fail(Result::BusNotReady);
        }
        // This core must never acquire a write capability through an otherwise
        // read-only attachment, even if a caller supplied one.
        bus_ = {bus.context, bus.read32, nullptr, bus.barLengthBytes};
        status_.stage = Stage::RegisterTransportReady;
        return fail(Result::Ok);
    }

    Result Device::readRegister(uint32_t offset, uint32_t &value) const
    {
        if (bus_.read32 == nullptr || bus_.context == nullptr ||
            (offset & 3U) != 0 || offset > bus_.barLengthBytes ||
            bus_.barLengthBytes - offset < sizeof(uint32_t))
        {
            return Result::InvalidRegister;
        }
        if (!bus_.read32(bus_.context, offset, &value) ||
            value == kInvalidRegisterWord)
        {
            return Result::RegisterReadFailed;
        }
        return Result::Ok;
    }

    Result Device::inspect()
    {
        if (status_.stage != Stage::RegisterTransportReady)
        {
            return fail(Result::WrongState);
        }
        const uint64_t ownerEpoch = busEpoch_;

        uint32_t srev = 0;
        Result result = readRegister(kRevisionRegister, srev);
        // A callback can revoke the MMIO owner before returning. Never
        // publish its sample or write diagnostics into a replacement owner,
        // even when a detach/reattach cycle restores the same bus pointers.
        if (busEpoch_ != ownerEpoch)
        {
            return Result::WrongState;
        }
        if (result != Result::Ok)
        {
            return fail(result);
        }

        Silicon silicon {};
        result = decodeRevision(srev, silicon);
        if (result != Result::Ok)
        {
            return fail(result);
        }
        status_.silicon = silicon;
        status_.stage = Stage::SiliconIdentified;

        uint32_t rtc = 0;
        result = readRegister(kRtcStatusRegister, rtc);
        if (busEpoch_ != ownerEpoch)
        {
            return Result::WrongState;
        }
        if (result != Result::Ok)
        {
            return fail(result);
        }
        status_.rtcStatus = rtc & kRtcStatusMask;
        if (status_.rtcStatus != kRtcOn)
        {
            return fail(Result::RadioAsleep);
        }

        uint32_t eeprom = 0;
        result = readRegister(kEepromStatusRegister, eeprom);
        if (busEpoch_ != ownerEpoch)
        {
            return Result::WrongState;
        }
        if (result != Result::Ok)
        {
            return fail(result);
        }
        status_.eepromStatus = eeprom;
        if ((eeprom & kEepromAbsent) != 0U)
        {
            return fail(Result::EepromUnavailable);
        }
        if ((eeprom & kEepromCorrupt) != 0U)
        {
            return fail(Result::EepromCorrupt);
        }

        // "Accessible" only means the EEPROM status register looked sane.
        // It DOES NOT mean the board data was read, checked or applied.
        status_.eepromAccessible = true;
        status_.stage = Stage::EepromStatusValidated;
        status_.stage = Stage::AwaitingResetAndCalibration;
        return fail(Result::Ok);
    }

    void Device::detach()
    {
        // Epoch changes before callbacks and status are revoked, so a read
        // already in progress cannot resurrect an old inspection afterwards.
        ++busEpoch_;
        status_ = {};
        bus_ = {};
        status_.stage = Stage::Detached;
        status_.lastResult = Result::Ok;
    }

} // namespace simpleath
