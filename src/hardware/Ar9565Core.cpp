// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565Core.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    static constexpr InitStep K_COMMON_PLAN[] = {
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
    static constexpr uint32_t K_MINIMUM_MAPPED_BAR = 0x7048;

    // A callback context must not point into its caller-owned descriptor:
    // invoking the provider could overwrite the function pointers we retain.
    // An enclosing PCI session may legitimately start with its Device member,
    // so the callback context itself is not required to avoid the Device.
    // Compare distances without overflowing at address-space boundaries.
    static bool overlapsStorage(const void *first, size_t firstBytes,
                                const void *second, size_t secondBytes)
    {
        if (!first || !second || !firstBytes || !secondBytes)
            return false;
        const auto left = reinterpret_cast<uintptr_t>(first);
        const auto right = reinterpret_cast<uintptr_t>(second);
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
        if (raw == 0xffffffffU || (raw & 0xffU) != 0xffU)
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
        result.revision = revision == 0   ? Revision::V1_0
                          : revision == 1 ? Revision::V1_0_1
                                          : Revision::V1_1;
        result.rawSrev = raw;
        result.usesPcie = true;
        out = result;
        return Result::Ok;
    }

    Result mapChannel(uint8_t number, Channel &out)
    {
        // Do not leave the caller's previous authorized-looking channel on an
        // invalid request. This static mapping never grants radio permission.
        out = {};
        if (number == 0 || number > 14)
        {
            return Result::InvalidChannel;
        }
        Channel result {};
        result.number = number;
        result.centerMhz =
            number == 14 ? static_cast<uint16_t>(2484)
                         : static_cast<uint16_t>(
                               2407U + static_cast<uint16_t>(number) * 5U);
        result.requiresJapanAuthorization = number == 14;
        out = result;
        return Result::Ok;
    }

    bool validatePermanentMac(const uint8_t mac[6])
    {
        if (!mac || (mac[0] & 0x01U) != 0)
        {
            return false; // Multicast or broadcast cannot identify a station.
        }
        bool allZero = true;
        bool allOnes = true;
        for (size_t index = 0; index < 6; ++index)
        {
            allZero = allZero && mac[index] == 0U;
            allOnes = allOnes && mac[index] == 0xffU;
        }
        return !allZero && !allOnes;
    }

    Result decodeEepromMac(const uint16_t words[3], uint8_t out[6])
    {
        if (!out)
        {
            return Result::InvalidMacAddress;
        }
        // Build the candidate before modifying out, so source words may
        // overlap the output on success. On failure, clear stale identity.
        if (!words)
        {
            for (size_t index = 0; index < 6; ++index)
            {
                out[index] = 0;
            }
            return Result::InvalidMacAddress;
        }
        uint8_t candidate[6] {};
        for (size_t index = 0; index < 3; ++index)
        {
            candidate[index * 2] = static_cast<uint8_t>(words[index] >> 8U);
            candidate[index * 2 + 1] =
                static_cast<uint8_t>(words[index] & 0xffU);
        }
        if (!validatePermanentMac(candidate))
        {
            // Failed decoding must revoke an old output, but not by erasing
            // the caller's borrowed EEPROM source. The public API supports
            // successful in-place decode, so reject only the invalid-source
            // overlap before writing failure cleanup into raw NVM evidence.
            const uintptr_t source = reinterpret_cast<uintptr_t>(words);
            const uintptr_t destination = reinterpret_cast<uintptr_t>(out);
            const bool aliased = source <= destination
                                     ? destination - source < sizeof(candidate)
                                     : source - destination < sizeof(candidate);
            if (aliased)
                return Result::InvalidMacAddress;
            for (size_t index = 0; index < sizeof(candidate); ++index)
            {
                out[index] = 0;
            }
            return Result::InvalidMacAddress;
        }
        for (size_t index = 0; index < 6; ++index)
        {
            out[index] = candidate[index];
        }
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
            revision, source, source ? K_COMMON_PLAN : nullptr,
            source ? (sizeof(K_COMMON_PLAN) / sizeof(K_COMMON_PLAN[0])) : 0U,
            false};
        return plan;
    }

    Device::Device() : status_ {}, bus_ {}, busEpoch_(0)
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
        if (!bus.read32 || !bus.context ||
            bus.barLengthBytes < K_MINIMUM_MAPPED_BAR ||
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

    Result Device::readRegister(uint32_t offset, uint32_t &value)
    {
        if (!bus_.read32 || !bus_.context || (offset & 3U) != 0 ||
            offset > bus_.barLengthBytes ||
            bus_.barLengthBytes - offset < sizeof(uint32_t))
        {
            return Result::InvalidRegister;
        }
        if (!bus_.read32(bus_.context, offset, &value) || value == 0xffffffffU)
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
            return Result::WrongState;
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
            return Result::WrongState;
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
            return Result::WrongState;
        if (result != Result::Ok)
        {
            return fail(result);
        }
        status_.eepromStatus = eeprom;
        if (eeprom & kEepromAbsent)
        {
            return fail(Result::EepromUnavailable);
        }
        if (eeprom & kEepromCorrupt)
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
