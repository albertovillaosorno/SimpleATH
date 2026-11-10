// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic USB callbacks only. No firmware distribution or physical device.
#include "bluetooth/Ath3kUsb.hpp"
#include "bluetooth/UsbHci.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 17U;
    constexpr uint32_t kRomVersion = 0x11223344U;
    constexpr size_t kImageBytes = 40U;
    constexpr size_t kVersionBytes = 20U;
    constexpr size_t kFirmwareHeaderBytes = 20U;
    constexpr size_t kWordBytes = 4U;
    constexpr size_t kPatchTrailerBytes = 8U;
    constexpr size_t kClockOffset = 12U;
    constexpr unsigned kBitsPerByte = 8U;
    constexpr uint8_t kVendorReadType = 0xc0U;
    constexpr uint8_t kVendorWriteType = 0x40U;
    constexpr uint8_t kReadStateRequest = 0x05U;
    constexpr uint8_t kReadVersionRequest = 0x09U;
    constexpr uint8_t kDownloadRequest = 0x01U;
    constexpr uint8_t kNormalModeRequest = 0x07U;
    constexpr uint8_t kSwitchIdentityRequest = 0x0aU;
    constexpr uint8_t kBulkOutEndpoint = 0x02U;
    constexpr uint8_t kEventInEndpoint = 0x81U;
    constexpr uint8_t kAclInEndpoint = 0x82U;
    constexpr uint8_t kInvalidClock = 0xffU;
    constexpr uint8_t kLoadedNormalState = 0xc0U | 0x0eU;
    constexpr uint16_t kAtherosUsbVendor = 0x0cf3U;
    constexpr uint16_t kAtherosUsbProduct = 0x0036U;
    constexpr size_t kEventBytes = 7U;

    struct UsbFake
    {
            std::array<uint8_t, kImageBytes> patch {};
            std::array<uint8_t, kImageBytes> config {};
            std::array<uint8_t, kVersionBytes> version {};
            std::array<uint8_t, kUsbHciMaxCommandBytes> transmitted {};
            size_t firmwareCalls {};
            size_t vendorWrites {};
            size_t bulkWrites {};
            size_t delivered {};
            size_t deliveredEventBytes {};
            size_t deliveredAclBytes {};
            uint8_t state {};
            uint8_t lastRequest {};
            uint8_t lastEndpoint {};
            bool valid {true};
            bool missingFirmware {};
            bool shortBulk {};
            bool failControl {};
            bool failDeliver {};
            bool revokeOnDelivery {};
    };

    bool permit(void *context, uint64_t epoch)
    {
        const auto &fake = *static_cast<UsbFake *>(context);
        return fake.valid && epoch == kEpoch;
    }

    bool readControl(void *context, Ath3kControl command, uint8_t *buffer,
                     size_t bytes)
    {
        auto &fake = *static_cast<UsbFake *>(context);
        if (fake.failControl || command.requestType != kVendorReadType ||
            buffer == nullptr)
        {
            return false;
        }
        if (command.request == kReadStateRequest && bytes == 1U)
        {
            *buffer = fake.state;
            return true;
        }
        if (command.request == kReadVersionRequest &&
            bytes == fake.version.size())
        {
            std::memcpy(buffer, fake.version.data(), bytes);
            return true;
        }
        return false;
    }

    bool writeControl(void *context, Ath3kControl command,
                      const uint8_t *buffer, size_t bytes)
    {
        auto &fake = *static_cast<UsbFake *>(context);
        ++fake.vendorWrites;
        fake.lastRequest = command.request;
        if (fake.failControl || command.requestType != kVendorWriteType)
        {
            return false;
        }
        if (command.request == kDownloadRequest &&
            bytes == kFirmwareHeaderBytes && buffer != nullptr)
        {
            return true;
        }
        return (command.request == kNormalModeRequest ||
                command.request == kSwitchIdentityRequest) &&
               bytes == 0U && buffer == nullptr;
    }

    bool bulkFirmware(void *context, uint8_t endpoint, const uint8_t *bytes,
                      size_t length, size_t *transferred)
    {
        auto &fake = *static_cast<UsbFake *>(context);
        ++fake.bulkWrites;
        if (endpoint != kBulkOutEndpoint || bytes == nullptr ||
            transferred == nullptr)
        {
            return false;
        }
        *transferred = fake.shortBulk ? length - 1U : length;
        return true;
    }

    bool firmware(void *context, const char *fileName,
                  Ath3kFirmwareImage *image)
    {
        auto &fake = *static_cast<UsbFake *>(context);
        ++fake.firmwareCalls;
        if (fake.missingFirmware || image == nullptr)
        {
            return false;
        }
        if (std::strcmp(fileName, "ar3k/AthrBT_0x11223344.dfu") == 0)
        {
            *image = {fake.patch.data(), fake.patch.size()};
            return true;
        }
        if (std::strcmp(fileName, "ar3k/ramps_0x11223344_26.dfu") == 0)
        {
            *image = {fake.config.data(), fake.config.size()};
            return true;
        }
        return false;
    }

    void delay(void * /* context */, uint32_t /* micros */)
    {
    }

    Ath3kIo usbIo(UsbFake &fake)
    {
        return {
            &fake,        kEpoch,       permit,   readControl,
            writeControl, bulkFirmware, firmware, delay,
        };
    }

    void storeLittle32(uint8_t *data, uint32_t value)
    {
        std::array<uint8_t, kWordBytes> encoded {};
        for (size_t index = 0; index < encoded.size(); ++index)
        {
            encoded.at(index) =
                static_cast<uint8_t>(value >> (kBitsPerByte * index));
        }
        std::memcpy(data, encoded.data(), encoded.size());
    }

    UsbFake newFake()
    {
        UsbFake fake {};
        storeLittle32(fake.version.data(), kRomVersion);
        storeLittle32(std::next(fake.version.data(),
                                static_cast<std::ptrdiff_t>(kWordBytes)),
                      1U);
        fake.version.at(kClockOffset) = 0U;
        storeLittle32(
            std::next(fake.patch.data(), static_cast<std::ptrdiff_t>(
                                             kImageBytes - kPatchTrailerBytes)),
            kRomVersion);
        storeLittle32(
            std::next(fake.patch.data(),
                      static_cast<std::ptrdiff_t>(kImageBytes - kWordBytes)),
            2U);
        return fake;
    }

    bool testFirmware()
    {
        const Ath3kUsbIdentity identity {
            kAtherosUsbVendor,
            kAtherosUsbProduct,
            1U,
            0U,
        };
        const Ath3kUsbIdentity bad {0x168cU, 0x0036U, 1U, 0U};
        if (!isSupportedAth3kUsbIdentity(identity) ||
            isSupportedAth3kUsbIdentity(bad) ||
            isSupportedAth3kUsbIdentity(
                {kAtherosUsbVendor, kAtherosUsbProduct, 1U, 1U}))
        {
            return false;
        }
        UsbFake fake = newFake();
        auto result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::AwaitReenumeration ||
            result.phase != Ath3kBootPhase::Done ||
            result.firmwareBytesTransferred != 2U * kImageBytes ||
            fake.vendorWrites != 4U || fake.bulkWrites != 2U ||
            fake.firmwareCalls != 2U || !result.requiresUsbReset ||
            fake.lastRequest != kSwitchIdentityRequest)
        {
            return false;
        }

        fake = newFake();
        result = bootstrapAth3kUsb(
            {kAtherosUsbVendor, kAtherosUsbProduct, 2U, 0U}, usbIo(fake));
        if (result.result != Ath3kBootResult::AlreadyOperational ||
            result.requiresUsbReset || fake.vendorWrites != 0U)
        {
            return false;
        }
        fake = newFake();
        result = bootstrapAth3kUsb(bad, usbIo(fake));
        if (result.result != Ath3kBootResult::UnsupportedDevice ||
            fake.firmwareCalls != 0U)
        {
            return false;
        }
        fake = newFake();
        storeLittle32(
            std::next(fake.patch.data(),
                      static_cast<std::ptrdiff_t>(kImageBytes - kWordBytes)),
            1U);
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::VersionMismatch ||
            result.requiresUsbReset || fake.vendorWrites != 0U)
        {
            return false;
        }
        fake = newFake();
        fake.version.at(kClockOffset) = kInvalidClock;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::UnsupportedClock ||
            !result.requiresUsbReset || fake.vendorWrites != 1U)
        {
            return false;
        }
        fake = newFake();
        fake.missingFirmware = true;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::FirmwareUnavailable ||
            result.requiresUsbReset)
        {
            return false;
        }
        fake = newFake();
        fake.shortBulk = true;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::UsbTransferFailed ||
            !result.requiresUsbReset || fake.bulkWrites != 1U)
        {
            return false;
        }
        fake = newFake();
        fake.state = kLoadedNormalState;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::AwaitReenumeration ||
            fake.firmwareCalls != 0U || fake.vendorWrites != 1U)
        {
            return false;
        }
        fake = newFake();
        fake.valid = false;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        return result.result == Ath3kBootResult::IdentityLost &&
               fake.firmwareCalls == 0U;
    }

    bool writeCommand(void *context, const uint8_t *packet, size_t bytes)
    {
        auto &fake = *static_cast<UsbFake *>(context);
        if (fake.failControl || packet == nullptr ||
            bytes > fake.transmitted.size())
        {
            return false;
        }
        std::memcpy(fake.transmitted.data(), packet, bytes);
        return true;
    }

    bool writeAcl(void *context, uint8_t endpoint, const uint8_t *packet,
                  size_t bytes, size_t *transferred)
    {
        auto &fake = *static_cast<UsbFake *>(context);
        fake.lastEndpoint = endpoint;
        if (endpoint != kBulkOutEndpoint || packet == nullptr ||
            transferred == nullptr)
        {
            return false;
        }
        *transferred = fake.shortBulk ? bytes - 1U : bytes;
        return true;
    }

    bool deliver(void *context, UsbHciPacketKind kind, const uint8_t *packet,
                 size_t bytes)
    {
        auto &fake = *static_cast<UsbFake *>(context);
        if (fake.failDeliver || packet == nullptr)
        {
            return false;
        }
        ++fake.delivered;
        if (kind == UsbHciPacketKind::Event)
        {
            fake.deliveredEventBytes += bytes;
        }
        else
        {
            fake.deliveredAclBytes += bytes;
        }
        if (fake.revokeOnDelivery)
        {
            fake.valid = false;
        }
        return true;
    }

    UsbHciHostCallbacks host(UsbFake &fake)
    {
        return {&fake, kEpoch, permit, writeCommand, writeAcl, deliver};
    }

    bool testHci()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        constexpr UsbHciEndpoints kEndpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        if (sendUsbHciCommand(state, host(fake), nullptr, 0U) !=
            UsbHciStatus::NotAttached)
        {
            return false;
        }
        if (attachUsbHci(state, {0x01U, kAclInEndpoint, kBulkOutEndpoint},
                         host(fake)) != UsbHciStatus::InvalidEndpoint ||
            attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            attachUsbHci(state, kEndpoints, host(fake)) !=
                UsbHciStatus::Faulted)
        {
            return false;
        }
        constexpr std::array<uint8_t, 3U> kReset {0x03U, 0x0cU, 0U};
        constexpr std::array<uint8_t, 5U> kAcl {0x01U, 0x20U, 1U, 0U, 0x7fU};
        if (sendUsbHciCommand(state, host(fake), kReset.data(),
                              kReset.size()) != UsbHciStatus::Ok ||
            fake.transmitted.at(0U) != kReset.at(0U) ||
            sendUsbHciAcl(state, host(fake), kAcl.data(), kAcl.size()) !=
                UsbHciStatus::Ok ||
            fake.lastEndpoint != kBulkOutEndpoint)
        {
            return false;
        }
        constexpr std::array<uint8_t, 7U> kEvents {
            0x0eU, 0x01U, 0x00U, 0x0fU, 0x02U, 0x01U, 0x00U,
        };
        if (receiveUsbHciEvent(state, host(fake), kEvents.data(), 1U) !=
                UsbHciStatus::Ok ||
            fake.delivered != 0U ||
            receiveUsbHciEvent(state, host(fake), std::next(kEvents.data(), 1U),
                               kEvents.size() - 1U) != UsbHciStatus::Ok ||
            fake.delivered != 2U || fake.deliveredEventBytes != kEventBytes)
        {
            return false;
        }
        if (receiveUsbHciAcl(state, host(fake), kAcl.data(), 3U) !=
                UsbHciStatus::Ok ||
            receiveUsbHciAcl(state, host(fake), std::next(kAcl.data(), 3U),
                             2U) != UsbHciStatus::Ok ||
            fake.delivered != 3U || fake.deliveredAclBytes != kAcl.size())
        {
            return false;
        }
        constexpr std::array<uint8_t, 4U> kBadAcl {
            0x01U,
            0x20U,
            0xffU,
            0xffU,
        };
        if (receiveUsbHciAcl(state, host(fake), kBadAcl.data(),
                             kBadAcl.size()) != UsbHciStatus::FrameTooLarge ||
            receiveUsbHciAcl(state, host(fake), kAcl.data(), kAcl.size()) !=
                UsbHciStatus::Faulted)
        {
            return false;
        }
        detachUsbHci(state);
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok)
        {
            return false;
        }
        fake.shortBulk = true;
        if (sendUsbHciAcl(state, host(fake), kAcl.data(), kAcl.size()) !=
                UsbHciStatus::TransferFailed ||
            !state.faulted)
        {
            return false;
        }
        detachUsbHci(state);
        fake.shortBulk = false;
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok)
        {
            return false;
        }
        fake.revokeOnDelivery = true;
        if (receiveUsbHciEvent(state, host(fake), kEvents.data(), 3U) !=
            UsbHciStatus::OwnershipLost)
        {
            return false;
        }
        detachUsbHci(state);
        return !state.attached && !state.faulted &&
               attachUsbHci(state, kEndpoints, host(fake)) ==
                   UsbHciStatus::OwnershipLost;
    }
} // namespace

int main()
{
    if (!testFirmware())
    {
        return 1;
    }
    return testHci() ? 0 : 2;
}
