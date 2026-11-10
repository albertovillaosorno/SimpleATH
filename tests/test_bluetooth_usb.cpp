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
    constexpr size_t kExpectedPackets = 5U;

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

    constexpr std::array<uint8_t, 6U> kResetComplete {
        0x0eU, 4U, 1U, 0x03U, 0x0cU, 0U,
    };
    constexpr std::array<uint8_t, 3U> kReadBufferSize {
        0x05U,
        0x10U,
        0U,
    };
    constexpr std::array<uint8_t, 13U> kBufferSizeResponse {
        0x0eU, 0x0bU, 0x01U, 0x05U, 0x10U, 0x00U, 0x05U,
        0x00U, 0x00U, 0x02U, 0x00U, 0x00U, 0x00U,
    };

    bool negotiateAclCredits(UsbHciState &state, UsbFake &fake)
    {
        return sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                                 kReadBufferSize.size()) == UsbHciStatus::Ok &&
               receiveUsbHciEvent(state, host(fake), kBufferSizeResponse.data(),
                                  kBufferSizeResponse.size()) ==
                   UsbHciStatus::Ok &&
               state.aclWindow.availableCredits == 2U;
    }

    bool testAclCredits()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        constexpr UsbHciEndpoints kEndpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        constexpr std::array<uint8_t, 5U> kFirst {1U, 0x20U, 1U, 0U, 0x7fU};
        constexpr std::array<uint8_t, 5U> kSecond {2U, 0x20U, 1U, 0U, 0x7fU};
        constexpr std::array<uint8_t, 7U> kCompleteOne {
            0x13U, 5U, 1U, 1U, 0U, 1U, 0U,
        };
        constexpr std::array<uint8_t, 11U> kDoubleComplete {
            0x13U, 9U, 2U, 1U, 0U, 1U, 0U, 2U, 0U, 2U, 0U,
        };
        constexpr std::array<uint8_t, 6U> kDisconnected {
            5U, 4U, 0U, 2U, 0U, 0x13U,
        };
        constexpr std::array<uint8_t, 7U> kCompleteTwo {
            0x13U, 5U, 1U, 2U, 0U, 1U, 0U,
        };
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            !negotiateAclCredits(state, fake) ||
            sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                              kReadBufferSize.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) !=
                UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kSecond.data(), kSecond.size()) !=
                UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) !=
                UsbHciStatus::NoControllerCredits ||
            state.aclWindow.availableCredits != 0U)
        {
            return false;
        }
        if (receiveUsbHciEvent(state, host(fake), kCompleteOne.data(),
                               kCompleteOne.size()) != UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 1U ||
            sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) !=
                UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kDisconnected.data(),
                               kDisconnected.size()) != UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 0U ||
            receiveUsbHciEvent(state, host(fake), kCompleteTwo.data(),
                               kCompleteTwo.size()) != UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 1U)
        {
            return false;
        }
        // There are now two outstanding packets on handle 1, none on 2.
        // A second handle completion in one event must not grant any credit.
        if (receiveUsbHciEvent(state, host(fake), kDoubleComplete.data(),
                               kDoubleComplete.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted || state.aclWindow.availableCredits != 1U ||
            receiveUsbHciEvent(state, host(fake), kCompleteOne.data(),
                               kCompleteOne.size()) != UsbHciStatus::Faulted)
        {
            return false;
        }
        detachUsbHci(state);
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            state.aclWindow.configured || !negotiateAclCredits(state, fake))
        {
            return false;
        }
        // Malformed connection handles and oversized controller packets must
        // be refused before consuming a credit or touching the USB pipe.
        constexpr std::array<uint8_t, 5U> kReserved {
            0xffU, 0x2fU, 1U, 0U, 0x7fU,
        };
        constexpr std::array<uint8_t, 10U> kTooLarge {
            1U, 0x20U, 6U, 0U, 1U, 2U, 3U, 4U, 5U, 6U,
        };
        if (sendUsbHciAcl(state, host(fake), kReserved.data(),
                          kReserved.size()) != UsbHciStatus::MalformedPacket ||
            sendUsbHciAcl(state, host(fake), kTooLarge.data(),
                          kTooLarge.size()) != UsbHciStatus::FrameTooLarge ||
            state.aclWindow.availableCredits != 2U)
        {
            return false;
        }
        // Controller Reset invalidates every negotiated packet slot even if
        // an earlier HCI connection had outstanding ACL completions.
        constexpr std::array<uint8_t, 3U> kControllerReset {
            0x03U,
            0x0cU,
            0U,
        };
        if (sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) !=
                UsbHciStatus::Ok ||
            sendUsbHciCommand(state, host(fake), kControllerReset.data(),
                              kControllerReset.size()) != UsbHciStatus::Ok ||
            state.aclWindow.configured ||
            sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                              kReadBufferSize.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            receiveUsbHciEvent(state, host(fake), kResetComplete.data(),
                               kResetComplete.size()) != UsbHciStatus::Ok ||
            !negotiateAclCredits(state, fake))
        {
            return false;
        }
        // Command Status rejection permits retry but never invents credits.
        detachUsbHci(state);
        constexpr std::array<uint8_t, 6U> kRejected {
            0x0fU, 4U, 0x0cU, 1U, 0x05U, 0x10U,
        };
        return attachUsbHci(state, kEndpoints, host(fake)) ==
                   UsbHciStatus::Ok &&
               sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                                 kReadBufferSize.size()) == UsbHciStatus::Ok &&
               receiveUsbHciEvent(state, host(fake), kRejected.data(),
                                  kRejected.size()) == UsbHciStatus::Ok &&
               !state.aclWindow.configured &&
               !state.aclWindow.readBufferPending &&
               sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) ==
                   UsbHciStatus::FlowControlUnavailable &&
               sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                                 kReadBufferSize.size()) == UsbHciStatus::Ok;
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
            receiveUsbHciEvent(state, host(fake), kResetComplete.data(),
                               kResetComplete.size()) != UsbHciStatus::Ok ||
            !negotiateAclCredits(state, fake) ||
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
            fake.delivered != 2U ||
            receiveUsbHciEvent(state, host(fake), std::next(kEvents.data(), 1U),
                               kEvents.size() - 1U) != UsbHciStatus::Ok ||
            fake.delivered != 4U ||
            fake.deliveredEventBytes != kEventBytes +
                                            kBufferSizeResponse.size() +
                                            kResetComplete.size())
        {
            return false;
        }
        if (receiveUsbHciAcl(state, host(fake), kAcl.data(), 3U) !=
                UsbHciStatus::Ok ||
            receiveUsbHciAcl(state, host(fake), std::next(kAcl.data(), 3U),
                             2U) != UsbHciStatus::Ok ||
            fake.delivered != kExpectedPackets ||
            fake.deliveredAclBytes != kAcl.size())
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
        if (!negotiateAclCredits(state, fake) ||
            sendUsbHciAcl(state, host(fake), kAcl.data(), kAcl.size()) !=
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
    if (!testHci())
    {
        return 2;
    }
    return testAclCredits() ? 0 : 3;
}
