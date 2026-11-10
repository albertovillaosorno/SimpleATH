// SPDX-License-Identifier: GPL-2.0-only
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
    constexpr uint8_t kLoadedPatchState = 0x80U;
    constexpr uint8_t kLoadedConfigurationState = 0x40U;
    constexpr uint8_t kLoadedNormalState = 0xc0U | 0x0eU;
    constexpr uint16_t kAtherosUsbVendor = 0x0cf3U;
    constexpr uint16_t kAtherosUsbProduct = 0x0036U;
    constexpr size_t kEventBytes = 7U;
    constexpr size_t kExpectedPackets = 6U;

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
            bool revokeOnStateRead {};
            bool revokeOnVersionRead {};
            bool revokeOnFirmwareDelay {};
            bool revokeOnFirmwareLookup {};
            bool failFirmwareLookupAndRevoke {};
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
            if (fake.revokeOnStateRead)
            {
                fake.valid = false;
            }
            return true;
        }
        if (command.request == kReadVersionRequest &&
            bytes == fake.version.size())
        {
            std::memcpy(buffer, fake.version.data(), bytes);
            if (fake.revokeOnVersionRead)
            {
                fake.valid = false;
            }
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
        if (fake.failFirmwareLookupAndRevoke)
        {
            fake.valid = false;
            return false;
        }
        const bool patch =
            std::strcmp(fileName, "ar3k/AthrBT_0x11223344.dfu") == 0;
        const bool config =
            std::strcmp(fileName, "ar3k/ramps_0x11223344_26.dfu") == 0;
        if (!patch && !config)
        {
            return false;
        }
        *image =
            patch ? Ath3kFirmwareImage {fake.patch.data(), fake.patch.size()}
                  : Ath3kFirmwareImage {fake.config.data(), fake.config.size()};
        if (fake.revokeOnFirmwareLookup)
        {
            fake.valid = false;
        }
        return true;
    }

    void delay(void *context, uint32_t /* micros */)
    {
        auto &fake = *static_cast<UsbFake *>(context);
        if (fake.revokeOnFirmwareDelay)
        {
            fake.valid = false;
        }
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
            result.phase != Ath3kBootPhase::LoadConfiguration ||
            result.requiresUsbReset || fake.vendorWrites != 0U ||
            fake.bulkWrites != 0U || fake.firmwareCalls != 0U)
        {
            return false;
        }
        // A loaded configuration needs no reference-clock filename; even
        // an unknown reported clock must not block unrelated patch startup.
        fake = newFake();
        fake.state = kLoadedConfigurationState;
        fake.version.at(kClockOffset) = kInvalidClock;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::AwaitReenumeration ||
            result.firmwareBytesTransferred != kImageBytes ||
            fake.firmwareCalls != 1U || fake.vendorWrites != 3U ||
            !result.requiresUsbReset)
        {
            return false;
        }
        // Even with an already-loaded patch, unknown configuration clocks
        // must be rejected before loading a firmware resource or USB write.
        fake = newFake();
        fake.state = kLoadedPatchState;
        fake.version.at(kClockOffset) = kInvalidClock;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::UnsupportedClock ||
            result.requiresUsbReset || fake.firmwareCalls != 0U ||
            fake.vendorWrites != 0U)
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

    bool testFirmwareOwnershipBoundary()
    {
        const Ath3kUsbIdentity identity {
            kAtherosUsbVendor,
            kAtherosUsbProduct,
            1U,
            0U,
        };
        UsbFake fake = newFake();
        fake.revokeOnStateRead = true;
        auto result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::IdentityLost ||
            result.phase != Ath3kBootPhase::ReadState ||
            fake.firmwareCalls != 0U || fake.vendorWrites != 0U)
        {
            return false;
        }

        fake = newFake();
        fake.revokeOnVersionRead = true;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::IdentityLost ||
            result.phase != Ath3kBootPhase::ReadVersion ||
            fake.firmwareCalls != 0U || fake.vendorWrites != 0U)
        {
            return false;
        }

        // Firmware is a borrowed resource; a revoked loader may already
        // have discarded it when returning from the callback. Never inspect
        // its patch trailer or try USB transfer under a stale owner.
        fake = newFake();
        fake.revokeOnFirmwareLookup = true;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::IdentityLost ||
            result.phase != Ath3kBootPhase::LoadPatch ||
            fake.firmwareCalls != 1U || fake.vendorWrites != 0U ||
            fake.bulkWrites != 0U || result.requiresUsbReset)
        {
            return false;
        }

        fake = newFake();
        fake.failFirmwareLookupAndRevoke = true;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        if (result.result != Ath3kBootResult::IdentityLost ||
            result.phase != Ath3kBootPhase::LoadPatch ||
            fake.firmwareCalls != 1U || fake.vendorWrites != 0U ||
            fake.bulkWrites != 0U || result.requiresUsbReset)
        {
            return false;
        }

        // An owner revoked during a timed firmware gap must not receive
        // even the first bulk packet after the already-submitted header.
        fake = newFake();
        fake.revokeOnFirmwareDelay = true;
        result = bootstrapAth3kUsb(identity, usbIo(fake));
        return result.result == Ath3kBootResult::IdentityLost &&
               result.phase == Ath3kBootPhase::LoadPatch &&
               result.requiresUsbReset &&
               result.firmwareBytesTransferred == kFirmwareHeaderBytes &&
               fake.vendorWrites == 1U && fake.bulkWrites == 0U;
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

    bool permitZeroEpoch(void * /*context*/, uint64_t epoch)
    {
        return epoch == 0U;
    }

    bool testHciAttachOwnership()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        const UsbHciEndpoints endpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        UsbHciHostCallbacks callbacks = host(fake);
        callbacks.ownerEpoch = 0U;
        callbacks.permit = permitZeroEpoch;
        if (attachUsbHci(state, endpoints, callbacks) !=
                UsbHciStatus::InvalidArgument ||
            state.attached || state.epoch != 0U)
        {
            return false;
        }
        // Descriptor selection normally rejects duplicate addresses, but
        // attaching directly must enforce the same physical pipe contract.
        const UsbHciEndpoints aliased {
            kEventInEndpoint,
            kEventInEndpoint,
            kBulkOutEndpoint,
        };
        if (attachUsbHci(state, aliased, host(fake)) !=
                UsbHciStatus::InvalidEndpoint ||
            state.attached || state.epoch != 0U)
        {
            return false;
        }
        return attachUsbHci(state, endpoints, host(fake)) == UsbHciStatus::Ok &&
               state.attached && state.epoch == kEpoch;
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

    // Classic ACL ownership must originate from a controller Connection
    // Complete, not a host-chosen handle in a packet or a buffer-size reply.
    constexpr std::array<uint8_t, 13U> kClassicConnected {
        3U, 11U, 0U, 2U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 0U,
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
        auto firstConnection = kClassicConnected;
        firstConnection.at(3U) = 1U;
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            !negotiateAclCredits(state, fake) ||
            sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                              kReadBufferSize.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            sendUsbHciAcl(state, host(fake), kFirst.data(), kFirst.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            state.aclWindow.availableCredits != 2U ||
            receiveUsbHciEvent(state, host(fake), firstConnection.data(),
                               firstConnection.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kClassicConnected.data(),
                               kClassicConnected.size()) != UsbHciStatus::Ok ||
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
            sendUsbHciAcl(state, host(fake), kSecond.data(), kSecond.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
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
        if (receiveUsbHciEvent(state, host(fake), firstConnection.data(),
                               firstConnection.size()) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kReserved.data(),
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

    bool testAclHandlePressure()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        constexpr UsbHciEndpoints kEndpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                              kReadBufferSize.size()) != UsbHciStatus::Ok)
        {
            return false;
        }
        // The physical controller can expose more buffers than this owner's
        // fixed number of live handle slots. Capacity must remain bounded.
        auto response = kBufferSizeResponse;
        constexpr size_t kTotalAclPacketsOffset = 9U;
        response.at(kTotalAclPacketsOffset) =
            static_cast<uint8_t>(kUsbHciTrackedAclHandles + 1U);
        if (receiveUsbHciEvent(state, host(fake), response.data(),
                               response.size()) != UsbHciStatus::Ok)
        {
            return false;
        }
        constexpr std::array<uint8_t, 5U> kExampleAcl {
            1U, 0x20U, 1U, 0U, 0x7fU,
        };
        auto acl = kExampleAcl;
        auto connected = kClassicConnected;
        for (size_t index = 0; index < kUsbHciTrackedAclHandles; ++index)
        {
            acl.at(0U) = static_cast<uint8_t>(index + 1U);
            connected.at(3U) = acl.at(0U);
            if (receiveUsbHciEvent(state, host(fake), connected.data(),
                                   connected.size()) != UsbHciStatus::Ok ||
                sendUsbHciAcl(state, host(fake), acl.data(), acl.size()) !=
                    UsbHciStatus::Ok)
            {
                return false;
            }
        }
        acl.at(0U) = static_cast<uint8_t>(kUsbHciTrackedAclHandles + 1U);
        if (state.aclWindow.availableCredits != 1U ||
            sendUsbHciAcl(state, host(fake), acl.data(), acl.size()) !=
                UsbHciStatus::FlowControlUnavailable)
        {
            return false;
        }
        // An in-flight handle cannot be reused. Once the controller returns
        // its credit AND reports a disconnection, its retired slot is free
        // for a separately confirmed new connection.
        constexpr std::array<uint8_t, 7U> kCompleteFirst {
            0x13U, 5U, 1U, 1U, 0U, 1U, 0U,
        };
        constexpr std::array<uint8_t, 6U> kDisconnectedFirst {
            0x05U, 4U, 0U, 1U, 0U, 0x13U,
        };
        connected.at(3U) = acl.at(0U);
        if (receiveUsbHciEvent(state, host(fake), kCompleteFirst.data(),
                               kCompleteFirst.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kDisconnectedFirst.data(),
                               kDisconnectedFirst.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), connected.data(),
                               connected.size()) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), acl.data(), acl.size()) !=
                UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 1U)
        {
            return false;
        }
        // Two entries for one handle in a single completion event are
        // ambiguous even when their sum does not exceed the outstanding
        // count. Neither entry may credit a partially validated event.
        constexpr std::array<uint8_t, 11U> kDuplicate {
            0x13U, 9U, 2U, 2U, 0U, 1U, 0U, 2U, 0U, 1U, 0U,
        };
        return receiveUsbHciEvent(state, host(fake), kDuplicate.data(),
                                  kDuplicate.size()) ==
                   UsbHciStatus::MalformedPacket &&
               state.faulted && state.aclWindow.availableCredits == 1U;
    }

    bool testAclInboundHandleAdmission()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        constexpr UsbHciEndpoints kEndpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        constexpr std::array<uint8_t, 5U> kInboundAcl {
            1U, 0x20U, 1U, 0U, 0x7fU,
        };
        constexpr std::array<uint8_t, 6U> kDisconnected {
            0x05U, 4U, 0U, 1U, 0U, 0x13U,
        };
        auto connected = kClassicConnected;
        connected.at(3U) = 1U;
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            !negotiateAclCredits(state, fake) ||
            receiveUsbHciAcl(state, host(fake), kInboundAcl.data(),
                             kInboundAcl.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted || fake.deliveredAclBytes != 0U)
        {
            return false;
        }
        detachUsbHci(state);
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            !negotiateAclCredits(state, fake) ||
            receiveUsbHciEvent(state, host(fake), connected.data(),
                               connected.size()) != UsbHciStatus::Ok ||
            receiveUsbHciAcl(state, host(fake), kInboundAcl.data(),
                             kInboundAcl.size()) != UsbHciStatus::Ok ||
            fake.deliveredAclBytes != kInboundAcl.size() ||
            receiveUsbHciEvent(state, host(fake), kDisconnected.data(),
                               kDisconnected.size()) != UsbHciStatus::Ok ||
            receiveUsbHciAcl(state, host(fake), kInboundAcl.data(),
                             kInboundAcl.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted || fake.deliveredAclBytes != kInboundAcl.size())
        {
            return false;
        }
        // Invalid RX never escapes to the host after link loss; ownership
        // can only restart following a new USB/HCI epoch and connection.
        return receiveUsbHciAcl(state, host(fake), kInboundAcl.data(),
                                kInboundAcl.size()) == UsbHciStatus::Faulted;
    }

    bool testCommandCredits()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        constexpr UsbHciEndpoints kEndpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        constexpr std::array<uint8_t, 3U> kLocalName {0x14U, 0x0cU, 0U};
        constexpr std::array<uint8_t, 3U> kOther {0x15U, 0x0cU, 0U};
        constexpr std::array<uint8_t, 6U> kWrongOpcode {
            0x0eU, 4U, 2U, 0x15U, 0x0cU, 0U,
        };
        constexpr std::array<uint8_t, 6U> kCompleteTwoCredits {
            0x0eU, 4U, 2U, 0x14U, 0x0cU, 0U,
        };
        constexpr std::array<uint8_t, 6U> kStatusOneCredit {
            0x0fU, 4U, 0U, 1U, 0x15U, 0x0cU,
        };
        constexpr std::array<uint8_t, 6U> kCompleteZeroCredits {
            0x0eU, 4U, 0U, 0x14U, 0x0cU, 0U,
        };
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            state.commandWindow.credits != 1U || state.commandWindow.pending ||
            sendUsbHciCommand(state, host(fake), kLocalName.data(),
                              kLocalName.size()) != UsbHciStatus::Ok ||
            state.commandWindow.credits != 0U || !state.commandWindow.pending ||
            sendUsbHciCommand(state, host(fake), kOther.data(),
                              kOther.size()) != UsbHciStatus::NoCommandCredits)
        {
            return false;
        }
        // A response for an unsent opcode must not mint command credits.
        if (receiveUsbHciEvent(state, host(fake), kWrongOpcode.data(),
                               kWrongOpcode.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted || state.commandWindow.credits != 0U)
        {
            return false;
        }
        detachUsbHci(state);
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            sendUsbHciCommand(state, host(fake), kLocalName.data(),
                              kLocalName.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kCompleteTwoCredits.data(),
                               kCompleteTwoCredits.size()) !=
                UsbHciStatus::Ok ||
            state.commandWindow.credits != 2U || state.commandWindow.pending ||
            sendUsbHciCommand(state, host(fake), kOther.data(),
                              kOther.size()) != UsbHciStatus::Ok ||
            state.commandWindow.credits != 1U ||
            sendUsbHciCommand(state, host(fake), kLocalName.data(),
                              kLocalName.size()) !=
                UsbHciStatus::NoCommandCredits ||
            receiveUsbHciEvent(state, host(fake), kStatusOneCredit.data(),
                               kStatusOneCredit.size()) != UsbHciStatus::Ok ||
            state.commandWindow.credits != 1U || state.commandWindow.pending ||
            sendUsbHciCommand(state, host(fake), kLocalName.data(),
                              kLocalName.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kCompleteZeroCredits.data(),
                               kCompleteZeroCredits.size()) !=
                UsbHciStatus::Ok ||
            state.commandWindow.credits != 0U || state.commandWindow.pending ||
            sendUsbHciCommand(state, host(fake), kOther.data(),
                              kOther.size()) != UsbHciStatus::NoCommandCredits)
        {
            return false;
        }
        // A completed command must not be counted twice.
        if (receiveUsbHciEvent(state, host(fake), kCompleteTwoCredits.data(),
                               kCompleteTwoCredits.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted || state.commandWindow.credits != 0U)
        {
            return false;
        }
        detachUsbHci(state);
        // A new physical USB epoch starts with the one HCI-defined initial
        // command credit, never the prior epoch's reported allowance.
        constexpr std::array<uint8_t, 6U> kReadBufferAccepted {
            0x0fU, 4U, 0U, 1U, 0x05U, 0x10U,
        };
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            state.commandWindow.credits != 1U || state.commandWindow.pending ||
            sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                              kReadBufferSize.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kReadBufferAccepted.data(),
                               kReadBufferAccepted.size()) !=
                UsbHciStatus::Ok ||
            !state.aclWindow.readBufferPending ||
            sendUsbHciCommand(state, host(fake), kLocalName.data(),
                              kLocalName.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            receiveUsbHciEvent(state, host(fake), kBufferSizeResponse.data(),
                               kBufferSizeResponse.size()) !=
                UsbHciStatus::Ok ||
            !state.aclWindow.configured || state.commandWindow.credits != 1U)
        {
            return false;
        }
        // A failed HCI Reset command blocks recovery of stale credit
        // ownership, even if Command Status advertises spare slots.
        constexpr std::array<uint8_t, 3U> kReset {0x03U, 0x0cU, 0U};
        constexpr std::array<uint8_t, 6U> kRejectedReset {
            0x0fU, 4U, 0x0cU, 1U, 0x03U, 0x0cU,
        };
        return sendUsbHciCommand(state, host(fake), kReset.data(),
                                 kReset.size()) == UsbHciStatus::Ok &&
               sendUsbHciCommand(state, host(fake), kLocalName.data(),
                                 kLocalName.size()) ==
                   UsbHciStatus::FlowControlUnavailable &&
               receiveUsbHciEvent(state, host(fake), kRejectedReset.data(),
                                  kRejectedReset.size()) ==
                   UsbHciStatus::MalformedPacket &&
               state.faulted;
    }

    bool testLePreliminaryCommandStatus()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        constexpr UsbHciEndpoints kEndpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        constexpr std::array<uint8_t, 5U> kLeProcedureOpcodes {
            0x06U, 0x08U, 0x0aU, 0x0bU, 0x0cU,
        };
        constexpr uint8_t kLeOpcodeGroup = 0x20U;
        constexpr uint8_t kRejectedControllerStatus = 0x0cU;
        constexpr std::array<uint8_t, 3U> kOtherCommand {
            0x14U,
            0x0cU,
            0x00U,
        };
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok)
        {
            return false;
        }
        // Advertising and scan command procedures both await a final CC.
        // A preliminary successful Status must not free the pending opcode
        // or permit a different HCI command to overtake it.
        for (const uint8_t opcode : kLeProcedureOpcodes)
        {
            const std::array<uint8_t, 3U> command {opcode, kLeOpcodeGroup, 0U};
            const std::array<uint8_t, 6U> status {
                0x0fU, 4U, 0U, 1U, opcode, kLeOpcodeGroup,
            };
            const std::array<uint8_t, 6U> complete {
                0x0eU, 4U, 1U, opcode, kLeOpcodeGroup, 0U,
            };
            if (sendUsbHciCommand(state, host(fake), command.data(),
                                  command.size()) != UsbHciStatus::Ok ||
                receiveUsbHciEvent(state, host(fake), status.data(),
                                   status.size()) != UsbHciStatus::Ok ||
                !state.commandWindow.pending ||
                !state.commandWindow.preliminaryStatusSeen ||
                state.commandWindow.credits != 1U ||
                sendUsbHciCommand(state, host(fake), kOtherCommand.data(),
                                  kOtherCommand.size()) !=
                    UsbHciStatus::NoCommandCredits ||
                receiveUsbHciEvent(state, host(fake), complete.data(),
                                   complete.size()) != UsbHciStatus::Ok ||
                state.commandWindow.pending ||
                state.commandWindow.preliminaryStatusSeen ||
                state.commandWindow.credits != 1U)
            {
                return false;
            }
        }
        // Repeated successful Status must not repeatedly grant credits.
        const std::array<uint8_t, 3U> command {
            kLeProcedureOpcodes.front(),
            kLeOpcodeGroup,
            0U,
        };
        const std::array<uint8_t, 6U> status {
            0x0fU, 4U, 0U, 1U, kLeProcedureOpcodes.front(), kLeOpcodeGroup,
        };
        if (sendUsbHciCommand(state, host(fake), command.data(),
                              command.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), status.data(),
                               status.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), status.data(),
                               status.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted)
        {
            return false;
        }
        detachUsbHci(state);
        // An explicit controller rejection is terminal, not preliminary.
        auto rejected = status;
        rejected.at(2U) = kRejectedControllerStatus;
        return attachUsbHci(state, kEndpoints, host(fake)) ==
                   UsbHciStatus::Ok &&
               sendUsbHciCommand(state, host(fake), command.data(),
                                 command.size()) == UsbHciStatus::Ok &&
               receiveUsbHciEvent(state, host(fake), rejected.data(),
                                  rejected.size()) == UsbHciStatus::Ok &&
               !state.commandWindow.pending &&
               !state.commandWindow.preliminaryStatusSeen &&
               state.commandWindow.credits == 1U;
    }

    constexpr std::array<uint8_t, 3U> kLeReadSize {
        0x02U,
        0x20U,
        0U,
    };
    constexpr std::array<uint8_t, 6U> kLeAcceptedStatus {
        0x0fU, 4U, 0U, 1U, 0x02U, 0x20U,
    };
    constexpr std::array<uint8_t, 9U> kLeDedicatedResponse {
        0x0eU, 7U, 1U, 0x02U, 0x20U, 0U, 5U, 0U, 2U,
    };
    constexpr std::array<uint8_t, 9U> kLeSharedResponse {
        0x0eU, 7U, 1U, 0x02U, 0x20U, 0U, 0U, 0U, 0U,
    };
    constexpr std::array<uint8_t, 21U> kLeConnected {
        0x3eU, 19U, 1U, 0U,    1U, 0U, 0U, 0U,    0U, 0U, 0U,
        0U,    0U,  0U, 0x18U, 0U, 0U, 0U, 0x48U, 0U, 0U,
    };
    constexpr std::array<uint8_t, 5U> kLeAcl {
        1U, 0x20U, 1U, 0U, 0x7fU,
    };
    constexpr std::array<uint8_t, 10U> kLeOversized {
        1U, 0x20U, 6U, 0U, 1U, 2U, 3U, 4U, 5U, 6U,
    };
    constexpr std::array<uint8_t, 5U> kClassicAcl {
        2U, 0x20U, 1U, 0U, 0x7fU,
    };
    constexpr std::array<uint8_t, 7U> kLeCompleted {
        0x13U, 5U, 1U, 1U, 0U, 1U, 0U,
    };
    constexpr std::array<uint8_t, 7U> kClassicCompleted {
        0x13U, 5U, 1U, 2U, 0U, 1U, 0U,
    };
    constexpr std::array<uint8_t, 6U> kLeDisconnected {
        0x05U, 4U, 0U, 1U, 0U, 0x13U,
    };
    constexpr UsbHciEndpoints kLeEndpoints {
        kEventInEndpoint,
        kAclInEndpoint,
        kBulkOutEndpoint,
    };

    bool testDedicatedLeCredits()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        if (attachUsbHci(state, kLeEndpoints, host(fake)) != UsbHciStatus::Ok ||
            sendUsbHciCommand(state, host(fake), kLeReadSize.data(),
                              kLeReadSize.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kLeAcceptedStatus.data(),
                               kLeAcceptedStatus.size()) != UsbHciStatus::Ok ||
            !state.leAclWindow.readBufferPending ||
            sendUsbHciCommand(state, host(fake), kReadBufferSize.data(),
                              kReadBufferSize.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            receiveUsbHciEvent(state, host(fake), kLeDedicatedResponse.data(),
                               kLeDedicatedResponse.size()) !=
                UsbHciStatus::Ok ||
            !state.leAclWindow.configured ||
            state.leAclWindow.availableCredits != 2U ||
            state.aclWindow.configured ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            receiveUsbHciEvent(state, host(fake), kLeConnected.data(),
                               kLeConnected.size()) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kLeOversized.data(),
                          kLeOversized.size()) != UsbHciStatus::FrameTooLarge ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::Ok ||
            state.leAclWindow.availableCredits != 0U ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::NoControllerCredits ||
            sendUsbHciAcl(state, host(fake), kClassicAcl.data(),
                          kClassicAcl.size()) !=
                UsbHciStatus::FlowControlUnavailable)
        {
            return false;
        }
        // Read Buffer Size is independent of the already configured LE pool.
        if (!negotiateAclCredits(state, fake) ||
            receiveUsbHciEvent(state, host(fake), kClassicConnected.data(),
                               kClassicConnected.size()) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kClassicAcl.data(),
                          kClassicAcl.size()) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kClassicAcl.data(),
                          kClassicAcl.size()) != UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 0U ||
            receiveUsbHciEvent(state, host(fake), kLeCompleted.data(),
                               kLeCompleted.size()) != UsbHciStatus::Ok ||
            state.leAclWindow.availableCredits != 1U ||
            state.aclWindow.availableCredits != 0U ||
            receiveUsbHciEvent(state, host(fake), kClassicCompleted.data(),
                               kClassicCompleted.size()) != UsbHciStatus::Ok ||
            state.leAclWindow.availableCredits != 1U ||
            state.aclWindow.availableCredits != 1U)
        {
            return false;
        }
        // A wrong late completion in a mixed-pool event never partially
        // restores either ledger. The entire transport faults closed.
        constexpr std::array<uint8_t, 11U> kMixedInvalid {
            0x13U, 9U, 2U, 1U, 0U, 1U, 0U, 2U, 0U, 2U, 0U,
        };
        return receiveUsbHciEvent(state, host(fake), kMixedInvalid.data(),
                                  kMixedInvalid.size()) ==
                   UsbHciStatus::MalformedPacket &&
               state.faulted && state.leAclWindow.availableCredits == 1U &&
               state.aclWindow.availableCredits == 1U;
    }

    bool testSharedLeCredits()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        if (attachUsbHci(state, kLeEndpoints, host(fake)) != UsbHciStatus::Ok ||
            !negotiateAclCredits(state, fake) ||
            sendUsbHciCommand(state, host(fake), kLeReadSize.data(),
                              kLeReadSize.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kLeSharedResponse.data(),
                               kLeSharedResponse.size()) != UsbHciStatus::Ok ||
            !state.leAclWindow.configured ||
            state.leAclWindow.totalCredits != 0U ||
            receiveUsbHciEvent(state, host(fake), kLeConnected.data(),
                               kLeConnected.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kClassicConnected.data(),
                               kClassicConnected.size()) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kClassicAcl.data(),
                          kClassicAcl.size()) != UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 0U ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::NoControllerCredits ||
            receiveUsbHciEvent(state, host(fake), kLeCompleted.data(),
                               kLeCompleted.size()) != UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 1U ||
            state.leAclWindow.availableCredits != 0U)
        {
            return false;
        }
        // Link shutdown must not refund an ACL buffer or permit another TX
        // on the retired handle. A later connection may reclassify it only
        // after all in-flight packets are physically completed.
        if (receiveUsbHciEvent(state, host(fake), kLeDisconnected.data(),
                               kLeDisconnected.size()) != UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 1U ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            receiveUsbHciEvent(state, host(fake), kLeConnected.data(),
                               kLeConnected.size()) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::Ok ||
            state.aclWindow.availableCredits != 0U)
        {
            return false;
        }
        constexpr std::array<uint8_t, 3U> kReset {0x03U, 0x0cU, 0U};
        if (sendUsbHciCommand(state, host(fake), kReset.data(),
                              kReset.size()) != UsbHciStatus::Ok ||
            state.aclWindow.configured || state.leAclWindow.configured ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            receiveUsbHciEvent(state, host(fake), kResetComplete.data(),
                               kResetComplete.size()) != UsbHciStatus::Ok ||
            state.commandWindow.credits != 1U)
        {
            return false;
        }
        return sendUsbHciCommand(state, host(fake), kLeReadSize.data(),
                                 kLeReadSize.size()) == UsbHciStatus::Ok;
    }

    bool testEnhancedLeConnection()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        // HCI LE Enhanced Connection Complete, subevent 0x0a (Bluetooth
        // privacy): 31 event parameter bytes, including the extra local and
        // peer resolvable addresses. This is a controller-reported LE handle,
        // not a host assertion based on the ACL packet's low 12 bits.
        constexpr std::array<uint8_t, 33U> kEnhancedConnected {
            0x3eU, 31U, 0x0aU, 0U, 1U, 0U,
        };
        constexpr size_t kLeMetaSubeventOffset = 2U;
        constexpr size_t kLeConnectionStatusOffset = 3U;
        constexpr uint8_t kConnectionRejected = 0x0cU;
        if (attachUsbHci(state, kLeEndpoints, host(fake)) != UsbHciStatus::Ok ||
            sendUsbHciCommand(state, host(fake), kLeReadSize.data(),
                              kLeReadSize.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), kLeDedicatedResponse.data(),
                               kLeDedicatedResponse.size()) !=
                UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::FlowControlUnavailable ||
            receiveUsbHciEvent(state, host(fake), kEnhancedConnected.data(),
                               kEnhancedConnected.size()) != UsbHciStatus::Ok ||
            !state.aclWindow.connections.at(0U).le ||
            sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) !=
                UsbHciStatus::Ok ||
            state.leAclWindow.availableCredits != 1U ||
            receiveUsbHciEvent(state, host(fake), kLeCompleted.data(),
                               kLeCompleted.size()) != UsbHciStatus::Ok ||
            state.leAclWindow.availableCredits != 2U)
        {
            return false;
        }
        // Duplicate connection metadata never reclassifies a live handle.
        if (receiveUsbHciEvent(state, host(fake), kEnhancedConnected.data(),
                               kEnhancedConnected.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted)
        {
            return false;
        }
        detachUsbHci(state);
        // Older 21-byte LE Connection Complete bodies cannot masquerade as
        // the 33-byte enhanced format. No ACL credit may escape this error.
        auto truncated = kLeConnected;
        truncated.at(kLeMetaSubeventOffset) =
            kEnhancedConnected.at(kLeMetaSubeventOffset);
        if (attachUsbHci(state, kLeEndpoints, host(fake)) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), truncated.data(),
                               truncated.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted)
        {
            return false;
        }
        detachUsbHci(state);
        // A controller-reported connection failure is legal but cannot mint
        // an LE ACL handle, even with a syntactically complete privacy event.
        auto failed = kEnhancedConnected;
        failed.at(kLeConnectionStatusOffset) = kConnectionRejected;
        return attachUsbHci(state, kLeEndpoints, host(fake)) ==
                   UsbHciStatus::Ok &&
               receiveUsbHciEvent(state, host(fake), failed.data(),
                                  failed.size()) == UsbHciStatus::Ok &&
               !state.aclWindow.connections.at(0U).active && !state.faulted;
    }

    bool testMalformedLeBufferSize()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        auto invalidResponse = kLeDedicatedResponse;
        constexpr size_t kLeBufferLengthOffset = 6U;
        invalidResponse.at(kLeBufferLengthOffset) = 0U;
        if (attachUsbHci(state, kLeEndpoints, host(fake)) != UsbHciStatus::Ok ||
            sendUsbHciCommand(state, host(fake), kLeReadSize.data(),
                              kLeReadSize.size()) != UsbHciStatus::Ok ||
            receiveUsbHciEvent(state, host(fake), invalidResponse.data(),
                               invalidResponse.size()) !=
                UsbHciStatus::MalformedPacket ||
            !state.faulted || state.leAclWindow.configured)
        {
            return false;
        }
        detachUsbHci(state);
        // A physical connection event must never switch an in-flight classic
        // handle into the dedicated LE credit pool.
        auto classicConnected = kClassicConnected;
        classicConnected.at(3U) = 1U;
        return attachUsbHci(state, kLeEndpoints, host(fake)) ==
                   UsbHciStatus::Ok &&
               negotiateAclCredits(state, fake) &&
               receiveUsbHciEvent(state, host(fake), classicConnected.data(),
                                  classicConnected.size()) ==
                   UsbHciStatus::Ok &&
               sendUsbHciAcl(state, host(fake), kLeAcl.data(), kLeAcl.size()) ==
                   UsbHciStatus::Ok &&
               receiveUsbHciEvent(state, host(fake), kLeConnected.data(),
                                  kLeConnected.size()) ==
                   UsbHciStatus::MalformedPacket &&
               state.faulted;
    }

    bool testControllerFaults()
    {
        UsbFake fake = newFake();
        UsbHciState state {};
        constexpr UsbHciEndpoints kEndpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        constexpr std::array<uint8_t, 5U> kAcl {
            1U, 0x20U, 1U, 0U, 0x7fU,
        };
        constexpr std::array<uint8_t, 3U> kHardwareError {
            0x10U,
            1U,
            0x01U,
        };
        constexpr std::array<uint8_t, 3U> kBufferOverflow {
            0x1aU,
            1U,
            0x01U,
        };
        if (attachUsbHci(state, kEndpoints, host(fake)) != UsbHciStatus::Ok ||
            !negotiateAclCredits(state, fake) ||
            receiveUsbHciEvent(state, host(fake), kHardwareError.data(),
                               kHardwareError.size()) !=
                UsbHciStatus::Faulted ||
            !state.faulted ||
            sendUsbHciAcl(state, host(fake), kAcl.data(), kAcl.size()) !=
                UsbHciStatus::Faulted)
        {
            return false;
        }
        detachUsbHci(state);
        return attachUsbHci(state, kEndpoints, host(fake)) ==
                   UsbHciStatus::Ok &&
               !state.faulted && negotiateAclCredits(state, fake) &&
               receiveUsbHciEvent(state, host(fake), kBufferOverflow.data(),
                                  kBufferOverflow.size()) ==
                   UsbHciStatus::Faulted &&
               state.faulted &&
               sendUsbHciAcl(state, host(fake), kAcl.data(), kAcl.size()) ==
                   UsbHciStatus::Faulted;
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
        auto connected = kClassicConnected;
        connected.at(3U) = 1U;
        constexpr std::array<uint8_t, 5U> kAcl {0x01U, 0x20U, 1U, 0U, 0x7fU};
        if (sendUsbHciCommand(state, host(fake), kReset.data(),
                              kReset.size()) != UsbHciStatus::Ok ||
            fake.transmitted.at(0U) != kReset.at(0U) ||
            receiveUsbHciEvent(state, host(fake), kResetComplete.data(),
                               kResetComplete.size()) != UsbHciStatus::Ok ||
            !negotiateAclCredits(state, fake) ||
            receiveUsbHciEvent(state, host(fake), connected.data(),
                               connected.size()) != UsbHciStatus::Ok ||
            sendUsbHciAcl(state, host(fake), kAcl.data(), kAcl.size()) !=
                UsbHciStatus::Ok ||
            fake.lastEndpoint != kBulkOutEndpoint)
        {
            return false;
        }
        // Ordinary vendor events may be split/coalesced but must never
        // modify the controller's command credit ledger.
        constexpr std::array<uint8_t, 7U> kEvents {
            0xffU, 0x01U, 0x00U, 0xffU, 0x02U, 0x01U, 0x00U,
        };
        if (receiveUsbHciEvent(state, host(fake), kEvents.data(), 1U) !=
                UsbHciStatus::Ok ||
            fake.delivered != 3U ||
            receiveUsbHciEvent(state, host(fake), std::next(kEvents.data(), 1U),
                               kEvents.size() - 1U) != UsbHciStatus::Ok ||
            fake.delivered != kExpectedPackets - 1U ||
            fake.deliveredEventBytes !=
                kEventBytes + kBufferSizeResponse.size() +
                    kResetComplete.size() + kClassicConnected.size())
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
            receiveUsbHciEvent(state, host(fake), connected.data(),
                               connected.size()) != UsbHciStatus::Ok ||
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

    enum class EpochRaceEvent : uint8_t
    {
        None,
        Command,
        Acl,
        Deliver,
    };

    struct EpochRace
    {
            UsbHciState state {};
            uint64_t epoch {kEpoch};
            EpochRaceEvent trigger {EpochRaceEvent::None};
            bool reattach {true};
            bool failCallback {};
            bool successorAttached {};
    };

    bool racePermit(void *context, uint64_t epoch)
    {
        const auto &race = *static_cast<EpochRace *>(context);
        return race.epoch == epoch;
    }

    UsbHciHostCallbacks raceHost(EpochRace &race);

    void replaceRaceSession(EpochRace &race)
    {
        detachUsbHci(race.state);
        ++race.epoch;
        if (race.reattach)
        {
            constexpr UsbHciEndpoints endpoints {
                kEventInEndpoint,
                kAclInEndpoint,
                kBulkOutEndpoint,
            };
            race.successorAttached =
                attachUsbHci(race.state, endpoints, raceHost(race)) ==
                UsbHciStatus::Ok;
        }
    }

    bool raceCommand(void *context, const uint8_t *command, size_t bytes)
    {
        auto &race = *static_cast<EpochRace *>(context);
        if (command == nullptr || bytes == 0U)
        {
            return false;
        }
        if (race.trigger == EpochRaceEvent::Command)
        {
            replaceRaceSession(race);
        }
        return !race.failCallback;
    }

    bool raceAcl(void *context, uint8_t endpoint, const uint8_t *packet,
                 size_t bytes, size_t *transferred)
    {
        auto &race = *static_cast<EpochRace *>(context);
        if (packet == nullptr || endpoint != kBulkOutEndpoint ||
            transferred == nullptr || bytes == 0U)
        {
            return false;
        }
        *transferred = bytes;
        if (race.trigger == EpochRaceEvent::Acl)
        {
            replaceRaceSession(race);
        }
        return !race.failCallback;
    }

    bool raceDeliver(void *context, UsbHciPacketKind /*kind*/,
                     const uint8_t *packet, size_t bytes)
    {
        auto &race = *static_cast<EpochRace *>(context);
        if (packet == nullptr || bytes == 0U)
        {
            return false;
        }
        if (race.trigger == EpochRaceEvent::Deliver)
        {
            replaceRaceSession(race);
        }
        return !race.failCallback;
    }

    UsbHciHostCallbacks raceHost(EpochRace &race)
    {
        return {
            &race, race.epoch, racePermit, raceCommand, raceAcl, raceDeliver,
        };
    }

    bool checkStaleEpochCallback(EpochRaceEvent trigger, bool reattach,
                                 bool failCallback)
    {
        constexpr UsbHciEndpoints endpoints {
            kEventInEndpoint,
            kAclInEndpoint,
            kBulkOutEndpoint,
        };
        constexpr std::array<uint8_t, 5U> acl {
            2U, 0x20U, 1U, 0U, 0x7fU,
        };
        constexpr std::array<uint8_t, 3U> vendorEvent {0xffU, 1U, 0U};
        EpochRace race {};
        if (attachUsbHci(race.state, endpoints, raceHost(race)) !=
            UsbHciStatus::Ok)
        {
            return false;
        }
        if (trigger == EpochRaceEvent::Acl &&
            (sendUsbHciCommand(race.state, raceHost(race),
                               kReadBufferSize.data(),
                               kReadBufferSize.size()) != UsbHciStatus::Ok ||
             receiveUsbHciEvent(
                 race.state, raceHost(race), kBufferSizeResponse.data(),
                 kBufferSizeResponse.size()) != UsbHciStatus::Ok ||
             receiveUsbHciEvent(race.state, raceHost(race),
                                kClassicConnected.data(),
                                kClassicConnected.size()) != UsbHciStatus::Ok))
        {
            return false;
        }
        race.trigger = trigger;
        race.reattach = reattach;
        race.failCallback = failCallback;
        UsbHciStatus result = UsbHciStatus::Faulted;
        switch (trigger)
        {
            case EpochRaceEvent::Command:
                result = sendUsbHciCommand(race.state, raceHost(race),
                                           kReadBufferSize.data(),
                                           kReadBufferSize.size());
                break;
            case EpochRaceEvent::Acl:
                result = sendUsbHciAcl(race.state, raceHost(race), acl.data(),
                                       acl.size());
                break;
            case EpochRaceEvent::Deliver:
                result =
                    receiveUsbHciEvent(race.state, raceHost(race),
                                       vendorEvent.data(), vendorEvent.size());
                break;
            case EpochRaceEvent::None:
                return false;
        }
        return result == UsbHciStatus::OwnershipLost &&
               race.state.attached == reattach &&
               race.successorAttached == reattach && !race.state.faulted &&
               (!reattach || (race.state.epoch == race.epoch &&
                              !race.state.commandWindow.pending &&
                              race.state.commandWindow.credits == 1U));
    }

    bool testStaleHciEpochCallbacks()
    {
        constexpr std::array<EpochRaceEvent, 3U> triggers {
            EpochRaceEvent::Command,
            EpochRaceEvent::Acl,
            EpochRaceEvent::Deliver,
        };
        for (const EpochRaceEvent trigger : triggers)
        {
            for (const bool reattach : {false, true})
            {
                for (const bool failCallback : {false, true})
                {
                    if (!checkStaleEpochCallback(trigger, reattach,
                                                 failCallback))
                    {
                        return false;
                    }
                }
            }
        }
        return true;
    }

} // namespace

int main()
{
    if (!testFirmware())
    {
        return 1;
    }
    if (!testFirmwareOwnershipBoundary())
    {
        constexpr int kFirmwareOwnershipFailure = 10;
        return kFirmwareOwnershipFailure;
    }
    if (!testStaleHciEpochCallbacks())
    {
        constexpr int kStaleEpochFailure = 14;
        return kStaleEpochFailure;
    }
    if (!testHciAttachOwnership())
    {
        constexpr int kHciAttachOwnershipFailure = 12;
        return kHciAttachOwnershipFailure;
    }
    if (!testHci())
    {
        return 2;
    }
    if (!testAclCredits())
    {
        return 3;
    }
    if (!testEnhancedLeConnection())
    {
        constexpr int kEnhancedLeTestFailure = 7;
        return kEnhancedLeTestFailure;
    }
    if (!testAclHandlePressure())
    {
        return 4;
    }
    if (!testAclInboundHandleAdmission())
    {
        constexpr int kInboundAdmissionFailure = 11;
        return kInboundAdmissionFailure;
    }
    if (!testControllerFaults())
    {
        constexpr int kControllerFaultTestFailure = 5;
        return kControllerFaultTestFailure;
    }
    if (!testCommandCredits())
    {
        constexpr int kCommandCreditTestFailure = 6;
        return kCommandCreditTestFailure;
    }
    if (!testLePreliminaryCommandStatus())
    {
        constexpr int kLePreliminaryStatusFailure = 13;
        return kLePreliminaryStatusFailure;
    }
    if (!testDedicatedLeCredits())
    {
        constexpr int kDedicatedLeCreditTestFailure = 7;
        return kDedicatedLeCreditTestFailure;
    }
    if (!testSharedLeCredits())
    {
        constexpr int kSharedLeCreditTestFailure = 8;
        return kSharedLeCreditTestFailure;
    }
    constexpr int kMalformedLeTestFailure = 9;
    return testMalformedLeBufferSize() ? 0 : kMalformedLeTestFailure;
}
