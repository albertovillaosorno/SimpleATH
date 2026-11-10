// SPDX-License-Identifier: AGPL-3.0-only
#include "Ath3kUsb.hpp"
#include "UsbBytes.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kVendorWrite = 0x40U;
        constexpr uint8_t kVendorRead = 0xc0U;
        constexpr uint8_t kReadState = 0x05U;
        constexpr uint8_t kReadVersion = 0x09U;
        constexpr uint8_t kDownload = 0x01U;
        constexpr uint8_t kNormalMode = 0x07U;
        constexpr uint8_t kSwitchIdentity = 0x0aU;
        constexpr uint8_t kPatchLoaded = 0x80U;
        constexpr uint8_t kConfigurationLoaded = 0x40U;
        constexpr uint8_t kNormalModeValue = 0x0eU;
        constexpr uint8_t kModeMask = 0x3fU;
        constexpr size_t kVersionSize = 20U;
        constexpr size_t kFirmwareNameLength = 48U;
        constexpr size_t kWordBytes = 4U;
        constexpr size_t kHexDigits = 8U;
        constexpr unsigned kBitsPerNibble = 4U;
        constexpr unsigned kBitsPerByte = 8U;
        constexpr uint32_t kNibbleMask = 0x0fU;
        constexpr size_t kRefClockOffset = 12U;
        constexpr size_t kImageHeaderSize = 20U;
        constexpr size_t kPatchTrailerSize = 8U;
        constexpr size_t kMaxFirmwareBytes = size_t {1024U} * 1024U;
        constexpr size_t kBulkChunkBytes = 4096U;
        constexpr uint8_t kBulkFirmwareEndpoint = 0x02U;
        constexpr uint32_t kInterChunkDelayMicros = 75U;

        struct UsbId
        {
                uint16_t vendor;
                uint16_t product;
        };

        // Known AR3012 boot IDs from Linux ath3k.c, not an inference from
        // the QCA9565 PCI function's vendor/product identifiers.
        constexpr UsbId kAr3012BootIds[] {
            {0x0cf3U, 0x0036U}, {0x0cf3U, 0x3004U}, {0x0cf3U, 0x3008U},
            {0x0cf3U, 0x311dU}, {0x0cf3U, 0x311eU}, {0x0cf3U, 0x311fU},
            {0x0cf3U, 0x3121U}, {0x0cf3U, 0x817aU}, {0x0cf3U, 0x817bU},
            {0x0cf3U, 0xe003U}, {0x0cf3U, 0xe004U}, {0x0cf3U, 0xe005U},
            {0x0cf3U, 0xe006U}, {0x13d3U, 0x3362U}, {0x13d3U, 0x3375U},
            {0x13d3U, 0x3393U}, {0x13d3U, 0x3395U}, {0x13d3U, 0x3402U},
            {0x13d3U, 0x3408U}, {0x13d3U, 0x3423U}, {0x13d3U, 0x3432U},
            {0x13d3U, 0x3472U}, {0x13d3U, 0x3474U}, {0x13d3U, 0x3490U},
        };

        uint32_t loadLittle32(const uint8_t *data)
        {
            UsbBytes<uint8_t, kWordBytes> bytes {};
            __builtin_memcpy(bytes.data(), data,
                             UsbBytes<uint8_t, kWordBytes>::size());
            return static_cast<uint32_t>(bytes.at(0U)) |
                   (static_cast<uint32_t>(bytes.at(1U)) << kBitsPerByte) |
                   (static_cast<uint32_t>(bytes.at(2U))
                    << (2U * kBitsPerByte)) |
                   (static_cast<uint32_t>(bytes.at(3U)) << (3U * kBitsPerByte));
        }

        struct FirmwareVersion
        {
                uint32_t rom;
                uint32_t build;
                uint8_t clock;
        };

        bool authorized(const Ath3kIo &io)
        {
            return io.permit(io.context, io.epoch);
        }

        bool readState(const Ath3kIo &io, uint8_t &state)
        {
            return authorized(io) &&
                   io.controlIn(io.context, {kReadState, kVendorRead}, &state,
                                1U) &&
                   authorized(io);
        }

        bool readVersion(const Ath3kIo &io,
                         UsbBytes<uint8_t, kVersionSize> &version)
        {
            return authorized(io) &&
                   io.controlIn(io.context, {kReadVersion, kVendorRead},
                                version.data(),
                                UsbBytes<uint8_t, kVersionSize>::size()) &&
                   authorized(io);
        }

        using FirmwareName = UsbBytes<char, kFirmwareNameLength>;

        void appendHex32(FirmwareName &name, size_t &cursor, uint32_t value)
        {
            for (size_t index = 0; index < kHexDigits; ++index)
            {
                const auto shift = static_cast<unsigned>(
                    (kHexDigits - 1U - index) * kBitsPerNibble);
                const auto nibble =
                    static_cast<uint8_t>((value >> shift) & kNibbleMask);
                constexpr uint8_t kDecimalDigits = 10U;
                name.at(cursor++) = static_cast<char>(
                    nibble < kDecimalDigits ? ('0' + nibble)
                                            : ('a' + nibble - kDecimalDigits));
            }
        }

        void patchName(FirmwareName &name, const FirmwareVersion &version)
        {
            constexpr char kPrefix[] = "ar3k/AthrBT_0x";
            constexpr char kSuffix[] = ".dfu";
            size_t cursor = 0U;
            for (const char item : kPrefix)
            {
                if (item != '\0')
                {
                    name.at(cursor++) = item;
                }
            }
            appendHex32(name, cursor, version.rom);
            for (const char item : kSuffix)
            {
                name.at(cursor++) = item;
            }
        }

        bool configurationName(FirmwareName &name,
                               const FirmwareVersion &version)
        {
            constexpr char kPrefix[] = "ar3k/ramps_0x";
            constexpr char kSuffix[] = ".dfu";
            size_t cursor = 0U;
            for (const char item : kPrefix)
            {
                if (item != '\0')
                {
                    name.at(cursor++) = item;
                }
            }
            appendHex32(name, cursor, version.rom);
            name.at(cursor++) = '_';
            switch (version.clock)
            {
                case 0U:
                    name.at(cursor++) = '2';
                    name.at(cursor++) = '6';
                    break;
                case 1U:
                    name.at(cursor++) = '4';
                    name.at(cursor++) = '0';
                    break;
                case 2U:
                    name.at(cursor++) = '1';
                    name.at(cursor++) = '9';
                    break;
                default:
                    return false;
            }
            for (const char item : kSuffix)
            {
                name.at(cursor++) = item;
            }
            return true;
        }

        bool upload(const Ath3kIo &io, const Ath3kFirmwareImage &image,
                    Ath3kBootProgress &progress)
        {
            if (image.data == nullptr || image.size < kImageHeaderSize ||
                image.size > kMaxFirmwareBytes)
            {
                progress.result = Ath3kBootResult::InvalidFirmware;
                return false;
            }
            if (!authorized(io))
            {
                progress.result = Ath3kBootResult::IdentityLost;
                return false;
            }
            // A USB control failure is ambiguous: the device could have
            // accepted the DFU header before the host observed the failure.
            progress.requiresUsbReset = true;
            if (!io.controlOut(io.context, {kDownload, kVendorWrite},
                               image.data, kImageHeaderSize))
            {
                progress.result = Ath3kBootResult::UsbTransferFailed;
                return false;
            }
            progress.firmwareBytesTransferred += kImageHeaderSize;
            size_t cursor = kImageHeaderSize;
            while (cursor < image.size)
            {
                if (!authorized(io))
                {
                    progress.result = Ath3kBootResult::IdentityLost;
                    return false;
                }
                io.delayMicros(io.context, kInterChunkDelayMicros);
                const size_t remaining = image.size - cursor;
                const size_t chunk =
                    remaining < kBulkChunkBytes ? remaining : kBulkChunkBytes;
                size_t transferred = 0;
                if (!io.bulkOut(io.context, kBulkFirmwareEndpoint,
                                usbByteOffset(image.data, cursor), chunk,
                                &transferred) ||
                    transferred != chunk)
                {
                    progress.result = Ath3kBootResult::UsbTransferFailed;
                    return false;
                }
                cursor += chunk;
                progress.firmwareBytesTransferred += chunk;
            }
            return authorized(io);
        }

        bool loadImage(const Ath3kIo &io, const char *name, bool isPatch,
                       uint32_t rom, uint32_t build,
                       Ath3kBootProgress &progress)
        {
            Ath3kFirmwareImage image {nullptr, 0};
            if (!authorized(io))
            {
                progress.result = Ath3kBootResult::IdentityLost;
                return false;
            }
            if (!io.loadFirmware(io.context, name, &image))
            {
                progress.result = Ath3kBootResult::FirmwareUnavailable;
                return false;
            }
            if (image.data == nullptr ||
                image.size <
                    kImageHeaderSize + (isPatch ? kPatchTrailerSize : 0U) ||
                image.size > kMaxFirmwareBytes)
            {
                progress.result = Ath3kBootResult::InvalidFirmware;
                return false;
            }
            if (isPatch &&
                (loadLittle32(usbByteOffset(
                     image.data, image.size - kPatchTrailerSize)) != rom ||
                 loadLittle32(usbByteOffset(image.data,
                                            image.size - kWordBytes)) <= build))
            {
                progress.result = Ath3kBootResult::VersionMismatch;
                return false;
            }
            if (!upload(io, image, progress))
            {
                if (progress.result == Ath3kBootResult::AlreadyOperational)
                {
                    progress.result = Ath3kBootResult::IdentityLost;
                }
                return false;
            }
            return true;
        }
    } // namespace

    bool isSupportedAth3kUsbIdentity(const Ath3kUsbIdentity &identity)
    {
        if (identity.interfaceNumber != 0U)
        {
            return false;
        }
        bool known = false;
        for (const UsbId &entry : kAr3012BootIds)
        {
            known = known || (entry.vendor == identity.vendorId &&
                              entry.product == identity.productId);
        }
        return known;
    }

    Ath3kBootProgress bootstrapAth3kUsb(const Ath3kUsbIdentity &identity,
                                        const Ath3kIo &io)
    {
        Ath3kBootProgress progress {
            Ath3kBootResult::AlreadyOperational,
            Ath3kBootPhase::Probe,
            0,
            false,
        };
        if (!isSupportedAth3kUsbIdentity(identity))
        {
            progress.result = Ath3kBootResult::UnsupportedDevice;
            return progress;
        }
        if (io.context == nullptr || io.permit == nullptr ||
            io.controlIn == nullptr || io.controlOut == nullptr ||
            io.bulkOut == nullptr || io.loadFirmware == nullptr ||
            io.delayMicros == nullptr)
        {
            progress.result = Ath3kBootResult::InvalidBackend;
            return progress;
        }
        if (!authorized(io))
        {
            progress.result = Ath3kBootResult::IdentityLost;
            return progress;
        }
        // AR3012's bcdDevice>1 denotes an already-bootstrapped function,
        // per upstream ath3k. This is NOT evidence of native BLE readiness.
        if (identity.deviceRevision > 1U)
        {
            progress.phase = Ath3kBootPhase::Done;
            return progress;
        }
        progress.phase = Ath3kBootPhase::ReadState;
        uint8_t state = 0;
        if (!readState(io, state))
        {
            progress.result = Ath3kBootResult::UsbTransferFailed;
            return progress;
        }
        progress.phase = Ath3kBootPhase::ReadVersion;
        UsbBytes<uint8_t, kVersionSize> version {};
        if (!readVersion(io, version))
        {
            progress.result = Ath3kBootResult::UsbTransferFailed;
            return progress;
        }
        const FirmwareVersion boardVersion {
            loadLittle32(version.data()),
            loadLittle32(usbByteOffset(version.data(), kWordBytes)),
            version.at(kRefClockOffset),
        };
        const uint32_t rom = boardVersion.rom;
        const uint32_t build = boardVersion.build;
        if (rom == 0U || rom == UINT32_MAX)
        {
            progress.result = Ath3kBootResult::VersionMismatch;
            return progress;
        }
        FirmwareName name {};
        if ((state & kPatchLoaded) == 0U)
        {
            progress.phase = Ath3kBootPhase::LoadPatch;
            patchName(name, boardVersion);
            if (!loadImage(io, name.data(), true, rom, build, progress))
            {
                return progress;
            }
        }
        if ((state & kConfigurationLoaded) == 0U)
        {
            progress.phase = Ath3kBootPhase::LoadConfiguration;
            name.fill('\0');
            if (!configurationName(name, boardVersion))
            {
                progress.result = Ath3kBootResult::UnsupportedClock;
                return progress;
            }
            if (!loadImage(io, name.data(), false, rom, build, progress))
            {
                return progress;
            }
        }
        if ((state & kModeMask) != kNormalModeValue)
        {
            progress.phase = Ath3kBootPhase::EnterNormalMode;
            if (!authorized(io))
            {
                progress.result = Ath3kBootResult::IdentityLost;
                return progress;
            }
            progress.requiresUsbReset = true;
            if (!io.controlOut(io.context, {kNormalMode, kVendorWrite}, nullptr,
                               0U))
            {
                progress.result = Ath3kBootResult::UsbTransferFailed;
                return progress;
            }
        }
        progress.phase = Ath3kBootPhase::SwitchIdentity;
        if (!authorized(io))
        {
            progress.result = Ath3kBootResult::IdentityLost;
            return progress;
        }
        progress.requiresUsbReset = true;
        if (!io.controlOut(io.context, {kSwitchIdentity, kVendorWrite}, nullptr,
                           0U))
        {
            progress.result = Ath3kBootResult::UsbTransferFailed;
            return progress;
        }
        progress.result = Ath3kBootResult::AwaitReenumeration;
        progress.phase = Ath3kBootPhase::Done;
        return progress;
    }
} // namespace simpleath
