//
//  WirelessABI.hpp
//  SimpleATH
//
//  Created by laobamac on 2026/9/7.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEATH_WIRELESS_ABI_HPP
#define SIMPLEATH_WIRELESS_ABI_HPP

#include <stddef.h>
#include <stdint.h>

namespace ath
{

    constexpr uint32_t getCommand = 0xC02869C9;
    constexpr uint32_t setCommand = 0x802869C8;
    constexpr size_t commandCapacity = 0x3C00;
    constexpr size_t largeCommandCapacity = 0x3C000;
    constexpr size_t eventCapacity = 0x4000;
    constexpr size_t maximumEventPayload = 0x1000;
    constexpr uint32_t eventNotification = 0xE00002D5;
    constexpr uint32_t scanResultRequest = 11;
    constexpr uint32_t scanMultipleRequest = 86;
    constexpr size_t legacyScanMultipleSize = 0x14E0;
    constexpr size_t nativeScanMultipleSize = 0x14E8;
    constexpr uint32_t cardCapabilitiesRequest = 12;
    constexpr uint32_t scanDoneEvent = 10;
    constexpr uint32_t driverAvailableEvent = 0x37;
    constexpr size_t legacyDriverAvailableSize = 0xB8;
    constexpr size_t nativeDriverAvailableSize = 0xF8;
    constexpr size_t powerDataSize = 0x18;
    constexpr uint32_t powerStateAvailabilityReason = 0xE0821803;
    constexpr uint32_t associationDoneEvent = 9;
    constexpr size_t legacyCapabilitySize = 12;
    constexpr size_t scanCompletionCapabilityByte = 5;
    constexpr uint8_t scanCompletionCapabilityMask = 0x40;
    constexpr uint32_t associateRequest = 20;
    constexpr size_t legacyAssociateSize = 0x224;
    constexpr uint32_t roamProfileRequest = 216;
    constexpr size_t nativeRoamProfileSize = 0x180;
    constexpr size_t nativeRoamBandSize = 0x80;
    constexpr size_t legacyRoamBandSize = 0x7C;
    constexpr size_t legacyScanResultSize = 0x48C;
    constexpr size_t scanIELengthOffset = 0x8A;
    constexpr size_t scanIEOffset = 0x8C;
    constexpr size_t legacyScanIECapacity = 0x400;
    constexpr size_t interfaceNameBytes = 16U;
    constexpr size_t eventFilterBitmapBytes = 31U;
    constexpr unsigned bitsPerByte = 8U;
    constexpr unsigned bitsPerHalfWord = 16U;
    constexpr unsigned bitsPerThreeBytes = 24U;

    // Fixed on-wire field positions from the Sonoma/Sequoia/Tahoe layouts.
    // Named offsets keep validation tied to the exact ABI-sized fields.
    constexpr size_t scanMultipleCountOffset = 8U;
    constexpr size_t scanMultipleExtraCountOffset = 0x19CU;
    constexpr size_t scanMultipleLimitOffset = 0x210U;
    constexpr size_t scanMultipleEntryStart = 0x10U;
    constexpr size_t scanMultipleEntryBytes = 0x28U;
    constexpr uint32_t maximumScanMultipleEntries = 10U;
    constexpr uint32_t maximumScanMultipleExtras = 16U;
    constexpr uint32_t maximumScanMultipleLimit = 400U;
    constexpr uint32_t maximumSsidBytes = 32U;
    constexpr size_t powerAvailabilityMinimum = 0x14U;
    constexpr size_t powerRadioCountOffset = 4U;
    constexpr size_t powerRadioStatusOffset = 8U;
    constexpr size_t powerRadioWordBytes = 4U;
    constexpr size_t powerAvailableOutputOffset = 8U;
    constexpr size_t powerReasonOutputOffset = 0x10U;
    constexpr size_t sequoiaJoinMinimum = 0x10U;
    constexpr size_t sequoiaJoinStatus1 = 0x08U;
    constexpr size_t sequoiaJoinStatus2 = 0x0CU;
    constexpr size_t tahoeJoinStatus1 = 0x1B8U;
    constexpr size_t tahoeJoinStatus2 = 0x1BCU;
    constexpr size_t tahoeJoinResultOffset = 0x1C4U;
    constexpr size_t tahoeJoinAvailableOffset = 0x1C8U;
    constexpr size_t tahoeJoinBssidOffset = 0x1CCU;
    constexpr size_t kMacAddressBytes = 6U;
    constexpr size_t associateExtensionBytes = 0x2CU;
    constexpr size_t legacyAssociateFlagOffset = 0x202U;
    constexpr size_t extendedAssociateFlagOffset = 0x206U;
    constexpr size_t associateLowerOffset = 8U;
    constexpr size_t associateUpperOffset = 12U;
    constexpr size_t associateLowerByte0 = 6U;
    constexpr size_t associateLowerByte1 = 7U;
    constexpr size_t associateUpperByte0 = 8U;
    constexpr size_t associateUpperByte1 = 9U;
    constexpr size_t associateReserved0 = 10U;
    constexpr size_t associateReserved1 = 11U;
    constexpr size_t associateCopyBegin = 0xCU;
    constexpr size_t associateCopyEnd = 0x215U;
    constexpr size_t associateTailBegin = 0x218U;
    constexpr size_t roamHeaderBytes = 12U;
    constexpr size_t minimumEventRingBytes = 4096U;
    constexpr size_t maximumEventRingBytes = 0x80000U;
    constexpr uint32_t eventWrappedStatus = 0x50U;
    constexpr uint32_t eventWritingStatus = 0x52U;
    constexpr uint32_t eventPublishedStatus = 0x57U;

    enum class AirPortBackend : uint8_t
    {
        Original,
        Tahoe,
    };
    enum class AssociateLayout : uint8_t
    {
        Legacy,
        Extended,
    };
    enum class JoinEventPolicy : uint8_t
    {
        Passthrough,
        Sequoia,
        Tahoe,
    };

    struct UserABI
    {
            uint32_t kernel;
            const char *name;
            size_t scanResultSize;
            size_t capabilitySize;
            size_t associateSize;
            size_t joinStatusSize;
            uint32_t filterMonitorEvents;
            size_t scanMultipleSize;
            size_t roamProfileSize;
            size_t driverAvailableSize;
            uint32_t selectorCount;
            AirPortBackend backend;
            AssociateLayout associateLayout;
            JoinEventPolicy joinEventPolicy;
    };

    constexpr UserABI sonomaABI {
        23,
        "Sonoma",
        0x4CC,
        16,
        0x358,
        0,
        0,
        legacyScanMultipleSize,
        legacyRoamBandSize,
        legacyDriverAvailableSize,
        7,
        AirPortBackend::Original,
        AssociateLayout::Legacy,
        JoinEventPolicy::Passthrough,
    };
    constexpr UserABI sequoiaABI {
        24,
        "Sequoia",
        0x8D8,
        19,
        0x384,
        0x1CC,
        0,
        nativeScanMultipleSize,
        nativeRoamProfileSize,
        nativeDriverAvailableSize,
        9,
        AirPortBackend::Original,
        AssociateLayout::Extended,
        JoinEventPolicy::Sequoia,
    };
    constexpr UserABI tahoeABI {
        25,
        "Tahoe",
        0x8E0,
        21,
        0x38C,
        0x1D4,
        0x234,
        nativeScanMultipleSize,
        nativeRoamProfileSize,
        nativeDriverAvailableSize,
        9,
        AirPortBackend::Tahoe,
        AssociateLayout::Extended,
        JoinEventPolicy::Tahoe,
    };

    inline const UserABI *userABIForKernel(uint32_t kernel)
    {
        if (kernel == sonomaABI.kernel)
        {
            return &sonomaABI;
        }
        if (kernel == sequoiaABI.kernel)
        {
            return &sequoiaABI;
        }
        if (kernel == tahoeABI.kernel)
        {
            return &tahoeABI;
        }
        return nullptr;
    }

    inline size_t eventPayloadSize(uint32_t event, size_t length,
                                   const UserABI &abi)
    {
        return event == driverAvailableEvent &&
                       length == legacyDriverAvailableSize
                   ? abi.driverAvailableSize
                   : length;
    }

    inline bool copyEventPayload(uint32_t event, const void *source,
                                 size_t length, uint8_t *destination,
                                 size_t capacity, const UserABI &abi)
    {
        const auto outputLength = eventPayloadSize(event, length, abi);
        if (length > maximumEventPayload || outputLength < length ||
            outputLength > capacity ||
            (outputLength != 0 && (destination == nullptr)) ||
            (length != 0 && (source == nullptr)))
        {
            return false;
        }
        const auto *const bytes = static_cast<const uint8_t *>(source);
        for (size_t offset = 0; offset < length; ++offset)
        {
            destination[offset] = bytes[offset];
        }
        for (size_t offset = length; offset < outputLength; ++offset)
        {
            destination[offset] = 0;
        }
        return true;
    }

    enum class Selector : uint32_t
    {
        Command,
        UseIOUC,
        Subscribe,
        MonitorStart,
        MonitorStop,
        UseEventPipe,
        LargeCommand,
        DriverKitSupported,
        MapUserBuffer,
        Count,
    };

    struct Request
    {
            char interfaceName[interfaceNameBytes];
            int32_t type;
            int32_t value;
            uint32_t length;
            uint32_t reserved;
            uint64_t data;
    };

    struct LegacyRequest
    {
            Request request;
            uint32_t pointerSize;
            uint32_t reserved;
    };

    struct CommandHeader
    {
            uint32_t command;
            uint32_t length;
    };

    struct LocaleData
    {
            uint32_t version;
            uint32_t locale;
    };

    struct CountryCodeData
    {
            uint32_t version;
            char country[4];
    };

    constexpr uint32_t localeUnknown = 0;
    constexpr uint32_t localeETSI = 2;

    inline void resolveLocale(LocaleData &data, const CountryCodeData &country)
    {
        if (data.version == 1 && data.locale == localeUnknown &&
            country.version == 1 && country.country[0] == 'I' &&
            country.country[1] == 'L' && country.country[2] == '\0')
        {
            data.locale = localeETSI;
        }
    }

    inline const char *localeString(uint32_t locale)
    {
        static const char *const names[] = {
            "Unknown", "FCC",  "ETSI", "Japan",
            "Korea",   "APAC", "RoW",  "Indonesia",
        };
        size_t index = 0;
        for (const char *candidate : names)
        {
            if (index == locale)
            {
                return candidate;
            }
            ++index;
        }
        return names[0];
    }

    static_assert(sizeof(LocaleData) == 8 && offsetof(LocaleData, locale) == 4,
                  "Locale ABI");
    static_assert(sizeof(CountryCodeData) == 8 &&
                      offsetof(CountryCodeData, country) == 4,
                  "Country code ABI");

    inline bool encodeScalarResult(Request &request, uint8_t *buffer,
                                   size_t capacity)
    {
        if ((buffer == nullptr) || capacity < sizeof(request.value) ||
            request.length < sizeof(request.value))
        {
            return false;
        }
        // The target is Intel little-endian, and the scalar is exactly the
        // four-byte ABI field. Copy its representation without aliasing.
        __builtin_memcpy(buffer, &request.value, sizeof(request.value));
        request.length = sizeof(request.value);
        return true;
    }

    inline bool prepareScanResult(Request &request, uint8_t *buffer,
                                  size_t capacity, const UserABI &abi)
    {
        if ((buffer == nullptr) || abi.scanResultSize < legacyScanResultSize ||
            capacity < abi.scanResultSize ||
            request.length != abi.scanResultSize)
        {
            return false;
        }
        auto length = static_cast<uint16_t>(
            static_cast<uint32_t>(buffer[scanIELengthOffset]) |
            (static_cast<uint32_t>(buffer[scanIELengthOffset + 1])
             << bitsPerByte));
        if (length > legacyScanIECapacity)
        {
            length = legacyScanIECapacity;
        }
        buffer[scanIELengthOffset] = static_cast<uint8_t>(length);
        buffer[scanIELengthOffset + 1] =
            static_cast<uint8_t>(length >> bitsPerByte);
        request.length = legacyScanResultSize;
        return true;
    }

    inline bool expandScanResult(Request &request, uint8_t *buffer,
                                 size_t capacity, const UserABI &abi)
    {
        if ((buffer == nullptr) || abi.scanResultSize < legacyScanResultSize ||
            capacity < abi.scanResultSize ||
            request.length != legacyScanResultSize)
        {
            return false;
        }
        for (size_t offset = legacyScanResultSize; offset < abi.scanResultSize;
             ++offset)
        {
            buffer[offset] = 0;
        }
        request.length = static_cast<uint32_t>(abi.scanResultSize);
        return true;
    }

    inline bool expandCapabilities(Request &request, uint8_t *buffer,
                                   size_t capacity, const UserABI &abi,
                                   bool scanEvents)
    {
        if ((buffer == nullptr) || abi.capabilitySize < legacyCapabilitySize ||
            capacity < abi.capabilitySize ||
            request.length != legacyCapabilitySize)
        {
            return false;
        }
        for (size_t offset = legacyCapabilitySize; offset < abi.capabilitySize;
             ++offset)
        {
            buffer[offset] = 0;
        }
        if (scanEvents)
        {
            buffer[scanCompletionCapabilityByte] |=
                scanCompletionCapabilityMask;
        }
        request.length = static_cast<uint32_t>(abi.capabilitySize);
        return true;
    }

    inline uint32_t readUInt32(const uint8_t *buffer)
    {
        uint8_t octets[sizeof(uint32_t)] {};
        __builtin_memcpy(&octets[0], buffer, sizeof(octets));
        return static_cast<uint32_t>(octets[0]) |
               (static_cast<uint32_t>(octets[1]) << bitsPerByte) |
               (static_cast<uint32_t>(octets[2]) << bitsPerHalfWord) |
               (static_cast<uint32_t>(octets[3]) << bitsPerThreeBytes);
    }

    inline void writeUInt32(uint8_t *buffer, uint32_t value)
    {
        const uint8_t octets[sizeof(value)] {
            static_cast<uint8_t>(value),
            static_cast<uint8_t>(value >> bitsPerByte),
            static_cast<uint8_t>(value >> bitsPerHalfWord),
            static_cast<uint8_t>(value >> bitsPerThreeBytes),
        };
        __builtin_memcpy(buffer, &octets[0], sizeof(octets));
    }

    inline bool prepareScanMultiple(Request &request, uint8_t *buffer,
                                    size_t capacity, const UserABI &abi)
    {
        if ((buffer == nullptr) ||
            abi.scanMultipleSize < legacyScanMultipleSize ||
            capacity < abi.scanMultipleSize ||
            request.length != abi.scanMultipleSize || readUInt32(buffer) != 1 ||
            readUInt32(buffer + scanMultipleCountOffset) >
                maximumScanMultipleEntries ||
            readUInt32(buffer + scanMultipleExtraCountOffset) >
                maximumScanMultipleExtras ||
            readUInt32(buffer + scanMultipleLimitOffset) >
                maximumScanMultipleLimit)
        {
            return false;
        }
        for (size_t index = 0;
             index < readUInt32(buffer + scanMultipleCountOffset); ++index)
        {
            if (readUInt32(buffer + scanMultipleEntryStart +
                           (index * scanMultipleEntryBytes)) > maximumSsidBytes)
            {
                return false;
            }
        }
        for (size_t offset = legacyScanMultipleSize;
             offset < abi.scanMultipleSize; ++offset)
        {
            buffer[offset] = 0;
        }
        request.length = legacyScanMultipleSize;
        return true;
    }

    inline bool encodePowerAvailability(const uint8_t *power, size_t length,
                                        uint8_t *output, size_t capacity,
                                        const UserABI &abi)
    {
        // The fixed status and reason words occupy bytes through 0x13.
        if ((power == nullptr) || (output == nullptr) ||
            length != powerDataSize ||
            abi.driverAvailableSize < powerAvailabilityMinimum ||
            capacity < abi.driverAvailableSize || readUInt32(power) != 1)
        {
            return false;
        }
        const auto radios = readUInt32(power + powerRadioCountOffset);
        if ((radios == 0U) || radios > 4)
        {
            return false;
        }
        uint32_t available = 0;
        for (size_t index = 0; index < radios; ++index)
        {
            const auto value = readUInt32(power + powerRadioStatusOffset +
                                          (index * powerRadioWordBytes));
            if (value > 1)
            {
                return false;
            }
            available |= value;
        }
        for (size_t index = 0; index < abi.driverAvailableSize; ++index)
        {
            output[index] = 0;
        }
        writeUInt32(output + powerAvailableOutputOffset, available);
        writeUInt32(output + powerReasonOutputOffset,
                    powerStateAvailabilityReason);
        return true;
    }

    inline bool encodeJoinStatus(uint32_t status, uint32_t result,
                                 const uint8_t *bssid, size_t bssidLength,
                                 uint8_t *output, size_t capacity,
                                 const UserABI &abi)
    {
        const bool sequoia = abi.joinEventPolicy == JoinEventPolicy::Sequoia;
        const bool tahoe = abi.joinEventPolicy == JoinEventPolicy::Tahoe;
        // The 32-bit status fields and optional BSSID have policy-specific
        // fixed offsets; reject a shortened profile before any output write.
        const size_t minimum =
            sequoia ? sequoiaJoinMinimum : tahoeJoinBssidOffset + bssidLength;
        if ((!sequoia && !tahoe) || (output == nullptr) ||
            ((bssidLength != 0U) &&
             ((bssid == nullptr) || bssidLength != kMacAddressBytes)) ||
            abi.joinStatusSize < minimum || capacity < abi.joinStatusSize)
        {
            return false;
        }
        for (size_t index = 0; index < abi.joinStatusSize; ++index)
        {
            output[index] = 0;
        }
        writeUInt32(output + (sequoia ? sequoiaJoinStatus1 : tahoeJoinStatus1),
                    status);
        writeUInt32(output + (sequoia ? sequoiaJoinStatus2 : tahoeJoinStatus2),
                    status);
        if (!sequoia)
        {
            writeUInt32(output + tahoeJoinResultOffset, result);
            writeUInt32(output + tahoeJoinAvailableOffset, 1);
        }
        for (size_t index = 0; index < bssidLength; ++index)
        {
            output[(sequoia ? 0 : tahoeJoinBssidOffset) + index] = bssid[index];
        }
        return true;
    }

    inline bool prepareAssociate(Request &request, uint8_t *buffer,
                                 size_t capacity, const UserABI &abi)
    {
        // Extended layout shifts the bytes at 0x218..0x223 from
        // 0x244..0x24F; both source and destination must be present.
        const size_t minimum =
            abi.associateLayout == AssociateLayout::Legacy
                ? legacyAssociateSize
                : legacyAssociateSize + associateExtensionBytes;
        if ((abi.associateLayout != AssociateLayout::Legacy &&
             abi.associateLayout != AssociateLayout::Extended) ||
            (buffer == nullptr) || abi.associateSize < minimum ||
            capacity < abi.associateSize || request.length != abi.associateSize)
        {
            return false;
        }
        if (abi.associateLayout == AssociateLayout::Legacy)
        {
            if (buffer[legacyAssociateFlagOffset] > 3)
            {
                return false;
            }
            request.length = legacyAssociateSize;
            return true;
        }
        const auto lower = readUInt32(buffer + associateLowerOffset);
        const auto upper = readUInt32(buffer + associateUpperOffset);
        if (lower > UINT16_MAX || upper > UINT16_MAX ||
            buffer[extendedAssociateFlagOffset] > 3)
        {
            return false;
        }
        for (size_t offset = associateCopyBegin; offset < associateCopyEnd;
             ++offset)
        {
            buffer[offset] = buffer[offset + 4];
        }
        buffer[associateLowerByte0] = static_cast<uint8_t>(lower);
        buffer[associateLowerByte1] =
            static_cast<uint8_t>(lower >> bitsPerByte);
        buffer[associateUpperByte0] = static_cast<uint8_t>(upper);
        buffer[associateUpperByte1] =
            static_cast<uint8_t>(upper >> bitsPerByte);
        buffer[associateReserved0] = buffer[associateReserved1] = 0;
        for (size_t offset = associateCopyEnd; offset < associateTailBegin;
             ++offset)
        {
            buffer[offset] = 0;
        }
        for (size_t offset = associateTailBegin; offset < legacyAssociateSize;
             ++offset)
        {
            buffer[offset] = buffer[offset + associateExtensionBytes];
        }
        for (size_t offset = legacyAssociateSize; offset < abi.associateSize;
             ++offset)
        {
            buffer[offset] = 0;
        }
        request.length = legacyAssociateSize;
        return true;
    }

    inline bool prepareRoamBand(Request &request, uint8_t *buffer,
                                size_t capacity, const uint8_t *band,
                                size_t bandCapacity)
    {
        if ((buffer == nullptr) || (band == nullptr) ||
            capacity < legacyRoamBandSize ||
            bandCapacity < nativeRoamBandSize ||
            readUInt32(band + roamHeaderBytes) != 1)
        {
            return false;
        }
        for (size_t offset = 0; offset < 4; ++offset)
        {
            buffer[offset] = band[offset + roamHeaderBytes];
        }
        for (size_t offset = 4; offset < roamHeaderBytes; ++offset)
        {
            buffer[offset] = band[offset];
        }
        for (size_t offset = roamHeaderBytes; offset < legacyRoamBandSize;
             ++offset)
        {
            buffer[offset] = band[offset + 4];
        }
        request.length = legacyRoamBandSize;
        return true;
    }

    inline bool expandRoamBand(const Request &request, const uint8_t *buffer,
                               size_t capacity, uint8_t *band,
                               size_t bandCapacity)
    {
        if ((buffer == nullptr) || (band == nullptr) ||
            capacity < legacyRoamBandSize ||
            bandCapacity < nativeRoamBandSize ||
            request.length != legacyRoamBandSize)
        {
            return false;
        }
        for (size_t offset = legacyRoamBandSize; offset > roamHeaderBytes;
             --offset)
        {
            band[offset + 3] = buffer[offset - 1];
        }
        for (size_t offset = 4; offset < roamHeaderBytes; ++offset)
        {
            band[offset] = buffer[offset];
        }
        for (size_t offset = 0; offset < 4; ++offset)
        {
            band[offset + roamHeaderBytes] = buffer[offset];
        }
        for (size_t offset = 0; offset < 4; ++offset)
        {
            band[offset] = 0;
        }
        return true;
    }

    struct EventFilter
    {
            uint8_t all;
            uint8_t bitmap[eventFilterBitmapBytes];

            bool accepts(uint32_t event) const
            {
                if (all != 0U)
                {
                    return true;
                }
                if (event == 0U || event > sizeof(bitmap) * bitsPerByte)
                {
                    return false;
                }
                const size_t byteIndex = (event - 1U) / bitsPerByte;
                const uint8_t flag =
                    static_cast<uint8_t>(1U << ((event - 1U) % bitsPerByte));
                size_t index = 0;
                for (const uint8_t octet : bitmap)
                {
                    if (index == byteIndex)
                    {
                        return (octet & flag) != 0U;
                    }
                    ++index;
                }
                return false;
            }
    };

    struct EventState
    {
            uint32_t read;
            uint32_t write;
            uint32_t reserved;
    };

    struct __attribute__((packed, aligned(4))) EventHeader
    {
            uint32_t status;
            uint16_t flags;
            uint16_t sequence;
            uint64_t seconds;
            uint64_t microseconds;
            uint16_t length;
            uint16_t padding;
            uint32_t event;
            char interfaceName[interfaceNameBytes];
    };

    enum class RingResult : uint8_t
    {
        Written,
        Full,
        Invalid,
    };

    class EventRing
    {
        public:
            static RingResult append(uint8_t *ring, size_t capacity,
                                     EventState *state, uint32_t &write,
                                     uint16_t &sequence, const char *name,
                                     uint32_t event, const void *payload,
                                     size_t length, uint64_t seconds,
                                     uint64_t microseconds)
            {
                if ((ring == nullptr) || (state == nullptr) ||
                    (name == nullptr) || capacity < minimumEventRingBytes ||
                    capacity > maximumEventRingBytes ||
                    ((capacity & 3U) != 0U) || length > maximumEventPayload ||
                    ((length != 0U) && (payload == nullptr)))
                {
                    return RingResult::Invalid;
                }
                // The status word is atomically published at a 4-byte aligned
                // address. Never clobber retained ring/owner metadata or
                // borrowed inputs while serializing a new event record.
                const auto ringStart = reinterpret_cast<uintptr_t>(ring);
                const auto overlapsRing = [ringStart,
                                           capacity](const void *pointer,
                                                     size_t bytes) -> bool
                {
                    if (!pointer || !bytes)
                    {
                        return false;
                    }
                    const auto source = reinterpret_cast<uintptr_t>(pointer);
                    return ringStart <= source ? source - ringStart < capacity
                                               : ringStart - source < bytes;
                };
                if (((ringStart & (alignof(uint32_t) - 1U)) != 0U) ||
                    overlapsRing(state, sizeof(*state)) ||
                    overlapsRing(&write, sizeof(write)) ||
                    overlapsRing(&sequence, sizeof(sequence)) ||
                    overlapsRing(name, sizeof(EventHeader::interfaceName)) ||
                    overlapsRing(payload, length))
                {
                    return RingResult::Invalid;
                }
                const uint32_t read =
                    __atomic_load_n(&state->read, __ATOMIC_ACQUIRE);
                if (read >= capacity || write >= capacity ||
                    (((read | write) & 3U) != 0U))
                {
                    return RingResult::Invalid;
                }
                const size_t record = (sizeof(EventHeader) + length + 3) &
                                      ~static_cast<size_t>(3);
                const size_t tail = capacity - write;
                const size_t gap = tail < sizeof(EventHeader) ? tail : 0;
                const size_t available =
                    read > write ? read - write : capacity - write + read;
                if (record + gap + 4 > available)
                {
                    return RingResult::Full;
                }
                if (gap != 0U)
                {
                    for (size_t offset = write; offset < capacity; offset += 4)
                    {
                        __atomic_store_n(
                            reinterpret_cast<uint32_t *>(ring + offset),
                            eventWrappedStatus, __ATOMIC_RELEASE);
                    }
                    write = 0;
                }
                auto *header = reinterpret_cast<EventHeader *>(ring + write);
                __atomic_store_n(&header->status, eventWritingStatus,
                                 __ATOMIC_RELAXED);
                header->flags = 0;
                header->sequence = ++sequence;
                header->seconds = seconds;
                header->microseconds = microseconds;
                header->length = static_cast<uint16_t>(length);
                header->padding = static_cast<uint16_t>(
                    record - sizeof(EventHeader) - length);
                header->event = event;
                size_t index = 0;
                for (; index < sizeof(header->interfaceName) - 1 &&
                       (name[index] != 0);
                     ++index)
                {
                    header->interfaceName[index] = name[index];
                }
                for (; index < sizeof(header->interfaceName); ++index)
                {
                    header->interfaceName[index] = 0;
                }
                const auto *const bytes = static_cast<const uint8_t *>(payload);
                for (size_t offset = 0; offset < record - sizeof(EventHeader);
                     ++offset)
                {
                    ring[(write + sizeof(EventHeader) + offset) % capacity] =
                        offset < length ? bytes[offset] : 0;
                }
                __atomic_store_n(&header->status, eventPublishedStatus,
                                 __ATOMIC_RELEASE);
                write = static_cast<uint32_t>((write + record) % capacity);
                __atomic_store_n(&state->write, write, __ATOMIC_RELEASE);
                return RingResult::Written;
            }
    };

    static_assert(sizeof(Request) == 0x28, "Request ABI");
    static_assert(offsetof(Request, data) == 0x20, "Request pointer ABI");
    static_assert(sizeof(LegacyRequest) == 0x30, "Legacy request ABI");
    static_assert(sizeof(CommandHeader) + commandCapacity + sizeof(Request) ==
                      0x3C30,
                  "Command ABI");
    static_assert(sizeof(CommandHeader) + largeCommandCapacity +
                          sizeof(Request) ==
                      0x3C030,
                  "Large command ABI");
    static_assert(sizeof(EventFilter) == 0x20, "Event filter ABI");
    static_assert(sizeof(EventState) == 0xC, "Event state ABI");
    static_assert(sizeof(EventHeader) == 0x30, "Event header ABI");
    static_assert(offsetof(EventHeader, length) == 0x18, "Event length ABI");
    static_assert(offsetof(EventHeader, event) == 0x1C, "Event number ABI");

} // namespace ath

#endif
