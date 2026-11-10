// SPDX-License-Identifier: AGPL-3.0-only
#include "UsbHci.hpp"
#include "UsbBytes.hpp"

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kEndpointDirectionIn = 0x80U;
        constexpr uint8_t kEndpointNumberMask = 0x0fU;
        constexpr uint8_t kEndpointReservedMask = 0x70U;
        constexpr unsigned kBitsPerByte = 8U;
        constexpr size_t kEventHeaderBytes = 2U;
        constexpr size_t kAclHeaderBytes = 4U;
        constexpr size_t kHciCommandHeaderBytes = 3U;

        bool validEndpoint(uint8_t address, bool input)
        {
            return (address & kEndpointNumberMask) != 0U &&
                   (address & kEndpointReservedMask) == 0U &&
                   ((address & kEndpointDirectionIn) != 0U) == input;
        }

        bool validCallbacks(const UsbHciHostCallbacks &host)
        {
            return host.context != nullptr && host.permit != nullptr &&
                   host.commandControlOut != nullptr &&
                   host.aclBulkOut != nullptr && host.deliver != nullptr;
        }

        UsbHciStatus authorize(const UsbHciState &state,
                               const UsbHciHostCallbacks &host)
        {
            if (!state.attached)
            {
                return UsbHciStatus::NotAttached;
            }
            if (state.faulted)
            {
                return UsbHciStatus::Faulted;
            }
            if (!validCallbacks(host) || host.ownerEpoch != state.epoch ||
                !host.permit(host.context, host.ownerEpoch))
            {
                return UsbHciStatus::OwnershipLost;
            }
            return UsbHciStatus::Ok;
        }

        UsbHciStatus deliverComplete(UsbHciState &state, UsbHciStream &stream,
                                     const UsbHciHostCallbacks &host,
                                     UsbHciPacketKind kind)
        {
            if (!host.deliver(host.context, kind, stream.packet.data(),
                              stream.used))
            {
                state.faulted = true;
                return UsbHciStatus::CallbackFailed;
            }
            stream.used = 0U;
            stream.expected = 0U;
            if (authorize(state, host) != UsbHciStatus::Ok)
            {
                state.faulted = true;
                return UsbHciStatus::OwnershipLost;
            }
            return UsbHciStatus::Ok;
        }

        size_t expectedFrameBytes(const UsbHciStream &stream,
                                  UsbHciPacketKind kind)
        {
            if (kind == UsbHciPacketKind::Event)
            {
                return kEventHeaderBytes + stream.packet.at(1U);
            }
            return kAclHeaderBytes +
                   (static_cast<size_t>(stream.packet.at(2U)) |
                    (static_cast<size_t>(stream.packet.at(3U))
                     << kBitsPerByte));
        }

        UsbHciStatus ingest(UsbHciState &state, UsbHciStream &stream,
                            const UsbHciHostCallbacks &host,
                            UsbHciPacketKind kind, const uint8_t *data,
                            size_t bytes)
        {
            const UsbHciStatus permission = authorize(state, host);
            if (permission != UsbHciStatus::Ok)
            {
                return permission;
            }
            if (data == nullptr || bytes == 0U)
            {
                return UsbHciStatus::InvalidArgument;
            }
            const size_t headerBytes = kind == UsbHciPacketKind::Event
                                           ? kEventHeaderBytes
                                           : kAclHeaderBytes;
            const size_t maxBytes = kind == UsbHciPacketKind::Event
                                        ? kUsbHciMaxEventBytes
                                        : kUsbHciMaxAclBytes;
            for (size_t index = 0; index < bytes; ++index)
            {
                if (authorize(state, host) != UsbHciStatus::Ok)
                {
                    state.faulted = true;
                    return UsbHciStatus::OwnershipLost;
                }
                if (stream.used >= maxBytes)
                {
                    state.faulted = true;
                    return UsbHciStatus::FrameTooLarge;
                }
                stream.packet.at(stream.used) = *usbByteOffset(data, index);
                ++stream.used;
                if (stream.expected == 0U && stream.used == headerBytes)
                {
                    stream.expected = expectedFrameBytes(stream, kind);
                    if (stream.expected > maxBytes)
                    {
                        state.faulted = true;
                        return UsbHciStatus::FrameTooLarge;
                    }
                }
                if (stream.expected != 0U && stream.used == stream.expected)
                {
                    const UsbHciStatus delivered =
                        deliverComplete(state, stream, host, kind);
                    if (delivered != UsbHciStatus::Ok)
                    {
                        return delivered;
                    }
                }
            }
            return UsbHciStatus::Ok;
        }
    } // namespace

    UsbHciStatus attachUsbHci(UsbHciState &state,
                              const UsbHciEndpoints &endpoints,
                              const UsbHciHostCallbacks &host)
    {
        if (!validCallbacks(host))
        {
            return UsbHciStatus::InvalidArgument;
        }
        if (!validEndpoint(endpoints.eventInterruptIn, true) ||
            !validEndpoint(endpoints.aclBulkIn, true) ||
            !validEndpoint(endpoints.aclBulkOut, false))
        {
            return UsbHciStatus::InvalidEndpoint;
        }
        if (state.attached)
        {
            return UsbHciStatus::Faulted;
        }
        if (!host.permit(host.context, host.ownerEpoch))
        {
            return UsbHciStatus::OwnershipLost;
        }
        state = {};
        state.epoch = host.ownerEpoch;
        state.endpoints = endpoints;
        state.attached = true;
        return UsbHciStatus::Ok;
    }

    void detachUsbHci(UsbHciState &state)
    {
        state = {};
    }

    UsbHciStatus sendUsbHciCommand(UsbHciState &state,
                                   const UsbHciHostCallbacks &host,
                                   const uint8_t *command, size_t bytes)
    {
        const UsbHciStatus permission = authorize(state, host);
        if (permission != UsbHciStatus::Ok)
        {
            return permission;
        }
        if (command == nullptr || bytes < kHciCommandHeaderBytes ||
            bytes > kUsbHciMaxCommandBytes ||
            bytes != static_cast<size_t>(*usbByteOffset(command, 2U)) +
                         kHciCommandHeaderBytes)
        {
            return UsbHciStatus::MalformedPacket;
        }
        if (!host.commandControlOut(host.context, command, bytes))
        {
            state.faulted = true;
            return UsbHciStatus::TransferFailed;
        }
        if (authorize(state, host) != UsbHciStatus::Ok)
        {
            state.faulted = true;
            return UsbHciStatus::OwnershipLost;
        }
        return UsbHciStatus::Ok;
    }

    UsbHciStatus sendUsbHciAcl(UsbHciState &state,
                               const UsbHciHostCallbacks &host,
                               const uint8_t *packet, size_t bytes)
    {
        const UsbHciStatus permission = authorize(state, host);
        if (permission != UsbHciStatus::Ok)
        {
            return permission;
        }
        if (packet == nullptr || bytes < kAclHeaderBytes ||
            bytes > kUsbHciMaxAclBytes ||
            bytes != kAclHeaderBytes +
                         (static_cast<size_t>(*usbByteOffset(packet, 2U)) |
                          (static_cast<size_t>(*usbByteOffset(packet, 3U))
                           << kBitsPerByte)))
        {
            return UsbHciStatus::MalformedPacket;
        }
        size_t transferred = 0U;
        if (!host.aclBulkOut(host.context, state.endpoints.aclBulkOut, packet,
                             bytes, &transferred) ||
            transferred != bytes)
        {
            state.faulted = true;
            return UsbHciStatus::TransferFailed;
        }
        if (authorize(state, host) != UsbHciStatus::Ok)
        {
            state.faulted = true;
            return UsbHciStatus::OwnershipLost;
        }
        return UsbHciStatus::Ok;
    }

    UsbHciStatus receiveUsbHciEvent(UsbHciState &state,
                                    const UsbHciHostCallbacks &host,
                                    const uint8_t *transfer, size_t bytes)
    {
        return ingest(state, state.events, host, UsbHciPacketKind::Event,
                      transfer, bytes);
    }

    UsbHciStatus receiveUsbHciAcl(UsbHciState &state,
                                  const UsbHciHostCallbacks &host,
                                  const uint8_t *transfer, size_t bytes)
    {
        return ingest(state, state.acl, host, UsbHciPacketKind::Acl, transfer,
                      bytes);
    }
} // namespace simpleath
