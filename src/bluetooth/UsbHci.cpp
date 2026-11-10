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
        constexpr uint16_t kHciReadBufferSize = 0x1005U;
        constexpr uint16_t kHciReset = 0x0c03U;
        constexpr uint8_t kHciCommandComplete = 0x0eU;
        constexpr uint8_t kHciCommandStatus = 0x0fU;
        constexpr uint8_t kHciCompletedPackets = 0x13U;
        constexpr uint8_t kHciHardwareError = 0x10U;
        constexpr uint8_t kHciDataBufferOverflow = 0x1aU;
        constexpr size_t kControllerFaultBytes = 3U;
        constexpr size_t kReadBufferCompleteBytes = 13U;
        constexpr size_t kCommandStatusBytes = 6U;
        constexpr size_t kResetCompleteBytes = 6U;
        constexpr size_t kCommandCompletePrefixBytes = 5U;
        constexpr size_t kResponseStatusOffset = 5U;
        constexpr size_t kCompletedCountOffset = 2U;
        constexpr size_t kCompletionHeaderBytes = 3U;
        constexpr size_t kCompletedHandleBytes = 4U;
        constexpr uint16_t kHciHandleMask = 0x0fffU;
        constexpr uint16_t kHciMaximumHandle = 0x0effU;

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

        uint16_t little16(const uint8_t *bytes, size_t offset)
        {
            const uint32_t lo = *usbByteOffset(bytes, offset);
            const uint32_t hi = *usbByteOffset(bytes, offset + 1U);
            return static_cast<uint16_t>(lo | (hi << kBitsPerByte));
        }

        // A zero-outstanding slot can be safely reused for a new connection.
        // Never alias two live handles in the fixed controller ledger.
        UsbHciAclHandle *findHandle(UsbHciAclWindow &window, uint16_t handle,
                                    bool permitNew)
        {
            UsbHciAclHandle *vacant = nullptr;
            for (size_t i = 0; i < kUsbHciTrackedAclHandles; ++i)
            {
                UsbHciAclHandle &entry = window.connections.at(i);
                if (entry.outstanding != 0U && entry.handle == handle)
                {
                    return &entry;
                }
                if (entry.outstanding == 0U && vacant == nullptr)
                {
                    vacant = &entry;
                }
            }
            if (permitNew && vacant != nullptr)
            {
                vacant->handle = handle;
                return vacant;
            }
            return nullptr;
        }

        UsbHciStatus completeAcl(UsbHciState &state, const uint8_t *packet,
                                 size_t bytes)
        {
            UsbHciAclWindow &window = state.aclWindow;
            if (!window.configured)
            {
                return UsbHciStatus::Ok;
            }
            if (bytes < kCompletionHeaderBytes ||
                bytes != kCompletionHeaderBytes +
                             (static_cast<size_t>(*usbByteOffset(
                                  packet, kCompletedCountOffset)) *
                              kCompletedHandleBytes))
            {
                return UsbHciStatus::MalformedPacket;
            }
            // Validate all entries against a private snapshot, then publish
            // credits together. A late malformed handle never grants a
            // partial return of controller buffer ownership.
            UsbHciAclWindow candidate = window;
            for (size_t i = 0;
                 i < *usbByteOffset(packet, kCompletedCountOffset); ++i)
            {
                const size_t offset =
                    kCompletionHeaderBytes + (i * kCompletedHandleBytes);
                const uint16_t handle = little16(packet, offset);
                const uint16_t completed = little16(packet, offset + 2U);
                if (handle > kHciMaximumHandle)
                {
                    return UsbHciStatus::MalformedPacket;
                }
                for (size_t prior = 0; prior < i; ++prior)
                {
                    if (little16(packet, kCompletionHeaderBytes +
                                             (prior * kCompletedHandleBytes)) ==
                        handle)
                    {
                        return UsbHciStatus::MalformedPacket;
                    }
                }
                UsbHciAclHandle *entry = findHandle(candidate, handle, false);
                if (completed != 0U &&
                    (entry == nullptr || completed > entry->outstanding ||
                     completed >
                         candidate.totalCredits - candidate.availableCredits))
                {
                    return UsbHciStatus::MalformedPacket;
                }
                if (entry != nullptr)
                {
                    entry->outstanding =
                        static_cast<uint16_t>(entry->outstanding - completed);
                    candidate.availableCredits = static_cast<uint16_t>(
                        candidate.availableCredits + completed);
                }
            }
            window = candidate;
            return UsbHciStatus::Ok;
        }

        UsbHciStatus accountControllerEvent(UsbHciState &state,
                                            const uint8_t *packet, size_t bytes)
        {
            if (bytes < kEventHeaderBytes ||
                bytes != kEventHeaderBytes + *usbByteOffset(packet, 1U))
            {
                return UsbHciStatus::MalformedPacket;
            }
            const uint8_t eventCode = *usbByteOffset(packet, 0U);
            if (eventCode == kHciHardwareError ||
                eventCode == kHciDataBufferOverflow)
            {
                // The controller has lost hardware or packet-buffer
                // integrity. No old ACL credits/handles remain trustworthy;
                // the native owner must detach/reset before further traffic.
                return bytes == kControllerFaultBytes
                           ? UsbHciStatus::Faulted
                           : UsbHciStatus::MalformedPacket;
            }
            UsbHciAclWindow &window = state.aclWindow;
            if (window.resetPending &&
                *usbByteOffset(packet, 0U) == kHciCommandStatus &&
                bytes == kCommandStatusBytes &&
                little16(packet, 4U) == kHciReset &&
                *usbByteOffset(packet, 2U) != 0U)
            {
                return UsbHciStatus::MalformedPacket;
            }
            if (window.resetPending &&
                *usbByteOffset(packet, 0U) == kHciCommandComplete &&
                bytes >= kCommandCompletePrefixBytes &&
                little16(packet, 3U) == kHciReset)
            {
                if (bytes != kResetCompleteBytes ||
                    *usbByteOffset(packet, kResponseStatusOffset) != 0U)
                {
                    return UsbHciStatus::MalformedPacket;
                }
                window.resetPending = false;
                return UsbHciStatus::Ok;
            }
            if (*usbByteOffset(packet, 0U) == kHciCommandStatus &&
                bytes == kCommandStatusBytes &&
                little16(packet, 4U) == kHciReadBufferSize &&
                window.readBufferPending && *usbByteOffset(packet, 2U) != 0U)
            {
                window.readBufferPending = false;
                return UsbHciStatus::Ok;
            }
            if (*usbByteOffset(packet, 0U) == kHciCommandComplete &&
                bytes >= kCommandCompletePrefixBytes &&
                little16(packet, 3U) == kHciReadBufferSize &&
                window.readBufferPending)
            {
                window.readBufferPending = false;
                if (bytes != kReadBufferCompleteBytes)
                {
                    return UsbHciStatus::MalformedPacket;
                }
                if (*usbByteOffset(packet, kResponseStatusOffset) != 0U)
                {
                    return UsbHciStatus::Ok;
                }
                const uint16_t mtu = little16(packet, 6U);
                const uint16_t credits = little16(packet, 9U);
                if (mtu == 0U || credits == 0U || window.configured)
                {
                    return UsbHciStatus::MalformedPacket;
                }
                window.packetBytes = mtu;
                window.totalCredits = credits;
                window.availableCredits = credits;
                window.configured = true;
                return UsbHciStatus::Ok;
            }
            if (*usbByteOffset(packet, 0U) == kHciCompletedPackets)
            {
                return completeAcl(state, packet, bytes);
            }
            return UsbHciStatus::Ok;
        }

        UsbHciStatus deliverComplete(UsbHciState &state, UsbHciStream &stream,
                                     const UsbHciHostCallbacks &host,
                                     UsbHciPacketKind kind)
        {
            if (kind == UsbHciPacketKind::Event)
            {
                const UsbHciStatus processed = accountControllerEvent(
                    state, stream.packet.data(), stream.used);
                if (processed != UsbHciStatus::Ok)
                {
                    state.faulted = true;
                    return processed;
                }
            }
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
        const uint16_t opcode = little16(command, 0U);
        if ((opcode == kHciReadBufferSize &&
             (state.aclWindow.configured || state.aclWindow.readBufferPending ||
              state.aclWindow.resetPending)) ||
            (opcode == kHciReset && state.aclWindow.resetPending))
        {
            return UsbHciStatus::FlowControlUnavailable;
        }
        // Record the outstanding request before the USB callback; a host
        // adapter may synchronously deliver the command-complete event.
        if (opcode == kHciReadBufferSize)
        {
            state.aclWindow.readBufferPending = true;
        }
        else if (opcode == kHciReset)
        {
            // A successful controller reset discards its ACL buffer pool and
            // all connection handles. Revoke TX before command submission:
            // callbacks may immediately deliver reset completion, and a
            // failed/ambiguous reset will fault the whole transport.
            state.aclWindow = {};
            state.aclWindow.resetPending = true;
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
        UsbHciAclWindow &window = state.aclWindow;
        if (!window.configured)
        {
            return UsbHciStatus::FlowControlUnavailable;
        }
        if (bytes - kAclHeaderBytes > window.packetBytes)
        {
            return UsbHciStatus::FrameTooLarge;
        }
        const uint16_t handle = little16(packet, 0U) & kHciHandleMask;
        if (handle > kHciMaximumHandle)
        {
            return UsbHciStatus::MalformedPacket;
        }
        if (window.availableCredits == 0U)
        {
            return UsbHciStatus::NoControllerCredits;
        }
        UsbHciAclHandle *entry = findHandle(window, handle, true);
        if (entry == nullptr)
        {
            return UsbHciStatus::TooManyConnections;
        }
        // Consume the controller slot before USB I/O so that a synchronous
        // completion cannot race ahead of the accounting entry.
        ++entry->outstanding;
        --window.availableCredits;
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
