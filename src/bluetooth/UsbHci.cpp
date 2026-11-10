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
        constexpr uint16_t kHciLeReadBufferSize = 0x2002U;
        constexpr uint16_t kHciLeSetAdvertisingParameters = 0x2006U;
        constexpr uint16_t kHciLeSetAdvertisingData = 0x2008U;
        constexpr uint16_t kHciLeSetAdvertisingEnable = 0x200aU;
        constexpr uint16_t kHciLeSetScanParameters = 0x200bU;
        constexpr uint16_t kHciLeSetScanEnable = 0x200cU;
        constexpr uint16_t kHciReset = 0x0c03U;
        constexpr uint8_t kHciCommandComplete = 0x0eU;
        constexpr uint8_t kHciCommandStatus = 0x0fU;
        constexpr uint8_t kHciCompletedPackets = 0x13U;
        constexpr uint8_t kHciConnectionComplete = 0x03U;
        constexpr uint8_t kHciDisconnectionComplete = 0x05U;
        constexpr uint8_t kHciLeMeta = 0x3eU;
        constexpr uint8_t kHciLeConnectionComplete = 0x01U;
        constexpr uint8_t kHciLeEnhancedConnectionComplete = 0x0aU;
        constexpr uint8_t kHciAclLinkType = 0x01U;
        constexpr uint8_t kHciHardwareError = 0x10U;
        constexpr uint8_t kHciDataBufferOverflow = 0x1aU;
        constexpr size_t kControllerFaultBytes = 3U;
        constexpr size_t kReadBufferCompleteBytes = 13U;
        constexpr size_t kLeBufferCompleteBytes = 9U;
        constexpr size_t kClassicConnectionBytes = 13U;
        constexpr size_t kDisconnectionBytes = 6U;
        constexpr size_t kLeConnectionBytes = 21U;
        constexpr size_t kLeEnhancedConnectionBytes = 33U;
        constexpr size_t kCommandStatusBytes = 6U;
        constexpr size_t kCommandCreditOffset = 2U;
        constexpr size_t kStatusCreditOffset = 3U;
        constexpr size_t kResetCompleteBytes = 6U;
        constexpr size_t kCommandCompletePrefixBytes = 5U;
        constexpr size_t kResponseStatusOffset = 5U;
        constexpr size_t kCompletedCountOffset = 2U;
        constexpr size_t kCompletionHeaderBytes = 3U;
        constexpr size_t kCompletedHandleBytes = 4U;
        constexpr size_t kLeConnectionHandleOffset = 4U;
        constexpr size_t kClassicConnectionHandleOffset = 3U;
        constexpr size_t kClassicConnectionLinkTypeOffset = 11U;
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
            // The owner may revoke its lease and attach a successor *inside*
            // the permit callback. Its stale true result is not permission
            // to send/ingest packets through a replacement session.
            if (!state.attached || state.epoch != host.ownerEpoch ||
                state.faulted)
            {
                return UsbHciStatus::OwnershipLost;
            }
            return UsbHciStatus::Ok;
        }

        // A transport callback may synchronously complete an owner teardown
        // and attach a fresh USB instance before its old stack frame returns.
        // Do not fault or reset the successor while unwinding stale work.
        bool replacedSession(const UsbHciState &state, uint64_t epoch)
        {
            return !state.attached || state.epoch != epoch;
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
            UsbHciAclHandle *reusable = nullptr;
            for (size_t i = 0; i < kUsbHciTrackedAclHandles; ++i)
            {
                UsbHciAclHandle &entry = window.connections.at(i);
                if (entry.active && entry.handle == handle)
                {
                    return &entry;
                }
                if (!entry.active && vacant == nullptr)
                {
                    vacant = &entry;
                }
                else if (entry.active && entry.outstanding == 0U &&
                         !entry.connected && reusable == nullptr)
                {
                    reusable = &entry;
                }
            }
            if (!permitNew)
            {
                return nullptr;
            }
            UsbHciAclHandle *entry = vacant != nullptr ? vacant : reusable;
            if (entry != nullptr)
            {
                *entry = {};
                entry->handle = handle;
                entry->active = true;
                return entry;
            }
            return nullptr;
        }

        // LE and classic connection handles are classified ONLY from a
        // successful controller event, never from caller-supplied ACL bytes.
        UsbHciStatus accountConnectionType(UsbHciState &state,
                                           const uint8_t *packet, size_t bytes)
        {
            const uint8_t kind = *usbByteOffset(packet, 0U);
            const bool classic = kind == kHciConnectionComplete;
            const bool le =
                kind == kHciLeMeta && bytes >= 3U &&
                *usbByteOffset(packet, 2U) == kHciLeConnectionComplete;
            const bool enhancedLe =
                kind == kHciLeMeta && bytes >= 3U &&
                *usbByteOffset(packet, 2U) == kHciLeEnhancedConnectionComplete;
            if (!classic && !le && !enhancedLe)
            {
                return UsbHciStatus::Ok;
            }
            // Both LE connection-complete formats carry the same status and
            // connection handle, but the privacy-aware report appends local
            // and peer resolvable addresses before its connection timing.
            // Only the complete controller event can establish LE ACL credit
            // ownership. A truncated enhanced report must fail closed.
            size_t expectedBytes = kClassicConnectionBytes;
            if (le)
            {
                expectedBytes = kLeConnectionBytes;
            }
            if (enhancedLe)
            {
                expectedBytes = kLeEnhancedConnectionBytes;
            }
            if (bytes != expectedBytes)
            {
                return UsbHciStatus::MalformedPacket;
            }
            const size_t status = (le || enhancedLe) ? 3U : 2U;
            if (*usbByteOffset(packet, status) != 0U)
            {
                return UsbHciStatus::Ok;
            }
            if (classic &&
                *usbByteOffset(packet, kClassicConnectionLinkTypeOffset) !=
                    kHciAclLinkType)
            {
                // SCO is not transported on this ACL pipe.
                return UsbHciStatus::Ok;
            }
            const uint16_t handle = little16(
                packet, (le || enhancedLe) ? kLeConnectionHandleOffset
                                           : kClassicConnectionHandleOffset);
            if (handle > kHciMaximumHandle)
            {
                return UsbHciStatus::MalformedPacket;
            }
            // Reset clears all controller connection ownership before the
            // command leaves USB. A delayed Connection Complete from the
            // retiring controller state must not repopulate this ledger
            // before the new Reset Complete opens fresh link admission.
            if (state.aclWindow.resetPending)
            {
                return UsbHciStatus::Ok;
            }
            UsbHciAclHandle *entry = findHandle(state.aclWindow, handle, true);
            if (entry == nullptr || entry->outstanding != 0U)
            {
                return UsbHciStatus::MalformedPacket;
            }
            if (entry->connected)
            {
                return UsbHciStatus::MalformedPacket;
            }
            entry->le = le || enhancedLe;
            entry->classified = true;
            entry->connected = true;
            entry->retired = false;
            return UsbHciStatus::Ok;
        }

        // Disconnection revokes new submissions without inventing a
        // Number Of Completed Packets. Outstanding controller buffers stay
        // associated with their original pool until completion or reset.
        UsbHciStatus accountDisconnection(UsbHciState &state,
                                          const uint8_t *packet, size_t bytes)
        {
            if (*usbByteOffset(packet, 0U) != kHciDisconnectionComplete)
            {
                return UsbHciStatus::Ok;
            }
            if (bytes != kDisconnectionBytes)
            {
                return UsbHciStatus::MalformedPacket;
            }
            if (*usbByteOffset(packet, 2U) != 0U)
            {
                return UsbHciStatus::Ok;
            }
            const uint16_t handle = little16(packet, 3U);
            if (handle > kHciMaximumHandle)
            {
                return UsbHciStatus::MalformedPacket;
            }
            UsbHciAclHandle *entry = findHandle(state.aclWindow, handle, false);
            if (entry != nullptr)
            {
                entry->connected = false;
                entry->retired = true;
            }
            return UsbHciStatus::Ok;
        }

        UsbHciStatus accountConnectionLifecycle(UsbHciState &state,
                                                const uint8_t *packet,
                                                size_t bytes)
        {
            const UsbHciStatus connected =
                accountConnectionType(state, packet, bytes);
            if (connected != UsbHciStatus::Ok)
            {
                return connected;
            }
            return accountDisconnection(state, packet, bytes);
        }

        // Core HCI ACL header flags (Vol 4, Part E, 5.4.2). Reserved PB=3
        // must never reach the USB pipe or the host. Normal controller RX
        // cannot send host-only PB=0; LE-U does not support the BR/EDR
        // broadcast flag. The classic host retains role-policy ownership of
        // its permitted broadcast packets.
        bool validAclHeaderFlags(const uint8_t *packet,
                                 const UsbHciAclHandle &entry,
                                 bool hostToController)
        {
            constexpr uint8_t kBoundaryMask = 0x30U;
            constexpr uint8_t kBoundaryReserved = 0x30U;
            constexpr uint8_t kBoundaryHostOnly = 0x00U;
            constexpr uint8_t kBroadcastMask = 0xc0U;
            constexpr uint8_t kBrEdrBroadcast = 0x40U;
            const uint8_t flags = *usbByteOffset(packet, 1U);
            const uint8_t boundary = flags & kBoundaryMask;
            const uint8_t broadcast = flags & kBroadcastMask;
            return boundary != kBoundaryReserved &&
                   (hostToController || boundary != kBoundaryHostOnly) &&
                   (broadcast == 0U ||
                    (!entry.le && broadcast == kBrEdrBroadcast));
        }

        UsbHciAclCredits &creditPool(UsbHciAclWindow &classic,
                                     UsbHciLeAclWindow &le,
                                     const UsbHciAclHandle &entry)
        {
            if (entry.le && le.configured && le.totalCredits != 0U)
            {
                return le;
            }
            return classic;
        }

        UsbHciStatus completeAcl(UsbHciState &state, const uint8_t *packet,
                                 size_t bytes)
        {
            UsbHciAclWindow &window = state.aclWindow;
            if (!window.configured && !state.leAclWindow.configured)
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
            UsbHciLeAclWindow leCandidate = state.leAclWindow;
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
                if (entry == nullptr && completed != 0U)
                {
                    return UsbHciStatus::MalformedPacket;
                }
                if (entry != nullptr)
                {
                    UsbHciAclCredits &credits =
                        creditPool(candidate, leCandidate, *entry);
                    if (completed > entry->outstanding ||
                        completed >
                            credits.totalCredits - credits.availableCredits)
                    {
                        return UsbHciStatus::MalformedPacket;
                    }
                    entry->outstanding =
                        static_cast<uint16_t>(entry->outstanding - completed);
                    credits.availableCredits = static_cast<uint16_t>(
                        credits.availableCredits + completed);
                }
            }
            window = candidate;
            state.leAclWindow = leCandidate;
            return UsbHciStatus::Ok;
        }

        bool leProcedureNeedsComplete(uint16_t opcode)
        {
            // The LE discovery/advertising producers require controller
            // Command Complete, not merely a preliminary successful Status.
            return opcode == kHciLeSetAdvertisingParameters ||
                   opcode == kHciLeSetAdvertisingData ||
                   opcode == kHciLeSetAdvertisingEnable ||
                   opcode == kHciLeSetScanParameters ||
                   opcode == kHciLeSetScanEnable;
        }

        // A command response belongs to this exclusive HCI host. Do not
        // accept a mismatched or unsolicited response as a source of credits.
        // Num_HCI_Command_Packets is an absolute window, not an increment.
        UsbHciStatus accountCommandCredits(UsbHciState &state,
                                           const uint8_t *packet, size_t bytes)
        {
            const uint8_t eventCode = *usbByteOffset(packet, 0U);
            const bool complete = eventCode == kHciCommandComplete;
            const bool status = eventCode == kHciCommandStatus;
            if (!complete && !status)
            {
                return UsbHciStatus::Ok;
            }
            if (bytes < (complete ? kCommandCompletePrefixBytes
                                  : kCommandStatusBytes) ||
                (status && bytes != kCommandStatusBytes))
            {
                return UsbHciStatus::MalformedPacket;
            }
            const uint16_t opcode = little16(packet, complete ? 3U : 4U);
            UsbHciCommandWindow &commands = state.commandWindow;
            // A successful preliminary Command Status may precede a CC
            // for Reset or Read Buffer Size, with the ACL gate still pending.
            const bool awaitingSpecialComplete =
                complete && !commands.pending &&
                ((opcode == kHciReset && state.aclWindow.resetPending) ||
                 (opcode == kHciReadBufferSize &&
                  state.aclWindow.readBufferPending) ||
                 (opcode == kHciLeReadBufferSize &&
                  state.leAclWindow.readBufferPending));
            if ((!commands.pending && !awaitingSpecialComplete) ||
                (commands.pending && opcode != commands.pendingOpcode) ||
                (status && commands.preliminaryStatusSeen))
            {
                return UsbHciStatus::MalformedPacket;
            }
            commands.credits = *usbByteOffset(
                packet, complete ? kCommandCreditOffset : kStatusCreditOffset);
            if (status && *usbByteOffset(packet, 2U) == 0U &&
                leProcedureNeedsComplete(opcode))
            {
                // Keep the exclusive pending opcode until its final CC;
                // a Status credit is not permission to overtake this LE
                // procedure or accept a duplicate preliminary response.
                commands.preliminaryStatusSeen = true;
                return UsbHciStatus::Ok;
            }
            commands.pending = false;
            commands.preliminaryStatusSeen = false;
            commands.pendingOpcode = 0U;
            return UsbHciStatus::Ok;
        }

        UsbHciStatus accountLeReadBuffer(UsbHciState &state,
                                         const uint8_t *packet, size_t bytes)
        {
            UsbHciLeAclWindow &le = state.leAclWindow;
            const uint8_t event = *usbByteOffset(packet, 0U);
            if (event == kHciCommandStatus && bytes == kCommandStatusBytes &&
                little16(packet, 4U) == kHciLeReadBufferSize &&
                le.readBufferPending && *usbByteOffset(packet, 2U) != 0U)
            {
                le.readBufferPending = false;
                return UsbHciStatus::Ok;
            }
            if (event != kHciCommandComplete ||
                bytes < kCommandCompletePrefixBytes ||
                little16(packet, 3U) != kHciLeReadBufferSize ||
                !le.readBufferPending)
            {
                return UsbHciStatus::Ok;
            }
            le.readBufferPending = false;
            if (bytes != kLeBufferCompleteBytes)
            {
                return UsbHciStatus::MalformedPacket;
            }
            if (*usbByteOffset(packet, kResponseStatusOffset) != 0U)
            {
                return UsbHciStatus::Ok;
            }
            const uint16_t mtu = little16(packet, 6U);
            const uint8_t packets = *usbByteOffset(packet, 8U);
            if ((packets == 0U && mtu != 0U) || (packets != 0U && mtu == 0U) ||
                le.configured)
            {
                return UsbHciStatus::MalformedPacket;
            }
            le.packetBytes = mtu;
            le.totalCredits = packets;
            le.availableCredits = packets;
            le.configured = true;
            return UsbHciStatus::Ok;
        }

        UsbHciStatus controllerHardwareFault(const uint8_t *packet,
                                             size_t bytes)
        {
            const uint8_t eventCode = *usbByteOffset(packet, 0U);
            if (eventCode != kHciHardwareError &&
                eventCode != kHciDataBufferOverflow)
            {
                return UsbHciStatus::Ok;
            }
            // Hardware and data-buffer integrity faults invalidate both
            // command and ACL state until a physical USB owner reset.
            return bytes == kControllerFaultBytes
                       ? UsbHciStatus::Faulted
                       : UsbHciStatus::MalformedPacket;
        }

        UsbHciStatus accountControllerEvent(UsbHciState &state,
                                            const uint8_t *packet, size_t bytes)
        {
            if (bytes < kEventHeaderBytes ||
                bytes != kEventHeaderBytes + *usbByteOffset(packet, 1U))
            {
                return UsbHciStatus::MalformedPacket;
            }
            const UsbHciStatus hardwareFault =
                controllerHardwareFault(packet, bytes);
            if (hardwareFault != UsbHciStatus::Ok)
            {
                return hardwareFault;
            }
            const UsbHciStatus commandResult =
                accountCommandCredits(state, packet, bytes);
            if (commandResult != UsbHciStatus::Ok)
            {
                return commandResult;
            }
            const UsbHciStatus leResult =
                accountLeReadBuffer(state, packet, bytes);
            if (leResult != UsbHciStatus::Ok)
            {
                return leResult;
            }
            const UsbHciStatus connectionResult =
                accountConnectionLifecycle(state, packet, bytes);
            if (connectionResult != UsbHciStatus::Ok)
            {
                return connectionResult;
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
            else
            {
                // USB bulk-IN can outlive a controller disconnect or even
                // carry a stale handle from a previous HCI Reset. Events
                // from the controller, not incoming ACL bytes, establish
                // active connection ownership in this USB epoch.
                const uint16_t handle =
                    little16(stream.packet.data(), 0U) & kHciHandleMask;
                const UsbHciAclHandle *entry =
                    findHandle(state.aclWindow, handle, false);
                if (handle > kHciMaximumHandle || entry == nullptr ||
                    !entry->classified || !entry->connected || entry->retired ||
                    !validAclHeaderFlags(stream.packet.data(), *entry, false))
                {
                    state.faulted = true;
                    return UsbHciStatus::MalformedPacket;
                }
            }
            const uint64_t deliveryEpoch = state.epoch;
            stream.delivering = true;
            const bool delivered = host.deliver(
                host.context, kind, stream.packet.data(), stream.used);
            if (replacedSession(state, deliveryEpoch))
            {
                // A callback may have detached and replaced this stream.
                // Never clear the successor's delivery guard or fault state.
                return UsbHciStatus::OwnershipLost;
            }
            stream.delivering = false;
            if (state.faulted)
            {
                // Reentrant ingress faulted this stream before delivery
                // returned. Never report a successful outer packet.
                return UsbHciStatus::Faulted;
            }
            if (!delivered)
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
            if (stream.delivering)
            {
                // host.deliver still borrows stream.packet: an inline USB
                // response may recurse here and must not overwrite it.
                // The physical owner must recover under a fresh USB epoch.
                state.faulted = true;
                return UsbHciStatus::Faulted;
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
        if (!validCallbacks(host) || host.ownerEpoch == 0U)
        {
            // A zero epoch cannot identify an exclusive physical owner.
            return UsbHciStatus::InvalidArgument;
        }
        if (!validEndpoint(endpoints.eventInterruptIn, true) ||
            !validEndpoint(endpoints.aclBulkIn, true) ||
            !validEndpoint(endpoints.aclBulkOut, false) ||
            endpoints.eventInterruptIn == endpoints.aclBulkIn)
        {
            return UsbHciStatus::InvalidEndpoint;
        }
        if (state.attached)
        {
            return UsbHciStatus::Faulted;
        }
        if (!host.permit(host.context, host.ownerEpoch) || state.attached ||
            state.epoch != 0U || !host.permit(host.context, host.ownerEpoch) ||
            state.attached || state.epoch != 0U)
        {
            // One grant may be stale if the callback detached or attached
            // another owner inline. Confirm the still-live lease, and never
            // overwrite a successor's attached transport state.
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

    UsbHciStatus classifyUsbHciRead(bool ownerCurrent, bool completed,
                                    bool timedOut, size_t transferred,
                                    size_t capacity)
    {
        if (!ownerCurrent)
        {
            return UsbHciStatus::OwnershipLost;
        }
        if (completed && timedOut)
        {
            return UsbHciStatus::TransferFailed;
        }
        if (timedOut && transferred == 0U)
        {
            return UsbHciStatus::Idle;
        }
        if (!completed || transferred == 0U || transferred > capacity)
        {
            return UsbHciStatus::TransferFailed;
        }
        return UsbHciStatus::Ok;
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
        if (state.aclWindow.resetPending || state.aclWindow.readBufferPending ||
            state.leAclWindow.readBufferPending ||
            (opcode == kHciReadBufferSize &&
             (state.aclWindow.configured || state.aclWindow.readBufferPending ||
              state.aclWindow.resetPending)) ||
            (opcode == kHciLeReadBufferSize && state.leAclWindow.configured))
        {
            return UsbHciStatus::FlowControlUnavailable;
        }
        UsbHciCommandWindow &commands = state.commandWindow;
        if (commands.pending || commands.credits == 0U)
        {
            return UsbHciStatus::NoCommandCredits;
        }
        // Account before invoking the USB callback, which may deliver a
        // synchronous Command Complete/Status and re-enter the HCI owner.
        --commands.credits;
        commands.pending = true;
        commands.preliminaryStatusSeen = false;
        commands.pendingOpcode = opcode;
        // Record the outstanding request before the USB callback; a host
        // adapter may synchronously deliver the command-complete event.
        if (opcode == kHciReadBufferSize)
        {
            state.aclWindow.readBufferPending = true;
        }
        else if (opcode == kHciLeReadBufferSize)
        {
            state.leAclWindow.readBufferPending = true;
        }
        else if (opcode == kHciReset)
        {
            // A successful controller reset discards its ACL buffer pool and
            // all connection handles. Revoke TX before command submission:
            // callbacks may immediately deliver reset completion, and a
            // failed/ambiguous reset will fault the whole transport.
            state.aclWindow = {};
            state.leAclWindow = {};
            state.aclWindow.resetPending = true;
        }
        const uint64_t commandEpoch = state.epoch;
        const bool sent = host.commandControlOut(host.context, command, bytes);
        if (replacedSession(state, commandEpoch))
        {
            return UsbHciStatus::OwnershipLost;
        }
        if (!sent)
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
        const uint16_t handle = little16(packet, 0U) & kHciHandleMask;
        if (handle > kHciMaximumHandle)
        {
            return UsbHciStatus::MalformedPacket;
        }
        UsbHciAclHandle *entry = findHandle(window, handle, false);
        // A Read Buffer Size reply establishes capacity, not a link. For
        // BOTH classic and LE, only a successful controller Connection
        // Complete may authorize this exact ACL handle. Never send to a
        // phantom/reused handle merely because a shared pool has credits.
        if (entry == nullptr || !entry->classified || !entry->connected ||
            entry->retired || (entry->le && !state.leAclWindow.configured))
        {
            return UsbHciStatus::FlowControlUnavailable;
        }
        if (!validAclHeaderFlags(packet, *entry, true))
        {
            return UsbHciStatus::MalformedPacket;
        }
        UsbHciAclCredits &pool = creditPool(window, state.leAclWindow, *entry);
        if (!pool.configured)
        {
            return UsbHciStatus::FlowControlUnavailable;
        }
        if (bytes - kAclHeaderBytes > pool.packetBytes)
        {
            return UsbHciStatus::FrameTooLarge;
        }
        if (pool.availableCredits == 0U)
        {
            return UsbHciStatus::NoControllerCredits;
        }
        // The native controller still owns packet completion. Account before
        // the callback because it may synchronously deliver a completion.
        ++entry->outstanding;
        --pool.availableCredits;
        size_t transferred = 0U;
        const uint64_t aclEpoch = state.epoch;
        const bool sent =
            host.aclBulkOut(host.context, state.endpoints.aclBulkOut, packet,
                            bytes, &transferred);
        if (replacedSession(state, aclEpoch))
        {
            return UsbHciStatus::OwnershipLost;
        }
        if (!sent || transferred != bytes)
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
