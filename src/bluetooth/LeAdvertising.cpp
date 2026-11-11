#include "LeAdvertising.hpp"
#include "UsbBytes.hpp"
#include "UsbHci.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        constexpr uint8_t kCommandComplete = 0x0eU;
        constexpr uint8_t kCommandStatus = 0x0fU;
        constexpr uint16_t kSetParameters = 0x2006U;
        constexpr uint16_t kSetData = 0x2008U;
        constexpr uint16_t kSetEnable = 0x200aU;
        constexpr uint16_t kMinimumInterval = 0x00a0U;
        constexpr uint16_t kMaximumInterval = 0x4000U;
        constexpr uint8_t kNonConnectableUndirected = 0x03U;
        constexpr uint8_t kAllAdvertisingChannels = 0x07U;
        constexpr size_t kHciHeaderBytes = 3U;
        constexpr size_t kParametersBytes = 15U;
        constexpr size_t kChannelMapOffset = 13U;
        constexpr size_t kAdvertisingDataParameterBytes = 32U;
        constexpr size_t kEnableBytes = 1U;
        constexpr size_t kHciEventHeaderBytes = 2U;
        constexpr size_t kCommandResultBytes = 6U;
        constexpr unsigned kBitsPerByte = 8U;

        LeAdvertisingResult fault(LeAdvertisingState &state,
                                  LeAdvertisingResult result)
        {
            state.phase = LeAdvertisingPhase::Faulted;
            return result;
        }

        void clearAdvertising(LeAdvertisingState &state)
        {
            const uint64_t next = state.generation == UINT64_MAX
                                      ? UINT64_MAX
                                      : state.generation + 1U;
            state = {};
            state.generation = next;
        }

        bool ownerValid(const LeAdvertisingOwner &owner)
        {
            return owner.context != nullptr && owner.epoch != 0U &&
                   owner.permit != nullptr && owner.authorize != nullptr;
        }

        bool authorized(const LeAdvertisingState &state,
                        const UsbHciState &transport,
                        const UsbHciHostCallbacks &host,
                        const LeAdvertisingOwner &owner)
        {
            if (!ownerValid(owner) || state.epoch != owner.epoch ||
                !transport.attached || transport.faulted ||
                transport.epoch != owner.epoch ||
                host.ownerEpoch != owner.epoch)
            {
                return false;
            }
            const LeAdvertisingPhase phase = state.phase;
            const uint64_t sessionGeneration = state.generation;
            const uint64_t transportGeneration = transport.generation;
            // Host permission may synchronously revoke advertising or
            // replace the HCI transport before returning true.
            const bool permitted = owner.permit(owner.context, owner.epoch);
            return permitted && state.phase == phase &&
                   state.generation == sessionGeneration &&
                   state.epoch == owner.epoch && transport.attached &&
                   !transport.faulted && transport.epoch == owner.epoch &&
                   transport.generation == transportGeneration;
        }

        LeAdvertisingResult lostAuthorization(LeAdvertisingState &state,
                                              LeAdvertisingPhase previousPhase,
                                              uint64_t previousEpoch,
                                              uint64_t previousGeneration)
        {
            // Preserve a session already retired or replaced inside the
            // borrowed callback; never corrupt it with an old caller's fault.
            return state.phase != previousPhase ||
                           state.epoch != previousEpoch ||
                           state.generation != previousGeneration
                       ? LeAdvertisingResult::OwnershipLost
                       : fault(state, LeAdvertisingResult::OwnershipLost);
        }

        bool wellFormedAdvertisingData(const uint8_t *data, size_t bytes)
        {
            if (data == nullptr || bytes == 0U ||
                bytes > kLeAdvertisingDataBytes)
            {
                return false;
            }
            size_t cursor = 0U;
            while (cursor < bytes)
            {
                const size_t length = *usbByteOffset(data, cursor);
                // Each AD structure contains at least its AD type octet.
                // Check subtraction before advancing; never access past AD.
                if (length == 0U || length > bytes - cursor - 1U)
                {
                    return false;
                }
                cursor += length + 1U;
            }
            return cursor == bytes;
        }

        template <size_t N>
        bool send(const UsbHciHostCallbacks &host, UsbHciState &transport,
                  uint16_t opcode, const UsbBytes<uint8_t, N> &parameters)
        {
            static_assert(N + kHciHeaderBytes <= kUsbHciMaxCommandBytes,
                          "HCI command storage must fit one USB control OUT");
            UsbBytes<uint8_t, N + kHciHeaderBytes> command {};
            command.at(0U) = static_cast<uint8_t>(opcode);
            command.at(1U) = static_cast<uint8_t>(opcode >> kBitsPerByte);
            command.at(2U) = static_cast<uint8_t>(N);
            for (size_t index = 0U; index < N; ++index)
            {
                command.at(index + kHciHeaderBytes) = parameters.at(index);
            }
            return sendUsbHciCommand(transport, host, command.data(),
                                     command.size()) == UsbHciStatus::Ok;
        }

        bool sendParameters(UsbHciState &transport,
                            const UsbHciHostCallbacks &host, uint16_t interval)
        {
            UsbBytes<uint8_t, kParametersBytes> parameters {};
            parameters.at(0U) = static_cast<uint8_t>(interval);
            parameters.at(1U) = static_cast<uint8_t>(interval >> kBitsPerByte);
            parameters.at(2U) = parameters.at(0U);
            parameters.at(3U) = parameters.at(1U);
            parameters.at(4U) = kNonConnectableUndirected;
            // ownAddressType = public (0); peerAddressType/address = unused
            // zeros for undirected advertising; filter policy = no filtering.
            parameters.at(kChannelMapOffset) = kAllAdvertisingChannels;
            return send(host, transport, kSetParameters, parameters);
        }

        bool sendData(UsbHciState &transport, const UsbHciHostCallbacks &host,
                      const LeAdvertisingState &state)
        {
            UsbBytes<uint8_t, kAdvertisingDataParameterBytes> parameters {};
            parameters.at(0U) = static_cast<uint8_t>(state.dataBytes);
            for (size_t index = 0U; index < state.dataBytes; ++index)
            {
                parameters.at(index + 1U) = state.data.at(index);
            }
            return send(host, transport, kSetData, parameters);
        }

        bool sendEnable(UsbHciState &transport, const UsbHciHostCallbacks &host,
                        bool enable)
        {
            UsbBytes<uint8_t, kEnableBytes> parameters {};
            parameters.at(0U) = static_cast<uint8_t>(enable ? 1U : 0U);
            return send(host, transport, kSetEnable, parameters);
        }

        uint16_t loadOpcode(const uint8_t *event, size_t offset)
        {
            return static_cast<uint16_t>(
                static_cast<uint32_t>(*usbByteOffset(event, offset)) |
                (static_cast<uint32_t>(*usbByteOffset(event, offset + 1U))
                 << kBitsPerByte));
        }

        bool matchesPending(const LeAdvertisingState &state, uint16_t opcode)
        {
            switch (state.phase)
            {
                case LeAdvertisingPhase::AwaitParameters:
                    return opcode == kSetParameters;
                case LeAdvertisingPhase::AwaitData:
                    return opcode == kSetData;
                case LeAdvertisingPhase::AwaitEnable:
                case LeAdvertisingPhase::AwaitDisable:
                    return opcode == kSetEnable;
                default:
                    return false;
            }
        }

        LeAdvertisingResult completeCommand(LeAdvertisingState &state,
                                            UsbHciState &transport,
                                            const UsbHciHostCallbacks &host)
        {
            if (state.phase == LeAdvertisingPhase::AwaitDisable ||
                (state.stopRequested &&
                 (state.phase == LeAdvertisingPhase::AwaitParameters ||
                  state.phase == LeAdvertisingPhase::AwaitData)))
            {
                clearAdvertising(state);
                return LeAdvertisingResult::Ok;
            }
            const uint64_t issuedGeneration = state.generation;
            const uint64_t issuedEpoch = state.epoch;
            bool sent = false;
            if (state.phase == LeAdvertisingPhase::AwaitParameters)
            {
                state.phase = LeAdvertisingPhase::AwaitData;
                sent = sendData(transport, host, state);
            }
            else if (state.phase == LeAdvertisingPhase::AwaitData)
            {
                state.phase = LeAdvertisingPhase::AwaitEnable;
                sent = sendEnable(transport, host, true);
            }
            else if (state.stopRequested)
            {
                state.phase = LeAdvertisingPhase::AwaitDisable;
                sent = sendEnable(transport, host, false);
            }
            else
            {
                state.phase = LeAdvertisingPhase::Advertising;
                return LeAdvertisingResult::Ok;
            }
            // A native USB command callback can synchronously revoke this
            // advertising producer and start a successor on the SAME USB
            // epoch, with the SAME pending phase. Never fault or validate
            // that replacement using the obsolete command's result.
            if (state.generation != issuedGeneration ||
                state.epoch != issuedEpoch)
            {
                return sent && state.phase == LeAdvertisingPhase::Idle
                           ? LeAdvertisingResult::Ok
                           : LeAdvertisingResult::OwnershipLost;
            }
            if (!sent)
            {
                return fault(state, LeAdvertisingResult::TransportFailed);
            }
            // USB control OUT may dispatch its controller response inline.
            // A nested rejection must not be overwritten with a false Ok.
            return state.phase == LeAdvertisingPhase::Faulted
                       ? LeAdvertisingResult::Faulted
                       : LeAdvertisingResult::Ok;
        }

        LeAdvertisingResult acceptCommandEvent(LeAdvertisingState &state,
                                               UsbHciState &transport,
                                               const UsbHciHostCallbacks &host,
                                               const uint8_t *event,
                                               size_t bytes,
                                               bool commandComplete)
        {
            // Unrelated Command Complete responses may contain many return
            // parameters. Only the pending opcode's status layout is ours.
            const size_t opcodeEnd = commandComplete ? 5U : 6U;
            if (bytes < opcodeEnd)
            {
                return fault(state, LeAdvertisingResult::MalformedEvent);
            }
            const uint16_t opcode =
                loadOpcode(event, commandComplete ? 3U : 4U);
            if (!matchesPending(state, opcode))
            {
                return LeAdvertisingResult::Ignored;
            }
            if (bytes != kCommandResultBytes)
            {
                return fault(state, LeAdvertisingResult::MalformedEvent);
            }
            const uint8_t result =
                *usbByteOffset(event, commandComplete ? 5U : 2U);
            const uint8_t credits =
                *usbByteOffset(event, commandComplete ? 2U : 3U);
            if (result != 0U)
            {
                return fault(state, LeAdvertisingResult::ControllerRejected);
            }
            if (credits == 0U)
            {
                return fault(state,
                             LeAdvertisingResult::CommandCreditUnavailable);
            }
            // Command Status success does not complete a pending LE procedure.
            return commandComplete ? completeCommand(state, transport, host)
                                   : LeAdvertisingResult::Ignored;
        }

        struct InitialSubmission
        {
                uint64_t generation;
                uint16_t interval;
        };

        LeAdvertisingResult submitInitialParameters(
            LeAdvertisingState &state, UsbHciState &transport,
            const UsbHciHostCallbacks &host, const LeAdvertisingOwner &owner,
            InitialSubmission submission)
        {
            state.phase = LeAdvertisingPhase::AwaitParameters;
            const bool submitted =
                sendParameters(transport, host, submission.interval);
            if (state.generation != submission.generation ||
                state.epoch != owner.epoch)
            {
                return LeAdvertisingResult::OwnershipLost;
            }
            if (!submitted)
            {
                return fault(state, LeAdvertisingResult::TransportFailed);
            }
            if (state.phase == LeAdvertisingPhase::Faulted)
            {
                return LeAdvertisingResult::Faulted;
            }
            const LeAdvertisingPhase previousPhase = state.phase;
            const uint64_t previousEpoch = state.epoch;
            const uint64_t previousGeneration = state.generation;
            if (!authorized(state, transport, host, owner))
            {
                return lostAuthorization(state, previousPhase, previousEpoch,
                                         previousGeneration);
            }
            return LeAdvertisingResult::Ok;
        }
    } // namespace

    LeAdvertisingResult beginLeAdvertising(LeAdvertisingState &state,
                                           UsbHciState &transport,
                                           const UsbHciHostCallbacks &host,
                                           const LeAdvertisingOwner &owner,
                                           const uint8_t *data, size_t bytes,
                                           uint16_t interval)
    {
        if (state.phase != LeAdvertisingPhase::Idle)
        {
            return LeAdvertisingResult::Busy;
        }
        if (state.generation == UINT64_MAX)
        {
            return LeAdvertisingResult::Faulted;
        }
        if (!ownerValid(owner) || !wellFormedAdvertisingData(data, bytes) ||
            interval < kMinimumInterval || interval > kMaximumInterval)
        {
            return LeAdvertisingResult::InvalidArgument;
        }
        if (!transport.attached || transport.faulted ||
            transport.epoch != owner.epoch || host.ownerEpoch != owner.epoch)
        {
            return LeAdvertisingResult::OwnershipLost;
        }
        // Take a private immutable snapshot before calling external policy.
        // Reserve the state before invoking ANY owner callback: both permit
        // and authorize may synchronously reenter this producer. Until the
        // host has approved the operation, no HCI command is in flight.
        UsbBytes<uint8_t, kLeAdvertisingDataBytes> approved {};
        for (size_t index = 0U; index < bytes; ++index)
        {
            approved.at(index) = *usbByteOffset(data, index);
        }
        clearAdvertising(state);
        const uint64_t activeGeneration = state.generation;
        state.epoch = owner.epoch;
        state.phase = LeAdvertisingPhase::Authorizing;
        const bool permitted = owner.permit(owner.context, owner.epoch);
        if (state.phase != LeAdvertisingPhase::Authorizing ||
            state.epoch != owner.epoch || state.generation != activeGeneration)
        {
            return LeAdvertisingResult::OwnershipLost;
        }
        if (!permitted)
        {
            clearAdvertising(state);
            return LeAdvertisingResult::OwnershipLost;
        }
        if (state.stopRequested)
        {
            clearAdvertising(state);
            return LeAdvertisingResult::Ignored;
        }
        const bool approvedByHost = owner.authorize(
            owner.context, owner.epoch, approved.data(), bytes, interval);
        if (state.phase != LeAdvertisingPhase::Authorizing ||
            state.epoch != owner.epoch || state.generation != activeGeneration)
        {
            return LeAdvertisingResult::OwnershipLost;
        }
        if (!approvedByHost)
        {
            clearAdvertising(state);
            return LeAdvertisingResult::Unauthorized;
        }
        if (state.stopRequested)
        {
            clearAdvertising(state);
            return LeAdvertisingResult::Ignored;
        }
        // Recheck physical transport and both callbacks after authorization.
        // A callback can synchronously detach the old USB function and
        // replace it before returning a stale successful policy result.
        const bool transportLive = transport.attached && !transport.faulted &&
                                   transport.epoch == owner.epoch &&
                                   host.ownerEpoch == owner.epoch;
        const bool stillPermitted =
            transportLive && owner.permit(owner.context, owner.epoch);
        if (state.phase != LeAdvertisingPhase::Authorizing ||
            state.epoch != owner.epoch || state.generation != activeGeneration)
        {
            return LeAdvertisingResult::OwnershipLost;
        }
        if (!stillPermitted)
        {
            clearAdvertising(state);
            return LeAdvertisingResult::OwnershipLost;
        }
        if (state.stopRequested)
        {
            clearAdvertising(state);
            return LeAdvertisingResult::Ignored;
        }
        state.interval = interval;
        state.dataBytes = bytes;
        for (size_t index = 0U; index < bytes; ++index)
        {
            state.data.at(index) = approved.at(index);
        }
        return submitInitialParameters(state, transport, host, owner,
                                       {activeGeneration, interval});
    }

    LeAdvertisingResult endLeAdvertising(LeAdvertisingState &state,
                                         UsbHciState &transport,
                                         const UsbHciHostCallbacks &host,
                                         const LeAdvertisingOwner &owner)
    {
        if (state.phase == LeAdvertisingPhase::Idle)
        {
            return LeAdvertisingResult::NotAdvertising;
        }
        if (state.phase == LeAdvertisingPhase::Faulted)
        {
            return LeAdvertisingResult::Faulted;
        }
        {
            const LeAdvertisingPhase previousPhase = state.phase;
            const uint64_t previousEpoch = state.epoch;
            const uint64_t previousGeneration = state.generation;
            if (!authorized(state, transport, host, owner))
            {
                return lostAuthorization(state, previousPhase, previousEpoch,
                                         previousGeneration);
            }
        }
        if (state.phase == LeAdvertisingPhase::AwaitDisable)
        {
            return LeAdvertisingResult::Busy;
        }
        if (state.phase != LeAdvertisingPhase::Advertising)
        {
            state.stopRequested = true;
            return LeAdvertisingResult::Ok;
        }
        state.phase = LeAdvertisingPhase::AwaitDisable;
        const uint64_t issuedGeneration = state.generation;
        const uint64_t issuedEpoch = state.epoch;
        const bool sent = sendEnable(transport, host, false);
        if (state.generation != issuedGeneration || state.epoch != issuedEpoch)
        {
            // A confirmed inline disable retires the original procedure.
            // A callback that already started a successor must be rejected.
            return sent && state.phase == LeAdvertisingPhase::Idle
                       ? LeAdvertisingResult::Ok
                       : LeAdvertisingResult::OwnershipLost;
        }
        if (!sent)
        {
            return fault(state, LeAdvertisingResult::TransportFailed);
        }
        if (state.phase == LeAdvertisingPhase::Faulted)
        {
            return LeAdvertisingResult::Faulted;
        }
        // A synchronous disable completion legitimately revokes the epoch
        // and returns the producer to Idle before control OUT unwinds.
        if (state.phase == LeAdvertisingPhase::Idle)
        {
            return LeAdvertisingResult::Ok;
        }
        {
            const LeAdvertisingPhase previousPhase = state.phase;
            const uint64_t previousEpoch = state.epoch;
            const uint64_t previousGeneration = state.generation;
            if (!authorized(state, transport, host, owner))
            {
                return lostAuthorization(state, previousPhase, previousEpoch,
                                         previousGeneration);
            }
        }
        return LeAdvertisingResult::Ok;
    }

    LeAdvertisingResult
    acceptLeAdvertisingEvent(LeAdvertisingState &state, UsbHciState &transport,
                             const UsbHciHostCallbacks &host,
                             const LeAdvertisingOwner &owner,
                             const uint8_t *event, size_t bytes)
    {
        if (state.phase == LeAdvertisingPhase::Idle)
        {
            return LeAdvertisingResult::Ignored;
        }
        if (state.phase == LeAdvertisingPhase::Faulted)
        {
            return LeAdvertisingResult::Faulted;
        }
        {
            const LeAdvertisingPhase previousPhase = state.phase;
            const uint64_t previousEpoch = state.epoch;
            const uint64_t previousGeneration = state.generation;
            if (!authorized(state, transport, host, owner))
            {
                return lostAuthorization(state, previousPhase, previousEpoch,
                                         previousGeneration);
            }
        }
        if (event == nullptr || bytes < kHciEventHeaderBytes ||
            bytes > kUsbHciMaxEventBytes ||
            bytes != *usbByteOffset(event, 1U) + kHciEventHeaderBytes)
        {
            return fault(state, LeAdvertisingResult::MalformedEvent);
        }
        const uint8_t type = *usbByteOffset(event, 0U);
        if (type != kCommandComplete && type != kCommandStatus)
        {
            return LeAdvertisingResult::Ignored;
        }
        const uint64_t issuedGeneration = state.generation;
        const uint64_t issuedEpoch = state.epoch;
        const LeAdvertisingResult result = acceptCommandEvent(
            state, transport, host, event, bytes, type == kCommandComplete);
        if (state.generation != issuedGeneration || state.epoch != issuedEpoch)
        {
            return result == LeAdvertisingResult::Ok &&
                           state.phase == LeAdvertisingPhase::Idle
                       ? LeAdvertisingResult::Ok
                       : LeAdvertisingResult::OwnershipLost;
        }
        if (result == LeAdvertisingResult::Ok &&
            state.phase != LeAdvertisingPhase::Idle)
        {
            const LeAdvertisingPhase previousPhase = state.phase;
            const uint64_t previousEpoch = state.epoch;
            const uint64_t previousGeneration = state.generation;
            if (!authorized(state, transport, host, owner))
            {
                return lostAuthorization(state, previousPhase, previousEpoch,
                                         previousGeneration);
            }
        }
        return result;
    }

    void revokeLeAdvertising(LeAdvertisingState &state)
    {
        clearAdvertising(state);
    }
} // namespace simpleath
