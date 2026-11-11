// Offline synthetic HCI USB transport. No physical controller or BLE RF.
#include "bluetooth/LeAdvertising.hpp"
#include "bluetooth/UsbBytes.hpp"
#include "bluetooth/UsbHci.hpp"
#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kOwnerEpoch = 19U;
    constexpr size_t kMaxCommands = 7U;
    constexpr size_t kDiagnosticModulo = 247U;
    constexpr uint16_t kAdvertisingInterval = 0x00a0U;
    constexpr uint16_t kLongAdvertisingInterval = 0x4000U;
    constexpr uint8_t kAdvertParamsOpcode = 0x06U;
    constexpr uint8_t kAdvertDataOpcode = 0x08U;
    constexpr uint8_t kAdvertEnableOpcode = 0x0aU;
    constexpr uint8_t kLeOgf = 0x20U;
    constexpr uint8_t kParametersBytes = 15U;
    constexpr uint8_t kDataBytes = 32U;
    constexpr uint8_t kEnableBytes = 1U;
    constexpr uint8_t kAllChannels = 0x07U;
    constexpr size_t kStatusOpcodeHighOffset = 5U;
    constexpr size_t kChannelMapCommandOffset = 16U;
    constexpr size_t kMaxAdvertLength = 31U;
    constexpr size_t kTruncatedCommandBytes = 5U;
    constexpr std::array<uint8_t, 7U> kAdvertisingData {
        0x02U, 0x01U, 0x06U, 0x03U, 0xffU, 0x11U, 0x22U,
    };
    constexpr std::array<uint8_t, 6U> kParametersComplete {
        0x0eU, 0x04U, 0x01U, 0x06U, 0x20U, 0x00U,
    };
    constexpr std::array<uint8_t, 6U> kDataComplete {
        0x0eU, 0x04U, 0x01U, 0x08U, 0x20U, 0x00U,
    };
    constexpr std::array<uint8_t, 6U> kEnableComplete {
        0x0eU, 0x04U, 0x01U, 0x0aU, 0x20U, 0x00U,
    };
    constexpr std::array<uint8_t, 6U> kParametersStatusSuccess {
        0x0fU, 0x04U, 0x00U, 0x01U, 0x06U, 0x20U,
    };
    constexpr std::array<uint8_t, 6U> kEnableStatusRejected {
        0x0fU, 0x04U, 0x0cU, 0x01U, 0x0aU, 0x20U,
    };
    constexpr std::array<uint8_t, 6U> kDataNoCredit {
        0x0eU, 0x04U, 0x00U, 0x08U, 0x20U, 0x00U,
    };
    constexpr std::array<uint8_t, 6U> kUnrelatedComplete {
        0x0eU, 0x04U, 0x01U, 0x03U, 0x0cU, 0x00U,
    };
    constexpr std::array<uint8_t, 8U> kLongUnrelatedComplete {
        0x0eU, 0x06U, 0x01U, 0x01U, 0x10U, 0x00U, 0x11U, 0x22U,
    };

    enum class InlineReply : uint8_t
    {
        None,
        Complete,
        Rejected,
    };

    struct Fake
    {
            std::array<std::array<uint8_t, kUsbHciMaxCommandBytes>,
                       kMaxCommands>
                commands {};
            std::array<size_t, kMaxCommands> commandSizes {};
            size_t commandCount {};
            size_t authorizations {};
            bool valid {true};
            bool allowAdvertising {true};
            bool revokeOnAuthorization {};
            bool reenterOnAuthorization {};
            bool reenterOnPermit {};
            bool revokeStateOnPermit {};
            bool replaceSamePhaseOnPermit {};
            LeAdvertisingResult (*replaceSamePhase)(void *) {};
            bool stopOnAuthorization {};
            bool revokeStateOnAuthorization {};
            void *reentryContext {};
            LeAdvertisingResult (*reenter)(void *) {};
            LeAdvertisingResult (*stop)(void *) {};
            void (*revokeState)(void *) {};
            LeAdvertisingResult reentryResult {LeAdvertisingResult::Ignored};
            LeAdvertisingResult stopResult {LeAdvertisingResult::Ignored};
            bool failCommand {};
            const LeAdvertisingPhase *pendingPhase {};
            InlineReply inlineReply {InlineReply::None};
            void *inlineContext {};
            bool (*inlineEvent)(void *, const uint8_t *, size_t) {};
    };

    bool permit(void *context, uint64_t epoch)
    {
        auto &fake = *static_cast<Fake *>(context);
        if (fake.revokeStateOnPermit && fake.revokeState != nullptr)
        {
            fake.revokeStateOnPermit = false;
            fake.revokeState(fake.reentryContext);
        }
        if (fake.replaceSamePhaseOnPermit && fake.replaceSamePhase != nullptr)
        {
            fake.replaceSamePhaseOnPermit = false;
            fake.reentryResult = fake.replaceSamePhase(fake.reentryContext);
        }
        if (fake.reenterOnPermit && fake.reenter != nullptr)
        {
            fake.reenterOnPermit = false;
            fake.reentryResult = fake.reenter(fake.reentryContext);
        }
        return fake.valid && epoch == kOwnerEpoch;
    }

    bool authorize(void *context, uint64_t epoch, const uint8_t *data,
                   size_t bytes, uint16_t interval)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.authorizations;
        if (fake.reenterOnAuthorization && fake.reenter != nullptr)
        {
            fake.reenterOnAuthorization = false;
            fake.reentryResult = fake.reenter(fake.reentryContext);
        }
        if (fake.stopOnAuthorization && fake.stop != nullptr)
        {
            fake.stopOnAuthorization = false;
            fake.stopResult = fake.stop(fake.reentryContext);
        }
        if (fake.revokeStateOnAuthorization && fake.revokeState != nullptr)
        {
            fake.revokeStateOnAuthorization = false;
            fake.revokeState(fake.reentryContext);
        }
        if (fake.revokeOnAuthorization)
        {
            fake.valid = false;
        }
        return fake.allowAdvertising && epoch == kOwnerEpoch &&
               data != nullptr && bytes == kAdvertisingData.size() &&
               interval == kAdvertisingInterval;
    }

    bool command(void *context, const uint8_t *data, size_t bytes)
    {
        auto &fake = *static_cast<Fake *>(context);
        if (fake.failCommand || data == nullptr || bytes < 3U ||
            bytes > kUsbHciMaxCommandBytes || fake.commandCount >= kMaxCommands)
        {
            return false;
        }
        // The HCI controller could synchronously complete a submitted
        // command. Observe state at the actual USB callback boundary, not
        // after send() has already returned to the producer.
        if (fake.pendingPhase == nullptr || bytes < 4U)
        {
            return false;
        }
        const uint8_t opcode = *usbByteOffset(data, 0U);
        LeAdvertisingPhase expected = LeAdvertisingPhase::Faulted;
        if (opcode == kAdvertParamsOpcode)
        {
            expected = LeAdvertisingPhase::AwaitParameters;
        }
        else if (opcode == kAdvertDataOpcode)
        {
            expected = LeAdvertisingPhase::AwaitData;
        }
        else if (opcode == kAdvertEnableOpcode)
        {
            expected = *usbByteOffset(data, 3U) == 0U
                           ? LeAdvertisingPhase::AwaitDisable
                           : LeAdvertisingPhase::AwaitEnable;
        }
        if (*fake.pendingPhase != expected)
        {
            return false;
        }
        for (size_t index = 0U; index < bytes; ++index)
        {
            fake.commands.at(fake.commandCount).at(index) =
                *usbByteOffset(data, index);
        }
        fake.commandSizes.at(fake.commandCount) = bytes;
        ++fake.commandCount;
        const InlineReply reply = fake.inlineReply;
        fake.inlineReply = InlineReply::None;
        if (reply == InlineReply::None)
        {
            return true;
        }
        if (fake.inlineEvent == nullptr)
        {
            return false;
        }
        auto response = reply == InlineReply::Rejected ? kEnableStatusRejected
                                                       : kParametersComplete;
        if (reply == InlineReply::Rejected)
        {
            response.at(4U) = *usbByteOffset(data, 0U);
            response.at(kStatusOpcodeHighOffset) = *usbByteOffset(data, 1U);
        }
        else
        {
            response.at(3U) = *usbByteOffset(data, 0U);
            response.at(4U) = *usbByteOffset(data, 1U);
        }
        // Inject a real controller event while the USB control OUT callback
        // is on the stack, as a synchronous HCI host is allowed to do.
        return fake.inlineEvent(fake.inlineContext, response.data(),
                                response.size());
    }

    bool acl(void * /*context*/, uint8_t /*endpoint*/,
             const uint8_t * /*packet*/, size_t /*bytes*/,
             size_t * /*transferred*/)
    {
        return false;
    }

    bool deliver(void * /*context*/, UsbHciPacketKind kind,
                 const uint8_t *packet, size_t bytes)
    {
        return kind == UsbHciPacketKind::Event && packet != nullptr &&
               bytes != 0U;
    }

    class Fixture
    {
            Fake fake_ {};
            UsbHciState transport_ {};
            LeAdvertisingState advertising_ {};

        public:
            static LeAdvertisingResult reenterBegin(void *context)
            {
                return static_cast<Fixture *>(context)->begin();
            }

            static LeAdvertisingResult replaceAwaitParameters(void *context)
            {
                auto &fixture = *static_cast<Fixture *>(context);
                // Retire the advertising producer without resetting USB.
                // Then consume its old command response and start a new
                // operation on the SAME physical epoch and pending phase.
                fixture.revoke();
                if (receiveUsbHciEvent(fixture.transport_, fixture.host(),
                                       kParametersComplete.data(),
                                       kParametersComplete.size()) !=
                    UsbHciStatus::Ok)
                {
                    return LeAdvertisingResult::Faulted;
                }
                return fixture.begin();
            }

            static LeAdvertisingResult stopDuringAuthorization(void *context)
            {
                return static_cast<Fixture *>(context)->stop();
            }

            static void revokeDuringAuthorization(void *context)
            {
                static_cast<Fixture *>(context)->revoke();
            }

            static bool deliverInline(void *context, const uint8_t *event,
                                      size_t bytes)
            {
                auto &fixture = *static_cast<Fixture *>(context);
                if (receiveUsbHciEvent(fixture.transport_, fixture.host(),
                                       event, bytes) != UsbHciStatus::Ok)
                {
                    return false;
                }
                const LeAdvertisingResult result = acceptLeAdvertisingEvent(
                    fixture.advertising_, fixture.transport_, fixture.host(),
                    fixture.owner(), event, bytes);
                return result == LeAdvertisingResult::Ok ||
                       result == LeAdvertisingResult::ControllerRejected;
            }

            Fake &fake()
            {
                return fake_;
            }

            LeAdvertisingPhase phase() const
            {
                return advertising_.phase;
            }

            bool stopRequested() const
            {
                return advertising_.stopRequested;
            }

            uint64_t epoch() const
            {
                return advertising_.epoch;
            }

            void exhaustGeneration()
            {
                advertising_.generation = UINT64_MAX;
            }

            LeAdvertisingOwner owner()
            {
                return {&fake_, kOwnerEpoch, permit, authorize};
            }

            UsbHciHostCallbacks host()
            {
                return {&fake_, kOwnerEpoch, permit, command, acl, deliver};
            }

            bool attach()
            {
                fake_.pendingPhase = &advertising_.phase;
                fake_.inlineContext = this;
                fake_.inlineEvent = deliverInline;
                const UsbHciEndpoints endpoints {0x81U, 0x82U, 0x02U};
                return attachUsbHci(transport_, endpoints, host()) ==
                       UsbHciStatus::Ok;
            }

            LeAdvertisingResult
            begin(const uint8_t *data = kAdvertisingData.data(),
                  size_t bytes = kAdvertisingData.size(),
                  uint16_t interval = kAdvertisingInterval)
            {
                return beginLeAdvertising(advertising_, transport_, host(),
                                          owner(), data, bytes, interval);
            }

            LeAdvertisingResult accept(const uint8_t *data, size_t bytes)
            {
                // Account BOTH preliminary Status and final Complete in the
                // same USB stream before dispatching to the LE producer.
                constexpr size_t kResponseBytes = 6U;
                constexpr size_t kCompleteOpcode = 3U;
                constexpr size_t kStatusOpcode = 4U;
                constexpr unsigned kOpcodeShift = 8U;
                constexpr uint8_t kCompleteCode = 0x0eU;
                constexpr uint8_t kStatusCode = 0x0fU;
                if (data != nullptr && bytes == kResponseBytes)
                {
                    const uint8_t code = *usbByteOffset(data, 0U);
                    if (code == kCompleteCode || code == kStatusCode)
                    {
                        const size_t offset = code == kCompleteCode
                                                  ? kCompleteOpcode
                                                  : kStatusOpcode;
                        const auto opcode = static_cast<uint16_t>(
                            static_cast<uint32_t>(
                                *usbByteOffset(data, offset)) |
                            (static_cast<uint32_t>(
                                 *usbByteOffset(data, offset + 1U))
                             << kOpcodeShift));
                        if (transport_.commandWindow.pending &&
                            opcode == transport_.commandWindow.pendingOpcode &&
                            receiveUsbHciEvent(transport_, host(), data,
                                               bytes) != UsbHciStatus::Ok)
                        {
                            return LeAdvertisingResult::TransportFailed;
                        }
                    }
                }
                return acceptLeAdvertisingEvent(advertising_, transport_,
                                                host(), owner(), data, bytes);
            }

            LeAdvertisingResult completeParameters()
            {
                return accept(kParametersComplete.data(),
                              kParametersComplete.size());
            }

            LeAdvertisingResult completeData()
            {
                return accept(kDataComplete.data(), kDataComplete.size());
            }

            LeAdvertisingResult completeEnable()
            {
                return accept(kEnableComplete.data(), kEnableComplete.size());
            }

            bool start()
            {
                return attach() && begin() == LeAdvertisingResult::Ok &&
                       completeParameters() == LeAdvertisingResult::Ok &&
                       completeData() == LeAdvertisingResult::Ok &&
                       completeEnable() == LeAdvertisingResult::Ok &&
                       phase() == LeAdvertisingPhase::Advertising;
            }

            LeAdvertisingResult stop()
            {
                return endLeAdvertising(advertising_, transport_, host(),
                                        owner());
            }

            LeAdvertisingResult observeProducerEvent(const uint8_t *data,
                                                     size_t bytes)
            {
                return acceptLeAdvertisingEvent(advertising_, transport_,
                                                host(), owner(), data, bytes);
            }

            void revoke()
            {
                revokeLeAdvertising(advertising_);
            }
    };

    int normalLifecycle()
    {
        Fixture f {};
        if (!f.attach() || f.begin() != LeAdvertisingResult::Ok ||
            f.fake().authorizations != 1U || f.fake().commandCount != 1U ||
            f.phase() != LeAdvertisingPhase::AwaitParameters ||
            f.fake().commandSizes.at(0U) != kParametersBytes + 3U ||
            f.fake().commands.at(0U).at(0U) != kAdvertParamsOpcode ||
            f.fake().commands.at(0U).at(1U) != kLeOgf ||
            f.fake().commands.at(0U).at(3U) !=
                static_cast<uint8_t>(kAdvertisingInterval) ||
            f.fake().commands.at(0U).at(kChannelMapCommandOffset) !=
                kAllChannels ||
            f.begin() != LeAdvertisingResult::Busy)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (f.accept(kUnrelatedComplete.data(), kUnrelatedComplete.size()) !=
                LeAdvertisingResult::Ignored ||
            f.accept(kLongUnrelatedComplete.data(),
                     kLongUnrelatedComplete.size()) !=
                LeAdvertisingResult::Ignored ||
            f.accept(kParametersStatusSuccess.data(),
                     kParametersStatusSuccess.size()) !=
                LeAdvertisingResult::Ignored ||
            f.phase() != LeAdvertisingPhase::AwaitParameters ||
            f.completeParameters() != LeAdvertisingResult::Ok ||
            f.phase() != LeAdvertisingPhase::AwaitData ||
            f.fake().commandCount != 2U ||
            f.fake().commandSizes.at(1U) != kDataBytes + 3U ||
            f.fake().commands.at(1U).at(0U) != kAdvertDataOpcode ||
            f.fake().commands.at(1U).at(3U) != kAdvertisingData.size())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        for (size_t index = 0U; index < kAdvertisingData.size(); ++index)
        {
            if (f.fake().commands.at(1U).at(index + 4U) !=
                kAdvertisingData.at(index))
            {
                return (__LINE__ % kDiagnosticModulo) + 1;
            }
        }
        if (f.fake().commands.at(1U).at(kMaxAdvertLength + 3U) != 0U ||
            f.completeData() != LeAdvertisingResult::Ok ||
            f.phase() != LeAdvertisingPhase::AwaitEnable ||
            f.fake().commandCount != 3U ||
            f.fake().commandSizes.at(2U) != kEnableBytes + 3U ||
            f.fake().commands.at(2U).at(0U) != kAdvertEnableOpcode ||
            f.fake().commands.at(2U).at(3U) != 1U ||
            f.completeEnable() != LeAdvertisingResult::Ok ||
            f.phase() != LeAdvertisingPhase::Advertising)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (f.stop() != LeAdvertisingResult::Ok ||
            f.phase() != LeAdvertisingPhase::AwaitDisable ||
            f.fake().commandCount != 4U ||
            f.fake().commands.at(3U).at(3U) != 0U ||
            f.stop() != LeAdvertisingResult::Busy ||
            f.completeEnable() != LeAdvertisingResult::Ok ||
            f.phase() != LeAdvertisingPhase::Idle || f.epoch() != 0U ||
            f.stop() != LeAdvertisingResult::NotAdvertising)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int cancellation()
    {
        Fixture early {};
        if (!early.attach() || early.begin() != LeAdvertisingResult::Ok ||
            early.stop() != LeAdvertisingResult::Ok || !early.stopRequested() ||
            early.completeParameters() != LeAdvertisingResult::Ok ||
            early.phase() != LeAdvertisingPhase::Idle ||
            early.fake().commandCount != 1U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture data {};
        if (!data.attach() || data.begin() != LeAdvertisingResult::Ok ||
            data.completeParameters() != LeAdvertisingResult::Ok ||
            data.stop() != LeAdvertisingResult::Ok ||
            data.completeData() != LeAdvertisingResult::Ok ||
            data.phase() != LeAdvertisingPhase::Idle ||
            data.fake().commandCount != 2U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture enabled {};
        if (!enabled.attach() || enabled.begin() != LeAdvertisingResult::Ok ||
            enabled.completeParameters() != LeAdvertisingResult::Ok ||
            enabled.completeData() != LeAdvertisingResult::Ok ||
            enabled.stop() != LeAdvertisingResult::Ok ||
            enabled.completeEnable() != LeAdvertisingResult::Ok ||
            enabled.phase() != LeAdvertisingPhase::AwaitDisable ||
            enabled.fake().commandCount != 4U ||
            enabled.fake().commands.at(3U).at(3U) != 0U ||
            enabled.completeEnable() != LeAdvertisingResult::Ok ||
            enabled.phase() != LeAdvertisingPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int validation()
    {
        Fixture f {};
        constexpr std::array<uint8_t, 3U> kTruncated {
            0x03U,
            0x01U,
            0x06U,
        };
        constexpr std::array<uint8_t, 1U> kZeroLength {0x00U};
        if (!f.attach() ||
            f.begin(nullptr, kAdvertisingData.size()) !=
                LeAdvertisingResult::InvalidArgument ||
            f.begin(kTruncated.data(), kTruncated.size()) !=
                LeAdvertisingResult::InvalidArgument ||
            f.begin(kZeroLength.data(), kZeroLength.size()) !=
                LeAdvertisingResult::InvalidArgument ||
            f.begin(kAdvertisingData.data(), kMaxAdvertLength + 1U) !=
                LeAdvertisingResult::InvalidArgument ||
            f.begin(kAdvertisingData.data(), 0U) !=
                LeAdvertisingResult::InvalidArgument ||
            f.begin(kAdvertisingData.data(), kAdvertisingData.size(),
                    kAdvertisingInterval - 1U) !=
                LeAdvertisingResult::InvalidArgument ||
            f.begin(kAdvertisingData.data(), kAdvertisingData.size(),
                    kLongAdvertisingInterval + 1U) !=
                LeAdvertisingResult::InvalidArgument ||
            f.fake().commandCount != 0U || f.fake().authorizations != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        f.fake().allowAdvertising = false;
        if (f.begin() != LeAdvertisingResult::Unauthorized ||
            f.fake().commandCount != 0U ||
            f.phase() != LeAdvertisingPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        f.fake().allowAdvertising = true;
        f.fake().revokeOnAuthorization = true;
        if (f.begin() != LeAdvertisingResult::OwnershipLost ||
            f.fake().commandCount != 0U ||
            f.phase() != LeAdvertisingPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int policyReentry()
    {
        Fixture fixture {};
        if (!fixture.attach())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        fixture.fake().reenterOnAuthorization = true;
        fixture.fake().reentryContext = &fixture;
        fixture.fake().reenter = Fixture::reenterBegin;
        // An external host authorization can synchronously reenter the LE
        // producer. It must not start a second controller procedure while
        // the original request is still being authorized.
        if (fixture.begin() != LeAdvertisingResult::Ok ||
            fixture.fake().reentryResult != LeAdvertisingResult::Busy ||
            fixture.fake().commandCount != 1U ||
            fixture.phase() != LeAdvertisingPhase::AwaitParameters ||
            fixture.completeParameters() != LeAdvertisingResult::Ok ||
            fixture.phase() != LeAdvertisingPhase::AwaitData)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture earlyPermit {};
        if (!earlyPermit.attach())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        earlyPermit.fake().reenterOnPermit = true;
        earlyPermit.fake().reentryContext = &earlyPermit;
        earlyPermit.fake().reenter = Fixture::reenterBegin;
        if (earlyPermit.begin() != LeAdvertisingResult::Ok ||
            earlyPermit.fake().reentryResult != LeAdvertisingResult::Busy ||
            earlyPermit.fake().commandCount != 1U ||
            earlyPermit.phase() != LeAdvertisingPhase::AwaitParameters)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture canceled {};
        if (!canceled.attach())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        canceled.fake().stopOnAuthorization = true;
        canceled.fake().stop = Fixture::stopDuringAuthorization;
        canceled.fake().reentryContext = &canceled;
        if (canceled.begin() != LeAdvertisingResult::Ignored ||
            canceled.fake().stopResult != LeAdvertisingResult::Ok ||
            canceled.fake().commandCount != 0U ||
            canceled.phase() != LeAdvertisingPhase::Idle ||
            canceled.epoch() != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture revoked {};
        if (!revoked.attach())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        revoked.fake().revokeStateOnAuthorization = true;
        revoked.fake().revokeState = Fixture::revokeDuringAuthorization;
        revoked.fake().reentryContext = &revoked;
        if (revoked.begin() != LeAdvertisingResult::OwnershipLost ||
            revoked.fake().commandCount != 0U ||
            revoked.phase() != LeAdvertisingPhase::Idle ||
            revoked.epoch() != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int inlineControllerResponses()
    {
        Fixture rejectedBegin {};
        rejectedBegin.fake().inlineReply = InlineReply::Rejected;
        if (!rejectedBegin.attach() ||
            rejectedBegin.begin() != LeAdvertisingResult::Faulted ||
            rejectedBegin.phase() != LeAdvertisingPhase::Faulted ||
            rejectedBegin.fake().commandCount != 1U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture acceptedBegin {};
        acceptedBegin.fake().inlineReply = InlineReply::Complete;
        if (!acceptedBegin.attach() ||
            acceptedBegin.begin() != LeAdvertisingResult::Ok ||
            acceptedBegin.phase() != LeAdvertisingPhase::AwaitData ||
            acceptedBegin.fake().commandCount != 2U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture rejectedAdvance {};
        if (!rejectedAdvance.attach() ||
            rejectedAdvance.begin() != LeAdvertisingResult::Ok)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        rejectedAdvance.fake().inlineReply = InlineReply::Rejected;
        if (rejectedAdvance.completeParameters() !=
                LeAdvertisingResult::Faulted ||
            rejectedAdvance.phase() != LeAdvertisingPhase::Faulted ||
            rejectedAdvance.fake().commandCount != 2U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture rejectedDisable {};
        if (!rejectedDisable.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        rejectedDisable.fake().inlineReply = InlineReply::Rejected;
        if (rejectedDisable.stop() != LeAdvertisingResult::Faulted ||
            rejectedDisable.phase() != LeAdvertisingPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture completedDisable {};
        if (!completedDisable.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        completedDisable.fake().inlineReply = InlineReply::Complete;
        if (completedDisable.stop() != LeAdvertisingResult::Ok ||
            completedDisable.phase() != LeAdvertisingPhase::Idle ||
            completedDisable.epoch() != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int revokedInsidePermit()
    {
        // An owner may cancel its session synchronously while granting the
        // callback. No caller may reactivate or fault its already-retired
        // Idle state, or issue a late controller disable through old rights.
        Fixture stopping {};
        if (!stopping.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        stopping.fake().revokeStateOnPermit = true;
        stopping.fake().revokeState = Fixture::revokeDuringAuthorization;
        stopping.fake().reentryContext = &stopping;
        if (stopping.stop() != LeAdvertisingResult::OwnershipLost ||
            stopping.phase() != LeAdvertisingPhase::Idle ||
            stopping.epoch() != 0U || stopping.stopRequested() ||
            stopping.fake().commandCount != 3U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture receiving {};
        if (!receiving.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        receiving.fake().revokeStateOnPermit = true;
        receiving.fake().revokeState = Fixture::revokeDuringAuthorization;
        receiving.fake().reentryContext = &receiving;
        if (receiving.observeProducerEvent(kUnrelatedComplete.data(),
                                           kUnrelatedComplete.size()) !=
                LeAdvertisingResult::OwnershipLost ||
            receiving.phase() != LeAdvertisingPhase::Idle ||
            receiving.epoch() != 0U || receiving.fake().commandCount != 3U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int exhaustedSessionGeneration()
    {
        Fixture fixture {};
        if (!fixture.attach())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        fixture.exhaustGeneration();
        if (fixture.begin() != LeAdvertisingResult::Faulted ||
            fixture.fake().commandCount != 0U ||
            fixture.phase() != LeAdvertisingPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        fixture.revoke();
        return fixture.begin() == LeAdvertisingResult::Faulted &&
                       fixture.fake().commandCount == 0U
                   ? 0
                   : (__LINE__ % kDiagnosticModulo) + 1;
    }

    int sameEpochPhaseReplacement()
    {
        Fixture fixture {};
        if (!fixture.attach() || fixture.begin() != LeAdvertisingResult::Ok ||
            fixture.phase() != LeAdvertisingPhase::AwaitParameters)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        fixture.fake().replaceSamePhaseOnPermit = true;
        fixture.fake().replaceSamePhase = Fixture::replaceAwaitParameters;
        fixture.fake().reentryContext = &fixture;
        // Phase and physical epoch match the old operation after reentry.
        // A stale outer stop must NOT cancel the successor's live setup.
        return fixture.stop() == LeAdvertisingResult::OwnershipLost &&
                       fixture.fake().reentryResult ==
                           LeAdvertisingResult::Ok &&
                       fixture.phase() == LeAdvertisingPhase::AwaitParameters &&
                       fixture.epoch() == kOwnerEpoch &&
                       !fixture.stopRequested() &&
                       fixture.fake().commandCount == 2U
                   ? 0
                   : (__LINE__ % kDiagnosticModulo) + 1;
    }

    int errorsAndOwnership()
    {
        Fixture failed {};
        failed.fake().failCommand = true;
        if (!failed.attach() ||
            failed.begin() != LeAdvertisingResult::TransportFailed ||
            failed.phase() != LeAdvertisingPhase::Faulted ||
            failed.stop() != LeAdvertisingResult::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture controller {};
        if (!controller.attach() ||
            controller.begin() != LeAdvertisingResult::Ok ||
            controller.completeParameters() != LeAdvertisingResult::Ok ||
            controller.completeData() != LeAdvertisingResult::Ok ||
            controller.accept(kEnableStatusRejected.data(),
                              kEnableStatusRejected.size()) !=
                LeAdvertisingResult::ControllerRejected ||
            controller.phase() != LeAdvertisingPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture credits {};
        if (!credits.attach() || credits.begin() != LeAdvertisingResult::Ok ||
            credits.completeParameters() != LeAdvertisingResult::Ok ||
            credits.accept(kDataNoCredit.data(), kDataNoCredit.size()) !=
                LeAdvertisingResult::CommandCreditUnavailable ||
            credits.phase() != LeAdvertisingPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture malformed {};
        if (!malformed.attach() ||
            malformed.begin() != LeAdvertisingResult::Ok ||
            malformed.accept(kParametersComplete.data(),
                             kTruncatedCommandBytes) !=
                LeAdvertisingResult::MalformedEvent ||
            malformed.phase() != LeAdvertisingPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture revoked {};
        if (!revoked.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        revoked.fake().valid = false;
        if (revoked.stop() != LeAdvertisingResult::OwnershipLost ||
            revoked.phase() != LeAdvertisingPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        revoked.revoke();
        if (revoked.phase() != LeAdvertisingPhase::Idle ||
            revoked.epoch() != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }
} // namespace

int main()
{
    if (const int valid = normalLifecycle())
    {
        return valid;
    }
    if (const int cancelled = cancellation())
    {
        return cancelled;
    }
    if (const int rejected = validation())
    {
        return rejected;
    }
    if (const int reentry = policyReentry())
    {
        return reentry;
    }
    if (const int revoked = revokedInsidePermit())
    {
        return revoked;
    }
    if (const int exhausted = exhaustedSessionGeneration())
    {
        return exhausted;
    }
    if (const int replaced = sameEpochPhaseReplacement())
    {
        return replaced;
    }
    if (const int inlineResult = inlineControllerResponses())
    {
        return inlineResult;
    }
    return errorsAndOwnership();
}
