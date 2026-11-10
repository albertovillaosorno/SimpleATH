// SPDX-License-Identifier: AGPL-3.0-only
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
            bool failCommand {};
            const LeAdvertisingPhase *pendingPhase {};
            InlineReply inlineReply {InlineReply::None};
            void *inlineContext {};
            bool (*inlineEvent)(void *, const uint8_t *, size_t) {};
    };

    bool permit(void *context, uint64_t epoch)
    {
        const auto &fake = *static_cast<Fake *>(context);
        return fake.valid && epoch == kOwnerEpoch;
    }

    bool authorize(void *context, uint64_t epoch, const uint8_t *data,
                   size_t bytes, uint16_t interval)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.authorizations;
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
    if (const int inlineResult = inlineControllerResponses())
    {
        return inlineResult;
    }
    return errorsAndOwnership();
}
