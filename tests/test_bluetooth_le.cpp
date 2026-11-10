// SPDX-License-Identifier: GPL-2.0-only
// Offline legacy BLE controller scan tests. No Bluetooth hardware or host API.
#include "bluetooth/LeDiscovery.hpp"
#include "bluetooth/UsbBytes.hpp"
#include "bluetooth/UsbHci.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 501U;
    constexpr uint16_t kInterval = 0x00a0U;
    constexpr uint16_t kWindow = 0x0050U;
    constexpr uint8_t kAdByte = 0x02U;
    constexpr uint8_t kFirstAddress = 0xa1U;
    constexpr int8_t kRssi = -45;
    constexpr size_t kMaxCommands = 8U;
    constexpr int kDiagnosticModulo = 250;
    constexpr size_t kMultiReportBytes = 30U;
    constexpr size_t kFirstReportOffset = 4U;
    constexpr size_t kSecondReportOffset = 17U;
    constexpr size_t kReportPayloadBytes = 13U;
    constexpr size_t kReportDataLengthOffset = 8U;
    constexpr uint8_t kMultiEventPayloadBytes = 28U;
    constexpr uint8_t kTwoReports = 2U;
    constexpr uint8_t kLeMetaType = 0x3eU;
    constexpr size_t kParameterCommandBytes = 10U;
    constexpr size_t kScanWindowLsbOffset = 6U;
    constexpr size_t kAdvertDataLengthOffset = 12U;
    constexpr uint8_t kParamsOpcode = 0x0bU;
    constexpr uint8_t kEnableOpcode = 0x0cU;
    constexpr uint8_t kEventPayloadBytes = 0x0fU;
    constexpr uint8_t kOverlongAdvertBytes = 0x20U;
    constexpr uint8_t kIntervalLsb = 0xa0U;
    constexpr uint8_t kWindowLsb = 0x50U;

    enum class InlineReply : uint8_t
    {
        None,
        Complete,
        Rejected,
    };

    constexpr size_t kInlineResponseBytes = 6U;
    constexpr uint8_t kInlineStatusCode = 0x0fU;
    constexpr uint8_t kInlineCompleteCode = 0x0eU;
    constexpr uint8_t kInlineRejectedStatus = 0x0cU;

    struct Fake
    {
            std::array<std::array<uint8_t, kUsbHciMaxCommandBytes>,
                       kMaxCommands>
                commands {};
            std::array<size_t, kMaxCommands> commandSizes {};
            size_t commandCount {};
            size_t reports {};
            size_t deliveredBytes {};
            size_t hostDeliveredEvents {};
            size_t aclTransfers {};
            uint8_t observedAddress {};
            int8_t observedRssi {};
            bool valid {true};
            bool failCommand {};
            const LeScanPhase *pendingPhase {};
            InlineReply inlineReply {InlineReply::None};
            void *inlineContext {};
            bool (*inlineEvent)(void *, const uint8_t *, size_t) {};
            bool failAdvertisement {};
            bool revokeOnAdvertisement {};
            bool reboundEpoch {};
            void *reportContext {};
            bool (*onFirstReport)(void *) {};
            bool allowActiveScan {true};
            bool revokeOnActiveAuthorization {};
            size_t activeAuthorizations {};
            uint8_t expectedEventType {};
            uint8_t expectedAdByte {kAdByte};
    };

    uint64_t activeEpoch(const Fake &fake)
    {
        return fake.reboundEpoch ? kEpoch + 1U : kEpoch;
    }

    bool authorizeActive(void *context, uint64_t epoch, uint16_t interval,
                         uint16_t window)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.activeAuthorizations;
        if (fake.revokeOnActiveAuthorization)
        {
            fake.valid = false;
        }
        return fake.allowActiveScan && epoch == activeEpoch(fake) &&
               interval == kInterval && window == kWindow;
    }

    bool permit(void *context, uint64_t epoch)
    {
        const auto &fake = *static_cast<Fake *>(context);
        return fake.valid && epoch == activeEpoch(fake);
    }

    bool sendCommand(void *context, const uint8_t *packet, size_t bytes)
    {
        auto &fake = *static_cast<Fake *>(context);
        if (fake.failCommand || packet == nullptr ||
            fake.commandCount >= kMaxCommands)
        {
            return false;
        }
        // Controller/HCI host callbacks may complete a command inline.
        // The producer must publish its pending phase before USB control OUT.
        if (fake.pendingPhase == nullptr || bytes < 4U)
        {
            return false;
        }
        const uint8_t opcode = *usbByteOffset(packet, 0U);
        LeScanPhase expected = LeScanPhase::Faulted;
        if (opcode == kParamsOpcode)
        {
            expected = LeScanPhase::AwaitParameters;
        }
        else if (opcode == kEnableOpcode)
        {
            expected = *usbByteOffset(packet, 3U) == 0U
                           ? LeScanPhase::AwaitDisable
                           : LeScanPhase::AwaitEnable;
        }
        if (*fake.pendingPhase != expected)
        {
            return false;
        }
        for (size_t index = 0U; index < bytes; ++index)
        {
            fake.commands.at(fake.commandCount).at(index) =
                *usbByteOffset(packet, index);
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
        std::array<uint8_t, kInlineResponseBytes> response {};
        response.at(0U) = reply == InlineReply::Rejected ? kInlineStatusCode
                                                         : kInlineCompleteCode;
        response.at(1U) = 0x04U;
        response.at(2U) =
            reply == InlineReply::Rejected ? kInlineRejectedStatus : 0x01U;
        response.at(3U) =
            reply == InlineReply::Rejected ? 0x01U : *usbByteOffset(packet, 0U);
        response.at(4U) = reply == InlineReply::Rejected
                              ? *usbByteOffset(packet, 0U)
                              : *usbByteOffset(packet, 1U);
        response.at(kInlineResponseBytes - 1U) =
            reply == InlineReply::Rejected ? *usbByteOffset(packet, 1U) : 0U;
        // Controller responses may be dispatched before USB OUT returns.
        return fake.inlineEvent(fake.inlineContext, response.data(),
                                response.size());
    }

    bool aclOut(void *context, uint8_t endpoint, const uint8_t *packet,
                size_t bytes, size_t *transferred)
    {
        if (context == nullptr || packet == nullptr || transferred == nullptr ||
            endpoint == 0U || bytes == 0U)
        {
            return false;
        }
        *transferred = bytes;
        auto &fake = *static_cast<Fake *>(context);
        ++fake.aclTransfers;
        return fake.valid;
    }

    bool deliver(void *context, UsbHciPacketKind kind, const uint8_t *packet,
                 size_t bytes)
    {
        if (context == nullptr || kind != UsbHciPacketKind::Event ||
            packet == nullptr || bytes == 0U)
        {
            return false;
        }
        auto &fake = *static_cast<Fake *>(context);
        ++fake.hostDeliveredEvents;
        return fake.valid;
    }

    bool observe(void *context, uint64_t epoch,
                 const LeLegacyAdvertisement &advertisement)
    {
        auto &fake = *static_cast<Fake *>(context);
        if (fake.failAdvertisement || epoch != activeEpoch(fake) ||
            advertisement.dataBytes != 3U ||
            advertisement.data.at(0U) != fake.expectedAdByte ||
            advertisement.eventType != fake.expectedEventType ||
            advertisement.addressType != 1U)
        {
            return false;
        }
        ++fake.reports;
        fake.deliveredBytes += advertisement.dataBytes;
        fake.observedAddress = advertisement.address.at(0U);
        fake.observedRssi = advertisement.rssi;
        if (fake.revokeOnAdvertisement)
        {
            fake.valid = false;
        }
        if (fake.reports == 1U && fake.onFirstReport != nullptr)
        {
            return fake.onFirstReport(fake.reportContext);
        }
        return true;
    }

    UsbHciHostCallbacks hostFor(Fake &fake)
    {
        return {&fake, activeEpoch(fake), permit, sendCommand, aclOut, deliver};
    }

    LeDiscoveryOwner ownerFor(Fake &fake)
    {
        return {&fake, activeEpoch(fake), permit, observe};
    }

    // Command Complete: one command credit + the echoed 16-bit opcode.
    constexpr std::array<uint8_t, 6> kParamsComplete = {
        0x0eU, 0x04U, 0x01U, 0x0bU, 0x20U, 0x00U,
    };
    constexpr std::array<uint8_t, 6> kEnableComplete = {
        0x0eU, 0x04U, 0x01U, 0x0cU, 0x20U, 0x00U,
    };
    constexpr std::array<uint8_t, 6> kZeroCredits = {
        0x0eU, 0x04U, 0x00U, 0x0bU, 0x20U, 0x00U,
    };
    constexpr std::array<uint8_t, 6> kRejected = {
        0x0eU, 0x04U, 0x01U, 0x0bU, 0x20U, 0x0cU,
    };
    constexpr std::array<uint8_t, 6> kUnrelatedComplete = {
        0x0eU, 0x04U, 0x01U, 0x05U, 0x10U, 0x00U,
    };
    constexpr std::array<uint8_t, 6> kParamsStatusRejected = {
        0x0fU, 0x04U, 0x0cU, 0x01U, 0x0bU, 0x20U,
    };
    constexpr std::array<uint8_t, 6> kEnableStatusRejected = {
        0x0fU, 0x04U, 0x0cU, 0x01U, 0x0cU, 0x20U,
    };
    constexpr std::array<uint8_t, 6> kParamsStatusSuccess = {
        0x0fU, 0x04U, 0x00U, 0x01U, 0x0bU, 0x20U,
    };
    constexpr std::array<uint8_t, 6> kParamsStatusNoCredits = {
        0x0fU, 0x04U, 0x00U, 0x00U, 0x0bU, 0x20U,
    };
    constexpr std::array<uint8_t, 6> kUnrelatedStatus = {
        0x0fU, 0x04U, 0x0cU, 0x01U, 0x05U, 0x10U,
    };
    constexpr std::array<uint8_t, 18> kAdvertisement = {
        0x3eU, 0x10U, 0x02U, 0x01U, 0x00U, 0x01U, 0xa1U, 0xa2U, 0xa3U,
        0xa4U, 0xa5U, 0xa6U, 0x03U, 0x02U, 0x01U, 0x06U, 0xd3U, 0x00U,
    };

    class Fixture
    {
            Fake fake_ {};
            UsbHciState transport_ {};
            LeDiscoveryState scan_ {};

        public:
            static bool stopDuringReport(void *context)
            {
                auto &fixture = *static_cast<Fixture *>(context);
                return fixture.stop() == LeDiscoveryResult::Ok;
            }

            static bool revokeDuringReport(void *context)
            {
                auto &fixture = *static_cast<Fixture *>(context);
                fixture.revoke();
                return true;
            }

            static bool rebindDuringReport(void *context)
            {
                auto &fixture = *static_cast<Fixture *>(context);
                // A new epoch is valid only after quiescing the old USB
                // transport; a producer revoke alone is insufficient.
                detachUsbHci(fixture.transport_);
                fixture.revoke();
                fixture.fake_.reboundEpoch = true;
                return fixture.attach() &&
                       fixture.begin() == LeDiscoveryResult::Ok;
            }

            static bool rejectAfterRebind(void *context)
            {
                (void)rebindDuringReport(context);
                return false;
            }

            void rebindFromFirstReport(bool rejectDelivery)
            {
                fake_.reportContext = this;
                fake_.onFirstReport =
                    rejectDelivery ? rejectAfterRebind : rebindDuringReport;
            }

            void stopFromFirstReport()
            {
                fake_.reportContext = this;
                fake_.onFirstReport = stopDuringReport;
            }

            void revokeFromFirstReport()
            {
                fake_.reportContext = this;
                fake_.onFirstReport = revokeDuringReport;
            }

            static bool deliverInline(void *context, const uint8_t *event,
                                      size_t bytes)
            {
                auto &fixture = *static_cast<Fixture *>(context);
                if (receiveUsbHciEvent(fixture.transport_,
                                       hostFor(fixture.fake_), event,
                                       bytes) != UsbHciStatus::Ok)
                {
                    return false;
                }
                const LeDiscoveryResult result = acceptLeHciEvent(
                    fixture.scan_, fixture.transport_, hostFor(fixture.fake_),
                    ownerFor(fixture.fake_), event, bytes);
                return result == LeDiscoveryResult::Ok ||
                       result == LeDiscoveryResult::ControllerRejected;
            }

            Fake &fake()
            {
                return fake_;
            }

            LeScanPhase phase() const
            {
                return scan_.phase;
            }

            uint64_t epoch() const
            {
                return scan_.epoch;
            }

            void revoke()
            {
                revokeLeDiscovery(scan_);
            }

            bool attach()
            {
                fake_.pendingPhase = &scan_.phase;
                fake_.inlineContext = this;
                fake_.inlineEvent = deliverInline;
                const UsbHciEndpoints endpoints {0x81U, 0x82U, 0x02U};
                return attachUsbHci(transport_, endpoints, hostFor(fake_)) ==
                       UsbHciStatus::Ok;
            }

            LeDiscoveryResult begin(uint16_t interval = kInterval,
                                    uint16_t window = kWindow)
            {
                return beginLePassiveScan(scan_, transport_, hostFor(fake_),
                                          ownerFor(fake_), interval, window);
            }

            LeDiscoveryResult
            beginActive(LeActiveScanAuthorization authorize = authorizeActive,
                        uint16_t interval = kInterval,
                        uint16_t window = kWindow)
            {
                return beginLeActiveScan(scan_, transport_, hostFor(fake_),
                                         ownerFor(fake_), interval, window,
                                         authorize);
            }

            LeDiscoveryResult accept(const uint8_t *event, size_t bytes)
            {
                // Account BOTH preliminary Status and final Complete in the
                // same USB stream before dispatching to the LE producer.
                constexpr size_t kResponseBytes = 6U;
                constexpr size_t kCompleteOpcode = 3U;
                constexpr size_t kStatusOpcode = 4U;
                constexpr unsigned kOpcodeShift = 8U;
                constexpr uint8_t kCompleteCode = 0x0eU;
                constexpr uint8_t kStatusCode = 0x0fU;
                if (event != nullptr && bytes == kResponseBytes)
                {
                    const uint8_t code = *usbByteOffset(event, 0U);
                    if (code == kCompleteCode || code == kStatusCode)
                    {
                        const size_t offset = code == kCompleteCode
                                                  ? kCompleteOpcode
                                                  : kStatusOpcode;
                        const auto opcode = static_cast<uint16_t>(
                            static_cast<uint32_t>(
                                *usbByteOffset(event, offset)) |
                            (static_cast<uint32_t>(
                                 *usbByteOffset(event, offset + 1U))
                             << kOpcodeShift));
                        if (transport_.commandWindow.pending &&
                            opcode == transport_.commandWindow.pendingOpcode &&
                            receiveUsbHciEvent(transport_, hostFor(fake_),
                                               event,
                                               bytes) != UsbHciStatus::Ok)
                        {
                            return LeDiscoveryResult::TransportFailed;
                        }
                    }
                }
                return acceptLeHciEvent(scan_, transport_, hostFor(fake_),
                                        ownerFor(fake_), event, bytes);
            }

            LeDiscoveryResult completeParameters()
            {
                return accept(kParamsComplete.data(), kParamsComplete.size());
            }

            LeDiscoveryResult completeEnable()
            {
                return accept(kEnableComplete.data(), kEnableComplete.size());
            }

            bool start()
            {
                return attach() && begin() == LeDiscoveryResult::Ok &&
                       completeParameters() == LeDiscoveryResult::Ok &&
                       completeEnable() == LeDiscoveryResult::Ok &&
                       scan_.phase == LeScanPhase::Scanning;
            }

            LeDiscoveryResult stop()
            {
                return endLeScan(scan_, transport_, hostFor(fake_),
                                 ownerFor(fake_));
            }
    };

    int normalLifecycle()
    {
        Fixture f {};
        if (!f.attach() || f.begin() != LeDiscoveryResult::Ok ||
            f.phase() != LeScanPhase::AwaitParameters ||
            f.fake().commandCount != 1U ||
            f.fake().commandSizes.at(0U) != kParameterCommandBytes ||
            f.fake().commands.at(0U).at(0U) != kParamsOpcode ||
            f.fake().commands.at(0U).at(3U) != 0U ||
            f.fake().commands.at(0U).at(4U) != kIntervalLsb ||
            f.fake().commands.at(0U).at(kScanWindowLsbOffset) != kWindowLsb ||
            f.begin() != LeDiscoveryResult::Busy)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        if (f.accept(kUnrelatedComplete.data(), kUnrelatedComplete.size()) !=
                LeDiscoveryResult::Ignored ||
            f.completeParameters() != LeDiscoveryResult::Ok ||
            f.fake().commands.at(1U).at(0U) != kEnableOpcode ||
            f.fake().commands.at(1U).at(3U) != 0x01U ||
            f.completeEnable() != LeDiscoveryResult::Ok ||
            f.phase() != LeScanPhase::Scanning)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // Correct 17-byte LE Meta event: legacy ADV_IND, random addr, 3 AD
        // bytes and signed RSSI. The synthetic USB buffer is never retained.
        auto advertising = kAdvertisement;
        advertising.at(1U) = kEventPayloadBytes;
        if (f.accept(advertising.data(), advertising.size() - 1U) !=
                LeDiscoveryResult::Ok ||
            f.fake().reports != 1U || f.fake().deliveredBytes != 3U ||
            f.fake().observedAddress != kFirstAddress ||
            f.fake().observedRssi != kRssi ||
            f.stop() != LeDiscoveryResult::Ok ||
            f.phase() != LeScanPhase::AwaitDisable ||
            f.fake().commands.at(2U).at(3U) != 0x00U ||
            f.completeEnable() != LeDiscoveryResult::Ok ||
            f.phase() != LeScanPhase::Idle ||
            f.stop() != LeDiscoveryResult::NotScanning)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int activeScanAuthorization()
    {
        Fixture missing {};
        if (!missing.attach() ||
            missing.beginActive(nullptr) !=
                LeDiscoveryResult::InvalidArgument ||
            missing.fake().commandCount != 0U ||
            missing.phase() != LeScanPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture denied {};
        denied.fake().allowActiveScan = false;
        if (!denied.attach() ||
            denied.beginActive() != LeDiscoveryResult::Unauthorized ||
            denied.fake().activeAuthorizations != 1U ||
            denied.fake().commandCount != 0U ||
            denied.phase() != LeScanPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture revoked {};
        revoked.fake().revokeOnActiveAuthorization = true;
        if (!revoked.attach() ||
            revoked.beginActive() != LeDiscoveryResult::OwnershipLost ||
            revoked.fake().commandCount != 0U ||
            revoked.phase() != LeScanPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture active {};
        if (!active.attach() || active.beginActive() != LeDiscoveryResult::Ok ||
            active.fake().activeAuthorizations != 1U ||
            active.fake().commands.at(0U).at(3U) != 1U ||
            active.beginActive() != LeDiscoveryResult::Busy ||
            active.fake().activeAuthorizations != 1U ||
            active.completeParameters() != LeDiscoveryResult::Ok ||
            active.completeEnable() != LeDiscoveryResult::Ok ||
            active.phase() != LeScanPhase::Scanning)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // Passive policy must not forward unsolicited SCAN_RSP records,
        // even if a controller emits a syntactically valid response.
        Fixture passive {};
        if (!passive.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto unsolicited = kAdvertisement;
        unsolicited.at(1U) = kEventPayloadBytes;
        unsolicited.at(4U) = 4U;
        if (passive.accept(unsolicited.data(), unsolicited.size() - 1U) !=
                LeDiscoveryResult::Ok ||
            passive.fake().reports != 0U ||
            passive.phase() != LeScanPhase::Scanning)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // The active controller can also deliver SCAN_RSP (event type 4).
        auto scanResponse = kAdvertisement;
        scanResponse.at(1U) = kEventPayloadBytes;
        scanResponse.at(4U) = 4U;
        active.fake().expectedEventType = 4U;
        if (active.accept(scanResponse.data(), scanResponse.size() - 1U) !=
                LeDiscoveryResult::Ok ||
            active.fake().reports != 1U ||
            active.stop() != LeDiscoveryResult::Ok ||
            active.fake().commands.at(2U).at(3U) != 0U ||
            active.completeEnable() != LeDiscoveryResult::Ok ||
            active.phase() != LeScanPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture interrupted {};
        if (!interrupted.attach() ||
            interrupted.beginActive() != LeDiscoveryResult::Ok ||
            interrupted.stop() != LeDiscoveryResult::Ok ||
            interrupted.completeParameters() != LeDiscoveryResult::Ok ||
            interrupted.fake().commandCount != 1U ||
            interrupted.phase() != LeScanPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int cancellation()
    {
        Fixture beforeParams {};
        if (!beforeParams.attach() ||
            beforeParams.begin() != LeDiscoveryResult::Ok ||
            beforeParams.stop() != LeDiscoveryResult::Ok ||
            beforeParams.completeParameters() != LeDiscoveryResult::Ok ||
            beforeParams.fake().commandCount != 1U ||
            beforeParams.phase() != LeScanPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture beforeEnable {};
        if (!beforeEnable.attach() ||
            beforeEnable.begin() != LeDiscoveryResult::Ok ||
            beforeEnable.completeParameters() != LeDiscoveryResult::Ok ||
            beforeEnable.stop() != LeDiscoveryResult::Ok ||
            beforeEnable.completeEnable() != LeDiscoveryResult::Ok ||
            beforeEnable.phase() != LeScanPhase::AwaitDisable ||
            beforeEnable.fake().commandCount != 3U ||
            beforeEnable.fake().commands.at(2U).at(3U) != 0x00U ||
            beforeEnable.completeEnable() != LeDiscoveryResult::Ok ||
            beforeEnable.phase() != LeScanPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int commandStatusLifecycle()
    {
        Fixture pending {};
        if (!pending.attach() || pending.begin() != LeDiscoveryResult::Ok ||
            pending.accept(kUnrelatedStatus.data(), kUnrelatedStatus.size()) !=
                LeDiscoveryResult::Ignored ||
            pending.accept(kParamsStatusSuccess.data(),
                           kParamsStatusSuccess.size()) !=
                LeDiscoveryResult::Ignored ||
            pending.phase() != LeScanPhase::AwaitParameters ||
            pending.completeParameters() != LeDiscoveryResult::Ok ||
            pending.phase() != LeScanPhase::AwaitEnable ||
            pending.accept(kEnableStatusRejected.data(),
                           kEnableStatusRejected.size()) !=
                LeDiscoveryResult::ControllerRejected ||
            pending.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture rejected {};
        if (!rejected.attach() || rejected.begin() != LeDiscoveryResult::Ok ||
            rejected.accept(kParamsStatusRejected.data(),
                            kParamsStatusRejected.size()) !=
                LeDiscoveryResult::ControllerRejected ||
            rejected.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture noCredits {};
        if (!noCredits.attach() || noCredits.begin() != LeDiscoveryResult::Ok ||
            noCredits.accept(kParamsStatusNoCredits.data(),
                             kParamsStatusNoCredits.size()) !=
                LeDiscoveryResult::CommandCreditUnavailable ||
            noCredits.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture disabling {};
        if (!disabling.start() || disabling.stop() != LeDiscoveryResult::Ok ||
            disabling.accept(kEnableStatusRejected.data(),
                             kEnableStatusRejected.size()) !=
                LeDiscoveryResult::ControllerRejected ||
            disabling.phase() != LeScanPhase::Faulted)
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
            rejectedBegin.begin() != LeDiscoveryResult::Faulted ||
            rejectedBegin.phase() != LeScanPhase::Faulted ||
            rejectedBegin.fake().commandCount != 1U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture acceptedBegin {};
        acceptedBegin.fake().inlineReply = InlineReply::Complete;
        if (!acceptedBegin.attach() ||
            acceptedBegin.begin() != LeDiscoveryResult::Ok ||
            acceptedBegin.phase() != LeScanPhase::AwaitEnable ||
            acceptedBegin.fake().commandCount != 2U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture rejectedEnable {};
        if (!rejectedEnable.attach() ||
            rejectedEnable.begin() != LeDiscoveryResult::Ok)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        rejectedEnable.fake().inlineReply = InlineReply::Rejected;
        if (rejectedEnable.completeParameters() != LeDiscoveryResult::Faulted ||
            rejectedEnable.phase() != LeScanPhase::Faulted ||
            rejectedEnable.fake().commandCount != 2U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture rejectedDisable {};
        if (!rejectedDisable.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        rejectedDisable.fake().inlineReply = InlineReply::Rejected;
        if (rejectedDisable.stop() != LeDiscoveryResult::Faulted ||
            rejectedDisable.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture completedDisable {};
        if (!completedDisable.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        completedDisable.fake().inlineReply = InlineReply::Complete;
        if (completedDisable.stop() != LeDiscoveryResult::Ok ||
            completedDisable.phase() != LeScanPhase::Idle ||
            completedDisable.epoch() != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int malformedAndOwnership()
    {
        Fixture invalid {};
        if (!invalid.attach() ||
            invalid.begin(0U, kWindow) != LeDiscoveryResult::InvalidArgument ||
            invalid.begin(kInterval, kInterval + 1U) !=
                LeDiscoveryResult::InvalidArgument ||
            invalid.fake().commandCount != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture rejected {};
        if (!rejected.attach() || rejected.begin() != LeDiscoveryResult::Ok ||
            rejected.accept(kRejected.data(), kRejected.size()) !=
                LeDiscoveryResult::ControllerRejected ||
            rejected.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture noCredits {};
        if (!noCredits.attach() || noCredits.begin() != LeDiscoveryResult::Ok ||
            noCredits.accept(kZeroCredits.data(), kZeroCredits.size()) !=
                LeDiscoveryResult::CommandCreditUnavailable ||
            noCredits.phase() != LeScanPhase::Faulted ||
            noCredits.fake().commandCount != 1U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture failCommand {};
        failCommand.fake().failCommand = true;
        if (!failCommand.attach() ||
            failCommand.begin() != LeDiscoveryResult::TransportFailed ||
            failCommand.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture badReport {};
        if (!badReport.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto event = kAdvertisement;
        event.at(1U) = kEventPayloadBytes;
        event.at(kAdvertDataLengthOffset) =
            kOverlongAdvertBytes; // legacy AD length exceeds 31.
        if (badReport.accept(event.data(), event.size() - 1U) !=
                LeDiscoveryResult::MalformedEvent ||
            badReport.fake().reports != 0U ||
            badReport.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture malformedAd {};
        if (!malformedAd.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto invalidAd = kAdvertisement;
        invalidAd.at(1U) = kEventPayloadBytes;
        // Report Data_Length is 3, but the AD field claims four bytes.
        invalidAd.at(kAdvertDataLengthOffset + 1U) = 4U;
        if (malformedAd.accept(invalidAd.data(), invalidAd.size() - 1U) !=
                LeDiscoveryResult::MalformedEvent ||
            malformedAd.fake().reports != 0U ||
            malformedAd.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // A zero AD length terminates the structures; trailing zero padding
        // is legal, but nonzero data after termination is not.
        Fixture padded {};
        if (!padded.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto paddedEvent = kAdvertisement;
        paddedEvent.at(1U) = kEventPayloadBytes;
        paddedEvent.at(kAdvertDataLengthOffset + 1U) = 1U;
        paddedEvent.at(kAdvertDataLengthOffset + 2U) = 1U;
        paddedEvent.at(kAdvertDataLengthOffset + 3U) = 0U;
        padded.fake().expectedAdByte = 1U;
        if (padded.accept(paddedEvent.data(), paddedEvent.size() - 1U) !=
                LeDiscoveryResult::Ok ||
            padded.fake().reports != 1U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture trailingData {};
        if (!trailingData.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        paddedEvent.at(kAdvertDataLengthOffset + 1U) = 0U;
        if (trailingData.accept(paddedEvent.data(), paddedEvent.size() - 1U) !=
                LeDiscoveryResult::MalformedEvent ||
            trailingData.fake().reports != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture revoked {};
        if (!revoked.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        revoked.fake().valid = false;
        if (revoked.stop() != LeDiscoveryResult::OwnershipLost ||
            revoked.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        revoked.revoke();
        if (revoked.phase() != LeScanPhase::Idle || revoked.epoch() != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }

    int multipleReports()
    {
        Fixture valid {};
        if (!valid.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        auto packet = std::array<uint8_t, kMultiReportBytes> {};
        packet.at(0U) = kLeMetaType;
        packet.at(1U) = kMultiEventPayloadBytes;
        packet.at(2U) = kAdByte;
        packet.at(3U) = kTwoReports;
        for (size_t index = 0U; index < kReportPayloadBytes; ++index)
        {
            const uint8_t value = kAdvertisement.at(kFirstReportOffset + index);
            packet.at(kFirstReportOffset + index) = value;
            packet.at(kSecondReportOffset + index) = value;
        }
        if (valid.accept(packet.data(), packet.size()) !=
                LeDiscoveryResult::Ok ||
            valid.fake().reports != kTwoReports)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // The owner can cancel from the first report callback. The second
        // already-validated report must not escape the canceled scan.
        Fixture canceled {};
        if (!canceled.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        canceled.stopFromFirstReport();
        if (canceled.accept(packet.data(), packet.size()) !=
                LeDiscoveryResult::Ok ||
            canceled.fake().reports != 1U ||
            canceled.phase() != LeScanPhase::AwaitDisable ||
            canceled.fake().commandCount != 3U ||
            canceled.completeEnable() != LeDiscoveryResult::Ok ||
            canceled.phase() != LeScanPhase::Idle)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // A synchronous reset from the observer revokes this scan. It must
        // remain Idle rather than being faulted by the outer dispatch.
        Fixture reset {};
        if (!reset.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        reset.revokeFromFirstReport();
        if (reset.accept(packet.data(), packet.size()) !=
                LeDiscoveryResult::Ok ||
            reset.fake().reports != 1U || reset.phase() != LeScanPhase::Idle ||
            reset.epoch() != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        // The previous delivery completes after a new physical USB epoch
        // has attached. A stale false return must not fault the successor
        // or emit the second report from the old HCI transfer.
        for (const bool rejectDelivery : {false, true})
        {
            Fixture rebound {};
            if (!rebound.start())
            {
                return (__LINE__ % kDiagnosticModulo) + 1;
            }
            rebound.rebindFromFirstReport(rejectDelivery);
            if (rebound.accept(packet.data(), packet.size()) !=
                    LeDiscoveryResult::Ok ||
                rebound.fake().reports != 1U ||
                rebound.phase() != LeScanPhase::AwaitParameters ||
                rebound.epoch() != activeEpoch(rebound.fake()) ||
                rebound.fake().commandCount != 3U ||
                rebound.completeParameters() != LeDiscoveryResult::Ok ||
                rebound.completeEnable() != LeDiscoveryResult::Ok ||
                rebound.phase() != LeScanPhase::Scanning)
            {
                return (__LINE__ % kDiagnosticModulo) + 1;
            }
        }
        Fixture invalid {};
        if (!invalid.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        packet.at(kSecondReportOffset + kReportDataLengthOffset) =
            kOverlongAdvertBytes;
        if (invalid.accept(packet.data(), packet.size()) !=
                LeDiscoveryResult::MalformedEvent ||
            invalid.fake().reports != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        Fixture invalidAd {};
        if (!invalidAd.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        packet.at(kSecondReportOffset + kReportDataLengthOffset) = 3U;
        packet.at(kSecondReportOffset + kReportDataLengthOffset + 1U) = 4U;
        // Validate all reports before delivering the first.
        if (invalidAd.accept(packet.data(), packet.size()) !=
                LeDiscoveryResult::MalformedEvent ||
            invalidAd.fake().reports != 0U)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        packet.at(kSecondReportOffset + kReportDataLengthOffset + 1U) = kAdByte;
        Fixture revoked {};
        if (!revoked.start())
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        packet.at(kSecondReportOffset + kReportDataLengthOffset) = 3U;
        revoked.fake().revokeOnAdvertisement = true;
        if (revoked.accept(packet.data(), packet.size()) !=
                LeDiscoveryResult::OwnershipLost ||
            revoked.fake().reports != 1U ||
            revoked.phase() != LeScanPhase::Faulted)
        {
            return (__LINE__ % kDiagnosticModulo) + 1;
        }
        return 0;
    }
} // namespace

int main()
{
    if (const int normal = normalLifecycle())
    {
        return normal;
    }
    if (const int active = activeScanAuthorization())
    {
        return active;
    }
    if (const int stopped = cancellation())
    {
        return stopped;
    }
    if (const int statuses = commandStatusLifecycle())
    {
        return statuses;
    }
    if (const int inlineResult = inlineControllerResponses())
    {
        return inlineResult;
    }
    if (const int errors = malformedAndOwnership())
    {
        return errors;
    }
    return multipleReports();
}
