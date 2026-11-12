// Copyright:
//   - Copyright © 2026 laobamac. All rights reserved.
// SPDX-License-Identifier:
//   - LicenseRef-SimpleBCM-All-Rights-Reserved
// Confidential:
//   - false
// License-File:
//   - LICENSE-SIMPLEBCM
// Provenance:
//   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for simple ath.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for simple ath.
// - Description:
//   - Implements or verifies the SimpleATH source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for simple ath.

// Native AR9565 PCI owner: power, BAR access, RTC reset and board acquisition.
#include "diagnostics/NativeDiagnostics.hpp"
#include "hardware/Ar9003Descriptors.hpp"
#include "hardware/Ar9003TxControl.hpp"
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565KeyCache.hpp"
#include "hardware/Ar9565MacControl.hpp"
#include "hardware/Ar9565NvmReader.hpp"
#include "hardware/Ar9565Regulator.hpp"
#include "hardware/Ar9565RfIni.hpp"
#include "hardware/Ar9565RtcPower.hpp"
#include "hardware/Ar9565RxTsf.hpp"
#include "platform/Ar9565NativePci.hpp"
#include "platform/Ar9565NativeQueues.hpp"
#include "platform/Ar9565PciSession.hpp"
#include "platform/NativeLinkRetirement.hpp"
#include "platform/tahoe/NativeWirelessEpoch.hpp"
#include "platform/tahoe/NativeWirelessOwner.hpp"
#include "platform/tahoe/TahoeJoinSession.hpp"
#include "wifi/AwdlAction.hpp"
#include "wifi/DataFrames.hpp"
#include "wifi/DataPath.hpp"
#include "wifi/Eapol.hpp"
#include "wifi/Frames.hpp"
#include "wifi/LegacyScanBridge.hpp"
#include "wifi/LinkMonitor.hpp"
#include "wifi/NativePortSecurityAdmission.hpp"
#include "wifi/ScanCache.hpp"
#include "wifi/Station.hpp"
#include "wifi/WifiEngine.hpp"
#include "wifi/Wpa2Supplicant.hpp"
#include "wifi/crypto/Ccmp.hpp"
#include "wifi/crypto/Wpa2CryptoAdapter.hpp"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/pwr_mgt/IOPMpowerState.h>
#include <kern/clock.h>
#include <libkern/OSTypes.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSMetaClass.h>
#include <mach/i386/kern_return.h>
#include <mach/kern_return.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
// The pinned Tahoe XNU SDK declares this exported kernel CSPRNG only when
// the kernel API is enabled by sys/appleapiopts.h. Never synthesize WPA2
// nonces from a timestamp or untrusted userland data.
#include <sys/random.h>

class SimpleATH;

namespace
{
    struct RegisterAccess
    {
            SimpleATH *owner;
    };

    // Kernel entrypoint writes this before IOKit calls probe/start.
    // A function-local state slot avoids unrelated mutable globals.
    bool &driverEnabled()
    {
        static bool enabled = true;
        return enabled;
    }

    constexpr size_t kNvmStorageBytes = 4096;
    constexpr size_t kNativeEthernetCapacity = 1518;
    constexpr size_t kNativeTxMpduCapacity = 1600;
    constexpr size_t kMinimumEthernetBytes = 14;
    constexpr size_t kMinimumMpduBytes = 24;
    constexpr size_t kMaximumMpduBytes = 2342;
    constexpr size_t kFcsBytes = 4;
    constexpr uint16_t kEtherTypeEapol = 0x888eU;
    constexpr size_t kCcmpExtIvBytes = 8;
    constexpr size_t kCcmpMicBytes = 8;
    constexpr size_t kCcmpKeyIdOffset = 3;
    constexpr uint8_t kCcmpKeyIdShift = 6;
    static_assert(simpleath::kCcmpGroupSlots ==
                      simpleath::ieee80211::crypto::kCcmpReceiveKeyIndexCount,
                  "Native GTK ledger must cover every CCMP Key ID");
    constexpr uint8_t kAllGroupKeySlotsRevoked =
        (1U << simpleath::kCcmpGroupSlots) - 1U;
    constexpr uint8_t kNoKeyCacheSlot = 0xff;
    constexpr uint8_t kProtectedFrameFlag = 0x40U;
    constexpr uint16_t kSequenceMask = 0x0fffU;
    constexpr size_t kSequenceControlOffset = 22;
    constexpr uint8_t kSequenceFragmentBits = 4;
    constexpr uint8_t kByteBits = 8;
    constexpr uint64_t kMicrosPerMillisecond = 1000;
    constexpr unsigned int kCounterPropertyWidthBits = 64;
    constexpr size_t kManagementReplyCapacity = 4096;
    constexpr uint16_t kNativePassiveDwellMs = 120;
    constexpr uint8_t kNativeQosDataSubtype = 8U;
    constexpr size_t kNativeQosHeaderBytes = 26U;
    constexpr size_t kNativeQosControlOffset = 24U;
    constexpr uint8_t kNativeAmsduPresent = 0x80U;
    constexpr uint32_t kNativeLinkWatchdogMs = 1000U;
    constexpr uint32_t kNativeJoinTimeoutMs = 10000U;
    constexpr uint32_t kNativePortOpenTimeoutMs = 15000U;
    constexpr uint8_t kAwdlSocialChannelSix = 6U;
    constexpr uint8_t kAwdlActionSubtype = 13U;
    constexpr unsigned int kAwdlCounterWidthBits = 64U;

    struct NativeTransmitRequest
    {
            const uint8_t *bytes;
            size_t length;
    };

    struct NativeScanResultRequest
    {
            uint64_t generation;
            simpleath::ieee80211::NativeBssSnapshot *result;
    };

    struct NativeScanCompletionRequest
    {
            uint64_t epoch;
            uint64_t generation;
    };

    struct NativeSubscribeRequest
    {
            void *observer;
            IOReturn (*notify)(void *, simpleath::tahoe::WirelessEvent,
                               uint64_t, uint64_t);
            void (*receive)(void *, uint64_t, uint64_t, const uint8_t *,
                            size_t);
    };

    // The native command gate may wait for an earlier radio operation. A
    // synchronously borrowed OS packet or key is not immutable during that
    // wait, so callbacks take an owned snapshot and erase it on return.
    void scrubRequest(void *storage, size_t bytes)
    {
        auto *clear = static_cast<volatile uint8_t *>(storage);
        for (size_t index = 0; index < bytes; ++index)
        {
            // NOLINTNEXTLINE(*bounds-pointer-arithmetic)
            clear[index] = 0;
        }
    }

    constexpr unsigned int kRfPropertyWidthBits = 32;
    constexpr uint32_t kRfKillInputRegister = 0x404c;
} // namespace

class SimpleATH final : public IOService
{
        // Expand the pinned IOKit metaclass macro explicitly, as the native USB
        // owner does: preserve its exported RTTI/constructor ABI while keeping
        // the service constructor explicit and preventing copied PCI/DMA
        // ownership.
    private:
        static constexpr const OSMetaClass *superClass = &IOService::gMetaClass;

    public:
        static const OSMetaClass *const metaClass;

        static class MetaClass : public OSMetaClass
        {
            public:
                MetaClass() noexcept;
                OSObject *alloc() const APPLE_KEXT_OVERRIDE;
        } gMetaClass;
        friend class SimpleATH::MetaClass;
        const OSMetaClass *getMetaClass() const APPLE_KEXT_OVERRIDE;
        // Tahoe OSDefineDefaultStructors emits these allocation methods.
        // Keep the SDK-defined allocation/free implementation paired
        // with its declarations; this does not alter the vtable.
        // Tahoe's metaclass allocation ABI requires these exact signatures.
        // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
        void *operator new(size_t size);
        // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
        void operator delete(void *memory, size_t size);

    protected:
        explicit SimpleATH(const OSMetaClass *meta);

    public:
        // IOService destruction remains virtual; a public destructor matches
        // the C++ polymorphic lifetime contract without changing its vtable.
        ~SimpleATH() APPLE_KEXT_OVERRIDE;
        SimpleATH();
        SimpleATH(const SimpleATH &) = delete;
        SimpleATH &operator=(const SimpleATH &) = delete;
        SimpleATH(SimpleATH &&) = delete;
        SimpleATH &operator=(SimpleATH &&) = delete;

        IOService *probe(IOService *provider, SInt32 *score) override
        {
            return driverEnabled() && OSDynamicCast(IOPCIDevice, provider)
                       ? IOService::probe(provider, score)
                       : nullptr;
        }

        IOWorkLoop *getWorkLoop() const override
        {
            return loop_;
        }

        bool start(IOService *provider) override
        {
            if (!driverEnabled() || !IOService::start(provider))
            {
                return false;
            }
            pci_ = OSDynamicCast(IOPCIDevice, provider);
            if (pci_ == nullptr)
            {
                return failStart(provider, "PCIProvider", kIOReturnBadArgument);
            }
            lifecycle_ = IOLockAlloc();
            if (observerLock_ == nullptr)
            {
                observerLock_ = IOLockAlloc();
            }
            loop_ = IOWorkLoop::workLoop();
            gate_ = IOCommandGate::commandGate(this);
            if ((lifecycle_ == nullptr) || (observerLock_ == nullptr) ||
                (loop_ == nullptr) || (gate_ == nullptr))
            {
                return failStart(provider, "WorkLoop", kIOReturnNoMemory);
            }
            const IOReturn added = loop_->addEventSource(gate_);
            if (added != kIOReturnSuccess)
            {
                return failStart(provider, "CommandGate", added);
            }
            gateAttached_ = true;
            scanTimer_ = IOTimerEventSource::timerEventSource(
                kIOTimerEventSourceOptionsPriorityWorkLoop, this,
                scanTimerFired);
            if (scanTimer_ == nullptr)
            {
                return failStart(provider, "ScanTimer", kIOReturnNoMemory);
            }
            const IOReturn timerAdded = loop_->addEventSource(scanTimer_);
            if (timerAdded != kIOReturnSuccess)
            {
                return failStart(provider, "ScanTimer", timerAdded);
            }
            scanTimerAttached_ = true;
            // Association liveness is independent of an active scan dwell.
            // A successful association arms this same-workloop watchdog;
            // board acquisition alone never starts it or grants RF access.
            linkTimer_ = IOTimerEventSource::timerEventSource(
                kIOTimerEventSourceOptionsPriorityWorkLoop, this,
                linkTimerFired);
            if (linkTimer_ == nullptr)
            {
                return failStart(provider, "LinkTimer", kIOReturnNoMemory);
            }
            const IOReturn linkTimerAdded = loop_->addEventSource(linkTimer_);
            if (linkTimerAdded != kIOReturnSuccess)
            {
                return failStart(provider, "LinkTimer", linkTimerAdded);
            }
            linkTimerAttached_ = true;
            access_.owner = this;
            const simpleath::NativePciPowerGate power {&access_, poweredGate};
            if (!backend_.configure(this, pci_, power))
            {
                return failStart(provider, "PCIConfigure", kIOReturnNotReady);
            }
            storage_ = static_cast<uint8_t *>(IOMalloc(kNvmStorageBytes));
            scratch_ = static_cast<uint8_t *>(
                IOMalloc(simpleath::kAr9565EepromScratchBytes));
            if ((storage_ == nullptr) || (scratch_ == nullptr))
            {
                return failStart(provider, "NVMStorage", kIOReturnNoMemory);
            }
            diagnostics_ = simpleath::readNativeDiagnostics();
            simpleath::publishNativeDiagnostics(this, diagnostics_);
            setProperty("SimpleATHMode", "NativeAR9565");
            setProperty("SimpleATHDriverReady", false);
            PMinit();
            pmInitialized_ = true;
            provider->joinPMtree(this);
            const IOReturn registered =
                registerPowerDriver(this, &powerStates_[0], 2);
            if (registered != kIOReturnSuccess)
            {
                return failStart(provider, "PowerRegistration", registered);
            }
            const IOReturn result = startClient();
            if (result != kIOReturnSuccess)
            {
                return failStart(provider, "HardwareStart", result);
            }
            started_ = true;
            changePowerStateTo(1);
            registerService();
            return true;
        }

        IOReturn setPowerState(unsigned long state,
                               IOService * /*whatDevice*/) override
        {
            // PM invokes this on a sleepable thread. The same gate serializes
            // reset/NVM, sleep, stop and provider termination; no worker needs
            // to reenter it while an operation is waiting.
            if ((gate_ != nullptr) && started_)
            {
                if (state == 0)
                {
                    stopClient(ClientStopMode::Suspend);
                }
                else
                {
                    startClient();
                }
            }
            return kIOPMAckImplied;
        }

        bool willTerminate(IOService *provider, IOOptionBits options) override
        {
            stopClient(ClientStopMode::Terminate);
            return IOService::willTerminate(provider, options);
        }

        void stop(IOService *provider) override
        {
            if (pmInitialized_)
            {
                PMstop();
                pmInitialized_ = false;
            }
            stopClient(ClientStopMode::FinalStop);
            cleanup();
            IOService::stop(provider);
        }

        void free() override
        {
            cleanup();
            // The transport retains the provider until its synchronous
            // unsubscribe. The observer lock must outlive stop()/cleanup().
            if (observerLock_ != nullptr)
            {
                IOLockFree(observerLock_);
                observerLock_ = nullptr;
            }
            IOService::free();
        }

        IOReturn callPlatformFunction(const char *name, bool wait, void *p1,
                                      void *p2, void *p3, void *p4) override
        {
            if (name == nullptr)
            {
                return kIOReturnBadArgument;
            }
            if (strcmp(name, &simpleath::tahoe::kWirelessOwnerFunction[0]) != 0)
            {
                return IOService::callPlatformFunction(name, wait, p1, p2, p3,
                                                       p4);
            }
            if ((p1 == nullptr) || (p2 != nullptr) || (p3 != nullptr) ||
                (p4 != nullptr))
            {
                return kIOReturnBadArgument;
            }
            auto *out = static_cast<simpleath::tahoe::WirelessOwnerV7 *>(p1);
            if (out->abiVersion != simpleath::tahoe::kWirelessOwnerAbi ||
                out->structureBytes != sizeof(*out))
            {
                return kIOReturnUnsupported;
            }
            if (gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            return gate_->runAction(exportWirelessOwnerAction, out);
        }

    private:
        // The Tahoe child binds to a real PCI owner, never to IORegistry
        // readiness properties. Provider entrypoints execute on this owner's
        // serialized gate; only the mailbox notification callback crosses to
        // the child's independent work loop.
        static IOReturn exportWirelessOwnerAction(OSObject *object, void *arg,
                                                  void * /*unused*/,
                                                  void * /*unused*/,
                                                  void * /*unused*/)
        {
            auto *typed = OSDynamicCast(SimpleATH, object);
            if (typed == nullptr)
            {
                return kIOReturnBadArgument;
            }
            auto &self = *typed;
            if (!self.powered_ || self.stopping_ ||
                (self.board_.view(self.epoch_) == nullptr) ||
                (self.observerLock_ == nullptr))
            {
                return kIOReturnNotReady;
            }
            auto &out = *static_cast<simpleath::tahoe::WirelessOwnerV7 *>(arg);
            const simpleath::tahoe::WirelessOwnerV7 callbacks {
                simpleath::tahoe::kWirelessOwnerAbi,
                sizeof(simpleath::tahoe::WirelessOwnerV7),
                &self,
                ownerSnapshot,
                ownerSetPower,
                ownerSetMac,
                ownerBeginScan,
                ownerCancelScan,
                ownerNextBss,
                ownerConnect,
                ownerDisconnect,
                ownerInstallKey,
                ownerAuthorizePort,
                ownerTransmitEthernet,
                ownerSubscribe,
                ownerUnsubscribe,
                ownerRetryScanCompletion,
                ownerAcknowledgeScanCompletion,
            };
            out = callbacks;
            return kIOReturnSuccess;
        }

        // OS join phase is bookkeeping only: real link and controlled-port
        // authority are verified separately against physical EDMA and RF.
        void populateNativeJoinSnapshot(simpleath::tahoe::WirelessSnapshot &out)
        {
            const auto &self = *this;
            if (self.joinEpoch_ == self.epoch_ && self.joinRequestId_ != 0)
            {
                out.joinRequestId = self.joinRequestId_;
                out.joinStatus = self.joinStatus_;
                out.associatedBeaconObserved = self.associatedBeaconObserved_;
                if (self.joinStatus_ != kIOReturnSuccess)
                {
                    out.joinPhase = simpleath::tahoe::NativeJoinPhase::Failed;
                }
                else
                {
                    switch (self.engine_.stationState())
                    {
                        case simpleath::ieee80211::StationState::
                            CandidateSelected:
                        case simpleath::ieee80211::StationState::
                            AuthenticationFramePrepared:
                            out.joinPhase = simpleath::tahoe::NativeJoinPhase::
                                Authenticating;
                            break;
                        case simpleath::ieee80211::StationState::Authenticated:
                        case simpleath::ieee80211::StationState::
                            AssociationFramePrepared:
                            out.joinPhase =
                                simpleath::tahoe::NativeJoinPhase::Associating;
                            break;
                        case simpleath::ieee80211::StationState::
                            WaitingForWpa2Keys:
                        case simpleath::ieee80211::StationState::
                            HardwareKeysInstalled:
                        case simpleath::ieee80211::StationState::AssociatedOpen:
                            // No Ready claim on key presence or association
                            // alone: authenticated RF, live data port and a
                            // fresh same-epoch AP beacon are all mandatory.
                            out.joinPhase =
                                self.controlledPortAuthorized_ &&
                                        self.associatedBeaconObserved_
                                    ? simpleath::tahoe::NativeJoinPhase::Ready
                                    : simpleath::tahoe::NativeJoinPhase::
                                          Handshaking;
                            break;
                        default:
                            out.joinPhase =
                                simpleath::tahoe::NativeJoinPhase::Failed;
                            out.joinStatus = kIOReturnNotReady;
                            break;
                    }
                }
            }
        }

        static IOReturn ownerSnapshotAction(OSObject *object, void *arg,
                                            void * /*unused*/,
                                            void * /*unused*/,
                                            void * /*unused*/)
        {
            auto *typed = OSDynamicCast(SimpleATH, object);
            if (typed == nullptr)
            {
                return kIOReturnBadArgument;
            }
            auto &self = *typed;
            auto &out = *static_cast<simpleath::tahoe::WirelessSnapshot *>(arg);
            out = {};
            const auto *board = self.board_.view(self.epoch_);
            if (!self.powered_ || self.stopping_ || (board == nullptr))
            {
                return kIOReturnNotReady;
            }
            out.epoch = self.epoch_;
            self.populateNativeJoinSnapshot(out);
            memcpy(&out.permanentMac[0], &board->summary.mac[0],
                   sizeof(out.permanentMac));
            // This is the physical PCU identity, not the permanent NVM
            // address. A verified locally administered override persists
            // across reset but is exposed only after hardware readback.
            if (!self.stationMacProgrammed_)
            {
                return kIOReturnNotReady;
            }
            memcpy(&out.currentMac[0], &self.stationMac_[0],
                   sizeof(out.currentMac));
            const auto link = self.engine_.linkStatus();
            const bool liveRfKill = self.liveRfKillUnblocked();
            // Association precedes WPA2 key installation. Report only a
            // genuinely received association on the active radio epoch;
            // controlledPortOpen independently gates IP traffic and DHCP.
            out.associated =
                self.pendingLocalLeaveToken_ == 0 && liveRfKill &&
                self.radioOperational_ && self.channelAuthorized_ &&
                self.queues_.epoch() == self.epoch_ &&
                self.queues_.phase() == simpleath::NativeQueuePhase::Running &&
                link.state == simpleath::ieee80211::LinkState::Associated;
            if (out.associated)
            {
                simpleath::ieee80211::Bss selected {};
                if (!self.engine_.copyAssociatedBss(selected) ||
                    self.associationGeneration_ == 0 ||
                    selected.beacon.ssidLength > sizeof(out.ssid) ||
                    selected.beacon.rateCount >
                        sizeof(out.associatedBss.rates) ||
                    selected.beacon.rsnIeLength >
                        sizeof(out.associatedBss.rsnInformationElement))
                {
                    // Native UI state must not claim an association without
                    // the exact BSS chosen by the actual 802.11 handshake.
                    out.associated = false;
                }
                else
                {
                    out.associationGeneration = self.associationGeneration_;
                    memcpy(&out.bssid[0], &link.bssid.bytes[0],
                           sizeof(out.bssid));
                    out.ssidLength = selected.beacon.ssidLength;
                    memcpy(&out.ssid[0], &selected.beacon.ssid[0],
                           out.ssidLength);
                    out.channel = selected.beacon.channel;
                    // Return real scan/association BSS metadata, never an
                    // invented empty RSN, fabricated rates or stale channel.
                    const auto &beacon = selected.beacon;
                    out.associatedBss.bssid = beacon.bssid;
                    out.associatedBss.ssidLength = beacon.ssidLength;
                    __builtin_memcpy(&out.associatedBss.ssid[0],
                                     &beacon.ssid[0], beacon.ssidLength);
                    out.associatedBss.channel = beacon.channel;
                    out.associatedBss.capabilities = beacon.capabilities;
                    out.associatedBss.beaconIntervalTu = beacon.intervalTu;
                    out.associatedBss.rateCount = beacon.rateCount;
                    __builtin_memcpy(&out.associatedBss.rates[0],
                                     &beacon.rates[0], beacon.rateCount);
                    out.associatedBss.rsnIeLength = beacon.rsnIeLength;
                    __builtin_memcpy(
                        &out.associatedBss.rsnInformationElement[0],
                        &beacon.rsnIe[0], beacon.rsnIeLength);
                    out.associatedBss.htSupported = beacon.htSupported;
                    out.associatedBss.ht40Allowed = beacon.ht40Allowed;
                    out.associatedBss.security = beacon.rsn.security;
                    // RSSI only comes from verified on-air RX in this
                    // association, and expires if the AP falls silent.
                    const uint64_t observedAt = link.lastBeaconMs;
                    const uint64_t nowMs =
                        nowMicros(nullptr) / kMicrosPerMillisecond;
                    constexpr uint64_t kMaxSignalAgeMs = 3000U;
                    out.signalMeasured = self.associatedSignalMeasured_ &&
                                         self.associatedBeaconObserved_ &&
                                         nowMs >= observedAt &&
                                         nowMs - observedAt <= kMaxSignalAgeMs;
                    if (out.signalMeasured)
                    {
                        out.rssiDbm = self.associatedRssiDbm_;
                        out.associatedBss.rssiDbm = out.rssiDbm;
                        out.associatedBss.signalMeasured = true;
                    }
                }
            }
            out.scanning = self.scanBridge_.status().radioScanRunning &&
                           self.scanEpoch_ == self.epoch_;
            out.powered = self.powered_;
            out.radioAvailable =
                liveRfKill && self.radioOperational_ &&
                self.channelAuthorized_ &&
                self.queues_.phase() == simpleath::NativeQueuePhase::Running;
            out.controlledPortOpen =
                out.associated && self.controlledPortAuthorized_ &&
                out.joinPhase == simpleath::tahoe::NativeJoinPhase::Ready;
            if (!out.associated &&
                out.joinPhase == simpleath::tahoe::NativeJoinPhase::Ready)
            {
                out.joinPhase = simpleath::tahoe::NativeJoinPhase::Failed;
                out.joinStatus = kIOReturnNotReady;
            }
            // No country code or current channel is published until the
            // physical/regulatory owner has actually authorized one.
            out.rfKillBlocked = !liveRfKill;
            return kIOReturnSuccess;
        }

        static IOReturn ownerSnapshot(void *context,
                                      simpleath::tahoe::WirelessSnapshot *out)
        {
            if ((context == nullptr) || (out == nullptr))
            {
                return kIOReturnBadArgument;
            }
            auto const &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            return self.gate_->runAction(ownerSnapshotAction, out);
        }

        static IOReturn ownerSetPower(void *context, bool on)
        {
            if (context == nullptr)
            {
                return kIOReturnBadArgument;
            }
            auto &self = *static_cast<SimpleATH *>(context);
            if (!self.started_ || self.stopping_)
            {
                return kIOReturnNotReady;
            }
            if (on)
            {
                // Power-on performs the real PCI/RTC/EEPROM sequence, not a
                // synthetic radio-ready transition.
                return self.startClient();
            }
            // The explicit AirPort radio-off request is not an IOPM
            // acknowledgement. Report a quarantined DMA release or failed
            // device gate to WCL instead of claiming a clean power-down.
            return self.stopClient(ClientStopMode::Suspend);
        }

        static IOReturn ownerSetMacAction(OSObject *object, void *argument,
                                          void * /*unused1*/,
                                          void * /*unused2*/,
                                          void * /*unused3*/)
        {
            // The native OS request was copied before entering this gate;
            // revalidate the live PCI lease before every identity MMIO.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            const auto *requested = static_cast<const uint8_t *>(argument);
            const auto *board = self.board_.view(self.epoch_);
            if (board == nullptr || !self.stationMacProgrammed_ ||
                self.stopping_)
            {
                return kIOReturnNotReady;
            }
            // An idempotent request never touches MMIO and is safe even while
            // associated; only an actual identity change needs isolation.
            if (memcmp(requested, &self.stationMac_[0],
                       sizeof(self.stationMac_)) == 0)
            {
                return kIOReturnSuccess;
            }
            if (!self.enginesQuiesced_ || self.keyCache_.requiresReset ||
                self.queues_.epoch() != self.epoch_ || !self.queuesAdopted_ ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Prepared ||
                !self.queues_.initialStartEligibleGated() ||
                self.radioOperational_ || self.channelAuthorized_ ||
                self.scanBridge_.status().radioScanRunning ||
                self.engine_.linkStatus().state ==
                    simpleath::ieee80211::LinkState::Associated ||
                self.joinWatchRequestId_ != 0 ||
                self.programmedBssidEpoch_ != 0 ||
                self.nativePairwiseTx_.installed() ||
                self.nativePairwiseRx_.installed() ||
                self.nativeGroupInstalled())
            {
                // A live link or device-owned descriptor cannot be moved
                // from one station address to another without a new epoch.
                return kIOReturnNotReady;
            }
            // MAC privacy addresses must be locally administered and unicast.
            // The true NVM address can always be restored while quiesced.
            if (!simpleath::validatePermanentMac(requested) ||
                (((requested[0] & 0x02U) == 0U) &&
                 memcmp(requested, &board->summary.mac[0],
                        sizeof(self.stationMac_)) != 0))
            {
                return kIOReturnBadArgument;
            }
            const auto registers = self.backend_.activeRegisters();
            const simpleath::RegisterBus bus {
                &self.access_,
                readRegister,
                writeRegister,
                registers.barLengthBytes,
            };
            const auto progress = simpleath::programAr9565StationMac(
                bus, requested, self.epoch_, stationMacPermit);
            self.setProperty("SimpleATHStationAddressResult",
                             static_cast<uint32_t>(progress.result),
                             kRfPropertyWidthBits);
            if (progress.result != simpleath::MacIdentityResult::Ok)
            {
                // An attempted identity write may have reached the PCU even
                // if MMIO reported a failure. Quarantine this physical epoch;
                // never publish or reuse either address as current.
                self.retireNativeLink(kIOReturnNotReady);
                self.stationMacProgrammed_ = false;
                memset(&self.stationMac_[0], 0, sizeof(self.stationMac_));
                self.keyCache_.requiresReset = true;
                self.setProperty("SimpleATHKeyCacheResetRequired", true);
                self.setProperty("SimpleATHStationAddressProgrammed", false);
                return kIOReturnIOError;
            }
            memcpy(&self.stationMac_[0], requested, sizeof(self.stationMac_));
            memcpy(&self.requestedStationMac_[0], requested,
                   sizeof(self.requestedStationMac_));
            self.requestedStationMacValid_ =
                memcmp(requested, &board->summary.mac[0],
                       sizeof(self.requestedStationMac_)) != 0;
            if (self.requestedStationMacValid_)
            {
                // Only this physical board may reuse its privacy identity
                // after suspend or a new owner epoch. The PCI device ID alone
                // cannot distinguish two cards with different NVM identities.
                memcpy(&self.requestedStationBoardMac_[0],
                       &board->summary.mac[0],
                       sizeof(self.requestedStationBoardMac_));
            }
            else
            {
                memset(&self.requestedStationMac_[0], 0,
                       sizeof(self.requestedStationMac_));
                memset(&self.requestedStationBoardMac_[0], 0,
                       sizeof(self.requestedStationBoardMac_));
            }
            self.notifyWirelessChange(false);
            return kIOReturnSuccess;
        }

        static IOReturn
        ownerSetMac(void *context,
                    const uint8_t address[simpleath::tahoe::kWirelessMacBytes])
        {
            if (context == nullptr || address == nullptr)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            uint8_t stable[simpleath::tahoe::kWirelessMacBytes] {};
            memcpy(&stable[0], address, sizeof(stable));
            return self.gate_->runAction(ownerSetMacAction, &stable[0]);
        }

        // The platform scan contract uses bridge generations, not the
        // separate WifiEngine dwell generation. Only a real, calibrated,
        // verified on-channel receiver can enter this path: NVM acquisition,
        // a registry property, or a queued DMA map is not a tuning proof.
        static IOReturn ownerBeginScanAction(OSObject *object, void *argument,
                                             void * /*unused1*/,
                                             void * /*unused2*/,
                                             void * /*unused3*/)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            auto &request =
                *static_cast<simpleath::tahoe::NativeScanStartRequest *>(
                    argument);
            request.generation = 0;
            request.acceptedEpoch = 0;
            if (request.requestedEpoch == 0U ||
                request.requestedEpoch != self.epoch_ ||
                self.scanTimer_ == nullptr || !self.powered_ ||
                self.stopping_ || !self.radioOperational_ ||
                !self.channelAuthorized_ || !self.liveRfKillUnblocked() ||
                self.pendingLocalLeaveToken_ != 0 ||
                self.verifiedReceiveChannel_ == 0 ||
                self.board_.view(self.epoch_) == nullptr ||
                self.queues_.epoch() != self.epoch_ ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Running)
            {
                return kIOReturnNotReady;
            }
            if (self.scanBridge_.status().radioScanRunning ||
                self.scanSerial_ == UINT32_MAX)
            {
                return kIOReturnBusy;
            }
            simpleath::ieee80211::ScanBridgeTicket ticket {};
            const uint32_t serial = self.scanSerial_ + 1U;
            if (self.scanBridge_.beginScan(serial, ticket) !=
                simpleath::ieee80211::ScanBridgeResult::Ok)
            {
                return kIOReturnBusy;
            }
            self.scanSerial_ = serial;
            // Until real channel hopping/OS regulatory selection is joined to
            // RF reset, limit this scan to the physically confirmed channel.
            // Never enumerate guessed country channels or send probe frames.
            const simpleath::ieee80211::ScanChannelDwell dwell {
                self.verifiedReceiveChannel_,
                kNativePassiveDwellMs,
            };
            const uint64_t now = nowMicros(nullptr) / kMicrosPerMillisecond;
            uint64_t engineGeneration = 0;
            const simpleath::ieee80211::ScanScheduleRequest schedule {
                &dwell, 1U, now, true, true,
            };
            const auto started =
                self.engine_.beginChannelScan(schedule, engineGeneration);
            simpleath::ieee80211::ScanProgress first {};
            const bool tuned =
                started == simpleath::ieee80211::EngineResult::Ok &&
                self.engine_.pollChannelScan(now, first) ==
                    simpleath::ieee80211::EngineResult::Ok &&
                first.kind ==
                    simpleath::ieee80211::ScanProgressKind::TuneRequired &&
                first.channel == self.verifiedReceiveChannel_ &&
                self.engine_.acknowledgeChannelTune(
                    {engineGeneration, first.channel, now, true}) ==
                    simpleath::ieee80211::EngineResult::Ok;
            if (!tuned || self.scanTimer_->setTimeoutMS(
                              kNativePassiveDwellMs) != kIOReturnSuccess)
            {
                // A failed timer or incomplete engine transition cannot
                // publish a completion, let alone an unobserved BSS.
                if (started == simpleath::ieee80211::EngineResult::Ok)
                {
                    (void)self.engine_.cancelChannelScan(engineGeneration);
                }
                (void)self.scanBridge_.completeScan(self.engine_.scan(), ticket,
                                                    false);
                (void)self.scanBridge_.acknowledgeCompletion(ticket);
                return kIOReturnNotReady;
            }
            self.scanEpoch_ = self.epoch_;
            self.scanEngineGeneration_ = engineGeneration;
            self.scanTicket_ = ticket;
            request.acceptedEpoch = self.epoch_;
            request.generation = ticket.generation;
            return kIOReturnSuccess;
        }

        static IOReturn
        ownerBeginScan(void *context,
                       simpleath::tahoe::NativeScanStartRequest *request)
        {
            if (context == nullptr || request == nullptr)
            {
                return kIOReturnBadArgument;
            }
            request->acceptedEpoch = 0;
            request->generation = 0;
            const auto &self = *static_cast<SimpleATH *>(context);
            return self.gate_ == nullptr
                       ? kIOReturnNotReady
                       : self.gate_->runAction(ownerBeginScanAction, request);
        }

        static IOReturn ownerCancelScanAction(OSObject *object, void *argument,
                                              void * /*unused1*/,
                                              void * /*unused2*/,
                                              void * /*unused3*/)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            const uint64_t expected = *static_cast<const uint64_t *>(argument);
            if (self.scanEpoch_ != self.epoch_ ||
                self.scanEngineGeneration_ == 0 ||
                self.scanTicket_.generation != expected ||
                !self.scanBridge_.status().radioScanRunning)
            {
                return kIOReturnBadArgument;
            }
            if (self.engine_.cancelChannelScan(self.scanEngineGeneration_) !=
                simpleath::ieee80211::EngineResult::Ok)
            {
                return kIOReturnNotReady;
            }
            self.scanTimer_->cancelTimeout();
            self.scanEngineGeneration_ = 0;
            self.scanEpoch_ = 0;
            const auto cancelled = self.scanTicket_;
            self.scanTicket_ = {};
            // Keep the previous genuinely completed snapshot readable while
            // invalidating the newly cancelled in-flight generation.
            (void)self.scanBridge_.completeScan(self.engine_.scan(), cancelled,
                                                false);
            self.notifyWirelessScanFinished();
            return kIOReturnSuccess;
        }

        static IOReturn ownerCancelScan(void *context, uint64_t generation)
        {
            if (context == nullptr || generation == 0)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            return self.gate_ == nullptr
                       ? kIOReturnNotReady
                       : self.gate_->runAction(ownerCancelScanAction,
                                               &generation);
        }

        static IOReturn ownerNextBssAction(OSObject *object, void *argument,
                                           void * /*unused1*/,
                                           void * /*unused2*/,
                                           void * /*unused3*/)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            const auto &request =
                *static_cast<const NativeScanResultRequest *>(argument);
            if (!self.powered_ || self.stopping_ || !self.radioOperational_ ||
                !self.channelAuthorized_ || !self.liveRfKillUnblocked() ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Running)
            {
                // Even a previously successful BSS snapshot is no longer
                // authorized after radio or receive-queue revocation.
                return kIOReturnNotReady;
            }
            const auto ticket =
                request.generation == self.completedScanTicket_.generation
                    ? self.completedScanTicket_
                    : self.scanTicket_;
            if (ticket.generation != request.generation || ticket.serial == 0)
            {
                return kIOReturnNotReady;
            }
            const auto result = self.scanBridge_.next(ticket, *request.result);
            if (result == simpleath::ieee80211::ScanBridgeResult::Ok)
            {
                return kIOReturnSuccess;
            }
            if (result == simpleath::ieee80211::ScanBridgeResult::NoResult)
            {
                // A cancelled/failed scan must not be disguised as a
                // successful, empty result set. The previous successful
                // snapshot remains enumerable during a newer scan.
                const auto &status = self.scanBridge_.status();
                return status.completeSnapshotAvailable &&
                               status.completedGeneration == request.generation
                           ? kIOReturnNotFound
                           : kIOReturnNotReady;
            }
            return result == simpleath::ieee80211::ScanBridgeResult::
                                 ScanInProgress
                       ? kIOReturnBusy
                       : kIOReturnNotReady;
        }

        static IOReturn
        ownerNextBss(void *context, uint64_t generation,
                     simpleath::ieee80211::NativeBssSnapshot *out)
        {
            if (context == nullptr || out == nullptr || generation == 0)
            {
                return kIOReturnBadArgument;
            }
            *out = {};
            const auto &self = *static_cast<SimpleATH *>(context);
            NativeScanResultRequest request {generation, out};
            return self.gate_ == nullptr
                       ? kIOReturnNotReady
                       : self.gate_->runAction(ownerNextBssAction, &request);
        }

        static void linkTimerFired(OSObject *owner, IOTimerEventSource *unused)
        {
            (void)unused;
            // Only the serialized PCI owner can retire a pending join or link.
            // Sleep, stop and new associations invalidate this exact token.
            // Do not treat a timer callback as an RX/beacon observation.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(owner);
            if (self.loop_ == nullptr || !self.loop_->inGate() ||
                self.linkWatchEpoch_ == 0 ||
                self.linkWatchEpoch_ != self.epoch_)
            {
                return;
            }
            if (self.joinWatchRequestId_ != 0)
            {
                // Authentication/association replies may never arrive. The
                // physical owner must retire this exact outstanding join,
                // including its queued TX and hardware-key lifetime, rather
                // than leave a permanently pending native OS request.
                if (self.joinEpoch_ != self.epoch_ ||
                    self.joinRequestId_ != self.joinWatchRequestId_ ||
                    self.joinStatus_ != kIOReturnSuccess)
                {
                    self.retireNativeLink(kIOReturnNotReady);
                }
                else
                {
                    self.retireNativeLink(kIOReturnTimeout);
                }
                return;
            }
            if (self.linkWatchAssociationGeneration_ == 0 ||
                self.linkWatchAssociationGeneration_ !=
                    self.associationGeneration_)
            {
                return;
            }
            if (self.pendingLocalLeaveToken_ != 0)
            {
                // Local leave holds the old MAC only for the exact queued
                // disassociation TX. A lost/late completion cannot extend
                // that physical key and descriptor ownership indefinitely.
                self.retireNativeLink(kIOReturnTimeout);
                return;
            }
            if (!self.powered_ || self.stopping_ || !self.radioOperational_ ||
                !self.channelAuthorized_ || !self.liveRfKillUnblocked() ||
                self.queues_.epoch() != self.epoch_ ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Running ||
                self.joinEpoch_ != self.epoch_ ||
                self.engine_.linkStatus().state !=
                    simpleath::ieee80211::LinkState::Associated)
            {
                self.retireNativeLink(kIOReturnNotReady);
                return;
            }
            const uint64_t now = nowMicros(nullptr) / kMicrosPerMillisecond;
            // Beacons can remain healthy while an EAPOL or key-install
            // handshake never finishes. Bound the initial closed-port
            // lease separately from AP beacon liveness, even if a delayed
            // timer callback races a late OS supplicant response.
            if (self.portReadyPending_ &&
                (now < self.portReadyStartedMs_ ||
                 now - self.portReadyStartedMs_ >= kNativePortOpenTimeoutMs))
            {
                self.retireNativeLink(kIOReturnTimeout);
                return;
            }
            simpleath::ieee80211::EngineAction action {};
            const auto result = self.engine_.checkBeaconTimeout(now, action);
            if (result == simpleath::ieee80211::EngineResult::Ok &&
                action.kind == simpleath::ieee80211::ActionKind::LinkLost)
            {
                self.setProperty(
                    "SimpleATHLastLinkLoss",
                    static_cast<uint32_t>(
                        simpleath::ieee80211::LinkLoss::BeaconTimeout),
                    kRfPropertyWidthBits);
                self.retireNativeLink(kIOReturnTimeout);
                return;
            }
            // A monotonic-clock regression, failed poll or timer scheduling
            // failure must close the port, not make the AP immortal.
            if (result != simpleath::ieee80211::EngineResult::NoAction ||
                self.linkTimer_->setTimeoutMS(kNativeLinkWatchdogMs) !=
                    kIOReturnSuccess)
            {
                self.retireNativeLink(kIOReturnNotReady);
            }
        }

        static void scanTimerFired(OSObject *owner, IOTimerEventSource *unused)
        {
            (void)unused;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(owner);
            if (self.loop_ == nullptr || !self.loop_->inGate())
            {
                return;
            }
            if (self.scanEpoch_ != self.epoch_ ||
                self.scanEngineGeneration_ == 0 || !self.radioOperational_ ||
                !self.channelAuthorized_ || !self.liveRfKillUnblocked() ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Running)
            {
                // RF-kill can change between the last DMA RX and this
                // timer. Report a failed scan rather than silently losing
                // the native SCAN_DONE event or retaining an old BSS lease.
                const bool interrupted = self.abortActiveNativeScan();
                if (interrupted)
                {
                    self.notifyWirelessScanFinished();
                }
                // An RF-kill or queue failure can occur without a PCI epoch
                // change. Preserve the unsuccessful bridge completion until
                // the native consumer acknowledges its exact generation;
                // clearing it here would strand a posted SCAN_DONE and allow
                // a later scan to start before that notification is consumed.
                // Revoke all older BSS enumeration when the radio is unsafe.
                // Stop/reset and observer handover still clear the bridge.
                self.completedScanTicket_ = {};
                return;
            }
            const uint64_t now = nowMicros(nullptr) / kMicrosPerMillisecond;
            simpleath::ieee80211::ScanProgress progress {};
            const auto polled = self.engine_.pollChannelScan(now, progress);
            if (polled != simpleath::ieee80211::EngineResult::Ok)
            {
                (void)self.engine_.cancelChannelScan(
                    self.scanEngineGeneration_);
                (void)self.scanBridge_.completeScan(self.engine_.scan(),
                                                    self.scanTicket_, false);
                self.scanEngineGeneration_ = 0;
                self.scanEpoch_ = 0;
                self.notifyWirelessScanFinished();
                return;
            }
            if (progress.kind ==
                simpleath::ieee80211::ScanProgressKind::Dwelling)
            {
                const uint64_t remaining = progress.deadlineMs - now;
                // A workloop timer can run early. Preserve the entire
                // required passive dwell instead of claiming instant RX.
                if (remaining > 0 && remaining <= kNativePassiveDwellMs &&
                    self.scanTimer_->setTimeoutMS(
                        static_cast<uint32_t>(remaining)) == kIOReturnSuccess)
                {
                    return;
                }
            }
            const bool completed =
                progress.kind ==
                simpleath::ieee80211::ScanProgressKind::Complete;
            if (self.scanBridge_.completeScan(self.engine_.scan(),
                                              self.scanTicket_, completed) ==
                simpleath::ieee80211::ScanBridgeResult::Ok)
            {
                self.completedScanTicket_ = self.scanTicket_;
            }
            if (!completed)
            {
                (void)self.engine_.cancelChannelScan(
                    self.scanEngineGeneration_);
            }
            self.scanEngineGeneration_ = 0;
            self.scanEpoch_ = 0;
            self.notifyWirelessScanFinished();
        }

        IOReturn notifyWirelessScanFinished()
        {
            simpleath::ieee80211::ScanBridgeCompletion done {};
            if (observerLock_ == nullptr ||
                scanBridge_.completion(done) !=
                    simpleath::ieee80211::ScanBridgeResult::Ok ||
                done.ticket.generation == 0U)
            {
                return kIOReturnNotReady;
            }
            // Retries must not enqueue a second completion after a successful
            // handoff; the native consumer still owns acknowledgement.
            if (notifiedScanGeneration_ == done.ticket.generation)
            {
                return kIOReturnSuccess;
            }
            IOLockLock(observerLock_);
            IOReturn result = kIOReturnNotReady;
            if (wirelessObserver_ != nullptr && wirelessNotify_ != nullptr)
            {
                result = wirelessNotify_(
                    wirelessObserver_,
                    simpleath::tahoe::WirelessEvent::ScanFinished, epoch_,
                    done.ticket.generation);
            }
            IOLockUnlock(observerLock_);
            if (result == kIOReturnSuccess)
            {
                notifiedScanGeneration_ = done.ticket.generation;
            }
            // Only the matching native OS consumer may acknowledge this
            // ticket. A rejected mailbox handoff stays pending for a later
            // consumer-driven retry, never a fabricated SCAN_DONE.
            return result;
        }

        static IOReturn ownerRetryScanCompletionAction(OSObject *object, void *,
                                                       void *, void *, void *)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            if (!self.started_ || self.stopping_ || !self.powered_ ||
                self.epoch_ == 0U)
            {
                return kIOReturnNotReady;
            }
            return self.notifyWirelessScanFinished();
        }

        static IOReturn ownerRetryScanCompletion(void *context)
        {
            if (context == nullptr)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            return self.gate_ == nullptr
                       ? kIOReturnNotReady
                       : self.gate_->runAction(ownerRetryScanCompletionAction);
        }

        static IOReturn ownerAcknowledgeScanCompletionAction(OSObject *object,
                                                             void *argument,
                                                             void *, void *,
                                                             void *)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            const auto &identity =
                *static_cast<const NativeScanCompletionRequest *>(argument);
            simpleath::ieee80211::ScanBridgeCompletion done {};
            if (self.stopping_ || identity.epoch == 0U ||
                identity.epoch != self.epoch_ || identity.generation == 0U ||
                self.scanBridge_.completion(done) !=
                    simpleath::ieee80211::ScanBridgeResult::Ok ||
                done.ticket.generation != identity.generation)
            {
                return kIOReturnNotReady;
            }
            const auto result =
                self.scanBridge_.acknowledgeCompletion(done.ticket);
            if (result != simpleath::ieee80211::ScanBridgeResult::Ok)
            {
                return kIOReturnNotReady;
            }
            self.notifiedScanGeneration_ = 0;
            return kIOReturnSuccess;
        }

        static IOReturn ownerAcknowledgeScanCompletion(void *context,
                                                       uint64_t epoch,
                                                       uint64_t generation)
        {
            if (context == nullptr || epoch == 0U || generation == 0U)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            NativeScanCompletionRequest identity {epoch, generation};
            return self.gate_->runAction(ownerAcknowledgeScanCompletionAction,
                                         &identity);
        }

        // A DMA/PCI failure or sleep can interrupt an on-channel scan
        // without another timer callback. Retire its exact radio generation
        // and produce a failed completion before erasing its bridge ticket.
        // No interrupted dwell or BSS may be reported as successful.
        bool abortActiveNativeScan()
        {
            if (scanTimer_ != nullptr)
            {
                scanTimer_->cancelTimeout();
            }
            const auto ticket = scanTicket_;
            const uint64_t generation = scanEngineGeneration_;
            const auto &bridge = scanBridge_.status();
            const bool active = scanEpoch_ == epoch_ && generation != 0 &&
                                bridge.radioScanRunning &&
                                ticket.generation == bridge.activeGeneration &&
                                ticket.serial == bridge.requestSerial;
            scanEpoch_ = 0;
            scanEngineGeneration_ = 0;
            scanTicket_ = {};
            if (generation != 0)
            {
                (void)engine_.cancelChannelScan(generation);
            }
            if (active)
            {
                // A failed scan returns InvalidState while recording a
                // pending, explicitly unsuccessful completion event.
                (void)scanBridge_.completeScan(engine_.scan(), ticket, false);
            }
            simpleath::ieee80211::ScanBridgeCompletion completion {};
            return active &&
                   scanBridge_.completion(completion) ==
                       simpleath::ieee80211::ScanBridgeResult::Ok &&
                   !completion.succeeded &&
                   completion.ticket.generation == ticket.generation &&
                   completion.ticket.serial == ticket.serial;
        }

        void failNativeJoin(IOReturn status)
        {
            // A failed/disconnected association must not leave a previously
            // scheduled timeout capable of retiring the next association.
            linkWatchEpoch_ = 0;
            linkWatchAssociationGeneration_ = 0;
            joinWatchRequestId_ = 0;
            joinWatchStartedMs_ = 0;
            portReadyStartedMs_ = 0;
            portReadyPending_ = false;
            pendingLocalLeaveToken_ = 0;
            pendingLocalLeaveEpoch_ = 0;
            if (linkTimer_ != nullptr)
            {
                linkTimer_->cancelTimeout();
            }
            // No partial verified MSDU survives a failed association.
            nativeProtectedFragments_.clear();
            if (joinEpoch_ == epoch_ && joinRequestId_ != 0)
            {
                joinStatus_ = status;
            }
            associatedBeaconObserved_ = false;
            associatedSignalMeasured_ = false;
            associatedRssiDbm_ = 0;
            deferredManagementBytes_ = 0;
            deferredManagementEpoch_ = 0;
            deferredJoinRequestId_ = 0;
            deferredGroup2_ = false;
            pendingWpa2Group2Token_ = 0;
            pendingWpa2M4Token_ = 0;
            wpa2M4TransmitConfirmed_ = false;
            authenticatedProtectedRxObserved_ = false;
            controlledPortAuthorized_ = false;
        }

        static IOReturn ownerConnectAction(OSObject *object, void *argument,
                                           void * /*unused1*/,
                                           void * /*unused2*/,
                                           void * /*unused3*/)
        {
            // This command gate was installed by exactly this provider.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            const auto &request =
                *static_cast<const simpleath::tahoe::NativeConnectRequest *>(
                    argument);
            // An old request can never consume or resurrect a later PCI
            // epoch's scan/handshake. IDs increase monotonically per epoch.
            if (request.epoch == 0 || request.epoch != self.epoch_ ||
                request.requestId == 0 ||
                (self.joinEpoch_ == self.epoch_ &&
                 request.requestId <= self.joinRequestId_))
            {
                return kIOReturnBadArgument;
            }
            // Do not overwrite the PCU BSSID of a still-pending join. The
            // previous OS request must cancel and clear its physical identity
            // after its last management TX completes before a new selection.
            if (self.programmedBssidEpoch_ == self.epoch_)
            {
                return kIOReturnBusy;
            }
            // A new association must never inherit a previous key stream.
            self.nativeProtectedFragments_.clear();
            self.joinEpoch_ = request.epoch;
            self.joinRequestId_ = request.requestId;
            self.joinStatus_ = kIOReturnSuccess;
            self.associatedBeaconObserved_ = false;
            self.associatedSignalMeasured_ = false;
            self.associatedRssiDbm_ = 0;
            self.deferredManagementBytes_ = 0;
            self.deferredManagementEpoch_ = 0;
            self.deferredJoinRequestId_ = 0;
            self.deferredGroup2_ = false;
            self.pendingWpa2Group2Token_ = 0;
            self.pendingWpa2M4Token_ = 0;
            self.wpa2M4TransmitConfirmed_ = false;
            self.authenticatedProtectedRxObserved_ = false;
            self.controlledPortAuthorized_ = false;
            __builtin_memcpy(&self.joinBssid_[0], &request.bssid[0],
                             sizeof(self.joinBssid_));
            const auto *board = self.board_.view(self.epoch_);
            // A scan-cache candidate is not RF authority. An OS join must
            // follow a real authorized channel tune and complete TX policy;
            // otherwise do not consume the candidate/handshake state.
            if (board == nullptr || !self.canSubmitTransmit() ||
                request.channel != self.verifiedReceiveChannel_)
            {
                self.failNativeJoin(kIOReturnNotReady);
                return kIOReturnNotReady;
            }
            if (!self.queues_.hasTransmitSpace())
            {
                self.failNativeJoin(kIOReturnNoResources);
                return kIOReturnNoResources;
            }
            simpleath::ieee80211::Mac station {};
            simpleath::ieee80211::Mac bssid {};
            __builtin_memcpy(&station.bytes[0], &self.stationMac_[0],
                             sizeof(station.bytes));
            __builtin_memcpy(&bssid.bytes[0], &request.bssid[0],
                             sizeof(bssid.bytes));
            // WCL V2 supplies a private PMK for driver-owned WPA2. Both
            // branches require the exact on-radio observed BSSID and channel;
            // never silently select another same-name access point.
            const auto chosen =
                request.wpa2Personal
                    ? self.engine_.chooseNetworkForDriverSupplicant(
                          station, bssid, &request.ssid[0], request.ssidLength,
                          request.channel, &request.pmk[0])
                    : self.engine_.chooseNetworkForDriverOpen(
                          station, bssid, &request.ssid[0], request.ssidLength,
                          request.channel);
            self.setProperty("SimpleATHNativeJoinSelectionResult",
                             static_cast<uint32_t>(chosen),
                             kRfPropertyWidthBits);
            if (chosen != simpleath::ieee80211::EngineResult::Ok)
            {
                IOReturn failure = kIOReturnNotReady;
                if (chosen == simpleath::ieee80211::EngineResult::InvalidInput)
                {
                    failure = kIOReturnBadArgument;
                }
                else if (chosen == simpleath::ieee80211::EngineResult::
                                       UnsupportedSecurity)
                {
                    failure = kIOReturnUnsupported;
                }
                self.failNativeJoin(failure);
                return failure;
            }
            // The PCU's exact BSSID match must follow the chosen, physically
            // tuned AP, not a stale scan cache or an OS-supplied guest BSSID.
            // Program the pre-association AID=0 before the first auth TX.
            if (!self.programNativeBssid(&request.bssid[0], 0))
            {
                return kIOReturnNotReady;
            }
            simpleath::ieee80211::EngineAction frame {};
            const auto prepared = self.engine_.requestAuthentication(
                self.txSequence_, &self.managementReply_[0],
                sizeof(self.managementReply_), frame);
            IOReturn sent = kIOReturnNotReady;
            if (prepared == simpleath::ieee80211::EngineResult::Ok &&
                frame.kind ==
                    simpleath::ieee80211::ActionKind::TransmitAuthentication &&
                frame.bytes >= kMinimumMpduBytes &&
                frame.bytes <= sizeof(self.managementReply_))
            {
                sent = self.submitPreparedTransmit(&self.managementReply_[0],
                                                   frame.bytes);
            }
            if (sent != kIOReturnSuccess)
            {
                // Never retain a selected/authenticating station when its
                // initial on-air request failed or was not actually queued.
                // BSSID was committed even if the first management frame
                // could not be queued. Never reuse that physical epoch.
                self.retireNativeBssidEpoch(sent);
                return sent;
            }
            self.txSequence_ =
                static_cast<uint16_t>((self.txSequence_ + 1U) & kSequenceMask);
            // An on-air authentication request is not yet an association.
            // Arm a bounded same-workloop deadline only after EDMA accepts
            // the physical TX. The association response switches this timer
            // to AP-beacon liveness; failed/aborted joins cancel it.
            self.linkWatchEpoch_ = self.epoch_;
            self.linkWatchAssociationGeneration_ = 0;
            self.joinWatchRequestId_ = self.joinRequestId_;
            self.joinWatchStartedMs_ =
                nowMicros(nullptr) / kMicrosPerMillisecond;
            if (self.linkTimer_ == nullptr ||
                self.linkTimer_->setTimeoutMS(kNativeJoinTimeoutMs) !=
                    kIOReturnSuccess)
            {
                self.retireNativeLink(kIOReturnNotReady);
                return kIOReturnNotReady;
            }
            return kIOReturnSuccess;
        }

        static IOReturn
        ownerConnect(void *context,
                     const simpleath::tahoe::NativeConnectRequest *request)
        {
            if (context == nullptr || request == nullptr ||
                request->ssidLength == 0 ||
                request->ssidLength > simpleath::tahoe::kWirelessSsidBytes ||
                request->channel == 0)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            // The gate may wait while the native client changes its request;
            // use an owned value, not a borrowed mutable OS buffer.
            simpleath::tahoe::NativeConnectRequest stable = *request;
            const IOReturn result =
                self.gate_->runAction(ownerConnectAction, &stable);
            // The WCL join ABI carries a private PMK in its v2 request. The
            // synchronous command gate must never leave that copied secret on
            // the caller's stack, even when the join was rejected.
            scrubRequest(&stable, sizeof(stable));
            return result;
        }

        static IOReturn ownerDisconnectAction(OSObject *object, void *argument,
                                              void * /*unused1*/,
                                              void * /*unused2*/,
                                              void * /*unused3*/)
        {
            // The provider owns this command gate and the physical link.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            const uint16_t reason = *static_cast<const uint16_t *>(argument);
            const auto link = self.engine_.linkStatus();
            const auto station = self.engine_.stationState();
            if (self.pendingLocalLeaveToken_ != 0)
            {
                // One EDMA management TX owns the current graceful leave.
                // A repeated OS disconnect must not send another frame or
                // change the deadline of the first outstanding descriptor.
                return kIOReturnBusy;
            }
            if (station ==
                    simpleath::ieee80211::StationState::CandidateSelected ||
                station == simpleath::ieee80211::StationState::
                               AuthenticationFramePrepared ||
                station == simpleath::ieee80211::StationState::Authenticated ||
                station == simpleath::ieee80211::StationState::
                               AssociationFramePrepared)
            {
                // A leave before association has no 802.11 disassociation
                // peer to address. Wait for an already submitted management
                // frame to retire, then forget the provisional station; its
                // late AP reply must not revive a cancelled connection.
                if (self.queues_.phase() ==
                        simpleath::NativeQueuePhase::Running &&
                    !self.queues_.hasTransmitSpace())
                {
                    return kIOReturnBusy;
                }
                if (self.engine_.cancelPendingJoin() !=
                    simpleath::ieee80211::EngineResult::Ok)
                {
                    self.retireNativeBssidEpoch(kIOReturnNotReady);
                    return kIOReturnNotReady;
                }
                // Software cancellation alone does not erase PCU BSSID/AID.
                // With the TX slot genuinely free, clear both words and
                // verify them before allowing another same-epoch join.
                if (!self.clearNativeBssid())
                {
                    return kIOReturnNotReady;
                }
                self.failNativeJoin(kIOReturnAborted);
                self.notifyWirelessChange(false);
                return kIOReturnSuccess;
            }
            if (link.state != simpleath::ieee80211::LinkState::Associated ||
                link.pmfNegotiated || !self.canSubmitTransmit())
            {
                return kIOReturnNotReady;
            }
            // A leave cannot send another on-air management frame under an
            // already expired AP lease while its watchdog callback is late.
            // The shared check retires stale hardware instead.
            const IOReturn lease = self.verifyNativeAssociationLease(
                nowMicros(nullptr) / kMicrosPerMillisecond);
            if (lease != kIOReturnSuccess)
            {
                return lease;
            }
            if (!self.queues_.hasTransmitSpace())
            {
                return kIOReturnNoResources;
            }
            size_t written = 0;
            const auto encoded =
                simpleath::ieee80211::makeDisassociationRequest(
                    link.station, link.bssid, {reason, self.txSequence_},
                    &self.managementReply_[0], sizeof(self.managementReply_),
                    written);
            if (encoded != simpleath::ieee80211::Result::Ok)
            {
                return kIOReturnBadArgument;
            }
            const uint64_t token = self.nextTransmitToken_;
            const IOReturn sent =
                self.submitPreparedTransmit(&self.managementReply_[0], written);
            if (sent != kIOReturnSuccess)
            {
                return sent;
            }
            self.txSequence_ =
                static_cast<uint16_t>((self.txSequence_ + 1U) & kSequenceMask);
            // One device-owned descriptor is still outstanding. Keep its
            // radio/queue lease just long enough for the actual completion,
            // but immediately close every native data/key/association entry.
            // On completion, or after one bounded watchdog interval, retire
            // MAC, DMA and key RAM in the same terminal path as AP link loss.
            self.pendingLocalLeaveToken_ = token;
            self.pendingLocalLeaveEpoch_ = self.epoch_;
            self.controlledPortAuthorized_ = false;
            self.associatedBeaconObserved_ = false;
            self.joinStatus_ = kIOReturnAborted;
            self.notifyWirelessChange(false);
            if (self.linkTimer_ == nullptr ||
                self.linkTimer_->setTimeoutMS(kNativeLinkWatchdogMs) !=
                    kIOReturnSuccess)
            {
                // Timer failure must not allow unbounded DMA or stale keys.
                self.retireNativeLink(kIOReturnNotReady);
            }
            return kIOReturnSuccess;
        }

        static IOReturn ownerDisconnect(void *context, uint16_t reason)
        {
            if (context == nullptr || reason == 0)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            uint16_t stable = reason;
            return self.gate_->runAction(ownerDisconnectAction, &stable);
        }

        // An OS key revocation is serialized with the native RX/TX owner;
        // never retire live PN state while hardware has a pending descriptor.
        IOReturn removeNativeOsKey(const simpleath::tahoe::NativeCcmpKey &key,
                                   const simpleath::ieee80211::Mac &bssid)
        {
            auto &self = *this;

            if (!self.queues_.hasTransmitSpace())
            {
                return kIOReturnBusy;
            }
            if (key.pairwise && key.keyId == 0 &&
                memcmp(&key.peer[0], &bssid.bytes[0],
                       simpleath::tahoe::kWirelessMacBytes) == 0)
            {
                self.nativePairwiseTx_.revoke();
                self.nativeProtectedFragments_.clear();
                self.nativePairwiseRx_.revoke();
                for (auto &group : self.nativeGroupRx_)
                {
                    group.revoke();
                }
                self.nativePairwiseKeyRevoked_ = true;
                self.controlledPortAuthorized_ = false;
                return kIOReturnSuccess;
            }
            if (!key.pairwise && self.nativeGroupSlot(key.keyId) != nullptr &&
                memcmp(&key.peer[0], &bssid.bytes[0],
                       simpleath::tahoe::kWirelessMacBytes) == 0)
            {
                // During a GTK rotation, removing the retired slot must
                // not close the OS-controlled port while a separately
                // installed new GTK remains. A retired slot stays
                // unusable for the rest of this physical key epoch;
                // reinstalling it would roll its receive PN floor back.
                if (!(*self.nativeGroupSlot(key.keyId)).installed())
                {
                    return kIOReturnUnsupported;
                }
                self.nativeProtectedFragments_.clear();
                (*self.nativeGroupSlot(key.keyId)).revoke();
                self.nativeGroupKeyRevokedMask_ |=
                    static_cast<uint8_t>(1U << key.keyId);
                if (!self.nativeGroupInstalled())
                {
                    self.controlledPortAuthorized_ = false;
                    self.notifyWirelessChange(false);
                }
                return kIOReturnSuccess;
            }
            return kIOReturnUnsupported;
        }

        static IOReturn ownerInstallKeyAction(OSObject *object, void *argument,
                                              void * /*unused*/,
                                              void * /*unused*/,
                                              void * /*unused*/)
        {
            auto *typed = OSDynamicCast(SimpleATH, object);
            if (typed == nullptr)
            {
                return kIOReturnBadArgument;
            }
            auto &self = *typed;
            const auto &key =
                *static_cast<const simpleath::tahoe::NativeCcmpKey *>(argument);
            const auto &link = self.engine_.linkStatus();
            // This is the native OS-owned software CCMP transmit key, not an
            // assertion that the AR9565 hardware keycache or RX port is ready.
            // Do not mix an OS supplicant with the portable installed-key
            // owner. Native EAPOL delivery and association control remain
            // separate prerequisites before this path can carry traffic.
            if (!self.powered_ || self.stopping_ || !self.radioOperational_ ||
                !self.channelAuthorized_ || !self.liveRfKillUnblocked() ||
                self.pendingLocalLeaveToken_ != 0 ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Running ||
                (self.board_.view(self.epoch_) == nullptr) ||
                link.state != simpleath::ieee80211::LinkState::Associated ||
                self.engine_.stationState() !=
                    simpleath::ieee80211::StationState::WaitingForWpa2Keys ||
                !self.engine_.osSupplicantOwnsWpa2() ||
                !simpleath::ieee80211::validStationMac(link.station) ||
                !simpleath::ieee80211::validStationMac(link.bssid))
            {
                return kIOReturnNotReady;
            }
            // Revocation is never allowed to race with a device-owned TX
            // descriptor. On stop/sleep the queue is isolated first instead.
            if (key.remove)
            {
                return self.removeNativeOsKey(key, link.bssid);
            }
            // The OS's key callback can outrun a delayed beacon/initial-port
            // timer. Never install or reset a CCMP PN under an expired link.
            // Explicit key removal remains independent of this live lease.
            const IOReturn lease = self.verifyNativeAssociationLease(
                nowMicros(nullptr) / kMicrosPerMillisecond);
            if (lease != kIOReturnSuccess)
            {
                return lease;
            }
            if (key.receivePacketNumber >
                    simpleath::ieee80211::crypto::kCcmpMaximumPacketNumber ||
                memcmp(&key.peer[0], &link.bssid.bytes[0],
                       simpleath::tahoe::kWirelessMacBytes) != 0 ||
                self.nativePairwiseKeyRevoked_ ||
                (key.pairwise && self.controlledPortAuthorized_))
            {
                return kIOReturnUnsupported;
            }
            if (!key.pairwise)
            {
                if (self.nativeGroupSlot(key.keyId) == nullptr ||
                    (self.nativeGroupKeyRevokedMask_ &
                     static_cast<uint8_t>(1U << key.keyId)) != 0U ||
                    !self.nativePairwiseTx_.installed() ||
                    !self.nativePairwiseRx_.installed() ||
                    (*self.nativeGroupSlot(key.keyId)).installed())
                {
                    return kIOReturnUnsupported;
                }
                // An OS-owned Group1/Group2 handshake may install a new
                // receive-only GTK in an unused slot while the data port is
                // open. Existing slot and pairwise PN state remain intact;
                // replacing the same slot without a fresh epoch is refused.
                // Never use the GTK to transmit station unicast data or
                // trust unauthenticated packet KeyID as a key selector.
                self.nativeProtectedFragments_.clear();
                const auto installed =
                    (*self.nativeGroupSlot(key.keyId))
                        .install(&key.material[0], &link.bssid.bytes[0],
                                 key.keyId, self.epoch_, 0,
                                 key.receivePacketNumber);
                return installed == simpleath::ieee80211::crypto::CcmpResult::Ok
                           ? kIOReturnSuccess
                           : kIOReturnBadArgument;
            }
            if (key.keyId != 0 || self.nativePairwiseTx_.installed() ||
                self.nativePairwiseRx_.installed() ||
                self.nativeGroupInstalled())
            {
                // In-place pairwise TK replacement cannot reset the TX PN.
                // Require a fresh connection epoch with guaranteed new keys.
                return kIOReturnUnsupported;
            }
            self.nativeProtectedFragments_.clear();
            const auto installed = self.nativePairwiseTx_.install(
                &key.material[0], &link.station.bytes[0], 0, self.epoch_, 0, 0);
            if (installed != simpleath::ieee80211::crypto::CcmpResult::Ok)
            {
                return kIOReturnBadArgument;
            }
            const auto receiveInstalled = self.nativePairwiseRx_.install(
                &key.material[0], &link.bssid.bytes[0], 0, self.epoch_, 0,
                key.receivePacketNumber);
            if (receiveInstalled !=
                simpleath::ieee80211::crypto::CcmpResult::Ok)
            {
                self.nativePairwiseTx_.revoke();
                return kIOReturnBadArgument;
            }
            // Software key presence does not authorize the controlled port:
            // native RX decrypt/GTK and OS supplicant arbitration are missing.
            return kIOReturnSuccess;
        }

        static IOReturn
        ownerInstallKey(void *context,
                        const simpleath::tahoe::NativeCcmpKey *key)
        {
            if ((context == nullptr) || (key == nullptr))
            {
                return kIOReturnBadArgument;
            }
            auto const &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            // The caller retains key storage only until this operation
            // completes, and may change it while waiting for the gate. Never
            // let an OS-owned pointer supply a torn CCMP key or replay floor.
            simpleath::tahoe::NativeCcmpKey stable {};
            __builtin_memcpy(&stable, key, sizeof(stable));
            const IOReturn result =
                self.gate_->runAction(ownerInstallKeyAction, &stable);
            scrubRequest(&stable, sizeof(stable));
            return result;
        }

        static IOReturn ownerAuthorizePortAction(OSObject *object,
                                                 void *argument,
                                                 void * /*unused1*/,
                                                 void * /*unused2*/,
                                                 void * /*unused3*/)
        {
            // IOKit delivers only this provider's registered gate callback.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            if (argument == nullptr)
            {
                return kIOReturnBadArgument;
            }
            const bool open = *static_cast<const bool *>(argument);
            if (!open)
            {
                self.controlledPortAuthorized_ = false;
                self.notifyWirelessChange(false);
                return kIOReturnSuccess;
            }
            const auto link = self.engine_.linkStatus();
            // V2's native connect runs the DRIVER-owned PSK supplicant.
            // A key-cache install does not prove completed M4 or authenticated
            // CCMP RX. The separate security policy enforces those facts in
            // addition to this exact RF, BSSID, beacon and PCI epoch gate.
            simpleath::ieee80211::Bss selected {};
            if (!self.engine_.copyAssociatedBss(selected) ||
                !simpleath::ieee80211::sameMac(selected.beacon.bssid,
                                               link.bssid) ||
                selected.beacon.channel != self.verifiedReceiveChannel_)
            {
                return kIOReturnNotReady;
            }
            bool hardwareGroup = false;
            for (const auto &slot : self.keyCache_.group)
            {
                hardwareGroup = slot.installed || hardwareGroup;
            }
            const simpleath::ieee80211::NativePortSecurityEvidence security {
                selected.beacon.rsn.security,
                self.engine_.stationState(),
                self.engine_.osSupplicantOwnsWpa2(),
                self.keyCache_.initialized &&
                    self.keyCache_.ownerContext == &self.access_ &&
                    self.keyCache_.ownerEpoch == self.epoch_,
                self.keyCache_.requiresReset,
                self.keyCache_.pairwiseInstalled,
                hardwareGroup,
                self.nativePairwiseTx_.installed(),
                self.nativePairwiseRx_.installed(),
                self.nativeGroupInstalled(),
                self.nativePairwiseKeyRevoked_,
                self.wpa2M4TransmitConfirmed_,
                self.authenticatedProtectedRxObserved_,
            };
            if (!self.powered_ || self.stopping_ || !self.radioOperational_ ||
                !self.channelAuthorized_ || !self.liveRfKillUnblocked() ||
                self.pendingLocalLeaveToken_ != 0 ||
                self.board_.view(self.epoch_) == nullptr ||
                self.queues_.epoch() != self.epoch_ ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Running ||
                !self.txSafety_.dmaMappingValid ||
                !self.txSafety_.channelRegulatoryAuthorized ||
                !self.txSafety_.transmitPowerLimitsValidated ||
                !self.txSafety_.siliconIdentified ||
                !self.txSafety_.boardCalibrationValidated ||
                !self.txSafety_.radioAwake || self.joinEpoch_ != self.epoch_ ||
                self.joinRequestId_ == 0 ||
                self.joinStatus_ != kIOReturnSuccess ||
                !self.associatedBeaconObserved_ ||
                memcmp(&link.bssid.bytes[0], &self.joinBssid_[0],
                       sizeof(self.joinBssid_)) != 0 ||
                link.state != simpleath::ieee80211::LinkState::Associated ||
                link.networkInterfaceReady ||
                !simpleath::ieee80211::nativeControlledPortSecurityReady(
                    security))
            {
                return kIOReturnNotReady;
            }
            // Initial port and beacon liveness are independent: a late OS
            // key confirmation must not win against a missed-beacon watchdog.
            const IOReturn lease = self.verifyNativeAssociationLease(
                nowMicros(nullptr) / kMicrosPerMillisecond);
            if (lease != kIOReturnSuccess)
            {
                return lease;
            }
            self.portReadyPending_ = false;
            self.controlledPortAuthorized_ = true;
            self.notifyWirelessChange(false);
            return kIOReturnSuccess;
        }

        static IOReturn ownerAuthorizePortScopedAction(OSObject *object,
                                                       void *argument,
                                                       void * /*unused1*/,
                                                       void * /*unused2*/,
                                                       void * /*unused3*/)
        {
            const auto *typed = OSDynamicCast(SimpleATH, object);
            if (typed == nullptr || argument == nullptr)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *typed;
            const auto &request =
                *static_cast<const simpleath::tahoe::NativePortRequest *>(
                    argument);
            if (!simpleath::tahoe::acceptWirelessPortIdentity(
                    request.epoch, request.joinRequestId,
                    request.associationGeneration, self.epoch_,
                    self.joinEpoch_ == self.epoch_ ? self.joinRequestId_ : 0U,
                    self.associationGeneration_))
            {
                return kIOReturnNotReady;
            }
            // Reuse the physical owner's existing security predicate while
            // staying on its single gate; do not reenter the work loop.
            bool open = request.open;
            return ownerAuthorizePortAction(object, &open, nullptr, nullptr,
                                            nullptr);
        }

        static IOReturn
        ownerAuthorizePort(void *context,
                           const simpleath::tahoe::NativePortRequest *request)
        {
            if (context == nullptr || request == nullptr)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            simpleath::tahoe::NativePortRequest stable = *request;
            return self.gate_->runAction(ownerAuthorizePortScopedAction,
                                         &stable);
        }

        simpleath::ieee80211::crypto::CcmpSession *nativeGroupSlot(uint8_t id)
        {
            size_t index = 0;
            for (auto &group : nativeGroupRx_)
            {
                if (index++ == id)
                {
                    return &group;
                }
            }
            return nullptr;
        }

        // Only the parsed, bounded CCMP ExtIV may propose a key class.
        // KeyID 0 in a group frame still means GTK 0, never unicast PTK 0.
        // This only selects a candidate: MIC/PN are verified separately.
        simpleath::ieee80211::crypto::CcmpSession *
        selectNativeReceiveKey(const simpleath::ieee80211::Frame &header,
                               const uint8_t *frame, size_t mpduBytes)
        {
            if (frame == nullptr || header.headerLength > mpduBytes ||
                mpduBytes - header.headerLength <
                    kCcmpExtIvBytes + kCcmpMicBytes + 1U)
            {
                return nullptr;
            }
            // Header, ExtIV and MIC spans have been bounded by the caller.
            const auto wireKeyByte =
                // NOLINTNEXTLINE(*bounds-pointer-arithmetic)
                frame[header.headerLength + kCcmpKeyIdOffset];
            const auto keyId =
                static_cast<uint8_t>(wireKeyByte >> kCcmpKeyIdShift);
            const bool group = (header.destination.bytes[0] & 1U) != 0U;
            const auto keyClass =
                simpleath::ieee80211::crypto::classifyCcmpReceiveKey(group,
                                                                     keyId);
            if (keyClass ==
                simpleath::ieee80211::crypto::CcmpReceiveKeyClass::Group)
            {
                return nativeGroupSlot(keyId);
            }
            return keyClass == simpleath::ieee80211::crypto::
                                   CcmpReceiveKeyClass::Pairwise
                       ? &nativePairwiseRx_
                       : nullptr;
        }

        bool nativeGroupInstalled() const
        {
            // Kernel SDK does not expose compatible std::algorithm headers.
            // Accumulate across the fixed four key slots without requiring a
            // C++ standard-library algorithm in a kernel translation unit.
            bool anyInstalled = false;
            for (const auto &group : nativeGroupRx_)
            {
                anyInstalled = group.installed() || anyInstalled;
            }
            return anyInstalled;
        }

        // Connect and every management/data TX share one physical safety
        // predicate. A selected BSSID or OS-owned key cannot confer RF/TPC
        // authority before the native radio owner publishes real evidence.
        bool canSubmitTransmit()
        {
            return powered_ && !stopping_ && radioOperational_ &&
                   pendingLocalLeaveToken_ == 0 && channelAuthorized_ &&
                   rfKillKnownUnblocked_ && board_.view(epoch_) != nullptr &&
                   stationMacProgrammed_ && queues_.epoch() == epoch_ &&
                   queues_.phase() == simpleath::NativeQueuePhase::Running &&
                   txSafety_.siliconIdentified &&
                   txSafety_.boardCalibrationValidated &&
                   txSafety_.channelRegulatoryAuthorized &&
                   txSafety_.transmitPowerLimitsValidated &&
                   txSafety_.rfKillUnblocked && txSafety_.radioAwake &&
                   txSafety_.dmaMappingValid && liveRfKillUnblocked();
        }

        void retireNativeBssidEpoch(IOReturn error)
        {
            retireNativeLink(error);
            // An ambiguous identity write (or a later TX failure) cannot
            // inherit the PCU BSSID/AID state in another attempted join.
            keyCache_.requiresReset = true;
            setProperty("SimpleATHKeyCacheResetRequired", true);
        }

        bool programNativeBssid(const uint8_t bssid[6], uint16_t aid)
        {
            const auto bus = backend_.activeRegisters();
            const simpleath::RegisterBus registers {
                &access_,
                readRegister,
                writeRegister,
                bus.barLengthBytes,
            };
            const auto progress = simpleath::programAr9565AssociationBssid(
                registers, bssid, aid, epoch_, liveBssidPermit);
            setProperty("SimpleATHLastBssidProgramResult",
                        static_cast<uint32_t>(progress.result),
                        kRfPropertyWidthBits);
            if (progress.result != simpleath::MacIdentityResult::Ok)
            {
                retireNativeBssidEpoch(kIOReturnNotReady);
                return false;
            }
            programmedBssidEpoch_ = epoch_;
            return true;
        }

        bool clearNativeBssid()
        {
            if (epoch_ == 0 || programmedBssidEpoch_ != epoch_)
            {
                // A pending station without a recorded physical BSSID is
                // inconsistent. No same-epoch reuse after losing the proof.
                retireNativeBssidEpoch(kIOReturnNotReady);
                return false;
            }
            const auto bus = backend_.activeRegisters();
            const simpleath::RegisterBus registers {
                &access_,
                readRegister,
                writeRegister,
                bus.barLengthBytes,
            };
            const auto cleared = simpleath::clearAr9565AssociationBssid(
                registers, epoch_, liveBssidPermit);
            setProperty("SimpleATHLastBssidClearResult",
                        static_cast<uint32_t>(cleared.result),
                        kRfPropertyWidthBits);
            if (cleared.result != simpleath::MacIdentityResult::Ok)
            {
                retireNativeBssidEpoch(kIOReturnNotReady);
                return false;
            }
            programmedBssidEpoch_ = 0;
            return true;
        }

        // A pending join's timer may be delivered after a management RX.
        // Reject an expired authentication/association lease before this RX
        // can queue another management frame, regardless of timer order.
        // The already-associated link has its own beacon/port deadline.
        bool verifyNativePendingJoinLease()
        {
            if (joinWatchRequestId_ == 0)
            {
                return true;
            }
            const uint64_t nowMs = nowMicros(nullptr) / kMicrosPerMillisecond;
            if (epoch_ != 0 && linkWatchEpoch_ == epoch_ &&
                joinEpoch_ == epoch_ && joinRequestId_ == joinWatchRequestId_ &&
                joinStatus_ == kIOReturnSuccess && joinWatchStartedMs_ != 0 &&
                nowMs >= joinWatchStartedMs_ &&
                nowMs - joinWatchStartedMs_ < kNativeJoinTimeoutMs)
            {
                return true;
            }
            // A clock regression, mismatched token or elapsed deadline ends
            // the physical PCU identity even if a timer callback is late.
            retireNativeBssidEpoch(kIOReturnTimeout);
            return false;
        }

        // Workloop timers are not ordered ahead of OS TX, key completions
        // or port authorization. Recheck both physical association leases
        // before any of those paths can emit a packet or open the port.
        // This does not grant RF permission: TX still needs canSubmitTransmit.
        IOReturn verifyNativeAssociationLease(uint64_t nowMs)
        {
            if (engine_.linkStatus().state !=
                simpleath::ieee80211::LinkState::Associated)
            {
                return kIOReturnNotReady;
            }
            if (portReadyPending_ &&
                (nowMs < portReadyStartedMs_ ||
                 nowMs - portReadyStartedMs_ >= kNativePortOpenTimeoutMs))
            {
                retireNativeLink(kIOReturnTimeout);
                return kIOReturnTimeout;
            }
            simpleath::ieee80211::EngineAction action {};
            const auto observed = engine_.checkBeaconTimeout(nowMs, action);
            if (observed == simpleath::ieee80211::EngineResult::NoAction)
            {
                return kIOReturnSuccess;
            }
            if (observed == simpleath::ieee80211::EngineResult::Ok &&
                action.kind == simpleath::ieee80211::ActionKind::LinkLost)
            {
                retireNativeLink(kIOReturnTimeout);
                return kIOReturnTimeout;
            }
            // Regressed clocks, malformed engine outputs and lost software
            // state cannot continue a physical CCMP/DMA ownership lease.
            retireNativeLink(kIOReturnNotReady);
            return kIOReturnNotReady;
        }

        // Submit only admitted 802.11 frames from the station engine or
        // the strict OS EAPOL/CCMP serializers. The RF owner must first
        // publish independently verified channel/rate/TPC authorization; no
        // EEPROM interpolation, software station state, or mailbox flag can
        // manufacture permission to transmit. This runs inside the PCI gate.
        IOReturn submitPreparedTransmit(const uint8_t *frame, size_t bytes,
                                        bool softwareProtected = false)
        {
            if (frame == nullptr || bytes < kMinimumMpduBytes ||
                bytes > kMaximumMpduBytes || !canSubmitTransmit())
            {
                return kIOReturnNotReady;
            }
            if (!queues_.hasTransmitSpace() || nextTransmitToken_ == 0 ||
                nextTransmitToken_ == UINT64_MAX)
            {
                return kIOReturnNoResources;
            }
            simpleath::edma::TxControlRequest control {};
            control.onAirFrameLength = static_cast<uint16_t>(bytes + kFcsBytes);
            control.packetType = simpleath::edma::TxPacketType::Normal;
            // The source CCMP session has already generated and authenticated
            // the entire 802.11 protected MPDU, including ExtIV and MIC. Use
            // hardware CLEAR descriptor mode to avoid double encryption; a
            // protected 802.11 frame with no software key is never accepted.
            uint16_t frameControl = 0;
            __builtin_memcpy(&frameControl, frame, sizeof(frameControl));
            constexpr uint16_t kProtectedFrameControl =
                static_cast<uint16_t>(kProtectedFrameFlag) << kByteBits;
            if (softwareProtected &&
                (!nativePairwiseTx_.installed() ||
                 (frameControl & kProtectedFrameControl) == 0))
            {
                return kIOReturnNotReady;
            }
            control.crypto = simpleath::edma::TxCrypto::Clear;
            control.keyCacheIndex = kNoKeyCacheSlot;
            control.rate[0] = txRate_;
            const IOReturn result = queues_.transmitGated(
                frame, bytes, nextTransmitToken_, control, txSafety_);
            if (result == kIOReturnSuccess)
            {
                ++nextTransmitToken_;
            }
            return result;
        }

        // Clear EAPOL M2/M4 is permitted only in the OS-owned WPA2
        // handshake. Other payloads cannot inherit this exception.
        simpleath::ieee80211::EngineResult prepareNativeClearHandshake(
            const NativeTransmitRequest &packet,
            const simpleath::ieee80211::LinkContext &connection,
            simpleath::ieee80211::EngineAction &action)
        {
            simpleath::ieee80211::SerializedData serialized {};
            const auto clear = simpleath::ieee80211::prepareStationTx(
                connection, packet.bytes, packet.length, txSequence_,
                &ethernetTx_[0], sizeof(ethernetTx_), serialized);
            if (clear != simpleath::ieee80211::DataPathResult::Ok ||
                !serialized.isEapol)
            {
                return simpleath::ieee80211::EngineResult::CryptoUnavailable;
            }
            action.kind = simpleath::ieee80211::ActionKind::TransmitEapol;
            action.bytes = serialized.frameBytes;
            return simpleath::ieee80211::EngineResult::Ok;
        }

        // The native pairwise session owns the CCMP PN/MIC. An error cannot
        // fall back to a clear data MPDU or fabricate OS-controlled-port trust.
        simpleath::ieee80211::EngineResult prepareNativeEncryptedEthernet(
            const NativeTransmitRequest &packet,
            const simpleath::ieee80211::LinkContext &connection,
            simpleath::ieee80211::EngineAction &action)
        {
            simpleath::ieee80211::SerializedData serialized {};
            const auto encrypted =
                simpleath::ieee80211::prepareProtectedStationTx(
                    connection, packet.bytes, packet.length, txSequence_,
                    nativePairwiseTx_, epoch_, &protectedScratch_[0],
                    sizeof(protectedScratch_), &ethernetTx_[0],
                    sizeof(ethernetTx_), serialized);
            if (encrypted == simpleath::ieee80211::DataPathResult::Ok)
            {
                action.kind =
                    serialized.isEapol
                        ? simpleath::ieee80211::ActionKind::TransmitEapol
                        : simpleath::ieee80211::ActionKind::TransmitData;
                action.bytes = serialized.frameBytes;
                return simpleath::ieee80211::EngineResult::Ok;
            }
            return encrypted ==
                           simpleath::ieee80211::DataPathResult::BufferTooSmall
                       ? simpleath::ieee80211::EngineResult::BufferTooSmall
                       : simpleath::ieee80211::EngineResult::CryptoUnavailable;
        }

        static IOReturn ownerTransmitEthernetAction(OSObject *object,
                                                    void *argument,
                                                    void * /*unused*/,
                                                    void * /*unused*/,
                                                    void * /*unused*/)
        {
            auto *self = OSDynamicCast(SimpleATH, object);
            if (self == nullptr || argument == nullptr)
            {
                return kIOReturnBadArgument;
            }
            const auto &packet =
                *static_cast<NativeTransmitRequest *>(argument);
            const auto link = self->engine_.linkStatus();
            // EAPOL M2/M4 and Group2 are part of OS-owned WPA2 key setup:
            // requiring the controlled data port to be open first would
            // deadlock the handshake. This exception MUST NOT admit general
            // Ethernet traffic, nor an unrelated AP or unparsed EAPOL frame.
            uint8_t ethernetHeader[kMinimumEthernetBytes] {};
            if (packet.bytes == nullptr ||
                packet.length < sizeof(ethernetHeader))
            {
                return kIOReturnBadArgument;
            }
            __builtin_memcpy(&ethernetHeader[0], packet.bytes,
                             sizeof(ethernetHeader));
            constexpr size_t kEtherTypeHighOffset = 12U;
            constexpr size_t kEtherTypeLowOffset = 13U;
            const bool isEapol =
                ethernetHeader[kEtherTypeHighOffset] ==
                    static_cast<uint8_t>(kEtherTypeEapol >> kByteBits) &&
                ethernetHeader[kEtherTypeLowOffset] ==
                    static_cast<uint8_t>(kEtherTypeEapol);
            const bool nativeHandshake =
                self->engine_.osSupplicantOwnsWpa2() &&
                self->engine_.stationState() ==
                    simpleath::ieee80211::StationState::WaitingForWpa2Keys;
            simpleath::ieee80211::StationEapolTxMode eapolMode =
                simpleath::ieee80211::StationEapolTxMode::Reject;
            if (isEapol)
            {
                // The complete fixed Ethernet header was copied above.
                // NOLINTNEXTLINE(*bounds-pointer-arithmetic)
                const auto *payload = packet.bytes + sizeof(ethernetHeader);
                eapolMode = simpleath::ieee80211::classifyStationEapolTx(
                    payload, packet.length - sizeof(ethernetHeader));
            }
            // A stale/replayed M2 after PTK installation is not a new
            // plaintext handshake. Group2 never selects a clear TX path.
            if (isEapol &&
                (!nativeHandshake ||
                 eapolMode ==
                     simpleath::ieee80211::StationEapolTxMode::Reject ||
                 (eapolMode == simpleath::ieee80211::StationEapolTxMode::
                                   ClearPairwise2 &&
                  self->nativePairwiseTx_.installed())))
            {
                return kIOReturnUnsupported;
            }
            if (!self->powered_ || self->stopping_ ||
                link.state != simpleath::ieee80211::LinkState::Associated ||
                self->nativePairwiseKeyRevoked_ ||
                (!self->controlledPortAuthorized_ &&
                 !(isEapol && nativeHandshake)))
            {
                return kIOReturnNotReady;
            }
            // An OS packet may reach this gate after the beacon/initial
            // EAPOL deadline but ahead of a delayed timer callback. Do not
            // consume CCMP TX PN or a DMA slot for that expired association.
            const IOReturn lease = self->verifyNativeAssociationLease(
                nowMicros(nullptr) / kMicrosPerMillisecond);
            if (lease != kIOReturnSuccess)
            {
                return lease;
            }
            if (!self->queues_.hasTransmitSpace())
            {
                return kIOReturnNoResources;
            }
            simpleath::ieee80211::InputTrust trust {};
            trust.radioReady = true;
            trust.channelAuthorized = true;
            simpleath::ieee80211::EngineAction action {};
            // The native owner uses an OS-supplied, same-epoch WPA2 key.
            // No generic WPA2 plaintext data is ever serialized. Initial
            // pairwise M2/M4 remain clear (by 802.11 specification); Group2
            // and ordinary post-key traffic MUST use the CCMP session.
            const bool protectedWpa2 = self->nativePairwiseTx_.installed();
            const bool keysReady = protectedWpa2 &&
                                   self->nativePairwiseRx_.installed() &&
                                   self->nativeGroupInstalled();
            const simpleath::ieee80211::LinkContext connection {
                link.station,
                link.bssid,
                simpleath::ieee80211::LinkSecurity::Wpa2Ccmp,
                true,
                self->radioOperational_,
                self->channelAuthorized_,
                keysReady,
            };
            simpleath::ieee80211::EngineResult prepared =
                simpleath::ieee80211::EngineResult::CryptoUnavailable;
            bool softwareProtected = false;
            const bool clearEapol =
                eapolMode ==
                    simpleath::ieee80211::StationEapolTxMode::ClearPairwise2 ||
                eapolMode ==
                    simpleath::ieee80211::StationEapolTxMode::ClearPairwise4;
            if (isEapol && clearEapol)
            {
                prepared = self->prepareNativeClearHandshake(packet, connection,
                                                             action);
            }
            // Never retry an invalid M2/M4 as CCMP. Only an explicit Group2
            // or admitted non-EAPOL data frame can enter encryption.
            if (prepared != simpleath::ieee80211::EngineResult::Ok &&
                protectedWpa2 && !clearEapol)
            {
                prepared = self->prepareNativeEncryptedEthernet(
                    packet, connection, action);
                softwareProtected =
                    prepared == simpleath::ieee80211::EngineResult::Ok;
            }
            else if (prepared != simpleath::ieee80211::EngineResult::Ok &&
                     !nativeHandshake && !protectedWpa2)
            {
                prepared = self->engine_.encodeOutgoingEthernet(
                    packet.bytes, packet.length, self->txSequence_, trust,
                    &self->ethernetTx_[0], sizeof(self->ethernetTx_), action);
            }
            if (prepared ==
                simpleath::ieee80211::EngineResult::CryptoUnavailable)
            {
                // A WPA2 data packet needs authentic CCMP PN/MIC handling;
                // never substitute an unencrypted MPDU for the OS payload.
                return kIOReturnUnsupported;
            }
            if (prepared != simpleath::ieee80211::EngineResult::Ok ||
                (action.kind !=
                     simpleath::ieee80211::ActionKind::TransmitData &&
                 action.kind !=
                     simpleath::ieee80211::ActionKind::TransmitEapol) ||
                action.bytes < kMinimumMpduBytes ||
                action.bytes > sizeof(self->ethernetTx_) - kFcsBytes)
            {
                return kIOReturnBadArgument;
            }
            const IOReturn result = self->submitPreparedTransmit(
                &self->ethernetTx_[0], action.bytes, softwareProtected);
            if (result == kIOReturnSuccess)
            {
                self->txSequence_ = static_cast<uint16_t>(
                    (self->txSequence_ + 1U) & kSequenceMask);
            }
            return result;
        }

        static IOReturn ownerTransmitEthernet(void *context,
                                              const uint8_t *bytes,
                                              size_t length)
        {
            if (context == nullptr || bytes == nullptr ||
                length < kMinimumEthernetBytes ||
                length > kNativeEthernetCapacity)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            // The owner gate may block behind reset/IRQ handling. Copy the
            // complete bounded Ethernet/EAPOL request before entering it;
            // a mutable OS packet must not change after preflight inspection.
            uint8_t stable[kNativeEthernetCapacity] {};
            __builtin_memcpy(&stable[0], bytes, length);
            NativeTransmitRequest request {&stable[0], length};
            const IOReturn result =
                self.gate_->runAction(ownerTransmitEthernetAction, &request);
            scrubRequest(&stable[0], sizeof(stable));
            return result;
        }

        static IOReturn ownerSubscribeAction(OSObject *object, void *argument,
                                             void * /*unused1*/,
                                             void * /*unused2*/,
                                             void * /*unused3*/)
        {
            // This action runs exclusively on the owner's registered gate.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(object);
            const auto &request =
                *static_cast<const NativeSubscribeRequest *>(argument);
            // A separate snapshot followed by a non-gated registration can
            // race a final provider stop. The same PCI work-loop gate must
            // protect live epoch validation AND callback publication.
            if (!self.started_ || !self.powered_ || self.stopping_ ||
                self.pci_ == nullptr || self.pci_->isInactive() ||
                self.epoch_ == 0 || self.board_.view(self.epoch_) == nullptr ||
                self.observerLock_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            IOLockLock(self.observerLock_);
            const bool vacant = self.wirelessObserver_ == nullptr;
            IOLockUnlock(self.observerLock_);
            if (!vacant)
            {
                return kIOReturnExclusiveAccess;
            }
            // Unsubscribe must be able to join callbacks after the PCI gate
            // has stopped, so it cannot safely mutate the engine. A new
            // subscription is serialized here on the live owner gate: retire
            // any scan or unacknowledged terminal ticket from the former
            // consumer before handing this epoch to a replacement observer.
            // Do not synthesize SCAN_DONE for the new OS consumer.
            (void)self.abortActiveNativeScan();
            self.scanBridge_.clear();
            self.completedScanTicket_ = {};
            self.notifiedScanGeneration_ = 0;
            IOLockLock(self.observerLock_);
            IOReturn registered = kIOReturnExclusiveAccess;
            if (self.wirelessObserver_ == nullptr)
            {
                self.wirelessObserver_ = request.observer;
                self.wirelessNotify_ = request.notify;
                self.wirelessReceive_ = request.receive;
                registered = kIOReturnSuccess;
            }
            IOLockUnlock(self.observerLock_);
            return registered;
        }

        static IOReturn ownerSubscribe(
            void *context, void *observer,
            IOReturn (*notify)(void *, simpleath::tahoe::WirelessEvent,
                               uint64_t, uint64_t),
            void (*receive)(void *, uint64_t, uint64_t, const uint8_t *,
                            size_t))
        {
            if (context == nullptr || observer == nullptr ||
                notify == nullptr || receive == nullptr)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            if (self.observerLock_ == nullptr || self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            NativeSubscribeRequest request {observer, notify, receive};
            // All validity and exclusive-registration checks run serially
            // with stop/terminate, not on the client's own work loop.
            return self.gate_->runAction(ownerSubscribeAction, &request);
        }

        static void ownerUnsubscribe(void *context, void *observer)
        {
            if ((context == nullptr) || (observer == nullptr))
            {
                return;
            }
            auto &self = *static_cast<SimpleATH *>(context);
            if (self.observerLock_ == nullptr)
            {
                return;
            }
            // Provider-stop notifications hold this lock throughout the
            // callback. Unsubscribe joins them before mailbox deallocation.
            IOLockLock(self.observerLock_);
            if (self.wirelessObserver_ == observer)
            {
                self.wirelessObserver_ = nullptr;
                self.wirelessNotify_ = nullptr;
                self.wirelessReceive_ = nullptr;
            }
            IOLockUnlock(self.observerLock_);
        }

        void notifyWirelessChange(bool terminating)
        {
            if (observerLock_ == nullptr)
            {
                return;
            }
            IOLockLock(observerLock_);
            if (wirelessObserver_ != nullptr && wirelessNotify_ != nullptr &&
                epoch_ != 0)
            {
                wirelessNotify_(
                    wirelessObserver_,
                    terminating
                        ? simpleath::tahoe::WirelessEvent::ProviderStopped
                        : simpleath::tahoe::WirelessEvent::RadioChanged,
                    epoch_, 0U);
            }
            IOLockUnlock(observerLock_);
        }

        static bool poweredGate(void *context)
        {
            auto const &self = *static_cast<RegisterAccess *>(context)->owner;
            return (self.loop_ != nullptr) && self.loop_->inGate() &&
                   self.powered_ && !self.stopping_ && (self.pci_ != nullptr) &&
                   !self.pci_->isInactive();
        }

        static uint64_t nowMicros(void * /*unused*/)
        {
            uint64_t absolute = 0;
            uint64_t nanos = 0;
            clock_get_uptime(&absolute);
            absolutetime_to_nanoseconds(absolute, &nanos);
            return nanos / kMicrosPerMillisecond;
        }

        static void delayMicros(void * /*unused*/, uint32_t micros)
        {
            // Round the deadline up; a short delay cannot count as a reset
            // pulse.
            const uint64_t end = nowMicros(nullptr) + micros + 1;
            IODelay((micros != 0U) ? micros : 1);
            while (nowMicros(nullptr) < end)
            {
                IODelay((micros != 0U) ? micros : 1);
            }
        }

        static bool nvmOwner(void *context)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return poweredGate(context) && self.epoch_ != 0 &&
                   self.session_.status().readAccessReady &&
                   (self.backend_.activeRegisters().read32 != nullptr);
        }

        static bool canReset(void *context, uint64_t epoch)
        {
            auto const &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && self.enginesQuiesced_ &&
                   nvmOwner(context);
        }

        static bool keyCachePermit(void *context, uint64_t epoch)
        {
            auto const &self = *static_cast<RegisterAccess *>(context)->owner;
            // Key RAM is mutable only with exclusive PCI ownership and all
            // descriptor engines and automatic MAC responses quiesced.
            const auto queue = self.queues_.phase();
            // A quarantined ring has uncertain ownership, even if the MAC
            // happens to report idle. Never touch key RAM during a DMA fault.
            return canReset(context, epoch) && !self.queuesAdopted_ &&
                   (queue == simpleath::NativeQueuePhase::Empty ||
                    queue == simpleath::NativeQueuePhase::Prepared) &&
                   !self.radioOperational_ && !self.channelAuthorized_;
        }

        simpleath::KeyCacheBackend keyCacheBackend()
        {
            return {
                &access_,
                epoch_,
                backend_.activeRegisters().barLengthBytes,
                keyCachePermit,
                readRegister,
                writeRegister,
            };
        }

        // Dynamic CCMP installation is admitted only within a native queue
        // lease that physically disabled MAC/DMA and bus mastering in this
        // exact owner epoch. Boot-time key-cache writes retain the stricter
        // all-engines-quiesced permit above.
        static bool liveKeyCachePermit(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && nvmOwner(context) &&
                   self.board_.view(epoch) != nullptr &&
                   self.radioOperational_ && self.channelAuthorized_ &&
                   self.liveRfKillUnblocked() &&
                   self.queues_.epoch() == epoch &&
                   self.queues_.keyUpdateIsolatedGated() &&
                   self.keyCache_.initialized &&
                   // Erasure temporarily marks requiresReset until all slots
                   // have actually been scrubbed. A write lease must still
                   // permit that rollback; preflight rejects new installs.
                   self.keyCache_.ownerContext == &self.access_ &&
                   self.keyCache_.ownerEpoch == epoch;
        }

        simpleath::KeyCacheBackend liveKeyCacheBackend()
        {
            return {
                &access_,
                epoch_,
                backend_.activeRegisters().barLengthBytes,
                liveKeyCachePermit,
                readRegister,
                writeRegister,
            };
        }

        // Link loss is a one-way terminal queue isolation, not a WPA2 rekey.
        // Only its specific physical same-epoch and no-pending-TX proof may
        // authorize the last keycache scrub before a complete hardware reset.
        static bool retiredLinkKeyCachePermit(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && nvmOwner(context) &&
                   self.board_.view(epoch) != nullptr &&
                   self.queues_.epoch() == epoch &&
                   self.queues_.linkRetirementIsolatedGated() &&
                   self.keyCache_.initialized &&
                   self.keyCache_.ownerContext == &self.access_ &&
                   self.keyCache_.ownerEpoch == epoch;
        }

        simpleath::KeyCacheBackend retiredLinkKeyCacheBackend()
        {
            return {
                &access_,
                epoch_,
                backend_.activeRegisters().barLengthBytes,
                retiredLinkKeyCachePermit,
                readRegister,
                writeRegister,
            };
        }

        static bool isolateRetiredLink(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && self.queues_.retireLinkGated();
        }

        static bool eraseRetiredLinkKeys(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            if (epoch != self.epoch_ || !self.keyCache_.initialized)
            {
                return false;
            }
            const auto result = simpleath::eraseAr9565Keys(
                self.retiredLinkKeyCacheBackend(), self.keyCache_);
            self.setProperty("SimpleATHLinkLossKeyCacheEraseResult",
                             static_cast<uint32_t>(result.result),
                             kRfPropertyWidthBits);
            return result.result == simpleath::KeyCacheResult::Ok &&
                   !result.requiresReset;
        }

        static bool nativeKeyInstallPermit(void *context)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            if (self.keyCache_.requiresReset)
            {
                return false;
            }
            if (self.queues_.phase() == simpleath::NativeQueuePhase::Running)
            {
                if (!self.canSubmitTransmit() ||
                    self.queues_.beginKeyUpdateGated() != kIOReturnSuccess)
                {
                    return false;
                }
            }
            return liveKeyCachePermit(context, self.epoch_);
        }

        static bool nativeNonce(void *context, uint8_t *data, size_t bytes)
        {
            if (context == nullptr || data == nullptr ||
                bytes != simpleath::ieee80211::kWpa2NonceBytes)
            {
                return false;
            }
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            // The callback runs synchronously on the PCI command gate, not
            // through untrusted or repeatable userland/random-number state.
            if (!nvmOwner(context) || !self.keyCache_.initialized ||
                self.keyCache_.ownerEpoch != self.epoch_ ||
                self.board_.view(self.epoch_) == nullptr ||
                !self.radioOperational_ || !self.channelAuthorized_ ||
                !self.liveRfKillUnblocked())
            {
                return false;
            }
            read_random(data, static_cast<unsigned int>(bytes));
            if (!nvmOwner(context) ||
                self.keyCache_.ownerEpoch != self.epoch_ ||
                !self.liveRfKillUnblocked())
            {
                scrubRequest(data, bytes);
                return false;
            }
            return true;
        }

        static bool nativeInstallPairwise(void *context,
                                          const simpleath::ieee80211::Mac &ap,
                                          const uint8_t *key)
        {
            if (context == nullptr || key == nullptr)
            {
                return false;
            }
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            const auto link = self.engine_.linkStatus();
            // Reject an unrelated AP or OS-owned handshake BEFORE stopping
            // live DMA. A rejected callback must not strand a key-update
            // lease that has no successful key installation to finish it.
            if (link.state != simpleath::ieee80211::LinkState::Associated ||
                self.engine_.osSupplicantOwnsWpa2() ||
                self.nativePairwiseKeyRevoked_ ||
                self.nativePairwiseTx_.installed() ||
                self.nativePairwiseRx_.installed() ||
                !simpleath::ieee80211::sameMac(link.bssid, ap) ||
                !nativeKeyInstallPermit(context))
            {
                return false;
            }
            const auto result = simpleath::installAr9565PairwiseKey(
                self.liveKeyCacheBackend(), self.keyCache_, ap, key);
            // Bind the same authenticated driver-owned TK to the software
            // CCMP MIC/PN verifier and TX sequencer. This does not assume
            // that hardware RX hands us untouched ciphertext: an on-air
            // protected MPDU must still pass independent MIC/PN verification.
            self.nativeProtectedFragments_.clear();
            const auto tx =
                result.result == simpleath::KeyCacheResult::Ok
                    ? self.nativePairwiseTx_.install(
                          key, &link.station.bytes[0], 0, self.epoch_, 0, 0)
                    : simpleath::ieee80211::crypto::CcmpResult::InvalidArgument;
            const auto rx =
                tx == simpleath::ieee80211::crypto::CcmpResult::Ok
                    ? self.nativePairwiseRx_.install(key, &ap.bytes[0], 0,
                                                     self.epoch_, 0, 0)
                    : simpleath::ieee80211::crypto::CcmpResult::InvalidArgument;
            if (result.result != simpleath::KeyCacheResult::Ok ||
                tx != simpleath::ieee80211::crypto::CcmpResult::Ok ||
                rx != simpleath::ieee80211::crypto::CcmpResult::Ok)
            {
                self.nativePairwiseTx_.revoke();
                self.nativeProtectedFragments_.clear();
                self.nativePairwiseRx_.revoke();
                // Once hardware key RAM may have been modified, an error is
                // not a harmless handshake retry. The borrowed RX callback
                // will unwind before NativeQueues tries to restart; denying
                // radioReady forces quarantine rather than reusing key RAM.
                self.keyCache_.requiresReset = true;
                self.controlledPortAuthorized_ = false;
                self.radioOperational_ = false;
                self.channelAuthorized_ = false;
                self.txSafety_ = {};
            }
            return result.result == simpleath::KeyCacheResult::Ok &&
                   tx == simpleath::ieee80211::crypto::CcmpResult::Ok &&
                   rx == simpleath::ieee80211::crypto::CcmpResult::Ok;
        }

        static bool nativeInstallGroup(void *context, uint8_t keyId,
                                       const uint8_t *key,
                                       const uint8_t *keyRsc)
        {
            if (context == nullptr || key == nullptr || keyRsc == nullptr)
            {
                return false;
            }
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            const auto link = self.engine_.linkStatus();
            auto *groupRx = self.nativeGroupSlot(keyId);
            if (link.state != simpleath::ieee80211::LinkState::Associated ||
                self.engine_.osSupplicantOwnsWpa2() || groupRx == nullptr ||
                !nativeKeyInstallPermit(context))
            {
                return false;
            }
            const auto result = simpleath::installAr9565GroupKey(
                self.liveKeyCacheBackend(), self.keyCache_, keyId, key, keyRsc);
            // The hardware keycache validated the MIC-authenticated RSC and
            // retained its 48-bit PN floor. Mirrored GTK replay state must
            // start at that exact floor, never an invented zero.
            self.nativeProtectedFragments_.clear();
            const auto mirrored =
                result.result == simpleath::KeyCacheResult::Ok
                    // groupRx is the bounded, epoch-local mirrored GTK.
                    ? groupRx->install(
                          key, &link.bssid.bytes[0], keyId, self.epoch_, 0,
                          // NOLINTNEXTLINE(*bounds-constant-array-index)
                          self.keyCache_.group[keyId].receiveFloor)
                    : simpleath::ieee80211::crypto::CcmpResult::InvalidArgument;
            if (result.result != simpleath::KeyCacheResult::Ok ||
                mirrored != simpleath::ieee80211::crypto::CcmpResult::Ok)
            {
                self.nativeProtectedFragments_.clear();
                groupRx->revoke();
                // Group-key failure can leave half-installed physical slots.
                // Refuse any deferred EDMA restart until the whole epoch is
                // reset, even if the portable supplicant resets its state.
                self.keyCache_.requiresReset = true;
                self.controlledPortAuthorized_ = false;
                self.radioOperational_ = false;
                self.channelAuthorized_ = false;
                self.txSafety_ = {};
            }
            return result.result == simpleath::KeyCacheResult::Ok &&
                   mirrored == simpleath::ieee80211::crypto::CcmpResult::Ok;
        }

        static void nativeRemoveKeys(void *context)
        {
            if (context == nullptr)
            {
                return;
            }
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            self.controlledPortAuthorized_ = false;
            self.pendingWpa2M4Token_ = 0;
            self.pendingWpa2Group2Token_ = 0;
            self.deferredGroup2_ = false;
            self.wpa2M4TransmitConfirmed_ = false;
            self.authenticatedProtectedRxObserved_ = false;
            self.nativePairwiseTx_.revoke();
            self.nativeProtectedFragments_.clear();
            self.nativePairwiseRx_.revoke();
            for (auto &slot : self.nativeGroupRx_)
            {
                slot.revoke();
            }
            // A partial install is indistinguishable from a full one: do not
            // trust a previously authorized data port until the key slots are
            // truly erased or the silicon has undergone a full reset.
            if (!self.keyCache_.initialized ||
                (!self.keyCache_.pairwiseInstalled &&
                 !self.keyCache_.group[0].installed &&
                 !self.keyCache_.group[1].installed &&
                 !self.keyCache_.group[2].installed &&
                 !self.keyCache_.group[3].installed))
            {
                return;
            }
            const bool leaseAcquiredHere =
                self.queues_.phase() == simpleath::NativeQueuePhase::Running;
            if (nativeKeyInstallPermit(context) &&
                simpleath::eraseAr9565Keys(self.liveKeyCacheBackend(),
                                           self.keyCache_)
                        .result == simpleath::KeyCacheResult::Ok)
            {
                // An explicit OS disconnect/key reset can run outside RX.
                // Do not strand its queue lease after verified key erasure.
                if (leaseAcquiredHere)
                {
                    (void)self.queues_.endKeyUpdateGated();
                }
                return;
            }
            // Unsafe or uncertain erasure cannot be treated as clean. Force
            // complete hardware reinitialization before another admission.
            self.keyCache_.requiresReset = true;
            self.radioOperational_ = false;
            self.channelAuthorized_ = false;
            self.txSafety_ = {};
            if (leaseAcquiredHere && self.queues_.keyUpdateIsolatedGated())
            {
                (void)self.queues_.endKeyUpdateGated();
            }
        }

        static bool stationMacPermit(void *context, uint64_t epoch)
        {
            const auto &self = *static_cast<RegisterAccess *>(context)->owner;
            // Initial NVM programming occurs before DMA adoption. A later
            // OS MAC override may run only while the same-epoch queues remain
            // physically Prepared, ineligible for RX and not borrowed by a
            // key-update isolation lease. Never program over running DMA.
            return canReset(context, epoch) &&
                   self.board_.view(epoch) != nullptr &&
                   (!self.queuesAdopted_ ||
                    (self.queues_.epoch() == epoch &&
                     self.queues_.phase() ==
                         simpleath::NativeQueuePhase::Prepared &&
                     self.queues_.initialStartEligibleGated())) &&
                   !self.radioOperational_ && !self.channelAuthorized_;
        }

        // This permit is valid only for a running, truly authorized native
        // station and a free TX descriptor. The PHY still belongs to the same
        // serialized live PCI epoch, but a stale scan selection cannot grant
        // PCU BSSID/AID register access or automatic TX authority.
        static bool liveBssidPermit(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && nvmOwner(context) &&
                   self.canSubmitTransmit() && self.queues_.hasTransmitSpace();
        }

        static bool rfBoardPermit(void *context, uint64_t epoch)
        {
            const auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return canReset(context, epoch) &&
                   self.board_.view(epoch) != nullptr && !self.queuesAdopted_ &&
                   !self.radioOperational_ && !self.channelAuthorized_;
        }

        static bool rfPowerPermit(void *context, uint64_t epoch)
        {
            if (!rfBoardPermit(context, epoch))
            {
                return false;
            }
            const auto &self = *static_cast<RegisterAccess *>(context)->owner;
            if (!self.rfKillPinConfigured_)
            {
                // Missing EEPROM GPIO is unknown, not permission for RF.
                // PMU/XTAL tuning cannot itself enable automatic responses.
                return true;
            }
            if (!self.rfKillKnownUnblocked_)
            {
                return false;
            }
            // The stable double sample established polarity. Recheck the
            // live input before EVERY regulator/XTAL MMIO operation: a switch
            // flipped mid-sequence revokes access even while still in D0.
            uint32_t level = 0;
            if (!readRegister(context, kRfKillInputRegister, &level))
            {
                return false;
            }
            const bool high = (level & (uint32_t {1} << self.rfKillGpio_)) != 0;
            return high != self.rfKillActiveHigh_;
        }

        // Native EDMA RX timestamp attestation is READ ONLY. The callback
        // synchronizes the AR9003 TSF register against the kernel monotonic
        // clock only during a live, physically authorized channel-six lease.
        // Neither a valid TSF nor a decoded MIF can turn radio readiness on.
        static bool awdlTsfPermit(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && nvmOwner(context) &&
                   self.board_.view(epoch) != nullptr &&
                   self.radioOperational_ && self.channelAuthorized_ &&
                   self.verifiedReceiveChannel_ == kAwdlSocialChannelSix &&
                   self.queues_.epoch() == epoch &&
                   self.queues_.phase() ==
                       simpleath::NativeQueuePhase::Running &&
                   self.liveRfKillUnblocked();
        }

        static bool rfKillRuntimePermit(void *context, uint64_t epoch)
        {
            const auto &self = *static_cast<RegisterAccess *>(context)->owner;
            // Unlike boot-time GPIO configuration, a runtime *read* must
            // remain legal when EDMA and the 802.11 MAC are active. Never
            // reuse rfBoardPermit's quiescence prerequisite here.
            return epoch == self.epoch_ && nvmOwner(context) &&
                   self.board_.view(epoch) != nullptr &&
                   self.rfKillPinConfigured_ && self.rfKillKnownUnblocked_;
        }

        bool liveRfKillUnblocked()
        {
            if (!rfKillRuntimePermit(&access_, epoch_))
            {
                return false;
            }
            const simpleath::RfKillBoardConfiguration board {
                rfKillPinConfigured_,
                rfKillGpio_,
                rfKillActiveHigh_,
            };
            const simpleath::RfKillReadBackend backend {
                &access_,
                epoch_,
                backend_.activeRegisters().barLengthBytes,
                rfKillRuntimePermit,
                readRegister,
                delayMicros,
            };
            return simpleath::observeAr9565RfKill(board, backend).result ==
                   simpleath::RfKillResult::Unblocked;
        }

        simpleath::RxAgcBackend rfPowerBackend()
        {
            const simpleath::RfIniBackend io {
                &access_,
                epoch_,
                backend_.activeRegisters().barLengthBytes,
                rfPowerPermit,
                writeRegister,
                delayMicros,
            };
            return {
                io,
                readRegister,
            };
        }

        simpleath::RfKillBackend rfKillBackend()
        {
            return {
                &access_,
                epoch_,
                backend_.activeRegisters().barLengthBytes,
                rfBoardPermit,
                readRegister,
                writeRegister,
                delayMicros,
            };
        }

        static bool readRegister(void *context, uint32_t offset,
                                 uint32_t *value)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            const auto bus = self.backend_.activeRegisters();
            return (bus.read32 != nullptr) &&
                   bus.read32(bus.context, offset, value);
        }

        static bool writeRegister(void *context, uint32_t offset,
                                  uint32_t value)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            const auto bus = self.backend_.activeRegisters();
            return (bus.write32 != nullptr) &&
                   bus.write32(bus.context, offset, value);
        }

        static bool currentQueueOwner(void *context, uint64_t epoch)
        {
            auto const &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && nvmOwner(context);
        }

        static bool queueRadioReady(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            // EDMA start and each descriptor submission must recheck the
            // physical switch, not just an earlier boot-time radio flag.
            return currentQueueOwner(context, epoch) &&
                   self.radioOperational_ && self.channelAuthorized_ &&
                   self.stationMacProgrammed_ && self.liveRfKillUnblocked();
        }

        static bool queueBusMaster(void *context, bool enabled)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return self.backend_.setBusMasterGated(enabled);
        }

        // Each completed EDMA buffer is borrowed only until this callback
        // returns. The native controller copies the constructed Ethernet
        // packet synchronously into its own mailbox; neither DMA nor CCMP
        // scratch pointers can escape this gate.
        void deliverNativeMsdu(const simpleath::ieee80211::Msdu &msdu,
                               bool protectedEapol)
        {
            const bool handshake =
                protectedEapol && msdu.etherType == kEtherTypeEapol;
            if (!radioOperational_ || !channelAuthorized_ ||
                queues_.phase() != simpleath::NativeQueuePhase::Running ||
                observerLock_ == nullptr ||
                (!controlledPortAuthorized_ && !handshake))
            {
                return;
            }
            size_t ethernetBytes = 0;
            if (simpleath::ieee80211::encodeReceivedEthernet(
                    msdu, &ethernetRx_[0], sizeof(ethernetRx_),
                    ethernetBytes) != simpleath::ieee80211::Result::Ok)
            {
                return;
            }
            IOLockLock(observerLock_);
            if (wirelessObserver_ != nullptr && wirelessReceive_ != nullptr &&
                radioOperational_ && channelAuthorized_ &&
                (controlledPortAuthorized_ || handshake))
            {
                wirelessReceive_(wirelessObserver_, epoch_,
                                 associationGeneration_, &ethernetRx_[0],
                                 ethernetBytes);
            }
            IOLockUnlock(observerLock_);
        }

        // Only a CCMP/PN-authenticated, borrowed Group1 may reach this
        // driver-owned WPA2 GTK replacement. The native key callback takes
        // a physical DMA/key-RAM lease; Group2 transmits after DMA release.
        void finishNativeDriverGroup1(const simpleath::ieee80211::Msdu &msdu)
        {
            // CCMP MIC/PN was verified exactly once above.
            // Do not re-decrypt the same Group1 and consume
            // its replay PN twice. The GTK callback must
            // isolate physical key RAM before any Group2 TX.
            simpleath::ieee80211::EngineAction group2 {};
            const simpleath::ieee80211::InputTrust trust {
                true,
                true,
                true,
                true,
            };
            const auto prepared =
                pendingWpa2Group2Token_ == 0
                    ? engine_.finishAuthenticatedGroupRekey(
                          msdu, trust, nativePairwiseRx_, nativePairwiseTx_,
                          epoch_, txSequence_, &protectedScratch_[0],
                          sizeof(protectedScratch_), &managementReply_[0],
                          sizeof(managementReply_), group2)
                    : simpleath::ieee80211::EngineResult::InvalidState;
            const bool ready =
                prepared == simpleath::ieee80211::EngineResult::Ok &&
                group2.kind ==
                    simpleath::ieee80211::ActionKind::TransmitEapol &&
                group2.bytes >= kMinimumMpduBytes &&
                group2.bytes <= sizeof(managementReply_) &&
                queues_.keyUpdateIsolatedGated();
            if (ready)
            {
                deferredGroup2_ = true;
                // Share the on-air MAC sequence with native
                // data TX; portable engine sequence is
                // separate.
                txSequence_ =
                    static_cast<uint16_t>((txSequence_ + 1U) & kSequenceMask);
                // Defers transmission until RX DMA unpins
                // and same-epoch MAC/EDMA physically restart.
                (void)finishNativeRxKeyLease(prepared, group2);
            }
            else
            {
                // An unacknowledgeable GTK replacement cannot leave old
                // key RAM, replay state or live EDMA in this association.
                retireNativeLink(kIOReturnNotReady);
            }
        }

        void receiveNativeDriverMsdu(const simpleath::ieee80211::Msdu &msdu)
        {
            // EAPOL is never forwarded to a second supplicant. Only Group1
            // may install GTK and produce a protected Group2 response.
            if (msdu.etherType == kEtherTypeEapol)
            {
                simpleath::ieee80211::KeyFrame key {};
                if (simpleath::ieee80211::parseEapolKey(
                        msdu.payload, msdu.payloadLength, key) ==
                        simpleath::ieee80211::EapolResult::Ok &&
                    key.message == simpleath::ieee80211::KeyMessage::Group1)
                {
                    finishNativeDriverGroup1(msdu);
                }
                return;
            }
            authenticatedProtectedRxObserved_ = true;
            if (!controlledPortAuthorized_ && wpa2M4TransmitConfirmed_ &&
                associatedBeaconObserved_)
            {
                bool requestOpen = true;
                (void)ownerAuthorizePortAction(this, &requestOpen, nullptr,
                                               nullptr, nullptr);
            }
            deliverNativeMsdu(msdu, false);
        }

        // One authenticated MPDU can contain several Ethernet subframes.
        // A synchronous OS receive callback may retire/rejoin the provider;
        // never forward a later subframe into that replacement association.
        void deliverNativeAmsdu(const simpleath::ieee80211::AmsduPayload &batch)
        {
            if (batch.count == 0U ||
                batch.count > simpleath::ieee80211::kMaximumAmsduSubframes)
            {
                return;
            }
            const uint64_t acceptedEpoch = epoch_;
            const uint64_t acceptedJoin = joinRequestId_;
            const uint64_t acceptedAssociation = associationGeneration_;
            const auto acceptedStationState = engine_.stationState();
            size_t delivered = 0U;
            for (const auto &subframe : batch.subframes)
            {
                if (delivered == batch.count ||
                    !simpleath::tahoe::acceptWirelessPortIdentity(
                        acceptedEpoch, acceptedJoin, acceptedAssociation,
                        epoch_, joinRequestId_, associationGeneration_) ||
                    joinEpoch_ != acceptedEpoch || !powered_ || stopping_ ||
                    !controlledPortAuthorized_ || !associatedBeaconObserved_ ||
                    pendingLocalLeaveToken_ != 0U || !radioOperational_ ||
                    !channelAuthorized_ || !liveRfKillUnblocked() ||
                    queues_.epoch() != acceptedEpoch ||
                    queues_.phase() != simpleath::NativeQueuePhase::Running ||
                    engine_.stationState() != acceptedStationState ||
                    engine_.linkStatus().state !=
                        simpleath::ieee80211::LinkState::Associated)
                {
                    break;
                }
                ++delivered;
                deliverNativeMsdu(subframe, false);
            }
        }

        // This is the one native path for protected QoS A-MSDUs. The CCMP
        // session itself rejects aggregation unless SPP was independently
        // negotiated at key installation. Every member of the aggregate
        // borrows decrypted scratch only until this RX callback returns.
        void receiveNativeProtectedAmsdu(
            const simpleath::ieee80211::LinkContext &connection,
            const uint8_t *frame, size_t bytes,
            simpleath::ieee80211::crypto::CcmpSession &receive)
        {
            if (!controlledPortAuthorized_ || !associatedBeaconObserved_ ||
                joinEpoch_ != epoch_ || bytes <= kFcsBytes)
            {
                return;
            }
            const size_t mpduBytes = bytes - kFcsBytes;
            simpleath::ieee80211::AmsduPayload decoded {};
            const auto result =
                simpleath::ieee80211::inspectProtectedStationAmsduRx(
                    connection, frame, bytes, true, true, receive, epoch_,
                    &protectedRxScratch_[0], sizeof(protectedRxScratch_),
                    decoded);
            setProperty("SimpleATHLastProtectedReceiveResult",
                        static_cast<uint32_t>(result), kRfPropertyWidthBits);
            if (result != simpleath::ieee80211::DataPathResult::Ok)
            {
                return;
            }
            // ExtIV and MIC are authenticated by the CCMP decoder. The FCS
            // was independently verified by the DMA owner and stripped.
            const size_t plainBytes =
                mpduBytes - kCcmpExtIvBytes - kCcmpMicBytes;
            const simpleath::ieee80211::InputTrust trust {
                true, channelAuthorized_, true, true, false,
            };
            simpleath::ieee80211::AmsduPayload accepted {};
            const auto admitted = engine_.acceptVerifiedProtectedAmsduRx(
                &protectedRxScratch_[0], plainBytes, trust, accepted);
            setProperty("SimpleATHLastAmsduReceiveResult",
                        static_cast<uint32_t>(admitted), kRfPropertyWidthBits);
            if (admitted == simpleath::ieee80211::EngineResult::Ok)
            {
                deliverNativeAmsdu(accepted);
                ++receivedFrames_;
                setProperty("SimpleATHReceivedFrames", receivedFrames_,
                            kCounterPropertyWidthBits);
            }
        }

        void publishNativeProtectedMsdu(const uint8_t *frame, size_t mpduBytes,
                                        bool driverOwned,
                                        const simpleath::ieee80211::Msdu &msdu)
        {
            // CCMP MIC/PN and complete fragment station admission precede
            // this call. Ordinary data consumes the shared QoS/legacy
            // sequence window; EAPOL Group1 retains its separate replay/MIC
            // rules and must not be dropped as an ordinary duplicate.
            const simpleath::ieee80211::InputTrust trust {
                true, channelAuthorized_, true, true, false,
            };
            const auto admitted = msdu.etherType == kEtherTypeEapol
                                      ? simpleath::ieee80211::EngineResult::Ok
                                      : engine_.acceptVerifiedProtectedDataRx(
                                            frame, mpduBytes, trust, msdu);
            if (admitted != simpleath::ieee80211::EngineResult::Ok)
            {
                return;
            }
            if (driverOwned)
            {
                receiveNativeDriverMsdu(msdu);
            }
            else
            {
                // OS-owned protected EAPOL may reach its single supplicant
                // before the OS opens the controlled data port.
                deliverNativeMsdu(msdu, true);
            }
        }

        void receiveNativeProtected(const uint8_t *frame, size_t bytes,
                                    const simpleath::edma::RxStatus &status)
        {
            // Do not guess a key from a 802.11 header before validating the
            // hardware status, FCS span, association and CCMP IV bounds.
            // The selected session then authenticates the MIC and replay PN.
            const auto link = engine_.linkStatus();
            const bool driverOwned =
                !engine_.osSupplicantOwnsWpa2() &&
                engine_.stationState() ==
                    simpleath::ieee80211::StationState::HardwareKeysInstalled &&
                keyCache_.initialized && keyCache_.ownerEpoch == epoch_ &&
                keyCache_.pairwiseInstalled && !keyCache_.requiresReset;
            if (frame == nullptr || bytes < kFcsBytes ||
                bytes > simpleath::ieee80211::crypto::kCcmpMaximumMpduBytes ||
                !status.frameValid || status.crcError || status.decryptError ||
                status.phyError || status.micError || status.keyMiss ||
                !powered_ || !radioOperational_ || !channelAuthorized_ ||
                queues_.phase() != simpleath::NativeQueuePhase::Running ||
                queues_.epoch() != epoch_ ||
                link.state != simpleath::ieee80211::LinkState::Associated ||
                (!driverOwned && !engine_.osSupplicantOwnsWpa2()) ||
                nativePairwiseKeyRevoked_ || !nativePairwiseTx_.installed() ||
                !nativePairwiseRx_.installed() || !nativeGroupInstalled())
            {
                nativeProtectedFragments_.clear();
                return;
            }
            const size_t mpduBytes = bytes - kFcsBytes;
            simpleath::ieee80211::Frame header {};
            if (simpleath::ieee80211::parseFrame(frame, mpduBytes, header) !=
                    simpleath::ieee80211::Result::Ok ||
                header.type != simpleath::ieee80211::FrameType::Data ||
                !header.protectedFrame ||
                mpduBytes <
                    header.headerLength + kCcmpExtIvBytes + kCcmpMicBytes + 1U)
            {
                return;
            }
            // Untrusted KeyID selects a candidate GTK/PTK only. The CCMP
            // owner must still authenticate the MIC and replay PN.
            auto *receive = selectNativeReceiveKey(header, frame, mpduBytes);
            if (receive == nullptr)
            {
                return;
            }
            const simpleath::ieee80211::LinkContext connection {
                link.station,
                link.bssid,
                simpleath::ieee80211::LinkSecurity::Wpa2Ccmp,
                true,
                radioOperational_,
                channelAuthorized_,
                true,
            };
            simpleath::ieee80211::Msdu msdu {};
            // A CCMP fragment authenticates *its own* IV/MIC before any
            // portion can enter an MSDU. No raw fragment may reach the native
            // Ethernet or EAPOL port. Ordinary CCMP packets retain the old
            // strictly nonfragmented path and PN/replay lifetime.
            const bool fragmented =
                header.moreFragments || header.fragment != 0U;
            // The untrusted QoS bit selects only a candidate decoder. The
            // CCMP SPP A-MSDU AAD and MIC must authenticate it before use.
            // Fragmented aggregates are not admitted by this RX contract.
            uint8_t qosControl = 0U;
            if (header.subtype == kNativeQosDataSubtype &&
                header.headerLength == kNativeQosHeaderBytes)
            {
                // A parsed QoS MPDU includes this complete fixed header.
                uint8_t qosHeader[kNativeQosHeaderBytes] {};
                __builtin_memcpy(&qosHeader[0], frame, sizeof(qosHeader));
                qosControl = qosHeader[kNativeQosControlOffset];
            }
            if ((qosControl & kNativeAmsduPresent) != 0U)
            {
                if (!fragmented)
                {
                    receiveNativeProtectedAmsdu(connection, frame, bytes,
                                                *receive);
                }
            }
            else
            {
                const auto result =
                    fragmented
                        ? simpleath::ieee80211::
                              inspectProtectedFragmentStationRx(
                                  connection, frame, bytes, true, true,
                                  *receive, epoch_, nativeProtectedFragments_,
                                  nowMicros(nullptr) / kMicrosPerMillisecond,
                                  &protectedRxScratch_[0],
                                  sizeof(protectedRxScratch_), msdu)
                        : simpleath::ieee80211::inspectProtectedStationRx(
                              connection, frame, bytes, true, true, *receive,
                              epoch_, &protectedRxScratch_[0],
                              sizeof(protectedRxScratch_), msdu);
                setProperty("SimpleATHLastProtectedReceiveResult",
                            static_cast<uint32_t>(result),
                            kRfPropertyWidthBits);
                if (result == simpleath::ieee80211::DataPathResult::Ok)
                {
                    publishNativeProtectedMsdu(frame, mpduBytes, driverOwned,
                                               msdu);
                }
            }
            // Scrub even malformed/authentication-failed partial plaintext.
            // Keep the borrowed Msdu strictly within this synchronous scope.
            volatile uint8_t *const clear = &protectedRxScratch_[0];
            for (size_t i = 0; i < sizeof(protectedRxScratch_); ++i)
            {
                // NOLINTNEXTLINE(*bounds-pointer-arithmetic)
                clear[i] = 0;
            }
        }

        void receiveNativePreKeyEapol(const uint8_t *frame, size_t bytes,
                                      const simpleath::edma::RxStatus &status)
        {
            // The OS supplicant is the only EAPOL/key owner on the native
            // data path. Inspect the selected AP and genuine EDMA/FCS status
            // before forwarding unprotected M1/M3 to that owner. Never admit
            // ordinary cleartext data or a protected frame without its key.
            const auto link = engine_.linkStatus();
            if (frame == nullptr || bytes < kFcsBytes || !status.frameValid ||
                status.crcError || status.decryptError || status.phyError ||
                status.micError || status.keyMiss ||
                queues_.epoch() != epoch_ ||
                queues_.phase() != simpleath::NativeQueuePhase::Running ||
                link.state != simpleath::ieee80211::LinkState::Associated ||
                engine_.stationState() !=
                    simpleath::ieee80211::StationState::WaitingForWpa2Keys ||
                !engine_.osSupplicantOwnsWpa2() ||
                nativePairwiseTx_.installed() ||
                nativePairwiseRx_.installed() || nativeGroupInstalled())
            {
                return;
            }
            const simpleath::ieee80211::LinkContext connection {
                link.station,
                link.bssid,
                simpleath::ieee80211::LinkSecurity::Wpa2Ccmp,
                true,
                radioOperational_,
                channelAuthorized_,
                false,
            };
            simpleath::ieee80211::Msdu msdu {};
            if (simpleath::ieee80211::inspectStationRx(
                    connection, frame, bytes, true, true, false, msdu) ==
                    simpleath::ieee80211::DataPathResult::Ok &&
                msdu.etherType == kEtherTypeEapol)
            {
                deliverNativeMsdu(msdu, true);
            }
        }

        void retireNativeLink(IOReturn reason)
        {
            // One command-gated terminal path handles AP deauthentication,
            // beacon timeout and OS disconnect. Revoke software delivery
            // FIRST; hardware must not consume a stale key or resume an old
            // queue even when physical erasure is not possible.
            controlledPortAuthorized_ = false;
            nativePairwiseTx_.revoke();
            nativeProtectedFragments_.clear();
            nativePairwiseRx_.revoke();
            for (auto &group : nativeGroupRx_)
            {
                group.revoke();
            }
            nativePairwiseKeyRevoked_ = true;
            nativeGroupKeyRevokedMask_ = kAllGroupKeySlotsRevoked;
            const simpleath::NativeLinkRetirementBackend backend {
                &access_,
                isolateRetiredLink,
                eraseRetiredLinkKeys,
            };
            const auto retired = simpleath::retireNativeLinkHardware(
                backend, epoch_, epoch_, keyCache_.initialized,
                keyCache_.ownerEpoch);
            setProperty("SimpleATHLinkLossQueueIsolated",
                        retired.queueIsolated);
            setProperty("SimpleATHLinkLossKeyCacheWipeConfirmed",
                        retired.hardwareKeysErased);
            // A verified wipe still cannot reactivate the retired EDMA,
            // inherited scan or original association in this physical epoch.
            // Lost ownership and partial erasure require a full silicon reset.
            programmedBssidEpoch_ = 0;
            keyCache_.requiresReset = retired.requiresNewPhysicalEpoch;
            setProperty("SimpleATHKeyCacheResetRequired",
                        keyCache_.requiresReset);
            radioOperational_ = false;
            channelAuthorized_ = false;
            txSafety_ = {};
            const bool scanAborted = abortActiveNativeScan();
            if (scanAborted)
            {
                notifyWirelessScanFinished();
            }
            // Link retirement revokes RF access, not the PCI epoch. Keep any
            // scan completion intent for the same-epoch native consumer to
            // acknowledge, while invalidating earlier BSS enumeration.
            completedScanTicket_ = {};
            memset(&protectedRxScratch_[0], 0, sizeof(protectedRxScratch_));
            engine_.radioStopped(nowMicros(nullptr) / kMicrosPerMillisecond,
                                 false);
            failNativeJoin(reason);
            notifyWirelessChange(false);
        }

        void recordNativeAssociation()
        {
            // A beacon seen in the scan epoch is NOT proof that the AP is
            // present after our station's actual association response.
            associatedBeaconObserved_ = false;
            associatedSignalMeasured_ = false;
            associatedRssiDbm_ = 0;
            pendingWpa2M4Token_ = 0;
            wpa2M4TransmitConfirmed_ = false;
            authenticatedProtectedRxObserved_ = false;
            if (joinEpoch_ != epoch_ || joinRequestId_ == 0 ||
                memcmp(&joinBssid_[0], &engine_.linkStatus().bssid.bytes[0],
                       sizeof(joinBssid_)) != 0)
            {
                // A forged, stale or inconsistent AP response cannot leave
                // the provisional BSSID installed in a still-running PCU.
                // It is too late to assume the original hardware identity
                // survived; terminate the physical queue/key epoch.
                retireNativeBssidEpoch(kIOReturnNotReady);
                return;
            }
            // A response may win the command gate before an already-expired
            // timer callback. Do not promote it to a fresh beacon lease.
            const uint64_t nowMs = nowMicros(nullptr) / kMicrosPerMillisecond;
            if (joinWatchRequestId_ != joinRequestId_ ||
                nowMs < joinWatchStartedMs_ ||
                nowMs - joinWatchStartedMs_ >= kNativeJoinTimeoutMs)
            {
                retireNativeLink(kIOReturnTimeout);
                return;
            }
            if (associationGeneration_ == UINT64_MAX || linkTimer_ == nullptr ||
                !radioOperational_ || !channelAuthorized_ ||
                !liveRfKillUnblocked() || queues_.epoch() != epoch_ ||
                queues_.phase() != simpleath::NativeQueuePhase::Running)
            {
                // Neither an exhausted OS-visible association token nor an
                // unverified hardware owner may publish a live connection.
                retireNativeLink(kIOReturnNotReady);
                engine_.radioStopped(nowMicros(nullptr) / kMicrosPerMillisecond,
                                     false);
                return;
            }
            // Source parser accepts only AID 1..2007 from the exact BSSID.
            // PCU hardware must match the same AID before the OS sees link-up.
            simpleath::ieee80211::Bss associated {};
            if (!engine_.copyAssociatedBss(associated) ||
                associated.beacon.channel != verifiedReceiveChannel_ ||
                engine_.associationId() == 0 ||
                !programNativeBssid(&joinBssid_[0], engine_.associationId()))
            {
                // programNativeBssid already retires a failed physical write.
                // An invalid software AID/channel also ends this join epoch.
                if (radioOperational_)
                {
                    retireNativeBssidEpoch(kIOReturnNotReady);
                }
                return;
            }
            ++associationGeneration_;
            joinWatchRequestId_ = 0;
            joinWatchStartedMs_ = 0;
            portReadyStartedMs_ = nowMs;
            portReadyPending_ = true;
            linkWatchEpoch_ = epoch_;
            linkWatchAssociationGeneration_ = associationGeneration_;
            if (linkTimer_->setTimeoutMS(kNativeLinkWatchdogMs) !=
                kIOReturnSuccess)
            {
                retireNativeLink(kIOReturnNotReady);
                engine_.radioStopped(nowMicros(nullptr) / kMicrosPerMillisecond,
                                     false);
                return;
            }
            controlledPortAuthorized_ = false;
            notifyWirelessChange(false);
        }

        // Only genuine FCS-verified DMA RX on the tuned channel-six radio
        // may feed the bounded AWDL peer table. No AirDrop/IPv6 packets are
        // delivered, scheduled or transmitted by this observer.
        void receiveNativeAwdl(const uint8_t *frame, size_t bytes,
                               const simpleath::edma::RxStatus &status)
        {
            if (!radioOperational_ || !channelAuthorized_ ||
                verifiedReceiveChannel_ != kAwdlSocialChannelSix ||
                queues_.epoch() != epoch_ ||
                queues_.phase() != simpleath::NativeQueuePhase::Running ||
                frame == nullptr || bytes <= kFcsBytes ||
                !simpleath::edma::admissibleRxMpdu(status, bytes))
            {
                return;
            }
            const size_t mpduBytes = bytes - kFcsBytes;
            simpleath::ieee80211::Frame header {};
            if (simpleath::ieee80211::parseFrame(frame, mpduBytes, header) !=
                simpleath::ieee80211::Result::Ok)
            {
                return;
            }
            const auto *board = board_.view(epoch_);
            if (!stationMacProgrammed_ || board == nullptr)
            {
                return;
            }
            simpleath::ieee80211::Mac local {};
            __builtin_memcpy(&local.bytes[0], &stationMac_[0],
                             sizeof(local.bytes));
            const uint64_t now = nowMicros(nullptr) / kMicrosPerMillisecond;
            if (header.type == simpleath::ieee80211::FrameType::Management &&
                header.subtype == kAwdlActionSubtype)
            {
                const simpleath::RxTsfBackend clockIo {
                    &access_,
                    epoch_,
                    backend_.activeRegisters().barLengthBytes,
                    awdlTsfPermit,
                    readRegister,
                    nowMicros,
                };
                simpleath::RxTsfSample hardwareArrival {};
                // No callback-arrival-time fallback: a delayed IRQ must not
                // be treated as the on-air MIF phase. Fail closed instead.
                if (simpleath::captureAr9565RxTsf(clockIo, status.timestamp,
                                                  hardwareArrival) !=
                    simpleath::RxTsfResult::Ok)
                {
                    return;
                }
                const uint64_t mifMs =
                    hardwareArrival.frameMonotonicUsec / kMicrosPerMillisecond;
                if (awdlNeighbors_.observeMifForLocal(mifMs, local, frame,
                                                      mpduBytes) ==
                    simpleath::ieee80211::Result::Ok)
                {
                    ++awdlReceivedMifs_;
                    setProperty("SimpleATHObservedAwdlMifs", awdlReceivedMifs_,
                                kAwdlCounterWidthBits);
                }
            }
            else if (header.type == simpleath::ieee80211::FrameType::Data)
            {
                // A complete MIF must already have created the peer;
                // Only data addressed to our physical station (or the
                // matching IPv6 multicast group) may refresh peer state.
                // This is not an AirDrop authorization or native IP RX.
                (void)awdlNeighbors_.observeIpv6ForLocal(now, local, frame,
                                                         mpduBytes);
            }
        }

        // Deaggregate one physically received OPEN QoS A-MSDU only after
        // the portable engine has accepted its shared per-TID duplicate
        // window. WPA2 aggregated RX remains blocked until SPP A-MSDU was
        // actually negotiated with the selected AP and CCMP installed
        // with its separate authenticated A-MSDU-bit contract.
        bool routeNativeOpenAmsdu(const uint8_t *frame, size_t bytes,
                                  const simpleath::edma::RxStatus &status)
        {
            if (frame == nullptr || bytes <= kFcsBytes)
            {
                return false;
            }
            simpleath::ieee80211::Frame header {};
            if (simpleath::ieee80211::parseFrame(frame, bytes - kFcsBytes,
                                                 header) !=
                    simpleath::ieee80211::Result::Ok ||
                header.type != simpleath::ieee80211::FrameType::Data ||
                header.subtype != kNativeQosDataSubtype ||
                header.headerLength < kNativeQosHeaderBytes)
            {
                return false;
            }
            // This has been bounds-checked by parseFrame. Copy instead of
            // borrowing a byte beyond the lifetime of the RX DMA callback.
            uint8_t qosHeader[kNativeQosHeaderBytes] {};
            __builtin_memcpy(&qosHeader[0], frame, sizeof(qosHeader));
            const uint8_t qosControl = qosHeader[kNativeQosControlOffset];
            if ((qosControl & kNativeAmsduPresent) == 0U)
            {
                return false;
            }
            // Once an A-MSDU is recognized, all denials CONSUME it. Never
            // fall through to unaggregated LLC or EAPOL processing.
            if (!controlledPortAuthorized_ || !radioOperational_ ||
                !channelAuthorized_ || !associatedBeaconObserved_ ||
                joinEpoch_ != epoch_ ||
                queues_.phase() != simpleath::NativeQueuePhase::Running ||
                queues_.epoch() != epoch_ ||
                engine_.stationState() !=
                    simpleath::ieee80211::StationState::AssociatedOpen ||
                engine_.linkStatus().state !=
                    simpleath::ieee80211::LinkState::Associated)
            {
                return true;
            }
            const simpleath::ieee80211::InputTrust trust {
                true,
                channelAuthorized_,
                status.frameValid && !status.crcError && !status.decryptError &&
                    !status.phyError && !status.micError && !status.keyMiss,
                false,
                true,
            };
            simpleath::ieee80211::AmsduPayload aggregate {};
            const auto admitted =
                engine_.acceptOpenAmsduRx(frame, bytes, trust, aggregate);
            setProperty("SimpleATHLastAmsduReceiveResult",
                        static_cast<uint32_t>(admitted), kRfPropertyWidthBits);
            if (admitted == simpleath::ieee80211::EngineResult::Ok)
            {
                // One DMA MPDU, one sequence acceptance; each authorized
                // Ethernet-II subframe is independently copied into the
                // native controller's fixed receive mailbox.
                deliverNativeAmsdu(aggregate);
                ++receivedFrames_;
                setProperty("SimpleATHReceivedFrames", receivedFrames_,
                            kCounterPropertyWidthBits);
            }
            return true;
        }

        // Keep driver-owned and OS-owned protected data out of the clear
        // WifiEngine RX parser. Only the selected CCMP MIC/PN session may
        // verify an encrypted MPDU before any native packet delivery.
        bool routeNativeSecurityRx(const uint8_t *frame, size_t bytes,
                                   const simpleath::edma::RxStatus &status)
        {
            auto &self = *this;
            // An OS-installed TK has a single security owner: data RX must
            // use the matching native CCMP session, not the portable engine's
            // cleartext M1/M3 supplicant. Management frames may still feed the
            // scan/association state machine without granting data readiness.
            if ((self.engine_.osSupplicantOwnsWpa2() &&
                 (self.nativePairwiseTx_.installed() ||
                  self.nativePairwiseRx_.installed() ||
                  self.nativeGroupInstalled())) ||
                (!self.engine_.osSupplicantOwnsWpa2() &&
                 self.engine_.stationState() ==
                     simpleath::ieee80211::StationState::HardwareKeysInstalled))
            {
                simpleath::ieee80211::Frame header {};
                if (frame == nullptr || bytes < kFcsBytes ||
                    simpleath::ieee80211::parseFrame(frame, bytes - kFcsBytes,
                                                     header) !=
                        simpleath::ieee80211::Result::Ok)
                {
                    return true;
                }
                if (header.type == simpleath::ieee80211::FrameType::Data)
                {
                    self.receiveNativeProtected(frame, bytes, status);
                    return true;
                }
                if (header.type != simpleath::ieee80211::FrameType::Management)
                {
                    return true;
                }
            }
            if (self.engine_.osSupplicantOwnsWpa2() &&
                self.engine_.stationState() ==
                    simpleath::ieee80211::StationState::WaitingForWpa2Keys &&
                self.engine_.linkStatus().state ==
                    simpleath::ieee80211::LinkState::Associated)
            {
                simpleath::ieee80211::Frame header {};
                if (frame == nullptr || bytes < kFcsBytes ||
                    simpleath::ieee80211::parseFrame(frame, bytes - kFcsBytes,
                                                     header) !=
                        simpleath::ieee80211::Result::Ok)
                {
                    return true;
                }
                if (header.type == simpleath::ieee80211::FrameType::Data)
                {
                    self.receiveNativePreKeyEapol(frame, bytes, status);
                    return true;
                }
            }
            return false;
        }

        // An RX callback can borrow a device-owned DMA buffer while writing
        // hardware keys. Defer the prepared reply until DMA truly restarts.
        bool
        finishNativeRxKeyLease(simpleath::ieee80211::EngineResult result,
                               const simpleath::ieee80211::EngineAction &action)
        {
            auto &self = *this;
            const bool hardwareKeyUpdate =
                self.queues_.keyUpdateIsolatedGated();
            if (hardwareKeyUpdate)
            {
                // A key-install callback has already isolated physical
                // DMA. Never restart that old key epoch if M4 construction
                // fails or the supplicant produces no bounded EAPOL reply.
                if (result != simpleath::ieee80211::EngineResult::Ok ||
                    action.kind !=
                        simpleath::ieee80211::ActionKind::TransmitEapol ||
                    action.bytes < kMinimumMpduBytes ||
                    action.bytes > sizeof(self.managementReply_))
                {
                    self.retireNativeLink(kIOReturnNotReady);
                    return true;
                }
                // The durable management buffer is not borrowed DMA. M4
                // cannot reach TX until the RX DMA borrower has unwound.
                self.deferredManagementBytes_ = action.bytes;
                self.deferredManagementEpoch_ = self.epoch_;
                self.deferredJoinRequestId_ = self.joinRequestId_;
                const IOReturn leaseEnd = self.queues_.endKeyUpdateGated();
                if (leaseEnd != kIOReturnSuccess)
                {
                    // A failed key-update restart cannot reuse keys or
                    // admit another handshake in the old physical epoch.
                    self.retireNativeLink(leaseEnd);
                    return true;
                }
                if (self.deferredManagementBytes_ != 0)
                {
                    // Transmit is performed by queueKeyUpdateResumed only
                    // after same-epoch physical DMA and MAC restart.
                    return true;
                }
            }
            return false;
        }

        // Only post-association, FCS-verified beacons for the exact BSSID
        // may establish the native OS's signal/association progress.
        void
        observeNativeAssociatedBeacon(uint32_t previousBeacons,
                                      const simpleath::edma::RxStatus &status)
        {
            auto &self = *this;
            const auto acceptedLink = self.engine_.linkStatus();
            if (self.joinEpoch_ == self.epoch_ && self.joinRequestId_ != 0 &&
                self.joinStatus_ == kIOReturnSuccess &&
                acceptedLink.state ==
                    simpleath::ieee80211::LinkState::Associated &&
                acceptedLink.acceptedBeacons > previousBeacons &&
                memcmp(&acceptedLink.bssid.bytes[0], &self.joinBssid_[0],
                       sizeof(self.joinBssid_)) == 0 &&
                self.queues_.epoch() == self.epoch_ &&
                self.queues_.phase() == simpleath::NativeQueuePhase::Running &&
                self.radioOperational_ && self.channelAuthorized_ &&
                self.verifiedReceiveChannel_ != 0)
            {
                simpleath::ieee80211::Bss selected {};
                if (self.engine_.copyAssociatedBss(selected) &&
                    selected.beacon.channel == self.verifiedReceiveChannel_)
                {
                    // LinkMonitor increments only after fully parsed,
                    // FCS-verified matching-BSSID beacon acceptance. Never
                    // count an earlier scan beacon as post-association proof.
                    const bool firstBeacon = !self.associatedBeaconObserved_;
                    self.associatedBeaconObserved_ = true;
                    self.associatedSignalMeasured_ = status.combinedRssi < 0;
                    self.associatedRssiDbm_ = self.associatedSignalMeasured_
                                                  ? status.combinedRssi
                                                  : 0;
                    if (firstBeacon)
                    {
                        // WCL owns no separate supplicant on an OPEN BSS.
                        // Physically authorize the data port only after
                        // genuine same-epoch AP beacon evidence and all the
                        // strict RF/channel/queue/TPC guards above pass.
                        // WPA2 remains closed until verified CCMP data RX/TX.
                        bool requestOpen = true;
                        if (self.engine_.stationState() ==
                                simpleath::ieee80211::StationState::
                                    AssociatedOpen ||
                            (self.engine_.stationState() ==
                                 simpleath::ieee80211::StationState::
                                     HardwareKeysInstalled &&
                             self.wpa2M4TransmitConfirmed_ &&
                             self.authenticatedProtectedRxObserved_))
                        {
                            (void)ownerAuthorizePortAction(
                                &self, &requestOpen, nullptr, nullptr, nullptr);
                        }
                        self.notifyWirelessChange(false);
                    }
                }
            }
        }

        // A failed management TX cannot leave a prepared station state live.
        // The association request's MAC sequence remains owned by the engine.
        bool sendNativeManagementResponse(
            simpleath::ieee80211::EngineResult result,
            const simpleath::ieee80211::EngineAction &action)
        {
            auto &self = *this;
            // Authentication/association and the WPA2 M2/M4 replies are
            // already serialized by WifiEngine. They need the same verified
            // RF/rate/power authorization as Ethernet data, but do not need
            // the controlled port to be open before association/handshake.
            if (result == simpleath::ieee80211::EngineResult::Ok &&
                (action.kind ==
                     simpleath::ieee80211::ActionKind::TransmitAssociation ||
                 action.kind ==
                     simpleath::ieee80211::ActionKind::TransmitEapol))
            {
                if (action.bytes < kMinimumMpduBytes ||
                    action.bytes > sizeof(self.managementReply_))
                {
                    // The portable station has already advanced its state.
                    // A malformed M2 or association request must not retain
                    // the physical BSSID/key/EDMA lease until a late timer.
                    self.retireNativeLink(kIOReturnNotReady);
                    return true;
                }
                // Driver-owned M4 follows a physical key-update lease and
                // must be tracked through a real EDMA completion. A direct
                // send after key installation has no M4 token/ACK owner.
                if (action.kind ==
                        simpleath::ieee80211::ActionKind::TransmitEapol &&
                    !self.engine_.osSupplicantOwnsWpa2() &&
                    self.engine_.stationState() ==
                        simpleath::ieee80211::StationState::
                            HardwareKeysInstalled)
                {
                    self.retireNativeLink(kIOReturnNotReady);
                    return true;
                }
                // The timer may run after this workloop RX callback. Do not
                // queue an association request on an expired physical join.
                if (action.kind ==
                        simpleath::ieee80211::ActionKind::TransmitAssociation &&
                    !self.verifyNativePendingJoinLease())
                {
                    return true;
                }
                // M2/M4 are portable EAPOL payloads but native *data* MPDUs.
                // The portable supplicant's independent sequence is not the
                // global physical non-QoS TX owner. A freshly serialized
                // clear EAPOL frame has no 802.11 header MIC, so stamp the
                // real native sequence before DMA publication. Group2 and
                // protected M4 have separate native CCMP/EDMA owners and do
                // not enter this immediate management reply branch.
                if (action.kind ==
                    simpleath::ieee80211::ActionKind::TransmitEapol)
                {
                    const uint16_t value = static_cast<uint16_t>(
                        self.txSequence_ << kSequenceFragmentBits);
                    self.managementReply_[kSequenceControlOffset] =
                        static_cast<uint8_t>(value);
                    self.managementReply_[kSequenceControlOffset + 1U] =
                        static_cast<uint8_t>(value >> kByteBits);
                }
                const IOReturn submitted = self.submitPreparedTransmit(
                    &self.managementReply_[0], action.bytes);
                self.setProperty("SimpleATHManagementTransmitResult",
                                 static_cast<uint32_t>(submitted),
                                 kRfPropertyWidthBits);
                if (submitted != kIOReturnSuccess)
                {
                    // The engine already advanced authentication or
                    // handshake state, and an attempted M4 may have staged
                    // live hardware PTK/GTK. Quarantine MAC/EDMA and key RAM
                    // before discarding the software association, even if
                    // the failed transmit itself never acquired a TX slot.
                    self.retireNativeLink(submitted);
                }
                else if (action.kind ==
                         simpleath::ieee80211::ActionKind::TransmitAssociation)
                {
                    // The station's association request owns the management
                    // sequence; subsequent open-data TX must not restart at
                    // zero and reuse it. WPA2 data remains CCMP-gated.
                    struct SequenceBytes
                    {
                            uint8_t low;
                            uint8_t high;
                    } sequence {};

                    __builtin_memcpy(
                        &sequence,
                        &self.managementReply_[kSequenceControlOffset],
                        sizeof(sequence));
                    const auto sequenceField = static_cast<uint16_t>(
                        (static_cast<uint32_t>(sequence.high) << kByteBits) |
                        static_cast<uint32_t>(sequence.low));
                    self.txSequence_ = static_cast<uint16_t>(
                        ((sequenceField >> kSequenceFragmentBits) + 1U) &
                        kSequenceMask);
                }
                else if (action.kind ==
                         simpleath::ieee80211::ActionKind::TransmitEapol)
                {
                    // Only successfully submitted M2/M4 consume the shared
                    // non-QoS sequence. A failed send retires the whole link
                    // above, never leaving a reusable old MAC number.
                    self.txSequence_ = static_cast<uint16_t>(
                        (self.txSequence_ + 1U) & kSequenceMask);
                }
                return true;
            }
            // BlockAck agreements are NOT implemented: answer only a
            // syntactically checked AP ADDBA Request with a negative response.
            // In particular, a mere accepted MIF/association frame does not
            // grant TX or a reorder lease. This response remains subject to
            // the same physical RF/TPC/channel/association/EDMA checks as
            // all other outbound management packets.
            if (result == simpleath::ieee80211::EngineResult::Ok &&
                action.kind ==
                    simpleath::ieee80211::ActionKind::TransmitAddbaDecline)
            {
                constexpr size_t kAddbaResponseBytes = 33U;
                if (action.bytes != kAddbaResponseBytes ||
                    self.engine_.linkStatus().state !=
                        simpleath::ieee80211::LinkState::Associated ||
                    !self.controlledPortAuthorized_ ||
                    !self.canSubmitTransmit() ||
                    self.verifyNativeAssociationLease(nowMicros(nullptr) /
                                                      kMicrosPerMillisecond) !=
                        kIOReturnSuccess)
                {
                    // Do not send an unauthenticated or stale reply. The AP
                    // still has no successfully negotiated BA session.
                    return true;
                }
                // The portable layer left sequence zero as a placeholder.
                // Only the native TX owner may consume the shared sequence
                // used by management and ordinary Ethernet data packets.
                const uint16_t value = static_cast<uint16_t>(
                    self.txSequence_ << kSequenceFragmentBits);
                constexpr size_t kManagementSequenceOffset = 22U;
                self.managementReply_[kManagementSequenceOffset] =
                    static_cast<uint8_t>(value);
                self.managementReply_[kManagementSequenceOffset + 1U] =
                    static_cast<uint8_t>(value >> kByteBits);
                const IOReturn submitted = self.submitPreparedTransmit(
                    &self.managementReply_[0], action.bytes);
                self.setProperty("SimpleATHBlockAckDeclineTransmitResult",
                                 static_cast<uint32_t>(submitted),
                                 kRfPropertyWidthBits);
                if (submitted == kIOReturnSuccess)
                {
                    self.txSequence_ = static_cast<uint16_t>(
                        (self.txSequence_ + 1U) & kSequenceMask);
                }
                else
                {
                    // An unacknowledged decline is NOT a BA agreement.
                    // Retire the link rather than risk accepting an AP's
                    // speculative aggregated traffic in this epoch.
                    self.retireNativeLink(submitted);
                }
                return true;
            }
            return false;
        }

        static void queueReceived(void *context, const uint8_t *frame,
                                  size_t bytes,
                                  const simpleath::edma::RxStatus &status)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            if (!self.radioOperational_ || !self.powered_ ||
                self.pendingLocalLeaveToken_ != 0 ||
                !self.liveRfKillUnblocked() ||
                !simpleath::edma::admissibleRxMpdu(status, bytes))
            {
                return;
            }
            // Native protected data and open A-MSDU bypass the portable
            // acceptRx clock gate. Reuse the same physical lease check as
            // outbound traffic before any key, EAPOL or Ethernet routing.
            if (self.engine_.linkStatus().state ==
                    simpleath::ieee80211::LinkState::Associated &&
                self.verifyNativeAssociationLease(nowMicros(nullptr) /
                                                  kMicrosPerMillisecond) !=
                    kIOReturnSuccess)
            {
                return;
            }
            // An authentication response can be parsed and trigger another
            // on-air management TX before a late pending-join timer fires.
            // The hardware owner checks the real deadline at the RX boundary.
            if (!self.verifyNativePendingJoinLease())
            {
                return;
            }
            self.receiveNativeAwdl(frame, bytes, status);
            if (self.routeNativeSecurityRx(frame, bytes, status) ||
                self.routeNativeOpenAmsdu(frame, bytes, status))
            {
                return;
            }
            simpleath::ieee80211::InputTrust trust {};
            trust.radioReady = true;
            trust.channelAuthorized = self.channelAuthorized_;
            // A valid EDMA frame length and CRC alone cannot sanitize an
            // independent PHY/decrypt/MIC/keycache error. Reject the whole
            // observation before it can enter EAPOL or beacon accounting.
            trust.dmaAndFcsVerified =
                status.frameValid && !status.crcError && !status.decryptError &&
                !status.phyError && !status.micError && !status.keyMiss;
            trust.rxFrameIncludesFcs = true;
            // The security owner supplies replay verification before protected
            // data can enter the controlled port; clear scan/management frames
            // do not require a key or a fabricated CCMP attestation.
            const uint32_t previousBeacons =
                self.engine_.linkStatus().acceptedBeacons;
            simpleath::ieee80211::EngineAction action {};
            const auto result = self.engine_.acceptRx(
                frame, bytes, trust,
                {
                    status.combinedRssi,
                    nowMicros(nullptr) / kMicrosPerMillisecond,
                },
                &self.managementReply_[0], sizeof(self.managementReply_),
                action);
            self.setProperty("SimpleATHLastReceiveResult",
                             static_cast<uint32_t>(result),
                             kRfPropertyWidthBits);
            if (self.finishNativeRxKeyLease(result, action))
            {
                return;
            }
            self.observeNativeAssociatedBeacon(previousBeacons, status);
            if (result == simpleath::ieee80211::EngineResult::CryptoFailure ||
                result ==
                    simpleath::ieee80211::EngineResult::AccessPointRejected)
            {
                if (self.queues_.phase() ==
                    simpleath::NativeQueuePhase::Quarantined)
                {
                    self.radioOperational_ = false;
                    self.channelAuthorized_ = false;
                    self.txSafety_ = {};
                }
                self.retireNativeLink(kIOReturnNotReady);
                return;
            }
            ++self.receivedFrames_;
            self.setProperty("SimpleATHReceivedFrames", self.receivedFrames_,
                             kCounterPropertyWidthBits);
            if (self.sendNativeManagementResponse(result, action))
            {
                return;
            }
            if (result == simpleath::ieee80211::EngineResult::Ok &&
                (action.kind ==
                     simpleath::ieee80211::ActionKind::AssociatedAwaitingKeys ||
                 action.kind == simpleath::ieee80211::ActionKind::
                                    OpenAssociationEstablished))
            {
                self.recordNativeAssociation();
                return;
            }
            if (result == simpleath::ieee80211::EngineResult::Ok &&
                action.kind == simpleath::ieee80211::ActionKind::LinkLost)
            {
                // Verified AP disconnects and silent beacon expiry share
                // one terminal port/key/association-watchdog path.
                self.retireNativeLink(kIOReturnNotReady);
                return;
            }
            // The engine accepts a data MSDU only after association,
            // address/security checks and duplicate suppression. The native
            // owner additionally requires its physical radio and controlled
            // port to remain live; never deliver unverified WPA2/CCMP bytes.
            if (result != simpleath::ieee80211::EngineResult::Ok ||
                action.kind !=
                    simpleath::ieee80211::ActionKind::ReceivedPayload ||
                !self.channelAuthorized_ || !self.controlledPortAuthorized_ ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Running ||
                !trust.dmaAndFcsVerified ||
                self.engine_.linkStatus().state !=
                    simpleath::ieee80211::LinkState::Associated ||
                self.observerLock_ == nullptr)
            {
                return;
            }
            // The decoder may have assembled an open data MSDU from several
            // individually FCS-verified fragments. Re-parsing the *last DMA
            // fragment* would reject that valid complete MSDU. The engine
            // instead publishes borrowed payload + copied Ethernet identities
            // only after full association, address, LLC and duplicate checks.
            // Do not cache its pointer across another acceptRx or IRQ.
            if (self.engine_.stationState() !=
                    simpleath::ieee80211::StationState::AssociatedOpen ||
                self.joinEpoch_ != self.epoch_ ||
                self.queues_.epoch() != self.epoch_ ||
                !self.associatedBeaconObserved_ ||
                action.receivedPayload == nullptr ||
                action.etherType == kEtherTypeEapol ||
                !simpleath::ieee80211::validStationMac(action.receivedSource))
            {
                return;
            }
            simpleath::ieee80211::Msdu msdu {};
            msdu.destination = action.receivedDestination;
            msdu.source = action.receivedSource;
            msdu.etherType = action.etherType;
            msdu.payload = action.receivedPayload;
            msdu.payloadLength = action.receivedPayloadBytes;
            self.deliverNativeMsdu(msdu, false);
        }

        static void
        queueTransmitted(void *context, uint64_t token,
                         const simpleath::edma::TxCompletion &status)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            if (token != 0 && token == self.pendingLocalLeaveToken_ &&
                self.pendingLocalLeaveEpoch_ == self.epoch_)
            {
                // NativeQueues has already retired the descriptor and
                // dropped txPending_ before invoking this callback. Only
                // now may the old MAC/keycache be physically quarantined.
                // Failed on-air delivery is still a terminal local leave.
                self.retireNativeLink(status.frameTransmitOk &&
                                              !status.excessiveRetries &&
                                              !status.filtered
                                          ? kIOReturnAborted
                                          : kIOReturnIOError);
            }
            if (token != 0 && token == self.pendingWpa2Group2Token_)
            {
                const bool complete =
                    self.joinEpoch_ == self.epoch_ &&
                    self.keyCache_.ownerEpoch == self.epoch_ &&
                    self.engine_.stationState() ==
                        simpleath::ieee80211::StationState::
                            HardwareKeysInstalled &&
                    self.controlledPortAuthorized_ &&
                    !self.keyCache_.requiresReset && status.frameTransmitOk &&
                    !status.excessiveRetries && !status.filtered;
                self.pendingWpa2Group2Token_ = 0;
                if (!complete)
                {
                    // Completion is terminal for this protected key
                    // generation. The EDMA TX slot was just retired, so
                    // attempt same-epoch isolation before hardware erasure.
                    self.retireNativeLink(kIOReturnIOError);
                }
            }
            if (token != 0 && token == self.pendingWpa2M4Token_)
            {
                const bool confirmed =
                    simpleath::ieee80211::nativeM4TransmitCompleted({
                        token,
                        self.pendingWpa2M4Token_,
                        self.joinEpoch_,
                        self.epoch_,
                        self.keyCache_.ownerEpoch,
                        self.engine_.stationState(),
                        status.frameTransmitOk,
                        status.excessiveRetries,
                        status.filtered,
                    });
                self.pendingWpa2M4Token_ = 0;
                if (confirmed)
                {
                    // EDMA reported a completed M4, not a synthetic key
                    // installation. A verified protected RX is still needed
                    // to prove peer traffic before opening the data port.
                    self.wpa2M4TransmitConfirmed_ = true;
                    if (self.associatedBeaconObserved_ &&
                        self.authenticatedProtectedRxObserved_)
                    {
                        bool requestOpen = true;
                        (void)ownerAuthorizePortAction(
                            &self, &requestOpen, nullptr, nullptr, nullptr);
                    }
                }
                else
                {
                    // Completion is terminal for this protected key
                    // generation. The EDMA TX slot was just retired, so
                    // attempt same-epoch isolation before hardware erasure.
                    self.retireNativeLink(kIOReturnIOError);
                }
            }
            ++self.transmitCompletions_;
            self.setProperty("SimpleATHTransmitCompletions",
                             self.transmitCompletions_,
                             kCounterPropertyWidthBits);
            self.setProperty("SimpleATHLastTransmitSucceeded",
                             status.frameTransmitOk);
            // The EDMA owner already freed its TX slot before this callback.
            // The native OS may retry a failed frame; availability is not a
            // packet-success notification. Never cross into its work loop.
            if (self.observerLock_ != nullptr)
            {
                IOLockLock(self.observerLock_);
                if (self.wirelessObserver_ != nullptr &&
                    self.wirelessNotify_ != nullptr && self.epoch_ != 0 &&
                    self.radioOperational_ && self.channelAuthorized_ &&
                    self.queues_.phase() ==
                        simpleath::NativeQueuePhase::Running)
                {
                    self.wirelessNotify_(
                        self.wirelessObserver_,
                        simpleath::tahoe::WirelessEvent::TransmitAvailable,
                        self.epoch_, 0U);
                }
                IOLockUnlock(self.observerLock_);
            }
        }

        static void queueFault(void *context, IOReturn result)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            // Stop device DMA before the owner revokes radio readiness. A
            // masked host interrupt alone cannot transfer ring ownership.
            self.queues_.stopGated(!self.pci_->isInactive());
            self.queuesAdopted_ = false;
            self.programmedBssidEpoch_ = 0;
            self.radioOperational_ = false;
            self.channelAuthorized_ = false;
            self.verifiedReceiveChannel_ = 0;
            const bool scanAborted = self.abortActiveNativeScan();
            self.awdlNeighbors_.clear();
            // A descriptor/IRQ fault destroys all derived RF/TPC claims. A
            // later queue or radio restart must recompute real channel and
            // per-rate limits under a fresh hardware setup, never inherit
            // safety bits from the failed ring.
            self.txSafety_ = {};
            self.txRate_ = {};
            self.txSequence_ = 0;
            self.controlledPortAuthorized_ = false;
            memset(&self.ethernetTx_[0], 0, sizeof(self.ethernetTx_));
            memset(&self.ethernetRx_[0], 0, sizeof(self.ethernetRx_));
            memset(&self.protectedScratch_[0], 0,
                   sizeof(self.protectedScratch_));
            memset(&self.managementReply_[0], 0, sizeof(self.managementReply_));
            self.nativePairwiseTx_.revoke();
            self.nativeProtectedFragments_.clear();
            self.nativePairwiseRx_.revoke();
            for (auto &group : self.nativeGroupRx_)
            {
                group.revoke();
            }
            self.nativePairwiseKeyRevoked_ = true;
            self.nativeGroupKeyRevokedMask_ = kAllGroupKeySlotsRevoked;
            // In particular the OS-owned supplicant does not call our
            // driver-owned key removal on reset. A DMA fault cannot borrow
            // that callback as evidence of hardware-key erasure.
            self.keyCache_.requiresReset = true;
            self.setProperty("SimpleATHKeyCacheResetRequired", true);
            memset(&self.protectedRxScratch_[0], 0,
                   sizeof(self.protectedRxScratch_));
            self.engine_.radioStopped(
                nowMicros(nullptr) / kMicrosPerMillisecond, false);
            self.failNativeJoin(result);
            if (scanAborted)
            {
                self.notifyWirelessScanFinished();
            }
            // A DMA fault revokes the old BSS lease and all radio readiness,
            // even if the PCI owner remains mapped. Do not discard a posted
            // failure completion: same-epoch native acknowledgement must
            // still be able to retire that exact bridge ticket.
            self.completedScanTicket_ = {};
            self.notifyWirelessChange(false);
            self.error("DMAInterrupt", static_cast<uint32_t>(result));
        }

        static void queueKeyUpdateResumed(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            const size_t bytes = self.deferredManagementBytes_;
            const bool group2 = self.deferredGroup2_;
            if (bytes == 0)
            {
                return;
            }
            // M4/Group2 may only enter EDMA with the mirrored CCMP keys
            // from this live key epoch. A missing session is terminal, not
            // permission to send an untracked reply.
            const bool sessionsReady = !self.engine_.osSupplicantOwnsWpa2() &&
                                       self.nativePairwiseTx_.installed() &&
                                       self.nativePairwiseRx_.installed() &&
                                       self.nativeGroupInstalled();
            const bool stillOwned =
                sessionsReady && epoch != 0 && epoch == self.epoch_ &&
                epoch == self.deferredManagementEpoch_ &&
                self.joinEpoch_ == epoch && self.deferredJoinRequestId_ != 0 &&
                self.joinRequestId_ == self.deferredJoinRequestId_ &&
                self.joinStatus_ == kIOReturnSuccess &&
                self.queues_.phase() == simpleath::NativeQueuePhase::Running &&
                self.queues_.epoch() == epoch &&
                self.engine_.stationState() ==
                    simpleath::ieee80211::StationState::HardwareKeysInstalled &&
                self.keyCache_.pairwiseInstalled &&
                !self.keyCache_.requiresReset;
            self.deferredManagementBytes_ = 0;
            self.deferredManagementEpoch_ = 0;
            self.deferredJoinRequestId_ = 0;
            self.deferredGroup2_ = false;
            const uint64_t submittedToken = self.nextTransmitToken_;
            const IOReturn lease =
                stillOwned ? self.verifyNativeAssociationLease(
                                 nowMicros(nullptr) / kMicrosPerMillisecond)
                           : kIOReturnNotReady;
            if (stillOwned && lease != kIOReturnSuccess)
            {
                // Verification already quarantined this link and its keys.
                // Do not repeat retirement while the callback unwinds.
                return;
            }
            const IOReturn result =
                stillOwned && self.canSubmitTransmit() &&
                        (!group2 || self.controlledPortAuthorized_)
                    ? self.submitPreparedTransmit(&self.managementReply_[0],
                                                  bytes, group2)
                    : kIOReturnNotReady;
            if (result == kIOReturnSuccess &&
                !self.engine_.osSupplicantOwnsWpa2() && submittedToken != 0 &&
                submittedToken != UINT64_MAX &&
                self.nativePairwiseTx_.installed() &&
                self.nativePairwiseRx_.installed() &&
                self.nativeGroupInstalled())
            {
                // Group2 completion is not M4 confirmation; never grant
                // controlled-port readiness for a rekey reply.
                if (group2)
                {
                    self.pendingWpa2Group2Token_ = submittedToken;
                }
                else
                {
                    self.pendingWpa2M4Token_ = submittedToken;
                }
            }
            self.setProperty("SimpleATHManagementTransmitResult",
                             static_cast<uint32_t>(result),
                             kRfPropertyWidthBits);
            if (result != kIOReturnSuccess)
            {
                // Deferred protected M4/Group2 could not reach real TX.
                // Revoke the newly restarted ring and key generation.
                self.retireNativeLink(result);
            }
        }

        static void queueInterrupt(OSObject *owner,
                                   IOInterruptEventSource * /*unused*/,
                                   int /*unused*/)
        {
            auto *typed = OSDynamicCast(SimpleATH, owner);
            if (typed == nullptr)
            {
                return;
            }
            auto &self = *typed;
            if (self.queuesAdopted_)
            {
                self.queues_.serviceInterruptGated();
            }
        }

        IOReturn startClient()
        {
            if ((lifecycle_ == nullptr) || (gate_ == nullptr))
            {
                return kIOReturnNotReady;
            }
            IOLockLock(lifecycle_);
            // Power-on after link retirement, a keycache fault or failed
            // queue teardown must acquire a FRESH physical owner epoch.
            // Do not reuse the prior NVM lease while the old DMA mappings
            // still belong to a quarantined device. All reset MMIO remains
            // command-gated; coherent mapping release stays off the gate.
            bool releaseRetiredQueues = false;
            IOReturn result = gate_->runAction(prepareFreshStartAction,
                                               &releaseRetiredQueues);
            if (result == kIOReturnSuccess && releaseRetiredQueues)
            {
                result = queues_.releaseClient();
            }
            if (result == kIOReturnSuccess)
            {
                result = gate_->runAction(startAction);
            }
            if (result == kIOReturnSuccess &&
                queues_.phase() == simpleath::NativeQueuePhase::Empty)
            {
                // NVM/reset completed under the gate. Mapping/preparation and
                // interrupt registration run on this retained, sleepable caller
                // outside the gate. Stop revokes the epoch before waiting here.
                const uint64_t preparedEpoch = epoch_;
                const simpleath::NativeQueueOwner callbacks {
                    &access_,
                    currentQueueOwner,
                    queueRadioReady,
                    queueBusMaster,
                    readRegister,
                    writeRegister,
                    delayMicros,
                    queueReceived,
                    queueTransmitted,
                    queueFault,
                    session_.status().barLengthBytes,
                    queueKeyUpdateResumed,
                };
                result = queues_.prepareClient(this, pci_, loop_, preparedEpoch,
                                               callbacks, queueInterrupt);
                if (result == kIOReturnSuccess)
                {
                    result = gate_->runAction(adoptQueuesAction);
                }
                if (result != kIOReturnSuccess)
                {
                    queues_.releaseClient();
                    gate_->runAction(failedQueueStartAction);
                }
            }
            else if (result == kIOReturnSuccess && queuesAdopted_ &&
                     queues_.phase() == simpleath::NativeQueuePhase::Prepared)
            {
                // A later power-on can retry an already-mapped, still-idle
                // receiver only after a fresh live RF/channel preflight.
                // Absent evidence keeps Prepared without starting DMA.
                result = gate_->runAction(activatePreparedQueuesAction);
                if (result != kIOReturnSuccess)
                {
                    gate_->runAction(failedQueueStartAction);
                    // The gate revoked the hardware epoch and stopped DMA.
                    // A quarantined mapping will refuse release and remain
                    // pinned; a cleanly isolated one can now be retired.
                    (void)queues_.releaseClient();
                }
            }
            IOLockUnlock(lifecycle_);
            return result;
        }

        enum class ClientStopMode : uint8_t
        {
            Suspend,
            Terminate,
            FinalStop,
        };

        IOReturn stopClient(ClientStopMode mode)
        {
            if (lifecycle_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            // Power-off, termination and stop must exclude a concurrent
            // startClient across BOTH device quiescence and DMA release.
            // The caller sleeps outside the command gate; hardware remains
            // serialized inside it. The same lock covers fresh-epoch start.
            IOLockLock(lifecycle_);
            IOReturn gated = kIOReturnNotReady;
            if (gate_ != nullptr &&
                (mode != ClientStopMode::FinalStop || gateAttached_))
            {
                switch (mode)
                {
                    case ClientStopMode::Suspend:
                        gated = gate_->runAction(sleepAction);
                        break;
                    case ClientStopMode::Terminate:
                        gated = gate_->runAction(terminateAction);
                        break;
                    case ClientStopMode::FinalStop:
                        gated = gate_->runAction(stopAction);
                        break;
                }
            }
            // Release even if the gate failed: do not abandon a potentially
            // mapped queue. A failed release stays quarantined in NativeQueues
            // and must not be reported as a successful native radio-off.
            const IOReturn released = queues_.releaseClient();
            if (released != kIOReturnSuccess)
            {
                // IOLog is the kernel's variadic diagnostic ABI; the format is
                // fixed and every argument is supplied with the matching type.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
                IOLog("SimpleATH: queue mappings quarantined (0x%x)\n",
                      released);
            }
            IOLockUnlock(lifecycle_);
            return gated != kIOReturnSuccess ? gated : released;
        }

        static IOReturn adoptQueuesAction(OSObject *owner, void * /*unused*/,
                                          void * /*unused*/, void * /*unused*/,
                                          void * /*unused*/)
        {
            auto *typed = OSDynamicCast(SimpleATH, owner);
            if (typed == nullptr)
            {
                return kIOReturnBadArgument;
            }
            auto &self = *typed;
            const IOReturn result = self.queues_.adoptGated(self.epoch_);
            if (result == kIOReturnSuccess)
            {
                self.queuesAdopted_ = true;
                self.setProperty("SimpleATHDmaMappingsReady", true);
                self.stage("DMAResourcesPrepared");
                // Adoption only transfers mapping and IRQ ownership. If the
                // already-completed PHY path holds physical, epoch-current RX
                // authority, start the actual EDMA rings now. Otherwise
                // leave them Prepared, with IRQ and bus mastering disabled.
                // An EEPROM lease or a mapped ring cannot satisfy this gate.
                const IOReturn started = activatePreparedQueuesAction(
                    owner, nullptr, nullptr, nullptr, nullptr);
                if (started == kIOReturnSuccess &&
                    self.queues_.phase() ==
                        simpleath::NativeQueuePhase::Prepared)
                {
                    // Board acquisition still changes the published PCI
                    // epoch even when no actual receiver can be started.
                    self.notifyWirelessChange(false);
                }
                return started;
            }
            return result;
        }

        static IOReturn activatePreparedQueuesAction(OSObject *owner,
                                                     void * /*unused1*/,
                                                     void * /*unused2*/,
                                                     void * /*unused3*/,
                                                     void * /*unused4*/)
        {
            auto *typed = OSDynamicCast(SimpleATH, owner);
            if (typed == nullptr)
            {
                return kIOReturnBadArgument;
            }
            auto &self = *typed;
            if (!self.queuesAdopted_ || self.queues_.epoch() != self.epoch_ ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Prepared)
            {
                return kIOReturnNotReady;
            }
            if (!self.queues_.initialStartEligibleGated())
            {
                // A WPA2 key update owns the Prepared queue until its
                // borrowed receive frame unwinds and the private restart
                // path completes. A power-on callback must not steal it.
                return kIOReturnSuccess;
            }
            if (!queueRadioReady(&self.access_, self.epoch_))
            {
                // Physical RF/antenna/channel proof has not arrived. This
                // is normal during board-acquisition-only startup, not a
                // successful receiver initialization or a DMA fault.
                return kIOReturnSuccess;
            }
            const IOReturn result = self.queues_.startGated();
            self.setProperty("SimpleATHNativeQueueStartResult",
                             static_cast<uint32_t>(result),
                             kRfPropertyWidthBits);
            if (result == kIOReturnSuccess)
            {
                self.stage("DMAReceiverStarted");
                self.notifyWirelessChange(false);
            }
            return result;
        }

        static IOReturn failedQueueStartAction(OSObject *owner,
                                               void * /*unused*/,
                                               void * /*unused*/,
                                               void * /*unused*/,
                                               void * /*unused*/)
        {
            auto *typed = OSDynamicCast(SimpleATH, owner);
            if (typed == nullptr)
            {
                return kIOReturnBadArgument;
            }
            auto &self = *typed;
            self.error("DMAPreparation", kIOReturnNoResources);
            self.stopHardware(simpleath::ProviderAccess::Available);
            return kIOReturnSuccess;
        }

        bool quiesceEngines()
        {
            enginesQuiesced_ = false;
            const auto bus = backend_.activeRegisters();
            const simpleath::RegisterBus active {
                &access_,
                readRegister,
                writeRegister,
                bus.barLengthBytes,
            };
            const auto result =
                simpleath::quiesceAr9565Mac(active, delayMicros);
            setProperty("SimpleATHMacStopResult", static_cast<uint32_t>(result),
                        kRfPropertyWidthBits);
            enginesQuiesced_ = result == simpleath::MacStopResult::Ok;
            return enginesQuiesced_;
        }

        void stage(const char *name)
        {
            setProperty("SimpleATHStartupStage", name);
            // IOLog is the kernel's variadic diagnostic ABI; the format is
            // fixed and every argument is supplied with the matching type.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
            IOLog("SimpleATH: %s\n", name);
            if (diagnostics_.detailed)
            {
                // IOLog is the kernel's variadic diagnostic ABI; the format is
                // fixed and every argument is supplied with the matching type.
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
                IOLog("SimpleATH debug: epoch=%llu powered=%u quiesced=%u "
                      "DMA=%u radio=%u channel=%u\n",
                      epoch_, static_cast<int>(powered_),
                      static_cast<int>(enginesQuiesced_),
                      static_cast<int>(queuesAdopted_),
                      static_cast<int>(radioOperational_),
                      static_cast<int>(channelAuthorized_));
            }
        }

        IOReturn error(const char *name, uint32_t detail)
        {
            setProperty("SimpleATHFailureStage", name);
            setProperty("SimpleATHFailureCode", detail, kRfPropertyWidthBits);
            setProperty("SimpleATHDriverReady", false);
            // IOLog is the kernel's variadic diagnostic ABI; the format is
            // fixed and every argument is supplied with the matching type.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
            IOLog("SimpleATH: %s failed (0x%x)\n", name, detail);
            return kIOReturnIOError;
        }

        // Preserve the opaque PCI owner token without a pointer/integer cast.
        static uintptr_t pointerToken(IOPCIDevice *provider)
        {
            static_assert(sizeof(IOPCIDevice *) == sizeof(uintptr_t),
                          "native owner token must preserve pointer identity");
            uintptr_t token = 0;
            __builtin_memcpy(&token, static_cast<const void *>(&provider),
                             sizeof(token));
            return token;
        }

        IOReturn startHardware()
        {
            if (powered_ && (board_.view(epoch_) != nullptr))
            {
                return kIOReturnSuccess;
            }
            if (stopping_ || epoch_ == UINT64_MAX)
            {
                return kIOReturnNotReady;
            }
            powered_ = true;
            ++epoch_;
            stage("PCIClaimAndMap");
            const auto pciResult = session_.start(backend_.callbacks());
            if (pciResult != simpleath::PciSessionResult::Ok)
            {
                return abortStart("PCIClaimAndMap",
                                  static_cast<uint32_t>(pciResult));
            }
            // Use the identity already obtained from live configuration by
            // the exclusive session, not IORegistry matching properties.
            identity_ = session_.hardwareStatus().pci;
            setProperty("SimpleATHVendorID", identity_.vendorId,
                        kRfPropertyWidthBits);
            setProperty("SimpleATHDeviceID", identity_.deviceId,
                        kRfPropertyWidthBits);
            setProperty("SimpleATHPciExclusiveOwner", true);
            setProperty("SimpleATHMmioTransportReady", true);
            stage("PhysicalSilicon");
            uint32_t rawRevision = 0;
            simpleath::Silicon silicon {};
            if (!readRegister(&access_, simpleath::kRevisionRegister,
                              &rawRevision))
            {
                return abortStart("PhysicalSilicon", kIOReturnIOError);
            }
            const auto decoded =
                simpleath::decodeRevision(rawRevision, silicon);
            if (decoded != simpleath::Result::Ok)
            {
                return abortStart("PhysicalSilicon",
                                  static_cast<uint32_t>(decoded));
            }
            stage("QuiesceMAC");
            if (!quiesceEngines())
            {
                return abortStart("QuiesceMAC", kIOReturnTimeout);
            }
            const auto bus = backend_.activeRegisters();
            const simpleath::RtcPowerBackend reset {
                &access_,
                pointerToken(pci_),
                epoch_,
                canReset,
                readRegister,
                writeRegister,
                nowMicros,
                delayMicros,
                bus.barLengthBytes,
                false,
                nullptr,
                nullptr,
            };
            simpleath::RtcPowerStatus resetStatus {};
            stage("RTCBootstrap");
            const auto rtcResult = simpleath::transitionAr9565Rtc(
                reset, identity_, simpleath::RtcOperation::BootstrapPowerOn,
                rtc_, resetStatus);
            if (rtcResult != simpleath::RtcResult::Ok)
            {
                return abortStart("RTCBootstrap",
                                  static_cast<uint32_t>(rtcResult));
            }
            if (!quiesceEngines())
            {
                return abortStart("PostResetQuiesce", kIOReturnTimeout);
            }
            // The old inspection-only path rejects EEPROM-absent functions,
            // including valid OTP-backed boards. Let actual NVM discovery
            // choose EEPROM or OTP instead of using that diagnostic as a
            // startup gate.
            setProperty("SimpleATHSREV", resetStatus.silicon.rawSrev,
                        kRfPropertyWidthBits);
            const simpleath::NvmReadBackend reader {
                &access_,  nvmOwner,    readRegister,
                nowMicros, delayMicros, bus.barLengthBytes,
            };
            simpleath::NvmDiscoveryStatus discovery {};
            stage("EEPROMDiscovery");
            const auto acquired = board_.acquire(
                reader, identity_, epoch_, storage_, kNvmStorageBytes, scratch_,
                simpleath::kAr9565EepromScratchBytes, discovery);
            if (acquired != simpleath::NvmDiscoveryResult::Ok)
            {
                setProperty("SimpleATHNvmCaptureResult",
                            static_cast<uint32_t>(discovery.lastCapture.result),
                            kRfPropertyWidthBits);
                setProperty("SimpleATHNvmRestoreResult",
                            static_cast<uint32_t>(discovery.lastRestore.result),
                            kRfPropertyWidthBits);
                return abortStart("EEPROMDiscovery",
                                  static_cast<uint32_t>(acquired));
            }
            const auto *board = board_.view(epoch_);
            if (board == nullptr)
            {
                return abortStart("EEPROMLease", kIOReturnNotReady);
            }
            setProperty("SimpleATHEepromValidated", true);
            auto *mac = OSData::withBytes(&board->summary.mac[0],
                                          simpleath::kPermanentMacBytes);
            if (mac == nullptr)
            {
                return abortStart("MACPublication", kIOReturnNoMemory);
            }
            setProperty("SimpleATHPermanentMAC", mac);
            mac->release();
            setProperty("SimpleATHNvmOrigin", board->origin,
                        kRfPropertyWidthBits);
            // The permanent MAC is not only a registry property: program
            // PCU identity and exact BSSID mask registers while automatic
            // ACK/CTS, DMA and transmit queues are quiesced. STA_ID1 mode
            // bits must survive; a partial write is recovered by full reset.
            stage("AR9565StationAddress");
            const auto mapped = backend_.activeRegisters();
            const simpleath::RegisterBus stationBus {
                &access_,
                readRegister,
                writeRegister,
                mapped.barLengthBytes,
            };
            // Preserve a user-approved locally administered address across
            // suspend/fresh PCI reset, but only for its original NVM board.
            // A different board cannot inherit the last card's privacy MAC.
            if (requestedStationMacValid_ &&
                memcmp(&requestedStationBoardMac_[0], &board->summary.mac[0],
                       sizeof(requestedStationBoardMac_)) != 0)
            {
                requestedStationMacValid_ = false;
                memset(&requestedStationMac_[0], 0,
                       sizeof(requestedStationMac_));
                memset(&requestedStationBoardMac_[0], 0,
                       sizeof(requestedStationBoardMac_));
            }
            const uint8_t *selected = requestedStationMacValid_
                                          ? &requestedStationMac_[0]
                                          : &board->summary.mac[0];
            const auto identityResult = simpleath::programAr9565StationMac(
                stationBus, selected, epoch_, stationMacPermit);
            setProperty("SimpleATHStationAddressResult",
                        static_cast<uint32_t>(identityResult.result),
                        kRfPropertyWidthBits);
            if (identityResult.result != simpleath::MacIdentityResult::Ok)
            {
                return abortStart("AR9565StationAddress",
                                  static_cast<uint32_t>(identityResult.result));
            }
            memcpy(&stationMac_[0], selected, sizeof(stationMac_));
            stationMacProgrammed_ = true;
            setProperty("SimpleATHStationAddressProgrammed", true);
            // The Atheros key RAM may contain stale keys from earlier OS or
            // firmware ownership. Before any protected path is permitted,
            // clear all 128 slots under the same live PCI epoch and gate.
            // Neither this stage nor an installed key is evidence of a
            // verified CCMP replay/PN engine or functional WPA2 data path.
            stage("CCMPKeyCacheScrub");
            const auto cacheResult = simpleath::initializeAr9565KeyCache(
                keyCacheBackend(), keyCache_);
            setProperty("SimpleATHKeyCacheInitResult",
                        static_cast<uint32_t>(cacheResult.result),
                        kRfPropertyWidthBits);
            if (cacheResult.result != simpleath::KeyCacheResult::Ok)
            {
                return abortStart("CCMPKeyCacheScrub",
                                  static_cast<uint32_t>(cacheResult.result));
            }
            setProperty("SimpleATHKeyCacheInitialized", true);
            // Register actual kernel entropy and physical AR9565 keycache
            // operations for a later driver-owned PMK join. This binds no
            // credentials and never authorizes RF or the controlled port.
            const simpleath::ieee80211::crypto::KeyHardware keyHardware {
                &access_,           nativeNonce,      nativeInstallPairwise,
                nativeInstallGroup, nativeRemoveKeys,
            };
            if (!engine_.configureKeys(keyHardware))
            {
                return abortStart("Wpa2HardwareAdapter", kIOReturnNotReady);
            }
            // The lease comes from an actual PCI-owned NVM read in this same
            // epoch, not an EEPROM template or a caller-supplied board.
            // PMU and XTAL tuning must precede PLL/PHY programming; neither
            // step grants RX, TX, automatic-response or coexistence readiness.
            const simpleath::RegulatorEvidence boardEvidence {
                board->valid && board->image.restored,
                enginesQuiesced_ && !queuesAdopted_ && !radioOperational_ &&
                    !channelAuthorized_,
            };
            // Read the physical RF-kill input only if this EEPROM actually
            // advertises a pin. A missing pin is UNKNOWN, not unblocked;
            // physical permission must be rechecked before future RF use.
            const simpleath::RfKillBoardConfiguration killPin {
                board->summary.rfKillConfigured,
                board->summary.rfKillGpio,
                board->summary.rfKillPolarity,
            };
            stage("AR9565RfKillSample");
            const auto kill =
                simpleath::sampleAr9565RfKill(killPin, rfKillBackend());
            setProperty("SimpleATHRfKillResult",
                        static_cast<uint32_t>(kill.result),
                        kRfPropertyWidthBits);
            setProperty("SimpleATHRfKillUnblocked",
                        kill.result == simpleath::RfKillResult::Unblocked);
            setProperty("SimpleATHRfKillResetRequired", kill.requiresReset);
            if (kill.result != simpleath::RfKillResult::Unblocked &&
                kill.result != simpleath::RfKillResult::NotConfigured)
            {
                return abortStart("AR9565RfKillSample",
                                  static_cast<uint32_t>(kill.result));
            }
            rfKillPinConfigured_ = killPin.configured;
            rfKillKnownUnblocked_ =
                kill.result == simpleath::RfKillResult::Unblocked;
            rfKillGpio_ = kill.gpio;
            rfKillActiveHigh_ = killPin.activeHigh;
            const auto analogIo = rfPowerBackend();
            stage("AR9565PMU1Regulator");
            const auto regulator = simpleath::configureAr9565InternalRegulator(
                board->image, boardEvidence, analogIo);
            setProperty("SimpleATHPMU1Result",
                        static_cast<uint32_t>(regulator.result),
                        kRfPropertyWidthBits);
            setProperty("SimpleATHPMU1ResetRequired", regulator.requiresReset);
            if (regulator.result != simpleath::RegulatorResult::Ok)
            {
                return abortStart("AR9565PMU1Regulator",
                                  static_cast<uint32_t>(regulator.result));
            }
            stage("AR9565XTALCapacitors");
            const auto crystal = simpleath::configureAr9565XtalCapacitors(
                board->image, boardEvidence, analogIo);
            setProperty("SimpleATHXTALResult",
                        static_cast<uint32_t>(crystal.result),
                        kRfPropertyWidthBits);
            setProperty("SimpleATHXTALResetRequired", crystal.requiresReset);
            if (crystal.result != simpleath::RegulatorResult::Ok)
            {
                return abortStart("AR9565XTALCapacitors",
                                  static_cast<uint32_t>(crystal.result));
            }
            setProperty("SimpleATHBoardAcquired", true);
            // This marks completed hardware acquisition, not network readiness.
            // RF calibration/queue/IO80211 integration must consume this board.
            stage("BoardAcquired");
            // IOLog is the kernel's variadic diagnostic ABI; the format is
            // fixed and every argument is supplied with the matching type.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
            IOLog("SimpleATH: physical AR9565 reset and EEPROM acquisition "
                  "complete\n");
            return kIOReturnSuccess;
        }

        IOReturn abortStart(const char *name, uint32_t detail)
        {
            const IOReturn result = error(name, detail);
            stopHardware(simpleath::ProviderAccess::Available);
            return result;
        }

        void stopHardware(simpleath::ProviderAccess access)
        {
            // Suspend and recoverable failures invalidate the data link but
            // keep the child subscribed for a later physical PCI epoch. Only
            // final termination revokes the provider callback contract.
            notifyWirelessChange(stopping_);
            failNativeJoin(kIOReturnNotReady);
            // Revoke any old RF/TPC permission before stopping the queue, so
            // suspend/reset cannot reuse a former channel's transmit policy.
            txSafety_ = {};
            txRate_ = {};
            txSequence_ = 0;
            memset(&ethernetTx_[0], 0, sizeof(ethernetTx_));
            memset(&protectedScratch_[0], 0, sizeof(protectedScratch_));
            memset(&protectedRxScratch_[0], 0, sizeof(protectedRxScratch_));
            nativePairwiseTx_.revoke();
            nativeProtectedFragments_.clear();
            nativePairwiseRx_.revoke();
            for (auto &group : nativeGroupRx_)
            {
                group.revoke();
            }
            nativePairwiseKeyRevoked_ = false;
            nativeGroupKeyRevokedMask_ = 0;
            if (queuesAdopted_ ||
                queues_.phase() == simpleath::NativeQueuePhase::Quarantined)
            {
                // A fault may already have detached the IRQ and cleared
                // queuesAdopted_. Retry real isolation while this PCI epoch
                // is still available; releaseClient rejects any mapping that
                // remains quarantined after an unsuccessful stop.
                queues_.stopGated(access ==
                                  simpleath::ProviderAccess::Available);
                queuesAdopted_ = false;
            }
            programmedBssidEpoch_ = 0;
            radioOperational_ = false;
            channelAuthorized_ = false;
            verifiedReceiveChannel_ = 0;
            const bool scanAborted = abortActiveNativeScan();
            if (scanAborted)
            {
                notifyWirelessScanFinished();
            }
            scanBridge_.clear();
            notifiedScanGeneration_ = 0;
            awdlNeighbors_.clear();
            completedScanTicket_ = {};
            // RTC or EEPROM startup can fail before the key RAM has ever
            // been initialized. A live mapped PCI epoch still needs a MAC
            // quiesce attempt before BAR release; keycache readiness only
            // determines whether a later physical key erasure is possible.
            const bool hardwareQuiesced =
                access == simpleath::ProviderAccess::Available &&
                session_.status().mapped &&
                queues_.phase() != simpleath::NativeQueuePhase::Quarantined &&
                quiesceEngines();
            // Portable supplicant key removal now runs only after the native
            // queues AND automatic MAC responses have been quiesced. This is
            // essential for the real AR9565 hardware-keycache callbacks.
            engine_.radioStopped(nowMicros(nullptr) / kMicrosPerMillisecond,
                                 true);
            if (keyCache_.initialized)
            {
                bool wiped = false;
                if (hardwareQuiesced && !keyCache_.requiresReset)
                {
                    const auto erasure = simpleath::eraseAr9565Keys(
                        keyCacheBackend(), keyCache_);
                    setProperty("SimpleATHKeyCacheEraseResult",
                                static_cast<uint32_t>(erasure.result),
                                kRfPropertyWidthBits);
                    wiped = erasure.result == simpleath::KeyCacheResult::Ok;
                }
                setProperty("SimpleATHKeyCacheWipeConfirmed", wiped);
            }
            setProperty("SimpleATHKeyCacheResetRequired",
                        keyCache_.requiresReset);
            keyCache_ = {};
            setProperty("SimpleATHKeyCacheInitialized", false);
            board_.invalidate();
            stationMacProgrammed_ = false;
            memset(&stationMac_[0], 0, sizeof(stationMac_));
            setProperty("SimpleATHStationAddressProgrammed", false);
            enginesQuiesced_ = false;
            // IRQ delivery and queue DMA stop before BAR/provider revocation.
            // Client mapping release occurs after leaving the gate; uncertain
            // hardware ownership remains quarantined in NativeQueues.
            session_.stop(access);
            powered_ = false;
            identity_ = {};
            setProperty("SimpleATHBoardAcquired", false);
            rfKillPinConfigured_ = false;
            rfKillKnownUnblocked_ = false;
            rfKillGpio_ = 0;
            rfKillActiveHigh_ = false;
            setProperty("SimpleATHRfKillUnblocked", false);
            setProperty("SimpleATHEepromValidated", false);
            setProperty("SimpleATHMmioTransportReady", false);
            setProperty("SimpleATHPciExclusiveOwner", false);
            removeProperty("SimpleATHPermanentMAC");
            removeProperty("SimpleATHNvmOrigin");
            setProperty("SimpleATHDriverReady", false);
        }

        static IOReturn prepareFreshStartAction(OSObject *owner, void *argument,
                                                void * /*unused2*/,
                                                void * /*unused3*/,
                                                void * /*unused4*/)
        {
            auto *typed = OSDynamicCast(SimpleATH, owner);
            if (typed == nullptr || argument == nullptr)
            {
                return kIOReturnBadArgument;
            }
            auto &self = *typed;
            auto &release = *static_cast<bool *>(argument);
            release = false;
            if (self.stopping_)
            {
                return kIOReturnNotReady;
            }
            const auto phase = self.queues_.phase();
            const bool mapped = phase != simpleath::NativeQueuePhase::Empty;
            const bool retired =
                phase == simpleath::NativeQueuePhase::Quarantined ||
                self.keyCache_.requiresReset;
            const bool orphaned = mapped && !self.queuesAdopted_;
            if (!retired && !orphaned)
            {
                return kIOReturnSuccess;
            }
            // If PCI/D0 ownership was already revoked, there is no safe
            // physical isolation operation to turn quarantined DMA into a
            // releasable buffer. Never start a new session over that IOVA.
            if (!self.powered_ &&
                phase == simpleath::NativeQueuePhase::Quarantined)
            {
                return kIOReturnNotReady;
            }
            if (self.powered_)
            {
                self.stopHardware(simpleath::ProviderAccess::Available);
            }
            release = mapped;
            return kIOReturnSuccess;
        }

        static IOReturn startAction(OSObject *owner, void * /*unused1*/,
                                    void * /*unused2*/, void * /*unused3*/,
                                    void * /*unused4*/)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            return static_cast<SimpleATH *>(owner)->startHardware();
        }

        static IOReturn sleepAction(OSObject *owner, void * /*unused1*/,
                                    void * /*unused2*/, void * /*unused3*/,
                                    void * /*unused4*/)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(owner);
            self.stopHardware(simpleath::ProviderAccess::Available);
            self.stage("Suspended");
            return kIOReturnSuccess;
        }

        static IOReturn stopAction(OSObject *owner, void * /*unused1*/,
                                   void * /*unused2*/, void * /*unused3*/,
                                   void * /*unused4*/)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(owner);
            if (!self.stopping_)
            {
                // Final stop without an earlier willTerminate must emit the
                // same provider-revocation event. Keep the hardware permit
                // valid until keycache/DMA teardown completes, then revoke
                // callbacks while the observer lock still exists.
                self.stopHardware(simpleath::ProviderAccess::Available);
                self.stopping_ = true;
                self.notifyWirelessChange(true);
            }
            self.stage("Stopped");
            return kIOReturnSuccess;
        }

        static IOReturn terminateAction(OSObject *owner, void * /*unused1*/,
                                        void * /*unused2*/, void * /*unused3*/,
                                        void * /*unused4*/)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
            auto &self = *static_cast<SimpleATH *>(owner);
            if (!self.stopping_)
            {
                self.stopping_ = true;
                self.stopHardware(simpleath::ProviderAccess::Unavailable);
            }
            return kIOReturnSuccess;
        }

        bool failStart(IOService *provider, const char *name, IOReturn result)
        {
            error(name, static_cast<uint32_t>(result));
            stop(provider);
            return false;
        }

        void cleanup()
        {
            if (linkTimer_ != nullptr)
            {
                linkTimer_->cancelTimeout();
                if (linkTimerAttached_ && loop_ != nullptr)
                {
                    loop_->removeEventSource(linkTimer_);
                }
                linkTimer_->release();
                linkTimer_ = nullptr;
                linkTimerAttached_ = false;
            }
            if (scanTimer_ != nullptr)
            {
                scanTimer_->cancelTimeout();
                if (scanTimerAttached_ && loop_ != nullptr)
                {
                    loop_->removeEventSource(scanTimer_);
                }
                scanTimer_->release();
                scanTimer_ = nullptr;
                scanTimerAttached_ = false;
            }
            backend_.clear();
            if (lifecycle_ != nullptr)
            {
                IOLockFree(lifecycle_);
                lifecycle_ = nullptr;
            }
            if (gate_ != nullptr)
            {
                if (gateAttached_)
                {
                    loop_->removeEventSource(gate_);
                }
                gate_->release();
                gate_ = nullptr;
                gateAttached_ = false;
            }
            if (loop_ != nullptr)
            {
                loop_->release();
                loop_ = nullptr;
            }
            if (storage_ != nullptr)
            {
                memset(storage_, 0, kNvmStorageBytes);
                IOFree(storage_, kNvmStorageBytes);
                storage_ = nullptr;
            }
            if (scratch_ != nullptr)
            {
                memset(scratch_, 0, simpleath::kAr9565EepromScratchBytes);
                IOFree(scratch_, simpleath::kAr9565EepromScratchBytes);
                scratch_ = nullptr;
            }
            pci_ = nullptr;
            started_ = false;
        }

        // Per-instance PM registration states, retained for the service's
        // complete lifetime instead of a writable globally shared array.
        IOPMPowerState powerStates_[2] {
            {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            {
                1,
                kIOPMDeviceUsable | kIOPMPowerOn,
                kIOPMPowerOn,
                kIOPMPowerOn,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            },
        };
        simpleath::DiagnosticSelection diagnostics_ {};
        RegisterAccess access_ {nullptr};
        IOLock *lifecycle_ {nullptr};
        // Independent of the PCI gate to permit synchronous unsubscribe
        // after stop() removes its work loop.
        IOLock *observerLock_ {nullptr};
        void *wirelessObserver_ {nullptr};
        IOReturn (*wirelessNotify_)(void *, simpleath::tahoe::WirelessEvent,
                                    uint64_t, uint64_t) {nullptr};
        void (*wirelessReceive_)(void *, uint64_t, uint64_t, const uint8_t *,
                                 size_t) {nullptr};
        bool controlledPortAuthorized_ {false};
        // Only the matching completed EDMA transmission of driver-owned M4
        // and later authenticated, replay-checked data RX are WPA2 proofs.
        // They are invalidated on every join/key/PCI owner revocation.
        uint64_t pendingWpa2M4Token_ {0};
        uint64_t pendingWpa2Group2Token_ {0};
        // The locally queued disassociation owns one outstanding EDMA
        // descriptor until its callback or the bounded link watchdog fires.
        // This is not a second association or permission for data traffic.
        uint64_t pendingLocalLeaveToken_ {0};
        uint64_t pendingLocalLeaveEpoch_ {0};
        bool wpa2M4TransmitConfirmed_ {false};
        bool authenticatedProtectedRxObserved_ {false};
        // Credential-free, epoch-bound WCL progress. Never retain a PMK or
        // borrowed join packet after the synchronous command-gate call.
        uint64_t joinEpoch_ {0};
        uint64_t joinRequestId_ {0};
        IOReturn joinStatus_ {kIOReturnNotReady};
        bool associatedBeaconObserved_ {false};
        bool associatedSignalMeasured_ {false};
        int8_t associatedRssiDbm_ {0};
        uint8_t joinBssid_[simpleath::tahoe::kWirelessMacBytes] {};
        // A successful PCU BSSID/AID write in this live physical epoch.
        // A new OS join cannot overwrite it until cancellation verifies
        // explicit hardware zeroing or terminal retirement revokes the epoch.
        uint64_t programmedBssidEpoch_ {0};
        simpleath::NativeQueues queues_;
        simpleath::ieee80211::WifiEngine engine_;
        simpleath::ieee80211::LegacyScanBridge scanBridge_;
        simpleath::ieee80211::AwdlNeighbors awdlNeighbors_;
        simpleath::ieee80211::ScanBridgeTicket scanTicket_ {};
        simpleath::ieee80211::ScanBridgeTicket completedScanTicket_ {};
        uint64_t notifiedScanGeneration_ {0};
        IOTimerEventSource *scanTimer_ {nullptr};
        IOTimerEventSource *linkTimer_ {nullptr};
        // Workloop-only join/association identity; canceled on failed joins,
        // disconnect, radio stop and physical PCI epoch retirement.
        uint64_t linkWatchEpoch_ {0};
        uint64_t linkWatchAssociationGeneration_ {0};
        // Only a submitted authentication request starts this timer lease.
        // Association replaces it with an AP-beacon watchdog.
        uint64_t joinWatchRequestId_ {0};
        uint64_t joinWatchStartedMs_ {0};
        // Until first controlled-port authorization, even a beacon-live AP
        // cannot hold pending EAPOL/security state indefinitely.
        uint64_t portReadyStartedMs_ {0};
        bool portReadyPending_ {false};
        uint64_t scanEpoch_ {0};
        uint64_t scanEngineGeneration_ {0};
        uint32_t scanSerial_ {0};
        // Only a successful, physically authorized RF tune can set this;
        // the current board-acquisition-only boot intentionally cannot.
        uint8_t verifiedReceiveChannel_ {0};
        bool scanTimerAttached_ {false};
        bool linkTimerAttached_ {false};
        uint8_t managementReply_[kManagementReplyCapacity] {};
        bool deferredGroup2_ {false};
        size_t deferredManagementBytes_ {0};
        uint64_t deferredManagementEpoch_ {0};
        uint64_t deferredJoinRequestId_ {0};
        uint8_t ethernetRx_[kNativeEthernetCapacity] {};
        uint8_t ethernetTx_[kNativeTxMpduCapacity] {};
        uint8_t protectedScratch_[kNativeTxMpduCapacity] {};
        uint8_t protectedRxScratch_
            [simpleath::ieee80211::crypto::kCcmpMaximumMpduBytes] {};
        // Only MIC/PN-verified plaintext may enter this same-key stream.
        // Cleared on every native key change, disconnect and radio reset.
        simpleath::ieee80211::ProtectedFragmentStream
            nativeProtectedFragments_ {};
        // Software CCMP sessions exist only in the current physical epoch.
        // TX uses local station address; RX needs the AP transmitter instead.
        // They are distinct because PN ownership differs by direction.
        simpleath::ieee80211::crypto::CcmpSession nativePairwiseTx_;
        simpleath::ieee80211::crypto::CcmpSession nativePairwiseRx_;
        simpleath::ieee80211::crypto::CcmpSession
            nativeGroupRx_[simpleath::kCcmpGroupSlots] {};
        bool nativePairwiseKeyRevoked_ {false};
        // GTK slot removal must not permit replay-floor rollback under the
        // same association/physical epoch; a fresh epoch resets this latch.
        uint8_t nativeGroupKeyRevokedMask_ {0};
        // Acquired only from independently validated native RF/TPC setup.
        // Source-only EEPROM power candidates must never populate these.
        simpleath::edma::TxSafetyPolicy txSafety_ {};
        simpleath::edma::TxRate txRate_ {};
        uint16_t txSequence_ {0};
        uint64_t nextTransmitToken_ {1};
        // Increment only after a genuine AP association response. Never
        // recycle across disconnect, radio stop, sleep or PCI epoch change.
        uint64_t associationGeneration_ {0};
        uint64_t receivedFrames_ {0};
        uint64_t awdlReceivedMifs_ {0};
        uint64_t transmitCompletions_ {0};
        bool queuesAdopted_ {false};
        bool stationMacProgrammed_ {false};
        // Retained only while the PCI instance exists; effective hardware
        // identity is published after each same-epoch readback, never solely
        // because a caller requested a locally administered MAC.
        uint8_t stationMac_[simpleath::kPermanentMacBytes] {};
        uint8_t requestedStationMac_[simpleath::kPermanentMacBytes] {};
        // NVM permanent address which owned the retained station MAC override.
        uint8_t requestedStationBoardMac_[simpleath::kPermanentMacBytes] {};
        bool requestedStationMacValid_ {false};
        bool radioOperational_ {false};
        bool channelAuthorized_ {false};
        IOPCIDevice *pci_ {nullptr};
        IOWorkLoop *loop_ {nullptr};
        IOCommandGate *gate_ {nullptr};
        simpleath::NativePciBackend backend_;
        simpleath::PciReadOnlySession session_;
        simpleath::NvmBoardLease board_;
        simpleath::KeyCacheState keyCache_ {};
        simpleath::RtcPowerContext rtc_ {};
        simpleath::Identity identity_ {};
        uint8_t *storage_ {nullptr};
        uint8_t *scratch_ {nullptr};
        uint64_t epoch_ {0};
        bool powered_ {false};
        bool enginesQuiesced_ {false};
        bool rfKillPinConfigured_ {false};
        bool rfKillKnownUnblocked_ {false};
        uint8_t rfKillGpio_ {0};
        bool rfKillActiveHigh_ {false};
        bool gateAttached_ {false};
        bool pmInitialized_ {false};
        bool started_ {false};
        bool stopping_ {false};
};

// Exact RTTI and IOService construction contract from the pinned IOKit
// metaclass macros; the native USB service uses the same explicit expansion.
SimpleATH::MetaClass SimpleATH::gMetaClass;
const OSMetaClass *const SimpleATH::metaClass = &SimpleATH::gMetaClass;
constexpr const OSMetaClass *SimpleATH::superClass;

SimpleATH::SimpleATH(const OSMetaClass *meta) : IOService(meta)
{
}

SimpleATH::~SimpleATH() = default;

const OSMetaClass *SimpleATH::getMetaClass() const
{
    return &gMetaClass;
}

SimpleATH::MetaClass::MetaClass() noexcept
    : OSMetaClass("SimpleATH", SimpleATH::superClass, sizeof(SimpleATH))
{
}

OSDefineDefaultStructors(SimpleATH, IOService)

    extern "C" kern_return_t
    // The kext loader requires this exact exported C symbol name.
    // NOLINTNEXTLINE(readability-identifier-naming)
    SimpleATH_kern_start(kmod_info_t * /*unused*/, void * /*unused*/)
{
    int ignored = 0;
    driverEnabled() =
        PE_parse_boot_argn("-simpleathoff", &ignored, sizeof(ignored)) == 0;
    return KERN_SUCCESS;
}

// The kext loader requires this exact exported C symbol name.
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" kern_return_t SimpleATH_kern_stop(kmod_info_t * /*unused*/,
                                             void * /*unused*/)
{
    return KERN_SUCCESS;
}
