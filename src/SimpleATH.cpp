// SPDX-License-Identifier: AGPL-3.0-only
// Native AR9565 PCI owner: power, BAR access, RTC reset and board acquisition.
#include "hardware/Ar9003Descriptors.hpp"
#include "hardware/Ar9003TxControl.hpp"
#include "hardware/Ar9565Calibration.hpp"
#include "hardware/Ar9565KeyCache.hpp"
#include "hardware/Ar9565MacControl.hpp"
#include "hardware/Ar9565NvmReader.hpp"
#include "hardware/Ar9565Regulator.hpp"
#include "hardware/Ar9565RfIni.hpp"
#include "hardware/Ar9565RtcPower.hpp"
#include "platform/Ar9565NativePci.hpp"
#include "platform/Ar9565NativeQueues.hpp"
#include "platform/tahoe/NativeWirelessOwner.hpp"
#include "wifi/DataFrames.hpp"
#include "wifi/DataPath.hpp"
#include "wifi/Frames.hpp"
#include "wifi/LinkMonitor.hpp"
#include "wifi/WifiEngine.hpp"
#include "wifi/crypto/Ccmp.hpp"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <cstddef>
#include <cstdint>
#include <kern/clock.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/libkern.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>
#include <string.h>

class SimpleATH;

namespace
{
    struct RegisterAccess
    {
            SimpleATH *owner;
    };

    bool gSimpleATHEnabled = true;
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
    constexpr uint8_t kAllGroupKeySlotsRevoked =
        (1U << simpleath::kCcmpGroupSlots) - 1U;
    constexpr uint8_t kNoKeyCacheSlot = 0xff;
    constexpr uint8_t kProtectedFrameFlag = 0x40U;
    constexpr uint16_t kSequenceMask = 0x0fffU;
    constexpr size_t kSequenceControlOffset = 22;
    constexpr uint8_t kSequenceFragmentBits = 4;
    constexpr uint8_t kByteBits = 8;
    constexpr uint64_t kMicrosPerMillisecond = 1000;

    struct NativeTransmitRequest
    {
            const uint8_t *bytes;
            size_t length;
    };

    constexpr unsigned int kRfPropertyWidthBits = 32;
    constexpr uint32_t kRfKillInputRegister = 0x404c;
    // IOService copies this table when registering the power driver.
    IOPMPowerState gPowerStates[2] = {
        {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {1, kIOPMDeviceUsable | kIOPMPowerOn, kIOPMPowerOn, kIOPMPowerOn, 0, 0,
         0, 0, 0, 0, 0, 0},
    };
} // namespace

class SimpleATH final : public IOService
{
    OSDeclareDefaultStructors(SimpleATH)

        public : IOService *probe(IOService *provider, SInt32 *score) override
        {
            return gSimpleATHEnabled && OSDynamicCast(IOPCIDevice, provider)
                       ? IOService::probe(provider, score)
                       : nullptr;
        }

        IOWorkLoop *getWorkLoop() const override
        {
            return loop_;
        }

        bool start(IOService *provider) override
        {
            if (!gSimpleATHEnabled || !IOService::start(provider))
                return false;
            pci_ = OSDynamicCast(IOPCIDevice, provider);
            if (!pci_)
                return failStart(provider, "PCIProvider", kIOReturnBadArgument);
            lifecycle_ = IOLockAlloc();
            if (!observerLock_)
                observerLock_ = IOLockAlloc();
            loop_ = IOWorkLoop::workLoop();
            gate_ = IOCommandGate::commandGate(this);
            if (!lifecycle_ || !observerLock_ || !loop_ || !gate_)
                return failStart(provider, "WorkLoop", kIOReturnNoMemory);
            const IOReturn added = loop_->addEventSource(gate_);
            if (added != kIOReturnSuccess)
                return failStart(provider, "CommandGate", added);
            gateAttached_ = true;
            access_.owner = this;
            const simpleath::NativePciPowerGate power {&access_, poweredGate};
            if (!backend_.configure(this, pci_, power))
                return failStart(provider, "PCIConfigure", kIOReturnNotReady);
            storage_ = static_cast<uint8_t *>(IOMalloc(kNvmStorageBytes));
            scratch_ = static_cast<uint8_t *>(
                IOMalloc(simpleath::kAr9565EepromScratchBytes));
            if (!storage_ || !scratch_)
                return failStart(provider, "NVMStorage", kIOReturnNoMemory);
            setProperty("SimpleATHMode", "NativeAR9565");
            setProperty("SimpleATHDriverReady", false);
            PMinit();
            pmInitialized_ = true;
            provider->joinPMtree(this);
            const IOReturn registered =
                registerPowerDriver(this, gPowerStates, 2);
            if (registered != kIOReturnSuccess)
                return failStart(provider, "PowerRegistration", registered);
            const IOReturn result = startClient();
            if (result != kIOReturnSuccess)
                return failStart(provider, "HardwareStart", result);
            started_ = true;
            changePowerStateTo(1);
            registerService();
            return true;
        }

        IOReturn setPowerState(unsigned long state, IOService *) override
        {
            // PM invokes this on a sleepable thread. The same gate serializes
            // reset/NVM, sleep, stop and provider termination; no worker needs
            // to reenter it while an operation is waiting.
            if (gate_ && started_)
            {
                if (state == 0)
                {
                    gate_->runAction(sleepAction);
                    releaseQueuesClient();
                }
                else
                    startClient();
            }
            return kIOPMAckImplied;
        }

        bool willTerminate(IOService *provider, IOOptionBits options) override
        {
            if (gate_)
            {
                gate_->runAction(terminateAction);
                releaseQueuesClient();
            }
            return IOService::willTerminate(provider, options);
        }

        void stop(IOService *provider) override
        {
            if (pmInitialized_)
            {
                PMstop();
                pmInitialized_ = false;
            }
            if (gate_ && gateAttached_)
                gate_->runAction(stopAction);
            releaseQueuesClient();
            cleanup();
            IOService::stop(provider);
        }

        void free() override
        {
            cleanup();
            // The transport retains the provider until its synchronous
            // unsubscribe. The observer lock must outlive stop()/cleanup().
            if (observerLock_)
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
            if (!p1 || p2 || p3 || p4)
                return kIOReturnBadArgument;
            auto *out = static_cast<simpleath::tahoe::WirelessOwnerV1 *>(p1);
            if (out->abiVersion != simpleath::tahoe::kWirelessOwnerAbi ||
                out->structureBytes != sizeof(*out))
                return kIOReturnUnsupported;
            if (!gate_)
                return kIOReturnNotReady;
            return gate_->runAction(exportWirelessOwnerAction, out);
        }

    private:
        // The Tahoe child binds to a real PCI owner, never to IORegistry
        // readiness properties. Provider entrypoints execute on this owner's
        // serialized gate; only the mailbox notification callback crosses to
        // the child's independent work loop.
        static IOReturn exportWirelessOwnerAction(OSObject *object, void *arg,
                                                  void *, void *, void *)
        {
            auto &self = *static_cast<SimpleATH *>(object);
            if (!self.powered_ || self.stopping_ ||
                !self.board_.view(self.epoch_) || !self.observerLock_)
                return kIOReturnNotReady;
            auto &out = *static_cast<simpleath::tahoe::WirelessOwnerV1 *>(arg);
            const simpleath::tahoe::WirelessOwnerV1 callbacks {
                simpleath::tahoe::kWirelessOwnerAbi,
                sizeof(simpleath::tahoe::WirelessOwnerV1),
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
            };
            out = callbacks;
            return kIOReturnSuccess;
        }

        static IOReturn ownerSnapshotAction(OSObject *object, void *arg, void *,
                                            void *, void *)
        {
            auto &self = *static_cast<SimpleATH *>(object);
            auto &out = *static_cast<simpleath::tahoe::WirelessSnapshot *>(arg);
            out = {};
            const auto *board = self.board_.view(self.epoch_);
            if (!self.powered_ || self.stopping_ || !board)
                return kIOReturnNotReady;
            out.epoch = self.epoch_;
            memcpy(out.permanentMac, board->summary.mac,
                   sizeof(out.permanentMac));
            memcpy(out.currentMac, board->summary.mac, sizeof(out.currentMac));
            const auto link = self.engine_.linkStatus();
            const bool liveRfKill = self.liveRfKillUnblocked();
            // Association precedes WPA2 key installation. Report only a
            // genuinely received association on the active radio epoch;
            // controlledPortOpen independently gates IP traffic and DHCP.
            out.associated =
                liveRfKill && self.radioOperational_ &&
                self.channelAuthorized_ &&
                self.queues_.epoch() == self.epoch_ &&
                self.queues_.phase() == simpleath::NativeQueuePhase::Running &&
                link.state == simpleath::ieee80211::LinkState::Associated;
            if (out.associated)
                memcpy(out.bssid, link.bssid.bytes, sizeof(out.bssid));
            out.powered = self.powered_;
            out.radioAvailable =
                liveRfKill && self.radioOperational_ &&
                self.channelAuthorized_ &&
                self.queues_.phase() == simpleath::NativeQueuePhase::Running;
            out.controlledPortOpen =
                out.associated && self.controlledPortAuthorized_;
            // No country code or current channel is published until the
            // physical/regulatory owner has actually authorized one.
            out.rfKillBlocked = !liveRfKill;
            return kIOReturnSuccess;
        }

        static IOReturn ownerSnapshot(void *context,
                                      simpleath::tahoe::WirelessSnapshot *out)
        {
            if (!context || !out)
                return kIOReturnBadArgument;
            auto &self = *static_cast<SimpleATH *>(context);
            if (!self.gate_)
                return kIOReturnNotReady;
            return self.gate_->runAction(ownerSnapshotAction, out);
        }

        static IOReturn ownerSetPower(void *context, bool on)
        {
            if (!context)
                return kIOReturnBadArgument;
            auto &self = *static_cast<SimpleATH *>(context);
            if (!self.started_ || self.stopping_)
                return kIOReturnNotReady;
            if (on)
            {
                // Power-on performs the real PCI/RTC/EEPROM sequence, not a
                // synthetic radio-ready transition.
                return self.startClient();
            }
            self.setPowerState(0, nullptr);
            return kIOReturnSuccess;
        }

        static IOReturn
        ownerSetMac(void *context,
                    const uint8_t address[simpleath::tahoe::kWirelessMacBytes])
        {
            if (!context || !address)
                return kIOReturnBadArgument;
            simpleath::tahoe::WirelessSnapshot current {};
            const IOReturn result = ownerSnapshot(context, &current);
            if (result != kIOReturnSuccess)
                return result;
            // Until hardware and native interface readdressing are wired,
            // only an idempotent request for the physical MAC is valid.
            return memcmp(address, current.currentMac,
                          sizeof(current.currentMac)) == 0
                       ? kIOReturnSuccess
                       : kIOReturnUnsupported;
        }

        static IOReturn ownerBeginScan(void *, uint64_t *generation)
        {
            if (!generation)
                return kIOReturnBadArgument;
            *generation = 0;
            // No authorized dwell itinerary or tuned RF receiver exists yet.
            return kIOReturnNotReady;
        }

        static IOReturn ownerCancelScan(void *, uint64_t)
        {
            return kIOReturnNotReady;
        }

        static IOReturn
        ownerNextBss(void *, uint64_t,
                     simpleath::ieee80211::NativeBssSnapshot *out)
        {
            if (!out)
                return kIOReturnBadArgument;
            *out = {};
            return kIOReturnNotReady;
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
            const auto *board = self.board_.view(self.epoch_);
            // A scan-cache candidate is not RF authority. An OS join must
            // follow a real authorized channel tune and complete TX policy;
            // otherwise do not consume the candidate/handshake state.
            if (board == nullptr || !self.canSubmitTransmit())
            {
                return kIOReturnNotReady;
            }
            if (!self.queues_.hasTransmitSpace())
            {
                return kIOReturnNoResources;
            }
            simpleath::ieee80211::Mac station {};
            simpleath::ieee80211::Mac bssid {};
            __builtin_memcpy(&station.bytes[0], &board->summary.mac[0],
                             sizeof(station.bytes));
            __builtin_memcpy(&bssid.bytes[0], &request.bssid[0],
                             sizeof(bssid.bytes));
            // Only a BSSID really observed in this radio epoch, with an
            // exact SSID/channel/security match, can start OS-owned WPA2.
            const auto chosen = self.engine_.chooseNetworkForOsSupplicant(
                station, bssid, &request.ssid[0], request.ssidLength,
                request.channel, request.wpa2Personal);
            self.setProperty("SimpleATHNativeJoinSelectionResult",
                             static_cast<uint32_t>(chosen),
                             kRfPropertyWidthBits);
            if (chosen != simpleath::ieee80211::EngineResult::Ok)
            {
                return chosen ==
                               simpleath::ieee80211::EngineResult::InvalidInput
                           ? kIOReturnBadArgument
                           : kIOReturnNotReady;
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
                self.engine_.radioStopped(
                    nowMicros(nullptr) / kMicrosPerMillisecond, false);
                self.controlledPortAuthorized_ = false;
                return sent;
            }
            self.txSequence_ =
                static_cast<uint16_t>((self.txSequence_ + 1U) & kSequenceMask);
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
            return self.gate_->runAction(ownerConnectAction, &stable);
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
            if (link.state != simpleath::ieee80211::LinkState::Associated ||
                link.pmfNegotiated || !self.canSubmitTransmit())
            {
                return kIOReturnNotReady;
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
            const IOReturn sent =
                self.submitPreparedTransmit(&self.managementReply_[0], written);
            if (sent != kIOReturnSuccess)
            {
                return sent;
            }
            self.txSequence_ =
                static_cast<uint16_t>((self.txSequence_ + 1U) & kSequenceMask);
            // A successfully queued disassociation ends the native local
            // association immediately; no stale PTK/GTK, replay state or
            // receive port may survive the leave request. Hardware DMA still
            // owns its copied management frame until completion.
            self.controlledPortAuthorized_ = false;
            self.nativePairwiseTx_.revoke();
            self.nativePairwiseRx_.revoke();
            for (auto &group : self.nativeGroupRx_)
            {
                group.revoke();
            }
            self.nativePairwiseKeyRevoked_ = true;
            self.nativeGroupKeyRevokedMask_ = kAllGroupKeySlotsRevoked;
            memset(&self.protectedRxScratch_[0], 0,
                   sizeof(self.protectedRxScratch_));
            self.engine_.radioStopped(
                nowMicros(nullptr) / kMicrosPerMillisecond, false);
            self.notifyWirelessChange(false);
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

        static IOReturn ownerInstallKeyAction(OSObject *object, void *argument,
                                              void *, void *, void *)
        {
            auto &self = *static_cast<SimpleATH *>(object);
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
                self.queues_.phase() != simpleath::NativeQueuePhase::Running ||
                !self.board_.view(self.epoch_) ||
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
                if (!self.queues_.hasTransmitSpace())
                    return kIOReturnBusy;
                if (key.pairwise && key.keyId == 0 &&
                    memcmp(key.peer, link.bssid.bytes,
                           simpleath::tahoe::kWirelessMacBytes) == 0)
                {
                    self.nativePairwiseTx_.revoke();
                    self.nativePairwiseRx_.revoke();
                    for (auto &group : self.nativeGroupRx_)
                        group.revoke();
                    self.nativePairwiseKeyRevoked_ = true;
                    self.controlledPortAuthorized_ = false;
                    return kIOReturnSuccess;
                }
                if (!key.pairwise && key.keyId < simpleath::kCcmpGroupSlots &&
                    memcmp(key.peer, link.bssid.bytes,
                           simpleath::tahoe::kWirelessMacBytes) == 0)
                {
                    // During a GTK rotation, removing the retired slot must
                    // not close the OS-controlled port while a separately
                    // installed new GTK remains. A retired slot stays
                    // unusable for the rest of this physical key epoch;
                    // reinstalling it would roll its receive PN floor back.
                    if (!self.nativeGroupRx_[key.keyId].installed())
                        return kIOReturnUnsupported;
                    self.nativeGroupRx_[key.keyId].revoke();
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
            if (key.receivePacketNumber >
                    simpleath::ieee80211::crypto::kCcmpMaximumPacketNumber ||
                memcmp(key.peer, link.bssid.bytes,
                       simpleath::tahoe::kWirelessMacBytes) != 0 ||
                self.nativePairwiseKeyRevoked_ ||
                (key.pairwise && self.controlledPortAuthorized_))
                return kIOReturnUnsupported;
            if (!key.pairwise)
            {
                if (key.keyId >= simpleath::kCcmpGroupSlots ||
                    (self.nativeGroupKeyRevokedMask_ &
                     static_cast<uint8_t>(1U << key.keyId)) != 0U ||
                    !self.nativePairwiseTx_.installed() ||
                    !self.nativePairwiseRx_.installed() ||
                    self.nativeGroupRx_[key.keyId].installed())
                    return kIOReturnUnsupported;
                // An OS-owned Group1/Group2 handshake may install a new
                // receive-only GTK in an unused slot while the data port is
                // open. Existing slot and pairwise PN state remain intact;
                // replacing the same slot without a fresh epoch is refused.
                // Never use the GTK to transmit station unicast data or
                // trust unauthenticated packet KeyID as a key selector.
                const auto installed = self.nativeGroupRx_[key.keyId].install(
                    key.material, link.bssid.bytes, key.keyId, self.epoch_, 0,
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
            const auto installed = self.nativePairwiseTx_.install(
                key.material, link.station.bytes, 0, self.epoch_, 0, 0);
            if (installed != simpleath::ieee80211::crypto::CcmpResult::Ok)
                return kIOReturnBadArgument;
            const auto receiveInstalled = self.nativePairwiseRx_.install(
                key.material, link.bssid.bytes, 0, self.epoch_, 0,
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
            if (!context || !key)
                return kIOReturnBadArgument;
            auto &self = *static_cast<SimpleATH *>(context);
            if (!self.gate_)
                return kIOReturnNotReady;
            // Borrowed material remains valid through synchronous runAction.
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            auto *request = const_cast<simpleath::tahoe::NativeCcmpKey *>(key);
            return self.gate_->runAction(ownerInstallKeyAction, request);
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
            // An OS supplicant may open this port only after association,
            // installation of a fresh pairwise TK and GTK, and physical
            // channel/queue/RF authorization in this PCI epoch. A key install
            // callback alone cannot advance the controlled port.
            if (!self.powered_ || self.stopping_ || !self.radioOperational_ ||
                !self.channelAuthorized_ || !self.liveRfKillUnblocked() ||
                self.board_.view(self.epoch_) == nullptr ||
                self.queues_.epoch() != self.epoch_ ||
                self.queues_.phase() != simpleath::NativeQueuePhase::Running ||
                !self.txSafety_.dmaMappingValid ||
                !self.txSafety_.channelRegulatoryAuthorized ||
                !self.txSafety_.transmitPowerLimitsValidated ||
                self.nativePairwiseKeyRevoked_ ||
                link.state != simpleath::ieee80211::LinkState::Associated ||
                self.engine_.stationState() !=
                    simpleath::ieee80211::StationState::WaitingForWpa2Keys ||
                !self.engine_.osSupplicantOwnsWpa2() ||
                !self.nativePairwiseTx_.installed() ||
                !self.nativePairwiseRx_.installed() ||
                !self.nativeGroupInstalled())
            {
                return kIOReturnNotReady;
            }
            self.controlledPortAuthorized_ = true;
            self.notifyWirelessChange(false);
            return kIOReturnSuccess;
        }

        static IOReturn ownerAuthorizePort(void *context, bool open)
        {
            if (context == nullptr)
            {
                return kIOReturnBadArgument;
            }
            const auto &self = *static_cast<SimpleATH *>(context);
            if (self.gate_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            bool requested = open;
            return self.gate_->runAction(ownerAuthorizePortAction, &requested);
        }

        bool nativeGroupInstalled() const
        {
            for (const auto &group : nativeGroupRx_)
            {
                if (group.installed())
                    return true;
            }
            return false;
        }

        // Connect and every management/data TX share one physical safety
        // predicate. A selected BSSID or OS-owned key cannot confer RF/TPC
        // authority before the native radio owner publishes real evidence.
        bool canSubmitTransmit()
        {
            return powered_ && !stopping_ && radioOperational_ &&
                   channelAuthorized_ && rfKillKnownUnblocked_ &&
                   board_.view(epoch_) != nullptr &&
                   queues_.epoch() == epoch_ &&
                   queues_.phase() == simpleath::NativeQueuePhase::Running &&
                   txSafety_.siliconIdentified &&
                   txSafety_.boardCalibrationValidated &&
                   txSafety_.channelRegulatoryAuthorized &&
                   txSafety_.transmitPowerLimitsValidated &&
                   txSafety_.rfKillUnblocked && txSafety_.radioAwake &&
                   txSafety_.dmaMappingValid && liveRfKillUnblocked();
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
            if (softwareProtected && (!nativePairwiseTx_.installed() ||
                                      (frame[1] & kProtectedFrameFlag) == 0))
                return kIOReturnNotReady;
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
            if (!self->powered_ || self->stopping_ ||
                link.state != simpleath::ieee80211::LinkState::Associated ||
                self->nativePairwiseKeyRevoked_ ||
                (!self->controlledPortAuthorized_ &&
                 !(isEapol && nativeHandshake)))
            {
                return kIOReturnNotReady;
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
            simpleath::ieee80211::EngineResult prepared =
                simpleath::ieee80211::EngineResult::CryptoUnavailable;
            bool softwareProtected = false;
            if (isEapol && nativeHandshake)
            {
                const simpleath::ieee80211::LinkContext connection {
                    link.station,
                    link.bssid,
                    simpleath::ieee80211::LinkSecurity::Wpa2Ccmp,
                    true,
                    self->radioOperational_,
                    self->channelAuthorized_,
                    keysReady,
                };
                simpleath::ieee80211::SerializedData serialized {};
                const auto clear = simpleath::ieee80211::prepareStationTx(
                    connection, packet.bytes, packet.length, self->txSequence_,
                    &self->ethernetTx_[0], sizeof(self->ethernetTx_),
                    serialized);
                if (clear == simpleath::ieee80211::DataPathResult::Ok &&
                    serialized.isEapol)
                {
                    action.kind =
                        simpleath::ieee80211::ActionKind::TransmitEapol;
                    action.bytes = serialized.frameBytes;
                    prepared = simpleath::ieee80211::EngineResult::Ok;
                }
            }
            if (prepared != simpleath::ieee80211::EngineResult::Ok &&
                protectedWpa2)
            {
                const simpleath::ieee80211::LinkContext connection {
                    link.station,
                    link.bssid,
                    simpleath::ieee80211::LinkSecurity::Wpa2Ccmp,
                    true,
                    self->radioOperational_,
                    self->channelAuthorized_,
                    keysReady,
                };
                simpleath::ieee80211::SerializedData serialized {};
                const auto encrypted =
                    simpleath::ieee80211::prepareProtectedStationTx(
                        connection, packet.bytes, packet.length,
                        self->txSequence_, self->nativePairwiseTx_,
                        self->epoch_, &self->protectedScratch_[0],
                        sizeof(self->protectedScratch_), &self->ethernetTx_[0],
                        sizeof(self->ethernetTx_), serialized);
                if (encrypted == simpleath::ieee80211::DataPathResult::Ok)
                {
                    action.kind =
                        serialized.isEapol
                            ? simpleath::ieee80211::ActionKind::TransmitEapol
                            : simpleath::ieee80211::ActionKind::TransmitData;
                    action.bytes = serialized.frameBytes;
                    prepared = simpleath::ieee80211::EngineResult::Ok;
                    softwareProtected = true;
                }
                else if (encrypted ==
                         simpleath::ieee80211::DataPathResult::BufferTooSmall)
                {
                    prepared =
                        simpleath::ieee80211::EngineResult::BufferTooSmall;
                }
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
            NativeTransmitRequest request {bytes, length};
            return self.gate_->runAction(ownerTransmitEthernetAction, &request);
        }

        static IOReturn ownerSubscribe(
            void *context, void *observer,
            void (*notify)(void *, simpleath::tahoe::WirelessEvent, uint64_t),
            void (*receive)(void *, const uint8_t *, size_t))
        {
            if (!context || !observer || !notify || !receive)
                return kIOReturnBadArgument;
            auto &self = *static_cast<SimpleATH *>(context);
            if (!self.observerLock_ || !self.gate_)
                return kIOReturnNotReady;
            simpleath::tahoe::WirelessSnapshot snapshot {};
            const IOReturn result = ownerSnapshot(context, &snapshot);
            if (result != kIOReturnSuccess)
                return result;
            IOLockLock(self.observerLock_);
            IOReturn registered = kIOReturnExclusiveAccess;
            if (!self.wirelessObserver_)
            {
                self.wirelessObserver_ = observer;
                self.wirelessNotify_ = notify;
                self.wirelessReceive_ = receive;
                registered = kIOReturnSuccess;
            }
            IOLockUnlock(self.observerLock_);
            return registered;
        }

        static void ownerUnsubscribe(void *context, void *observer)
        {
            if (!context || !observer)
                return;
            auto &self = *static_cast<SimpleATH *>(context);
            if (!self.observerLock_)
                return;
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
                    epoch_);
            }
            IOLockUnlock(observerLock_);
        }

        static bool poweredGate(void *context)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return self.loop_ && self.loop_->inGate() && self.powered_ &&
                   !self.stopping_ && self.pci_ && !self.pci_->isInactive();
        }

        static uint64_t nowMicros(void *)
        {
            uint64_t absolute = 0;
            uint64_t nanos = 0;
            clock_get_uptime(&absolute);
            absolutetime_to_nanoseconds(absolute, &nanos);
            return nanos / 1000;
        }

        static void delayMicros(void *, uint32_t micros)
        {
            // Round the deadline up; a short delay cannot count as a reset
            // pulse.
            const uint64_t end = nowMicros(nullptr) + micros + 1;
            do
            {
                IODelay(micros ? micros : 1);
            }
            while (nowMicros(nullptr) < end);
        }

        static bool nvmOwner(void *context)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return poweredGate(context) && self.epoch_ != 0 &&
                   self.session_.status().readAccessReady &&
                   self.backend_.activeRegisters().read32;
        }

        static bool canReset(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && self.enginesQuiesced_ &&
                   nvmOwner(context);
        }

        static bool keyCachePermit(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            // Key RAM is mutable only with exclusive PCI ownership and all
            // descriptor engines and automatic MAC responses quiesced.
            return canReset(context, epoch) && !self.queuesAdopted_ &&
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
                rfKillPinConfigured_, rfKillGpio_, rfKillActiveHigh_};
            const simpleath::RfKillReadBackend backend {
                &access_,
                epoch_,
                backend_.activeRegisters().barLengthBytes,
                rfKillRuntimePermit,
                readRegister,
                delayMicros};
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
            return bus.read32 && bus.read32(bus.context, offset, value);
        }

        static bool writeRegister(void *context, uint32_t offset,
                                  uint32_t value)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            const auto bus = self.backend_.activeRegisters();
            return bus.write32 && bus.write32(bus.context, offset, value);
        }

        static bool currentQueueOwner(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return epoch == self.epoch_ && nvmOwner(context);
        }

        static bool queueRadioReady(void *context, uint64_t epoch)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            // EDMA start and each descriptor submission must recheck the
            // physical switch, not just an earlier boot-time radio flag.
            return currentQueueOwner(context, epoch) &&
                   self.radioOperational_ && self.channelAuthorized_ &&
                   self.liveRfKillUnblocked();
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
                wirelessReceive_(wirelessObserver_, &ethernetRx_[0],
                                 ethernetBytes);
            }
            IOLockUnlock(observerLock_);
        }

        void receiveNativeProtected(const uint8_t *frame, size_t bytes,
                                    const simpleath::edma::RxStatus &status)
        {
            // Do not guess a key from a 802.11 header before validating the
            // hardware status, FCS span, association and CCMP IV bounds.
            // The selected session then authenticates the MIC and replay PN.
            const auto link = engine_.linkStatus();
            if (frame == nullptr || bytes < kFcsBytes ||
                bytes > simpleath::ieee80211::crypto::kCcmpMaximumMpduBytes ||
                !status.frameValid || status.crcError || status.decryptError ||
                status.phyError || status.micError || status.keyMiss ||
                !powered_ || !radioOperational_ || !channelAuthorized_ ||
                queues_.phase() != simpleath::NativeQueuePhase::Running ||
                queues_.epoch() != epoch_ ||
                link.state != simpleath::ieee80211::LinkState::Associated ||
                !engine_.osSupplicantOwnsWpa2() ||
                !nativePairwiseTx_.installed() ||
                !nativePairwiseRx_.installed() || !nativeGroupInstalled())
            {
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
            // A group MPDU may only select a currently installed GTK slot;
            // unicast must always use the pairwise key 0. The portable CCMP
            // bridge independently verifies the authenticated key ID.
            // Bound is checked above against complete ExtIV/MIC spans.
            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            const auto wireKeyByte =
                frame[header.headerLength + kCcmpKeyIdOffset];
            // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            const auto keyId =
                static_cast<uint8_t>(wireKeyByte >> kCcmpKeyIdShift);
            const bool group = (header.destination.bytes[0] & 1U) != 0U;
            if ((group &&
                 (keyId == 0U || keyId >= simpleath::kCcmpGroupSlots)) ||
                (!group && keyId != 0U))
            {
                return;
            }
            auto *receive = &nativePairwiseRx_;
            if (group)
            {
                size_t currentId = 0;
                for (auto &slot : nativeGroupRx_)
                {
                    if (currentId == keyId)
                    {
                        receive = &slot;
                        break;
                    }
                    ++currentId;
                }
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
            const auto result = simpleath::ieee80211::inspectProtectedStationRx(
                connection, frame, bytes, true, true, *receive, epoch_,
                &protectedRxScratch_[0], sizeof(protectedRxScratch_), msdu);
            setProperty("SimpleATHLastProtectedReceiveResult",
                        static_cast<uint32_t>(result), kRfPropertyWidthBits);
            // Protected post-install Group1 EAPOL can reach the OS-owned
            // supplicant before the data port opens. Ordinary IP/ARP remains
            // blocked until the OS explicitly authorizes the controlled port.
            if (result == simpleath::ieee80211::DataPathResult::Ok)
            {
                deliverNativeMsdu(msdu, true);
            }
            // Scrub even malformed/authentication-failed partial plaintext.
            // Keep the borrowed Msdu strictly within this synchronous scope.
            volatile uint8_t *const clear = &protectedRxScratch_[0];
            for (size_t i = 0; i < sizeof(protectedRxScratch_); ++i)
            {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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

        static void queueReceived(void *context, const uint8_t *frame,
                                  size_t bytes,
                                  const simpleath::edma::RxStatus &status)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            if (!self.radioOperational_ || !self.powered_ ||
                !self.liveRfKillUnblocked())
                return;
            // An OS-installed TK has a single security owner: data RX must
            // use the matching native CCMP session, not the portable engine's
            // cleartext M1/M3 supplicant. Management frames may still feed the
            // scan/association state machine without granting data readiness.
            if (self.engine_.osSupplicantOwnsWpa2() &&
                (self.nativePairwiseTx_.installed() ||
                 self.nativePairwiseRx_.installed() ||
                 self.nativeGroupInstalled()))
            {
                simpleath::ieee80211::Frame header {};
                if (frame == nullptr || bytes < kFcsBytes ||
                    simpleath::ieee80211::parseFrame(frame, bytes - kFcsBytes,
                                                     header) !=
                        simpleath::ieee80211::Result::Ok)
                {
                    return;
                }
                if (header.type == simpleath::ieee80211::FrameType::Data)
                {
                    self.receiveNativeProtected(frame, bytes, status);
                    return;
                }
                if (header.type != simpleath::ieee80211::FrameType::Management)
                {
                    return;
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
                    return;
                }
                if (header.type == simpleath::ieee80211::FrameType::Data)
                {
                    self.receiveNativePreKeyEapol(frame, bytes, status);
                    return;
                }
            }
            simpleath::ieee80211::InputTrust trust {};
            trust.radioReady = true;
            trust.channelAuthorized = self.channelAuthorized_;
            trust.dmaAndFcsVerified = status.frameValid && !status.crcError;
            trust.rxFrameIncludesFcs = true;
            // The security owner supplies replay verification before protected
            // data can enter the controlled port; clear scan/management frames
            // do not require a key or a fabricated CCMP attestation.
            simpleath::ieee80211::EngineAction action {};
            const auto result = self.engine_.acceptRx(
                frame, bytes, trust,
                {status.combinedRssi, nowMicros(nullptr) / 1000},
                self.managementReply_, sizeof(self.managementReply_), action);
            self.setProperty("SimpleATHLastReceiveResult",
                             static_cast<uint32_t>(result), 32);
            ++self.receivedFrames_;
            self.setProperty("SimpleATHReceivedFrames", self.receivedFrames_,
                             64);
            // Authentication/association and the WPA2 M2/M4 replies are
            // already serialized by WifiEngine. They need the same verified
            // RF/rate/power authorization as Ethernet data, but do not need
            // the controlled port to be open before association/handshake.
            if (result == simpleath::ieee80211::EngineResult::Ok &&
                (action.kind ==
                     simpleath::ieee80211::ActionKind::TransmitAssociation ||
                 action.kind ==
                     simpleath::ieee80211::ActionKind::TransmitEapol) &&
                action.bytes >= kMinimumMpduBytes &&
                action.bytes <= sizeof(self.managementReply_))
            {
                const IOReturn submitted = self.submitPreparedTransmit(
                    &self.managementReply_[0], action.bytes);
                self.setProperty("SimpleATHManagementTransmitResult",
                                 static_cast<uint32_t>(submitted),
                                 kRfPropertyWidthBits);
                if (submitted != kIOReturnSuccess)
                {
                    // The engine has advanced to a prepared station or
                    // handshake state. A failed delivery must not leave that
                    // state logically connected without an on-air response.
                    self.controlledPortAuthorized_ = false;
                    self.engine_.radioStopped(
                        nowMicros(nullptr) / kMicrosPerMillisecond, false);
                    self.notifyWirelessChange(false);
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
                return;
            }
            if (result == simpleath::ieee80211::EngineResult::Ok &&
                (action.kind ==
                     simpleath::ieee80211::ActionKind::AssociatedAwaitingKeys ||
                 action.kind == simpleath::ieee80211::ActionKind::
                                    OpenAssociationEstablished))
            {
                self.controlledPortAuthorized_ = false;
                self.notifyWirelessChange(false);
                return;
            }
            if (result == simpleath::ieee80211::EngineResult::Ok &&
                action.kind == simpleath::ieee80211::ActionKind::LinkLost)
            {
                // An AP disconnect revokes old key/PN ownership before any
                // native network client can receive or transmit another byte.
                self.controlledPortAuthorized_ = false;
                self.nativePairwiseTx_.revoke();
                self.nativePairwiseRx_.revoke();
                for (auto &group : self.nativeGroupRx_)
                {
                    group.revoke();
                }
                self.nativePairwiseKeyRevoked_ = true;
                self.nativeGroupKeyRevokedMask_ = kAllGroupKeySlotsRevoked;
                self.notifyWirelessChange(false);
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
            simpleath::ieee80211::Msdu msdu {};
            if (simpleath::ieee80211::decodeLlcData(
                    frame, bytes, trust.rxFrameIncludesFcs,
                    trust.ccmpMicAndReplayVerified,
                    msdu) != simpleath::ieee80211::Result::Ok ||
                msdu.payload != action.receivedPayload ||
                msdu.payloadLength != action.receivedPayloadBytes ||
                msdu.etherType != action.etherType)
            {
                return;
            }
            self.deliverNativeMsdu(msdu, false);
        }

        static void
        queueTransmitted(void *context, uint64_t,
                         const simpleath::edma::TxCompletion &status)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            ++self.transmitCompletions_;
            self.setProperty("SimpleATHTransmitCompletions",
                             self.transmitCompletions_, 64);
            self.setProperty("SimpleATHLastTransmitSucceeded",
                             status.frameTransmitOk);
            // The EDMA owner already freed its TX slot before this callback.
            // The native OS may retry a failed frame; availability is not a
            // packet-success notification. Never cross into its work loop.
            if (self.observerLock_ != nullptr)
            {
                IOLockLock(self.observerLock_);
                if (self.wirelessObserver_ != nullptr &&
                    self.wirelessNotify_ != nullptr && self.epoch_ != 0)
                {
                    self.wirelessNotify_(
                        self.wirelessObserver_,
                        simpleath::tahoe::WirelessEvent::TransmitAvailable,
                        self.epoch_);
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
            self.radioOperational_ = false;
            self.channelAuthorized_ = false;
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
            self.nativePairwiseRx_.revoke();
            for (auto &group : self.nativeGroupRx_)
            {
                group.revoke();
            }
            self.nativePairwiseKeyRevoked_ = true;
            self.nativeGroupKeyRevokedMask_ = kAllGroupKeySlotsRevoked;
            memset(&self.protectedRxScratch_[0], 0,
                   sizeof(self.protectedRxScratch_));
            self.engine_.radioStopped(
                nowMicros(nullptr) / kMicrosPerMillisecond, false);
            self.notifyWirelessChange(false);
            self.error("DMAInterrupt", static_cast<uint32_t>(result));
        }

        static void queueInterrupt(OSObject *owner, IOInterruptEventSource *,
                                   int)
        {
            auto &self = *static_cast<SimpleATH *>(owner);
            if (self.queuesAdopted_)
                self.queues_.serviceInterruptGated();
        }

        IOReturn startClient()
        {
            if (!lifecycle_ || !gate_)
                return kIOReturnNotReady;
            IOLockLock(lifecycle_);
            IOReturn result = gate_->runAction(startAction);
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
                    session_.status().barLengthBytes};
                result = queues_.prepareClient(this, pci_, loop_, preparedEpoch,
                                               callbacks, queueInterrupt);
                if (result == kIOReturnSuccess)
                    result = gate_->runAction(adoptQueuesAction);
                if (result != kIOReturnSuccess)
                {
                    queues_.releaseClient();
                    gate_->runAction(failedQueueStartAction);
                }
            }
            IOLockUnlock(lifecycle_);
            return result;
        }

        void releaseQueuesClient()
        {
            if (!lifecycle_)
                return;
            IOLockLock(lifecycle_);
            const IOReturn result = queues_.releaseClient();
            if (result != kIOReturnSuccess)
                IOLog("SimpleATH: queue mappings quarantined (0x%x)\n", result);
            IOLockUnlock(lifecycle_);
        }

        static IOReturn adoptQueuesAction(OSObject *owner, void *, void *,
                                          void *, void *)
        {
            auto &self = *static_cast<SimpleATH *>(owner);
            const IOReturn result = self.queues_.adoptGated(self.epoch_);
            if (result == kIOReturnSuccess)
            {
                self.queuesAdopted_ = true;
                self.setProperty("SimpleATHDmaMappingsReady", true);
                self.stage("DMAResourcesPrepared");
                // A new NVM/PCI epoch is observable as a radio transition,
                // but DMA mappings alone never make the receiver available.
                self.notifyWirelessChange(false);
            }
            return result;
        }

        static IOReturn failedQueueStartAction(OSObject *owner, void *, void *,
                                               void *, void *)
        {
            auto &self = *static_cast<SimpleATH *>(owner);
            self.error("DMAPreparation", kIOReturnNoResources);
            self.stopHardware(simpleath::ProviderAccess::Available);
            return kIOReturnSuccess;
        }

        bool quiesceEngines()
        {
            enginesQuiesced_ = false;
            const auto bus = backend_.activeRegisters();
            const simpleath::RegisterBus active {
                &access_, readRegister, writeRegister, bus.barLengthBytes};
            const auto result =
                simpleath::quiesceAr9565Mac(active, delayMicros);
            setProperty("SimpleATHMacStopResult", static_cast<uint32_t>(result),
                        32);
            enginesQuiesced_ = result == simpleath::MacStopResult::Ok;
            return enginesQuiesced_;
        }

        void stage(const char *name)
        {
            setProperty("SimpleATHStartupStage", name);
            IOLog("SimpleATH: %s\n", name);
        }

        IOReturn error(const char *name, uint32_t detail)
        {
            setProperty("SimpleATHFailureStage", name);
            setProperty("SimpleATHFailureCode", detail, 32);
            setProperty("SimpleATHDriverReady", false);
            IOLog("SimpleATH: %s failed (0x%x)\n", name, detail);
            return kIOReturnIOError;
        }

        IOReturn startHardware()
        {
            if (powered_ && board_.view(epoch_))
                return kIOReturnSuccess;
            if (stopping_ || epoch_ == UINT64_MAX)
                return kIOReturnNotReady;
            powered_ = true;
            ++epoch_;
            stage("PCIClaimAndMap");
            const auto pciResult = session_.start(backend_.callbacks());
            if (pciResult != simpleath::PciSessionResult::Ok)
                return abortStart("PCIClaimAndMap",
                                  static_cast<uint32_t>(pciResult));
            // Use the identity already obtained from live configuration by
            // the exclusive session, not IORegistry matching properties.
            identity_ = session_.hardwareStatus().pci;
            setProperty("SimpleATHVendorID", identity_.vendorId, 32);
            setProperty("SimpleATHDeviceID", identity_.deviceId, 32);
            setProperty("SimpleATHPciExclusiveOwner", true);
            setProperty("SimpleATHMmioTransportReady", true);
            stage("PhysicalSilicon");
            uint32_t rawRevision = 0;
            simpleath::Silicon silicon {};
            if (!readRegister(&access_, simpleath::kRevisionRegister,
                              &rawRevision))
                return abortStart("PhysicalSilicon", kIOReturnIOError);
            const auto decoded =
                simpleath::decodeRevision(rawRevision, silicon);
            if (decoded != simpleath::Result::Ok)
                return abortStart("PhysicalSilicon",
                                  static_cast<uint32_t>(decoded));
            stage("QuiesceMAC");
            if (!quiesceEngines())
                return abortStart("QuiesceMAC", kIOReturnTimeout);
            const auto bus = backend_.activeRegisters();
            const simpleath::RtcPowerBackend reset {
                &access_,
                reinterpret_cast<uintptr_t>(pci_),
                epoch_,
                canReset,
                readRegister,
                writeRegister,
                nowMicros,
                delayMicros,
                bus.barLengthBytes,
                false,
                nullptr,
                nullptr};
            simpleath::RtcPowerStatus resetStatus {};
            stage("RTCBootstrap");
            const auto rtcResult = simpleath::transitionAr9565Rtc(
                reset, identity_, simpleath::RtcOperation::BootstrapPowerOn,
                rtc_, resetStatus);
            if (rtcResult != simpleath::RtcResult::Ok)
                return abortStart("RTCBootstrap",
                                  static_cast<uint32_t>(rtcResult));
            if (!quiesceEngines())
                return abortStart("PostResetQuiesce", kIOReturnTimeout);
            // The old inspection-only path rejects EEPROM-absent functions,
            // including valid OTP-backed boards. Let actual NVM discovery
            // choose EEPROM or OTP instead of using that diagnostic as a
            // startup gate.
            setProperty("SimpleATHSREV", resetStatus.silicon.rawSrev, 32);
            const simpleath::NvmReadBackend reader {
                &access_,  nvmOwner,    readRegister,
                nowMicros, delayMicros, bus.barLengthBytes};
            simpleath::NvmDiscoveryStatus discovery {};
            stage("EEPROMDiscovery");
            const auto acquired = board_.acquire(
                reader, identity_, epoch_, storage_, kNvmStorageBytes, scratch_,
                simpleath::kAr9565EepromScratchBytes, discovery);
            if (acquired != simpleath::NvmDiscoveryResult::Ok)
            {
                setProperty("SimpleATHNvmCaptureResult",
                            static_cast<uint32_t>(discovery.lastCapture.result),
                            32);
                setProperty("SimpleATHNvmRestoreResult",
                            static_cast<uint32_t>(discovery.lastRestore.result),
                            32);
                return abortStart("EEPROMDiscovery",
                                  static_cast<uint32_t>(acquired));
            }
            const auto *board = board_.view(epoch_);
            if (!board)
                return abortStart("EEPROMLease", kIOReturnNotReady);
            setProperty("SimpleATHEepromValidated", true);
            auto *mac = OSData::withBytes(board->summary.mac,
                                          simpleath::kPermanentMacBytes);
            if (!mac)
                return abortStart("MACPublication", kIOReturnNoMemory);
            setProperty("SimpleATHPermanentMAC", mac);
            mac->release();
            setProperty("SimpleATHNvmOrigin", board->origin, 32);
            // The Atheros key RAM may contain stale keys from earlier OS or
            // firmware ownership. Before any protected path is permitted,
            // clear all 128 slots under the same live PCI epoch and gate.
            // Neither this stage nor an installed key is evidence of a
            // verified CCMP replay/PN engine or functional WPA2 data path.
            stage("CCMPKeyCacheScrub");
            const auto cacheResult = simpleath::initializeAr9565KeyCache(
                keyCacheBackend(), keyCache_);
            setProperty("SimpleATHKeyCacheInitResult",
                        static_cast<uint32_t>(cacheResult.result), 32);
            if (cacheResult.result != simpleath::KeyCacheResult::Ok)
                return abortStart("CCMPKeyCacheScrub",
                                  static_cast<uint32_t>(cacheResult.result));
            setProperty("SimpleATHKeyCacheInitialized", true);
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
            controlledPortAuthorized_ = false;
            // Revoke any old RF/TPC permission before stopping the queue, so
            // suspend/reset cannot reuse a former channel's transmit policy.
            txSafety_ = {};
            txRate_ = {};
            txSequence_ = 0;
            memset(&ethernetTx_[0], 0, sizeof(ethernetTx_));
            memset(&protectedScratch_[0], 0, sizeof(protectedScratch_));
            memset(&protectedRxScratch_[0], 0, sizeof(protectedRxScratch_));
            nativePairwiseTx_.revoke();
            nativePairwiseRx_.revoke();
            for (auto &group : nativeGroupRx_)
                group.revoke();
            nativePairwiseKeyRevoked_ = false;
            nativeGroupKeyRevokedMask_ = 0;
            if (queuesAdopted_)
            {
                queues_.stopGated(access ==
                                  simpleath::ProviderAccess::Available);
                queuesAdopted_ = false;
            }
            radioOperational_ = false;
            channelAuthorized_ = false;
            engine_.radioStopped(nowMicros(nullptr) / 1000, true);
            if (keyCache_.initialized)
            {
                bool wiped = false;
                if (access == simpleath::ProviderAccess::Available &&
                    quiesceEngines())
                {
                    const auto erasure = simpleath::eraseAr9565Keys(
                        keyCacheBackend(), keyCache_);
                    setProperty("SimpleATHKeyCacheEraseResult",
                                static_cast<uint32_t>(erasure.result), 32);
                    wiped = erasure.result == simpleath::KeyCacheResult::Ok;
                }
                setProperty("SimpleATHKeyCacheWipeConfirmed", wiped);
            }
            setProperty("SimpleATHKeyCacheResetRequired",
                        keyCache_.requiresReset);
            keyCache_ = {};
            setProperty("SimpleATHKeyCacheInitialized", false);
            board_.invalidate();
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

        static IOReturn startAction(OSObject *owner, void *, void *, void *,
                                    void *)
        {
            return static_cast<SimpleATH *>(owner)->startHardware();
        }

        static IOReturn sleepAction(OSObject *owner, void *, void *, void *,
                                    void *)
        {
            auto &self = *static_cast<SimpleATH *>(owner);
            self.stopHardware(simpleath::ProviderAccess::Available);
            self.stage("Suspended");
            return kIOReturnSuccess;
        }

        static IOReturn stopAction(OSObject *owner, void *, void *, void *,
                                   void *)
        {
            auto &self = *static_cast<SimpleATH *>(owner);
            self.stopHardware(simpleath::ProviderAccess::Available);
            self.stopping_ = true;
            self.stage("Stopped");
            return kIOReturnSuccess;
        }

        static IOReturn terminateAction(OSObject *owner, void *, void *, void *,
                                        void *)
        {
            auto &self = *static_cast<SimpleATH *>(owner);
            self.stopping_ = true;
            self.stopHardware(simpleath::ProviderAccess::Unavailable);
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
            backend_.clear();
            if (lifecycle_)
            {
                IOLockFree(lifecycle_);
                lifecycle_ = nullptr;
            }
            if (gate_)
            {
                if (gateAttached_)
                    loop_->removeEventSource(gate_);
                gate_->release();
                gate_ = nullptr;
                gateAttached_ = false;
            }
            if (loop_)
            {
                loop_->release();
                loop_ = nullptr;
            }
            if (storage_)
            {
                bzero(storage_, kNvmStorageBytes);
                IOFree(storage_, kNvmStorageBytes);
                storage_ = nullptr;
            }
            if (scratch_)
            {
                bzero(scratch_, simpleath::kAr9565EepromScratchBytes);
                IOFree(scratch_, simpleath::kAr9565EepromScratchBytes);
                scratch_ = nullptr;
            }
            pci_ = nullptr;
            started_ = false;
        }

        RegisterAccess access_ {nullptr};
        IOLock *lifecycle_ {nullptr};
        // Independent of the PCI gate to permit synchronous unsubscribe
        // after stop() removes its work loop.
        IOLock *observerLock_ {nullptr};
        void *wirelessObserver_ {nullptr};
        void (*wirelessNotify_)(void *, simpleath::tahoe::WirelessEvent,
                                uint64_t) {nullptr};
        void (*wirelessReceive_)(void *, const uint8_t *, size_t) {nullptr};
        bool controlledPortAuthorized_ {false};
        simpleath::NativeQueues queues_;
        simpleath::ieee80211::WifiEngine engine_;
        uint8_t managementReply_[4096] {};
        uint8_t ethernetRx_[kNativeEthernetCapacity] {};
        uint8_t ethernetTx_[kNativeTxMpduCapacity] {};
        uint8_t protectedScratch_[kNativeTxMpduCapacity] {};
        uint8_t protectedRxScratch_
            [simpleath::ieee80211::crypto::kCcmpMaximumMpduBytes] {};
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
        uint64_t receivedFrames_ {0};
        uint64_t transmitCompletions_ {0};
        bool queuesAdopted_ {false};
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

OSDefineMetaClassAndStructors(SimpleATH, IOService)

    extern "C" kern_return_t SimpleATH_kern_start(kmod_info_t *, void *)
{
    int ignored = 0;
    gSimpleATHEnabled =
        PE_parse_boot_argn("-simpleathoff", &ignored, sizeof(ignored)) == 0;
    return KERN_SUCCESS;
}

extern "C" kern_return_t SimpleATH_kern_stop(kmod_info_t *, void *)
{
    return KERN_SUCCESS;
}
