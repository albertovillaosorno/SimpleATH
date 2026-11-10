// SPDX-License-Identifier: AGPL-3.0-only
// Native AR9565 PCI owner: power, BAR access, RTC reset and board acquisition.
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
#include "wifi/WifiEngine.hpp"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <kern/clock.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/libkern.h>
#include <mach/kmod.h>
#include <pexpert/pexpert.h>

class SimpleATH;

namespace
{
    struct RegisterAccess
    {
            SimpleATH *owner;
    };

    bool gSimpleATHEnabled = true;
    constexpr size_t kNvmStorageBytes = 4096;
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
            // Never convert a software association into an OS link claim.
            out.associated =
                self.radioOperational_ &&
                link.state == simpleath::ieee80211::LinkState::Associated &&
                link.networkInterfaceReady;
            if (out.associated)
                memcpy(out.bssid, link.bssid.bytes, sizeof(out.bssid));
            out.powered = self.powered_;
            out.radioAvailable =
                self.radioOperational_ && self.channelAuthorized_ &&
                self.queues_.phase() == simpleath::NativeQueuePhase::Running;
            out.controlledPortOpen =
                out.associated && self.controlledPortAuthorized_;
            // No country code or current channel is published until the
            // physical/regulatory owner has actually authorized one.
            out.rfKillBlocked = !self.rfKillKnownUnblocked_;
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

        static IOReturn
        ownerConnect(void *,
                     const simpleath::tahoe::NativeConnectRequest *request)
        {
            return request ? kIOReturnNotReady : kIOReturnBadArgument;
        }

        static IOReturn ownerDisconnect(void *, uint16_t)
        {
            // A disassociation cannot be acknowledged before the native
            // station and protected management TX paths have completed.
            return kIOReturnNotReady;
        }

        static IOReturn
        ownerInstallKey(void *, const simpleath::tahoe::NativeCcmpKey *key)
        {
            return key ? kIOReturnNotReady : kIOReturnBadArgument;
        }

        static IOReturn ownerAuthorizePort(void *, bool)
        {
            // No DMA/CCMP replay proof or delivered native packet pool yet.
            return kIOReturnNotReady;
        }

        static IOReturn ownerTransmitEthernet(void *, const uint8_t *bytes,
                                              size_t length)
        {
            if (!bytes || length == 0)
                return kIOReturnBadArgument;
            return kIOReturnNotReady;
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
            return currentQueueOwner(context, epoch) && self.radioOperational_;
        }

        static bool queueBusMaster(void *context, bool enabled)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            return self.backend_.setBusMasterGated(enabled);
        }

        static void queueReceived(void *context, const uint8_t *frame,
                                  size_t bytes,
                                  const simpleath::edma::RxStatus &status)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            if (!self.radioOperational_ || !self.powered_)
                return;
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
        }

        static void queueFault(void *context, IOReturn result)
        {
            auto &self = *static_cast<RegisterAccess *>(context)->owner;
            // Stop device DMA before the owner revokes radio readiness. A
            // masked host interrupt alone cannot transfer ring ownership.
            self.queues_.stopGated(!self.pci_->isInactive());
            self.queuesAdopted_ = false;
            self.radioOperational_ = false;
            self.engine_.radioStopped(nowMicros(nullptr) / 1000, false);
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
