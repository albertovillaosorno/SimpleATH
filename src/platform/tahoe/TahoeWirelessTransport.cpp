// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for tahoe wireless transport.
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
//   - Native driver contracts and implementation for tahoe wireless transport.
// - Description:
//   - Implements or verifies the TahoeWirelessTransport source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: tahoe wireless transport.

#include "TahoeWirelessTransport.hpp"
#include "platform/tahoe/NativeWirelessEpoch.hpp"
#include "platform/tahoe/NativeWirelessOwner.hpp"
#include "wifi/LegacyScanBridge.hpp"
#include <IOKit/IOLocks.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace simpleath
{
    namespace tahoe
    {
        namespace
        {
            constexpr size_t kMinEthernetFrame = 14;
            constexpr size_t kEtherTypeOffset = 12;
            constexpr uint8_t kEapolEtherTypeHigh = 0x88U;
            constexpr uint8_t kEapolEtherTypeLow = 0x8eU;

            WirelessDataPortLease dataPortLease(const WirelessSnapshot &state)
            {
                return {state.associationGeneration,
                        state.radioAvailable,
                        state.powered,
                        state.rfKillBlocked,
                        state.associated,
                        state.controlledPortOpen,
                        state.associatedBeaconObserved};
            }

            bool isEapolEthernet(const uint8_t *bytes, size_t length)
            {
                if (bytes == nullptr || length < kMinEthernetFrame)
                {
                    return false;
                }
                // A complete bounded Ethernet-II header is required. The
                // provider, not this mailbox, authenticates the 802.11 frame.
                // NOLINTNEXTLINE(*bounds-pointer-arithmetic)
                const uint8_t high = bytes[kEtherTypeOffset];
                // NOLINTNEXTLINE(*bounds-pointer-arithmetic)
                const uint8_t low = bytes[kEtherTypeOffset + 1U];
                return high == kEapolEtherTypeHigh && low == kEapolEtherTypeLow;
            }

            constexpr uint8_t kMaxChannel2G = 14;
            constexpr uint32_t kCcmpPacketNumberBits = 48;

            bool validMac(const uint8_t address[kWirelessMacBytes])
            {
                if (address == nullptr)
                {
                    return false;
                }

                struct MacCopy
                {
                        uint8_t octets[kWirelessMacBytes];
                } copy {};

                memcpy(&copy, address, sizeof(copy));
                if ((copy.octets[0] & 1U) != 0U)
                {
                    return false;
                }
                uint8_t aggregate = 0;
                for (const uint8_t byte : copy.octets)
                {
                    aggregate |= byte;
                }
                return aggregate != 0;
            }

            bool validContract(const WirelessOwnerV7 &owner)
            {
                return owner.abiVersion == kWirelessOwnerAbi &&
                       owner.structureBytes >= sizeof(WirelessOwnerV7) &&
                       (owner.context != nullptr) &&
                       (owner.snapshot != nullptr) &&
                       (owner.setPower != nullptr) &&
                       (owner.setMac != nullptr) &&
                       (owner.beginScan != nullptr) &&
                       (owner.cancelScan != nullptr) &&
                       (owner.nextBss != nullptr) &&
                       (owner.connect != nullptr) &&
                       (owner.disconnect != nullptr) &&
                       (owner.installKey != nullptr) &&
                       (owner.authorizePort != nullptr) &&
                       (owner.transmitEthernet != nullptr) &&
                       (owner.subscribe != nullptr) &&
                       (owner.unsubscribe != nullptr) &&
                       (owner.retryScanCompletion != nullptr) &&
                       (owner.acknowledgeScanCompletion != nullptr);
            }

            // Disallow callers writing into the transport's own mailbox or
            // metadata. A large packet must never corrupt the queue indices.
            uintptr_t pointerAddress(const void *pointer)
            {
                uintptr_t address = 0;
                static_assert(sizeof(address) == sizeof(pointer),
                              "pointer address width");
                __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                                 sizeof(pointer));
                return address;
            }

            bool overlapsObject(const void *dest, size_t length,
                                const void *object, size_t objectLength)
            {
                const uintptr_t first = pointerAddress(dest);
                const uintptr_t second = pointerAddress(object);
                return first >= second ? first - second < objectLength
                                       : second - first < length;
            }

            bool validConnect(const NativeConnectRequest &request)
            {
                uint8_t pmkBits = 0;
                for (const uint8_t byte : request.pmk)
                {
                    pmkBits |= byte;
                }
                return request.epoch != 0 && request.requestId != 0 &&
                       (request.wpa2Personal || pmkBits == 0) &&
                       validMac(&request.bssid[0]) && request.ssidLength != 0 &&
                       request.ssidLength <= sizeof(request.ssid) &&
                       request.channel != 0 && request.channel <= kMaxChannel2G;
            }
        } // namespace

        TahoeWirelessTransport::~TahoeWirelessTransport()
        {
            unbind();
        }

        bool TahoeWirelessTransport::bound() const
        {
            if (!subscribed_ || (provider_ == nullptr) ||
                (owner_.context == nullptr) || (mailboxLock_ == nullptr))
            {
                return false;
            }
            IOLockLock(mailboxLock_);
            const bool valid = epoch_ != 0 && !providerStopped_;
            IOLockUnlock(mailboxLock_);
            return valid;
        }

        TahoeWirelessTransport::EventRecord *
        TahoeWirelessTransport::eventAt(size_t ordinal)
        {
            for (EventRecord &slot : events_)
            {
                if (ordinal == 0U)
                {
                    return &slot;
                }
                --ordinal;
            }
            return nullptr;
        }

        TahoeWirelessTransport::ReceiveRecord *
        TahoeWirelessTransport::receiveAt(size_t ordinal)
        {
            for (ReceiveRecord &slot : frames_)
            {
                if (ordinal == 0U)
                {
                    return &slot;
                }
                --ordinal;
            }
            return nullptr;
        }

        void TahoeWirelessTransport::invalidateMailboxes()
        {
            // Called under mailboxLock_, never while invoking an owner.
            receiveAuthorized_ = false;
            eapolReceiveAuthorized_ = false;
            eventHead_ = eventCount_ = 0;
            receiveHead_ = receiveCount_ = 0;
            scanGeneration_ = 0;
            previousScanGeneration_ = 0;
            associationGeneration_ = 0;
            memset(&events_[0], 0, sizeof(events_));
            memset(&frames_[0], 0, sizeof(frames_));
        }

        IOReturn TahoeWirelessTransport::bind(IOService *provider)
        {
            if ((provider == nullptr) || (provider_ != nullptr) ||
                (mailboxLock_ != nullptr))
            {
                return kIOReturnBadArgument;
            }
            IOLock *lock = IOLockAlloc();
            if (lock == nullptr)
            {
                return kIOReturnNoMemory;
            }
            WirelessOwnerV7 candidate {};
            candidate.abiVersion = kWirelessOwnerAbi;
            candidate.structureBytes = sizeof(candidate);
            const IOReturn lookup = provider->callPlatformFunction(
                &kWirelessOwnerFunction[0], false, &candidate, nullptr, nullptr,
                nullptr);
            if (lookup != kIOReturnSuccess || !validContract(candidate))
            {
                IOLockFree(lock);
                return lookup == kIOReturnSuccess ? kIOReturnUnsupported
                                                  : lookup;
            }
            WirelessSnapshot snapshotValue {};
            const IOReturn status =
                candidate.snapshot(candidate.context, &snapshotValue);
            if (status != kIOReturnSuccess || snapshotValue.epoch == 0)
            {
                IOLockFree(lock);
                return status == kIOReturnSuccess ? kIOReturnNotReady : status;
            }
            provider->retain();
            provider_ = provider;
            owner_ = candidate;
            mailboxLock_ = lock;
            epoch_ = snapshotValue.epoch;
            callbackRevision_ = 0;
            associationGeneration_ = snapshotValue.associated
                                         ? snapshotValue.associationGeneration
                                         : 0U;
            providerStopped_ = false;
            IOLockLock(lock);
            eapolReceiveAuthorized_ =
                snapshotValue.radioAvailable && snapshotValue.powered &&
                snapshotValue.associated && !snapshotValue.rfKillBlocked;
            receiveAuthorized_ =
                eapolReceiveAuthorized_ &&
                mayDeliverWirelessData(dataPortLease(snapshotValue));
            IOLockUnlock(lock);
            // A synchronous subscribe may invoke notify before returning;
            // the mailbox and initial owner epoch already exist.
            const IOReturn result =
                owner_.subscribe(owner_.context, this, notify, receive);
            if (result != kIOReturnSuccess)
            {
                // Subscription is atomic by owner contract: failure means
                // the owner did not retain these callback addresses.
                owner_ = {};
                provider_ = nullptr;
                mailboxLock_ = nullptr;
                epoch_ = 0;
                associationGeneration_ = 0;
                callbackRevision_ = 0;
                providerStopped_ = false;
                IOLockFree(lock);
                provider->release();
                return result;
            }
            subscribed_ = true;
            // A replacement/reset during subscription must not make old
            // mailbox data appear to belong to the new owner epoch.
            WirelessSnapshot after {};
            const IOReturn checked = this->snapshot(after);
            if (checked != kIOReturnSuccess)
            {
                unbind();
                return checked;
            }
            return kIOReturnSuccess;
        }

        void TahoeWirelessTransport::unbind()
        {
            if (provider_ == nullptr)
            {
                return;
            }
            if (mailboxLock_ != nullptr)
            {
                IOLockLock(mailboxLock_);
                epoch_ = 0;
                providerStopped_ = true;
                invalidateMailboxes();
                IOLockUnlock(mailboxLock_);
            }
            if (subscribed_)
            {
                owner_.unsubscribe(owner_.context, this);
            }
            subscribed_ = false;
            owner_ = {};
            IOService const *oldProvider = provider_;
            provider_ = nullptr;
            IOLock *oldLock = mailboxLock_;
            mailboxLock_ = nullptr;
            if (oldLock != nullptr)
            {
                IOLockFree(oldLock);
            }
            if (oldProvider != nullptr)
            {
                oldProvider->release();
            }
        }

        IOReturn TahoeWirelessTransport::snapshot(WirelessSnapshot &out)
        {
            out = {};
            if (!bound())
            {
                return kIOReturnNotReady;
            }
            // Snapshot's owner gate and mailbox lock cannot be held together.
            // An event between them invalidates this sampled state.
            IOLockLock(mailboxLock_);
            const uint64_t startingRevision = callbackRevision_;
            IOLockUnlock(mailboxLock_);
            WirelessSnapshot current {};
            const IOReturn result = owner_.snapshot(owner_.context, &current);
            if (result != kIOReturnSuccess || (current.epoch == 0U))
            {
                return result == kIOReturnSuccess ? kIOReturnNotReady : result;
            }
            IOLockLock(mailboxLock_);
            if (!acceptWirelessSnapshot(current.epoch, epoch_, startingRevision,
                                        callbackRevision_, providerStopped_))
            {
                IOLockUnlock(mailboxLock_);
                return kIOReturnNotReady;
            }
            const uint64_t currentAssociation =
                current.associated ? current.associationGeneration : 0U;
            if (current.epoch != epoch_)
            {
                // PCI replacement invalidates both events and scan tickets.
                invalidateMailboxes();
                epoch_ = current.epoch;
            }
            else if (currentAssociation != associationGeneration_)
            {
                // A new AP within the same PCI epoch retires *RX only*.
                // Keep the queued association events and scan results so
                // the native controller can observe the real transition.
                receiveHead_ = receiveCount_ = 0;
                memset(&frames_[0], 0, sizeof(frames_));
            }
            associationGeneration_ = currentAssociation;
            eapolReceiveAuthorized_ = current.radioAvailable &&
                                      current.powered && current.associated &&
                                      !current.rfKillBlocked;
            receiveAuthorized_ = eapolReceiveAuthorized_ &&
                                 mayDeliverWirelessData(dataPortLease(current));
            IOLockUnlock(mailboxLock_);
            out = current;
            return kIOReturnSuccess;
        }

        IOReturn TahoeWirelessTransport::setPower(bool on)
        {
            if (!bound())
            {
                return kIOReturnNotReady;
            }
            // Power-off invalidates the owner's board and makes snapshot()
            // return NotReady. Requiring an online RF snapshot *before*
            // invoking power-on would strand the device in that state.
            // Provider termination is still terminal; the physical owner
            // gates D0/reset and can reject a stale or unsupported request.
            IOLockLock(mailboxLock_);
            const bool stopped = providerStopped_;
            IOLockUnlock(mailboxLock_);
            if (stopped)
            {
                return kIOReturnNotReady;
            }
            const IOReturn result = owner_.setPower(owner_.context, on);
            if (result == kIOReturnSuccess && !on)
            {
                IOLockLock(mailboxLock_);
                invalidateMailboxes();
                IOLockUnlock(mailboxLock_);
            }
            return result;
        }

        IOReturn
        TahoeWirelessTransport::setMac(const uint8_t address[kWirelessMacBytes])
        {
            if ((address == nullptr) || !validMac(address))
            {
                return kIOReturnBadArgument;
            }
            if (!bound())
            {
                return kIOReturnNotReady;
            }
            return owner_.setMac(owner_.context, address);
        }

        IOReturn TahoeWirelessTransport::startScan(uint64_t &generation,
                                                   uint64_t &epoch)
        {
            generation = 0;
            epoch = 0;
            WirelessSnapshot state {};
            const IOReturn status = snapshot(state);
            if (status != kIOReturnSuccess)
            {
                return status;
            }
            if (!state.radioAvailable || !state.powered ||
                state.rfKillBlocked || state.scanning)
            {
                return kIOReturnNotReady;
            }
            NativeScanStartRequest accepted {state.epoch, 0, 0};
            const IOReturn result = owner_.beginScan(owner_.context, &accepted);
            if (result != kIOReturnSuccess)
            {
                return result;
            }
            IOLockLock(mailboxLock_);
            const bool stillCurrent = acceptWirelessScanStart(
                state.epoch, accepted.acceptedEpoch, accepted.generation,
                epoch_, providerStopped_);
            if (stillCurrent)
            {
                previousScanGeneration_ = scanGeneration_;
                scanGeneration_ = accepted.generation;
            }
            IOLockUnlock(mailboxLock_);
            if (!stillCurrent)
            {
                if (accepted.generation != 0U)
                {
                    (void)owner_.cancelScan(owner_.context,
                                            accepted.generation);
                }
                return kIOReturnNotReady;
            }
            generation = accepted.generation;
            epoch = accepted.acceptedEpoch;
            return kIOReturnSuccess;
        }

        IOReturn TahoeWirelessTransport::cancelScan(uint64_t generation)
        {
            if (!bound() || (generation == 0U))
            {
                return kIOReturnNotReady;
            }
            IOLockLock(mailboxLock_);
            const bool current = generation == scanGeneration_;
            IOLockUnlock(mailboxLock_);
            if (!current)
            {
                return kIOReturnNotReady;
            }
            const IOReturn result =
                owner_.cancelScan(owner_.context, generation);
            if (result == kIOReturnSuccess)
            {
                IOLockLock(mailboxLock_);
                // A provider callback may synchronously notify a reset or
                // supersede this ticket while cancelScan runs. Never erase
                // a newer scan's generation with an older cancellation.
                if (scanGeneration_ == generation)
                {
                    scanGeneration_ = 0;
                }
                IOLockUnlock(mailboxLock_);
            }
            return result;
        }

        IOReturn TahoeWirelessTransport::retryScanCompletion()
        {
            if (!bound())
            {
                return kIOReturnNotReady;
            }
            // This provider call enters only the PCI owner's gate. Its notify
            // callback takes the mailbox lock, never the native work loop.
            return owner_.retryScanCompletion(owner_.context);
        }

        IOReturn
        TahoeWirelessTransport::acknowledgeScanCompletion(uint64_t epoch,
                                                          uint64_t generation)
        {
            if (!bound() || epoch == 0U || generation == 0U)
            {
                return kIOReturnNotReady;
            }
            IOLockLock(mailboxLock_);
            const bool current = epoch == epoch_ && !providerStopped_;
            IOLockUnlock(mailboxLock_);
            return current ? owner_.acknowledgeScanCompletion(owner_.context,
                                                              epoch, generation)
                           : kIOReturnNotReady;
        }

        IOReturn
        TahoeWirelessTransport::nextBss(uint64_t generation,
                                        ieee80211::NativeBssSnapshot &out)
        {
            out = {};
            if (!bound() || (generation == 0U))
            {
                return kIOReturnNotReady;
            }
            IOLockLock(mailboxLock_);
            // The completed results from the preceding generation remain
            // enumerable while a new physical scan is in progress. The PCI
            // owner's ticket check still determines snapshot eligibility.
            const bool current = generation == scanGeneration_ ||
                                 generation == previousScanGeneration_;
            IOLockUnlock(mailboxLock_);
            return current ? owner_.nextBss(owner_.context, generation, &out)
                           : kIOReturnNotReady;
        }

        IOReturn
        TahoeWirelessTransport::connect(const NativeConnectRequest &request)
        {
            if (!validConnect(request))
            {
                return kIOReturnBadArgument;
            }
            WirelessSnapshot state {};
            const IOReturn status = snapshot(state);
            if (status != kIOReturnSuccess)
            {
                return status;
            }
            if (state.epoch != request.epoch || !state.powered ||
                !state.radioAvailable || state.rfKillBlocked || state.scanning)
            {
                return kIOReturnNotReady;
            }
            IOLockLock(mailboxLock_);
            receiveAuthorized_ = false;
            eapolReceiveAuthorized_ = false;
            associationGeneration_ = 0;
            receiveHead_ = receiveCount_ = 0;
            memset(&frames_[0], 0, sizeof(frames_));
            IOLockUnlock(mailboxLock_);
            // The physical provider receives a stable, short-lived copy even
            // if its gate waits. The PMK must not persist in this transport.
            NativeConnectRequest stable = request;
            const IOReturn result = owner_.connect(owner_.context, &stable);
            clearConnectRequest(stable);
            if (result != kIOReturnSuccess)
            {
                return result;
            }
            // A synchronous physical callback can reset the PCI owner or
            // replace the native join while the request is in flight. Never
            // begin a WCL join session for a superseded request. In
            // particular, do not disconnect the replacement session here.
            WirelessSnapshot observed {};
            const IOReturn refreshed = snapshot(observed);
            if (refreshed != kIOReturnSuccess)
            {
                return refreshed;
            }
            return acceptWirelessJoinCommit(request.epoch, request.requestId,
                                            observed.epoch,
                                            observed.joinRequestId) &&
                           observed.joinStatus == kIOReturnSuccess &&
                           observed.joinPhase != NativeJoinPhase::Failed
                       ? kIOReturnSuccess
                       : kIOReturnNotReady;
        }

        IOReturn TahoeWirelessTransport::disconnect(uint16_t reason)
        {
            if (!bound())
            {
                return kIOReturnNotReady;
            }
            IOLockLock(mailboxLock_);
            // No further EAPOL or ordinary data may escape the old station
            // lease once teardown is requested. The provider may notify the
            // end of association only after this native callback returns.
            receiveAuthorized_ = false;
            eapolReceiveAuthorized_ = false;
            associationGeneration_ = 0;
            receiveHead_ = receiveCount_ = 0;
            memset(&frames_[0], 0, sizeof(frames_));
            IOLockUnlock(mailboxLock_);
            return owner_.disconnect(owner_.context, reason);
        }

        IOReturn TahoeWirelessTransport::installKey(const NativeCcmpKey &key)
        {
            if (!bound() || key.keyId > 3 ||
                (key.pairwise && (key.keyId != 0 || !validMac(&key.peer[0]))) ||
                (!key.remove &&
                 key.receivePacketNumber >= (1ULL << kCcmpPacketNumberBits)))
            {
                return kIOReturnBadArgument;
            }
            // The caller's key storage is borrowed. Snapshot before a gate
            // transition that may block or synchronously call out, and scrub
            // the private secret immediately after the provider consumes it.
            NativeCcmpKey stable = key;
            const IOReturn result = owner_.installKey(owner_.context, &stable);
            for (volatile uint8_t &byte : stable.material)
            {
                byte = 0;
            }
            return result;
        }

        IOReturn TahoeWirelessTransport::authorizePort(bool open)
        {
            WirelessSnapshot state {};
            const IOReturn observed = snapshot(state);
            if (observed != kIOReturnSuccess)
            {
                return observed;
            }
            if (state.epoch == 0 || state.joinRequestId == 0 ||
                state.associationGeneration == 0 ||
                (open && (!state.associated || !state.powered ||
                          !state.radioAvailable || state.rfKillBlocked)))
            {
                return kIOReturnNotReady;
            }
            const NativePortRequest request {
                state.epoch,
                state.joinRequestId,
                state.associationGeneration,
                open,
            };
            // The PCI owner validates this exact identity on its own gate,
            // after any intervening reset, disconnection or next join.
            const IOReturn result =
                owner_.authorizePort(owner_.context, &request);
            if (result == kIOReturnSuccess && open)
            {
                WirelessSnapshot confirmed {};
                const IOReturn refreshed = snapshot(confirmed);
                const bool samePort =
                    refreshed == kIOReturnSuccess &&
                    acceptWirelessPortIdentity(
                        request.epoch, request.joinRequestId,
                        request.associationGeneration, confirmed.epoch,
                        confirmed.joinRequestId,
                        confirmed.associationGeneration);
                if (!samePort || !confirmed.controlledPortOpen)
                {
                    // A callback raced the confirmation. Roll back only the
                    // ORIGINAL association. Never close a successor's port
                    // after its own independent security authorization.
                    NativePortRequest revoke = request;
                    revoke.open = false;
                    (void)owner_.authorizePort(owner_.context, &revoke);
                    return refreshed == kIOReturnSuccess ? kIOReturnNotReady
                                                         : refreshed;
                }
            }
            if (result == kIOReturnSuccess && !open)
            {
                IOLockLock(mailboxLock_);
                receiveAuthorized_ = false;
                receiveHead_ = receiveCount_ = 0;
                memset(&frames_[0], 0, sizeof(frames_));
                IOLockUnlock(mailboxLock_);
            }
            return result;
        }

        IOReturn TahoeWirelessTransport::transmitEthernet(const uint8_t *bytes,
                                                          size_t length)
        {
            if ((bytes == nullptr) || length < kMinEthernetFrame ||
                length > kMaxEthernetFrame)
            {
                return kIOReturnBadArgument;
            }
            WirelessSnapshot state {};
            const IOReturn result = snapshot(state);
            if (result != kIOReturnSuccess)
            {
                return result;
            }
            if (!mayDeliverWirelessData(dataPortLease(state)))
            {
                return kIOReturnNotReady;
            }
            return owner_.transmitEthernet(owner_.context, bytes, length);
        }

        IOReturn TahoeWirelessTransport::notify(void *observer,
                                                WirelessEvent event,
                                                uint64_t epoch,
                                                uint64_t generation)
        {
            if (observer == nullptr)
            {
                return kIOReturnNotReady;
            }
            auto &self = *static_cast<TahoeWirelessTransport *>(observer);
            IOLock *lock = self.mailboxLock_;
            if (lock == nullptr)
            {
                return kIOReturnNotReady;
            }
            IOLockLock(lock);
            if ((epoch == 0U) || epoch < self.epoch_ || self.providerStopped_ ||
                event > WirelessEvent::ProviderStopped ||
                ((event == WirelessEvent::ScanFinished) != (generation != 0U)))
            {
                IOLockUnlock(lock);
                return kIOReturnNotReady;
            }
            if (self.callbackRevision_ == UINT64_MAX)
            {
                // Never wrap and accidentally validate an ancient snapshot.
                self.providerStopped_ = true;
                self.invalidateMailboxes();
                IOLockUnlock(lock);
                return kIOReturnNotReady;
            }
            ++self.callbackRevision_;
            if (epoch != self.epoch_)
            {
                // The same physical provider can resume on a fresh PCI
                // epoch. Clear stale scan/receive tickets and accept only
                // increasing epoch notifications, never an old DMA callback.
                self.invalidateMailboxes();
                self.epoch_ = epoch;
            }
            if (event == WirelessEvent::ProviderStopped ||
                event == WirelessEvent::LinkChanged ||
                event == WirelessEvent::AssociationChanged ||
                event == WirelessEvent::RadioChanged)
            {
                self.receiveAuthorized_ = false;
                self.eapolReceiveAuthorized_ = false;
                self.associationGeneration_ = 0;
                self.receiveCount_ = 0;
                self.receiveHead_ = 0;
                memset(&self.frames_[0], 0, sizeof(self.frames_));
            }
            if (event == WirelessEvent::ProviderStopped)
            {
                // All earlier notifications belong to a dead provider.
                // A saturated mailbox must still deliver its terminal event.
                self.providerStopped_ = true;
                self.epoch_ = 0;
                self.invalidateMailboxes();
            }
            if (event == WirelessEvent::ScanFinished &&
                self.eventCount_ == kEventCapacity &&
                (evictWirelessNoncriticalEvent(self.events_, self.eventHead_,
                                               self.eventCount_) ||
                 evictWirelessSupersededScanEvent(self.events_, self.eventHead_,
                                                  self.eventCount_, epoch,
                                                  generation)))
            {
                // Protect live completions against TX wakeups and old scan
                // generations even if every mailbox slot is terminal.
                --self.eventCount_;
                ++self.eventDrops_;
            }
            if (self.eventCount_ == kEventCapacity)
            {
                ++self.eventDrops_;
                IOLockUnlock(lock);
                return kIOReturnNoResources;
            }
            else
            {
                const size_t tail =
                    (self.eventHead_ + self.eventCount_) % kEventCapacity;
                EventRecord *slot = self.eventAt(tail);
                if (slot == nullptr)
                {
                    // Impossible for a valid modulo cursor; do not write an
                    // unchecked entry after corrupted mailbox bookkeeping.
                    self.invalidateMailboxes();
                    ++self.eventDrops_;
                    IOLockUnlock(lock);
                    return kIOReturnNotReady;
                }
                else
                {
                    *slot = {event, epoch, generation};
                    ++self.eventCount_;
                }
            }
            IOLockUnlock(lock);
            return kIOReturnSuccess;
        }

        void TahoeWirelessTransport::receive(void *observer, uint64_t epoch,
                                             uint64_t associationGeneration,
                                             const uint8_t *bytes,
                                             size_t length)
        {
            if (observer == nullptr)
            {
                return;
            }
            auto &self = *static_cast<TahoeWirelessTransport *>(observer);
            IOLock *lock = self.mailboxLock_;
            if (lock == nullptr)
            {
                return;
            }
            IOLockLock(lock);
            if ((bytes == nullptr) || length < kMinEthernetFrame ||
                length > kMaxEthernetFrame ||
                !acceptWirelessReceiveIdentity(
                    epoch, self.epoch_, associationGeneration,
                    self.associationGeneration_, self.providerStopped_) ||
                (!self.receiveAuthorized_ &&
                 !(self.eapolReceiveAuthorized_ &&
                   isEapolEthernet(bytes, length))) ||
                self.receiveCount_ == kRxCapacity)
            {
                ++self.receiveDrops_;
            }
            else
            {
                const size_t tail =
                    (self.receiveHead_ + self.receiveCount_) % kRxCapacity;
                ReceiveRecord *packet = self.receiveAt(tail);
                if (packet == nullptr)
                {
                    self.invalidateMailboxes();
                    ++self.receiveDrops_;
                }
                else
                {
                    packet->epoch = epoch;
                    packet->associationGeneration = associationGeneration;
                    packet->length = length;
                    memcpy(&packet->bytes[0], bytes, length);
                    ++self.receiveCount_;
                }
            }
            IOLockUnlock(lock);
        }

        IOReturn TahoeWirelessTransport::takeEvent(WirelessEvent &event,
                                                   uint64_t &epoch,
                                                   uint64_t &generation)
        {
            if (mailboxLock_ == nullptr)
            {
                return kIOReturnNotReady;
            }
            IOLockLock(mailboxLock_);
            if (eventCount_ == 0U)
            {
                IOLockUnlock(mailboxLock_);
                return kIOReturnNotFound;
            }
            EventRecord *slot = eventAt(eventHead_);
            if (slot == nullptr)
            {
                invalidateMailboxes();
                IOLockUnlock(mailboxLock_);
                return kIOReturnNotReady;
            }
            const EventRecord record = *slot;
            *slot = {};
            eventHead_ = (eventHead_ + 1) % kEventCapacity;
            --eventCount_;
            IOLockUnlock(mailboxLock_);
            event = record.event;
            epoch = record.epoch;
            generation = record.generation;
            return kIOReturnSuccess;
        }

        IOReturn TahoeWirelessTransport::takeEthernet(uint8_t *bytes,
                                                      size_t capacity,
                                                      size_t &length)
        {
            // A caller may not write a returned length into this object's
            // bookkeeping or use its internal receive storage as output.
            if (overlapsObject(&length, sizeof(length), this, sizeof(*this)) ||
                (bytes != nullptr &&
                 overlapsObject(bytes, capacity, &length, sizeof(length))))
            {
                // A caller must not alias the returned packet bytes with
                // its length output: zeroing or publishing length would
                // otherwise destroy the packet, possibly before the copy.
                return kIOReturnBadArgument;
            }
            length = 0;
            if ((bytes == nullptr) || (mailboxLock_ == nullptr) ||
                overlapsObject(bytes, capacity, this, sizeof(*this)))
            {
                return kIOReturnBadArgument;
            }
            IOLockLock(mailboxLock_);
            if ((receiveCount_ == 0U) || (epoch_ == 0U))
            {
                IOLockUnlock(mailboxLock_);
                return kIOReturnNotReady;
            }
            ReceiveRecord *slot = receiveAt(receiveHead_);
            if (slot == nullptr)
            {
                invalidateMailboxes();
                IOLockUnlock(mailboxLock_);
                return kIOReturnNotReady;
            }
            ReceiveRecord &packet = *slot;
            if (!acceptWirelessReceiveIdentity(
                    packet.epoch, epoch_, packet.associationGeneration,
                    associationGeneration_, providerStopped_))
            {
                memset(&packet, 0, sizeof(packet));
                receiveHead_ = (receiveHead_ + 1) % kRxCapacity;
                --receiveCount_;
                IOLockUnlock(mailboxLock_);
                return kIOReturnNotReady;
            }
            // Recheck the association/port policy at consumption as well as
            // callback ingress: a port revocation cannot release an earlier
            // queued IPv4 packet. WPA2 EAPOL remains eligible before data
            // authorization, but only from the verified native RX provider.
            if (!receiveAuthorized_ &&
                !(eapolReceiveAuthorized_ &&
                  isEapolEthernet(&packet.bytes[0], packet.length)))
            {
                memset(&packet, 0, sizeof(packet));
                receiveHead_ = (receiveHead_ + 1U) % kRxCapacity;
                --receiveCount_;
                IOLockUnlock(mailboxLock_);
                return kIOReturnNotReady;
            }
            if (capacity < packet.length)
            {
                IOLockUnlock(mailboxLock_);
                return kIOReturnNoSpace;
            }
            memcpy(bytes, &packet.bytes[0], packet.length);
            length = packet.length;
            memset(&packet, 0, sizeof(packet));
            receiveHead_ = (receiveHead_ + 1) % kRxCapacity;
            --receiveCount_;
            IOLockUnlock(mailboxLock_);
            return kIOReturnSuccess;
        }

        uint64_t TahoeWirelessTransport::droppedReceiveFrames() const
        {
            if (mailboxLock_ == nullptr)
            {
                return receiveDrops_;
            }
            IOLockLock(mailboxLock_);
            const uint64_t result = receiveDrops_;
            IOLockUnlock(mailboxLock_);
            return result;
        }

        uint64_t TahoeWirelessTransport::droppedEvents() const
        {
            if (mailboxLock_ == nullptr)
            {
                return eventDrops_;
            }
            IOLockLock(mailboxLock_);
            const uint64_t result = eventDrops_;
            IOLockUnlock(mailboxLock_);
            return result;
        }
    } // namespace tahoe
} // namespace simpleath
