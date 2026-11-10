// Intel Tahoe native wireless transport: epoch-scoped provider callbacks.
#ifndef SIMPLEATH_TAHOE_WIRELESS_TRANSPORT_HPP
#define SIMPLEATH_TAHOE_WIRELESS_TRANSPORT_HPP

#include "NativeWirelessOwner.hpp"
#include <IOKit/IOLocks.h>
#include <IOKit/IOService.h>

namespace simpleath
{
    namespace tahoe
    {
        // Native IO80211 controller calls these methods on its own serialized
        // work loop. The PCI owner may invoke notification callbacks on a
        // different gate. Those callbacks only copy into fixed mailboxes;
        // neither calls an Apple network interface nor enters a second gate.
        // This is the transport, not an assertion that 25G332 permits a
        // particular Apple80211 selector or Skywalk packet-pool layout.
        class TahoeWirelessTransport final
        {
            public:
                static constexpr size_t kMaxEthernetFrame = 1518;
                static constexpr size_t kRxCapacity = 8;
                static constexpr size_t kEventCapacity = 16;

                TahoeWirelessTransport() = default;
                ~TahoeWirelessTransport();
                TahoeWirelessTransport(const TahoeWirelessTransport &) = delete;
                TahoeWirelessTransport &
                operator=(const TahoeWirelessTransport &) = delete;
                TahoeWirelessTransport(TahoeWirelessTransport &&) = delete;
                TahoeWirelessTransport &
                operator=(TahoeWirelessTransport &&) = delete;

                IOReturn bind(IOService *provider);
                // unsubscribe synchronously completes all pending callbacks
                // before any mailbox buffer, callback context or provider
                // reference can be reclaimed.
                void unbind();
                IOReturn snapshot(WirelessSnapshot &out);
                IOReturn setPower(bool on);
                IOReturn setMac(const uint8_t address[kWirelessMacBytes]);
                IOReturn startScan(uint64_t &generation);
                IOReturn cancelScan(uint64_t generation);
                IOReturn nextBss(uint64_t generation,
                                 ieee80211::NativeBssSnapshot &out);
                IOReturn connect(const NativeConnectRequest &request);
                IOReturn disconnect(uint16_t reason);
                IOReturn installKey(const NativeCcmpKey &key);
                IOReturn authorizePort(bool open);
                IOReturn transmitEthernet(const uint8_t *bytes, size_t length);

                // Drain only in the native controller's own work-loop context.
                // Invalid/stale receive frames never leave the mailbox. On
                // buffer-too-small, the frame remains queued for retry.
                IOReturn takeEvent(WirelessEvent &event, uint64_t &epoch);
                IOReturn takeEthernet(uint8_t *bytes, size_t capacity,
                                      size_t &length);
                uint64_t droppedReceiveFrames() const;
                uint64_t droppedEvents() const;

            private:
                struct EventRecord
                {
                        WirelessEvent event;
                        uint64_t epoch;
                };

                struct ReceiveRecord
                {
                        uint64_t epoch;
                        uint64_t associationGeneration;
                        size_t length;
                        uint8_t bytes[kMaxEthernetFrame];
                };

                static void notify(void *observer, WirelessEvent event,
                                   uint64_t epoch);
                static void receive(void *observer, uint64_t epoch,
                                    uint64_t associationGeneration,
                                    const uint8_t *bytes, size_t length);
                void invalidateMailboxes();
                bool bound() const;
                // Walk small fixed rings rather than unchecked arithmetic on
                // native mailbox storage; invalid cursors fail closed.
                EventRecord *eventAt(size_t ordinal);
                ReceiveRecord *receiveAt(size_t ordinal);

                // Lifecycle methods run only on the controller's own gate;
                // the mailbox lock is never held across provider callbacks.
                WirelessOwnerV3 owner_ {};
                IOService *provider_ {nullptr};
                IOLock *mailboxLock_ {nullptr};
                uint64_t epoch_ {0};
                uint64_t associationGeneration_ {0};
                uint64_t scanGeneration_ {0};
                uint64_t previousScanGeneration_ {0};
                bool subscribed_ {false};
                bool providerStopped_ {false};
                // EAPOL handshakes precede the data-port authorization.
                // Both grants come from the same live provider snapshot and
                // are revoked by radio/association/epoch change.
                bool receiveAuthorized_ {false};
                bool eapolReceiveAuthorized_ {false};
                EventRecord events_[kEventCapacity] {};
                ReceiveRecord frames_[kRxCapacity] {};
                size_t eventHead_ {0};
                size_t eventCount_ {0};
                size_t receiveHead_ {0};
                size_t receiveCount_ {0};
                uint64_t receiveDrops_ {0};
                uint64_t eventDrops_ {0};
        };
    } // namespace tahoe
} // namespace simpleath
#endif
