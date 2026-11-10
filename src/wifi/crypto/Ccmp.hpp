// SPDX-License-Identifier: GPL-2.0-only
// 802.11 CCMP-128 for unfragmented, three-address data and QoS data.
// Pure source implementation; native key/PN ownership still requires wiring.
#ifndef SIMPLEATH_WIFI_CCMP_HPP
#define SIMPLEATH_WIFI_CCMP_HPP

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    namespace ieee80211
    {
        namespace crypto
        {
            constexpr size_t kCcmpTemporalKeyBytes = 16U;
            constexpr size_t kCcmpMacBytes = 6U;
            constexpr size_t kCcmpTidCount = 16U;
            constexpr size_t kCcmpMaximumMpduBytes = 2346U;
            constexpr uint64_t kCcmpMaximumPacketNumber = 0xffffffffffffULL;

            enum class CcmpResult : uint8_t
            {
                Ok,
                InvalidArgument,
                InvalidFrame,
                MissingKey,
                WrongEpoch,
                UnsupportedFrame,
                BufferTooSmall,
                PacketNumberExhausted,
                ReplayDetected,
                MicMismatch,
                OverlappingBuffers,
            };

            // A single installed temporal key and transmitter. The owning
            // station must serialize calls and ensure a TK is NEVER reused
            // after revoke/reset with a rolled-back transmit PN. No kernel
            // hardware keycache, AES offload or entropy ownership is implied.
            class CcmpSession final
            {
                public:
                    CcmpSession() = default;
                    ~CcmpSession();
                    CcmpSession(const CcmpSession &) = delete;
                    CcmpSession &operator=(const CcmpSession &) = delete;
                    CcmpSession(CcmpSession &&) = delete;
                    CcmpSession &operator=(CcmpSession &&) = delete;

                    // lastTransmittedPn / receiveFloor come from authenticated
                    // key-owner state, never untrusted 802.11 headers. For a
                    // fresh TK, both may be zero; first outgoing PN is one.
                    CcmpResult install(const uint8_t key[kCcmpTemporalKeyBytes],
                                       const uint8_t transmitter[kCcmpMacBytes],
                                       uint8_t keyId, uint64_t epoch,
                                       uint64_t lastTransmittedPn,
                                       uint64_t receiveFloor);
                    // No FCS on input or output. Output is committed only on
                    // full success; both directions require the same epoch.
                    // protect additionally requires pairwise key ID zero.
                    CcmpResult protect(uint64_t epoch, const uint8_t *frame,
                                       size_t bytes, uint8_t *output,
                                       size_t capacity, size_t &written);
                    CcmpResult unprotect(uint64_t epoch, const uint8_t *frame,
                                         size_t bytes, uint8_t *output,
                                         size_t capacity, size_t &written);
                    void revoke();

                    bool installed() const
                    {
                        return installed_;
                    }

                    uint64_t lastTransmittedPn() const
                    {
                        return txPn_;
                    }

                    // Diagnostic high watermark across TIDs; NEVER use this
                    // to authorize packets from a different priority stream.
                    uint64_t receiveFloor() const
                    {
                        return rxFloor_;
                    }

                private:
                    uint8_t key_[kCcmpTemporalKeyBytes] {};
                    uint8_t transmitter_[kCcmpMacBytes] {};
                    uint64_t epoch_ {};
                    uint64_t txPn_ {};
                    // Largest authenticated RX PN is diagnostic only. Replay
                    // admission is per 802.11 QoS TID; legacy non-QoS and
                    // QoS TID 0 share a nonce-priority/replay domain.
                    uint64_t rxFloor_ {};
                    uint64_t rxTidFloors_[kCcmpTidCount] {};
                    uint8_t keyId_ {};
                    bool installed_ {};
            };
        } // namespace crypto
    } // namespace ieee80211
} // namespace simpleath
#endif
