// SPDX-License-Identifier: AGPL-3.0-only
// AR9003 TX control/status codec; adapted from register layouts described in
// Linux ath9k ar9003_mac.c and mac.h, preserving provenance in the .cpp file.
// No PCI writes, queue doorbells, IOMMU operations or real RF transmission.
#ifndef SIMPLEATH_AR9003_TX_CONTROL_HPP
#define SIMPLEATH_AR9003_TX_CONTROL_HPP

#include "Ar9003Descriptors.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace edma
    {

        enum class TxCrypto : uint8_t
        {
            Clear = 0,
            Wep = 1,
            Ccmp = 2,
            Tkip = 3
        };

        enum class TxPacketType : uint8_t
        {
            Normal = 0,
            Beacon = 3,
            ProbeResponse = 4
        };

        enum class TxControlError : uint8_t
        {
            Ok,
            UninitializedPointerDescriptor,
            FrameLengthInvalid,
            RegulatoryNotVerified,
            RadioNotReady,
            InvalidPower,
            UnsupportedCipher,
            KeyUnavailable,
            InvalidRate,
            InvalidChain,
            InvalidDuration,
            UnsupportedControl,
            OverlappingBuffers
        };

        struct TxRate
        {
                uint8_t attempts; // Hardware 4-bit field, maximum 15.
                uint8_t rateCode; // AR9565 CCK/OFDM or single-stream MCS0..7.
                uint16_t rtsCtsDuration;  // Up to 0x7fff.
                uint8_t antennaChainMask; // AR9565 chain zero only (mask 1).
                uint8_t powerIndex;       // Hardware units; must not exceed
                                          // per-channel limit.
                bool ht40;
                bool shortGuardInterval;
                bool stbc;
                bool rtsCtsQualified;
        };

        struct TxControlRequest
        {
                // Includes four radio-generated FCS bytes. Other packet
                // types equal mapped DMA payload + 4; Beacon permits mapped
                // payload rounded up by 0..3 initialized alignment bytes.
                uint16_t onAirFrameLength; // 1..4095 hardware field.
                TxPacketType packetType;
                TxCrypto crypto;
                uint8_t keyCacheIndex; // 0xff when no key.
                bool noAck;
                bool rts;
                bool cts;
                bool durationUpdate;
                uint8_t rtsCtsRateCode;
                TxRate rate[4];
        };

        struct TxSafetyPolicy
        {
                bool siliconIdentified;
                bool boardCalibrationValidated;
                bool channelRegulatoryAuthorized;
                bool transmitPowerLimitsValidated;
                bool radioAwake;
                bool rfKillUnblocked;
                bool dmaMappingValid;
                bool hardwareKeyInstalled;
                bool ht40Authorized;
                bool shortGuardIntervalAuthorized;
                bool stbcSupported;
                uint8_t maximumTxPowerIndex[4];
        };

        // Only AR9565 single-chain rates, no STBC and no HT flags on legacy
        // rates. An RTS/CTS control rate must be supported legacy modulation.
        // Beacon and ProbeResponse packet types may use only cleartext;
        // protected management (BIP/PMF) is not implemented by this encoder.
        // Beacon also requires noAck, no RTS/CTS, one attempt/rate series,
        // and legacy-only modulation. Normal data retains multirate retry.
        // Encodes ctl11..ctl23 (the actual AR9003 rate/power/security fields)
        // into an existing validated pointer descriptor. This does not make a
        // packet safe to send until the macOS PCI owner and DMA completion path
        // are implemented. Request and policy must not overlap the descriptor;
        // aliases are rejected without modifying either input.
        TxControlError encodeTxControls(const TxControlRequest &request,
                                        const TxSafetyPolicy &policy,
                                        TxDescriptor &descriptor);

        struct TxCompletionWords
        {
                uint32_t word[9];
        };

        static_assert(sizeof(TxCompletionWords) == 36,
                      "AR9003 TX completion status size");

        struct TxCompletion
        {
                uint8_t queue;
                uint8_t finalRateSeries;
                uint16_t sequenceNumber;
                uint32_t timestamp;
                // AR_FrmXmitOK signals success, not proof of an ACK when the
                // transmission's policy did not request an ACK.
                bool frameTransmitOk;
                bool excessiveRetries;
                bool filtered;
                bool fifoUnderrun;
                bool configError;
                bool expired;
                bool txOpportunityExceeded;
                uint8_t shortRetries;
                uint8_t longRetries;
        };

        // Caller performs DMA synchronization before reading TX completion
        // status. Ordinary errors clear out, and a pending status is
        // Incomplete even when the vendor field has not been written yet.
        // A result aliasing raw status is rejected untouched to preserve DMA
        // source bytes. Queue IDs outside the supported 0..9 range are
        // rejected. The owner must confirm hardware has stopped DMA before ring
        // recycle.
        DescriptorError decodeTxCompletion(const TxCompletionWords &status,
                                           TxCompletion &out);

    } // namespace edma
} // namespace simpleath
#endif
