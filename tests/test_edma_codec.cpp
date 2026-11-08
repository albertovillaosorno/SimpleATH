// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Portable AR9003 descriptor codec contract only; no DMA mapping or hardware.
#include "hardware/Ar9003TxControl.hpp"

#include <cstring>

namespace
{
    template <typename T> bool same(const T &left, const T &right)
    {
        return std::memcmp(&left, &right, sizeof(T)) == 0;
    }
} // namespace

int main()
{
    using namespace simpleath::edma;
    TxPointerBlock pointer {};
    pointer.queue = 9;
    pointer.segmentCount = 2;
    pointer.segment[0] = {0x00001000ull, 512};
    pointer.segment[1] = {0x00004000ull, 48};
    TxDescriptor descriptor {};
    if (encodeTxPointers(pointer, descriptor) != DescriptorError::Ok ||
        !validTxPointerDescriptor(descriptor) ||
        descriptor.word[2] != 0x1000u || descriptor.word[3] != (512u << 16u) ||
        descriptor.word[4] != 0x4000u || descriptor.word[5] != (48u << 16u) ||
        descriptor.word[10] != txPointerChecksum(descriptor))
        return 1;

    const TxDescriptor beforeInvalid = descriptor;
    if (setNextTxDescriptor(descriptor, 3) != DescriptorError::InvalidLink ||
        !same(descriptor, beforeInvalid) ||
        setNextTxDescriptor(descriptor, 0x2000u) != DescriptorError::Ok ||
        !validTxPointerDescriptor(descriptor) || descriptor.word[1] != 0x2000u)
        return 2;
    const TxDescriptor beforeCorruption = descriptor;
    descriptor.word[3] |= 1u; // Reserved low bits forbidden.
    if (validTxPointerDescriptor(descriptor) ||
        setNextTxDescriptor(descriptor, 0x3000u) !=
            DescriptorError::InvalidDescriptor ||
        descriptor.word[1] != beforeCorruption.word[1])
        return 3;
    descriptor = beforeCorruption;

    TxPointerBlock invalid = pointer;
    invalid.segment[1].busAddress = 0x100000000ull;
    if (encodeTxPointers(invalid, descriptor) !=
            DescriptorError::InvalidAddress ||
        !same(descriptor, beforeCorruption))
        return 4;
    invalid = pointer;
    invalid.segmentCount = 0;
    if (encodeTxPointers(invalid, descriptor) !=
            DescriptorError::InvalidSegmentCount ||
        !same(descriptor, beforeCorruption))
        return 5;
    invalid = pointer;
    invalid.segment[1].busAddress = 0xfffffff0ull;
    invalid.segment[1].length = 48;
    if (encodeTxPointers(invalid, descriptor) !=
            DescriptorError::InvalidAddress ||
        !same(descriptor, beforeCorruption))
        return 6;

    TxControlRequest request {};
    request.onAirFrameLength =
        564; // 560 mapped payload octets plus 4-byte FCS.
    request.packetType = TxPacketType::Normal;
    request.crypto = TxCrypto::Clear;
    request.keyCacheIndex = 0xff;
    request.rate[0].attempts = 2;
    request.rate[0].rateCode = 0x0bu;
    request.rate[0].antennaChainMask = 1;
    request.rate[0].powerIndex = 1;
    TxSafetyPolicy policy {};
    policy.siliconIdentified = true;
    policy.boardCalibrationValidated = true;
    policy.channelRegulatoryAuthorized = true;
    policy.transmitPowerLimitsValidated = true;
    policy.radioAwake = true;
    policy.rfKillUnblocked = true;
    policy.dmaMappingValid = true;
    policy.maximumTxPowerIndex[0] = 8;

    const TxDescriptor beforeControl = descriptor;
    policy.boardCalibrationValidated = false;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::RegulatoryNotVerified ||
        !same(descriptor, beforeControl))
        return 7;
    policy.boardCalibrationValidated = true;
    if (encodeTxControls(request, policy, descriptor) != TxControlError::Ok ||
        !validTxPointerDescriptor(descriptor) ||
        descriptor.word[11] != (564u | (1u << 16u)) ||
        descriptor.word[13] != (2u << 16u) || descriptor.word[14] != 0x0bu)
        return 8;
    for (size_t index = 0; index <= 10; ++index)
        if (descriptor.word[index] != beforeControl.word[index])
            return 9;
    // The descriptor's four pointer segment lengths cover 560 payload
    // octets. The control field includes exactly four further hardware FCS
    // octets, not an independently forged length that could mismatch DMA.
    const TxDescriptor beforeLengthMismatch = descriptor;
    request.onAirFrameLength = 128;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::FrameLengthInvalid ||
        !same(descriptor, beforeLengthMismatch))
        return 28;
    request.onAirFrameLength = 563; // Even a one-byte shortfall is invalid.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::FrameLengthInvalid ||
        !same(descriptor, beforeLengthMismatch))
        return 29;
    request.onAirFrameLength = 565; // Reject overreading the pointer payload.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::FrameLengthInvalid ||
        !same(descriptor, beforeLengthMismatch))
        return 30;
    request.onAirFrameLength = 564;
    const TxDescriptor beforePolicyError = descriptor;
    request.crypto = TxCrypto::Ccmp;
    request.keyCacheIndex = 1;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::KeyUnavailable ||
        !same(descriptor, beforePolicyError))
        return 10;
    request.crypto = TxCrypto::Clear;
    request.keyCacheIndex = 0xff;
    request.rate[0].powerIndex = 9;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::InvalidPower ||
        !same(descriptor, beforePolicyError))
        return 11;

    // 1x1 AR9565 cannot use an arbitrary nonzero rate, multiple chains,
    // STBC, or HT-only flags on a legacy rate, regardless of caller policy.
    request.rate[0].powerIndex = 1;
    request.rate[0].rateCode = 0x88; // MCS8 is a second spatial stream.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::InvalidRate ||
        !same(descriptor, beforePolicyError))
        return 19;
    request.rate[0].rateCode = 0x04; // Unrecognized legacy encoding.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::InvalidRate ||
        !same(descriptor, beforePolicyError))
        return 20;
    request.rate[0].rateCode = 0x80;
    request.rate[0].antennaChainMask = 2;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::InvalidChain ||
        !same(descriptor, beforePolicyError))
        return 21;
    request.rate[0].antennaChainMask = 1;
    request.rate[0].stbc = true;
    policy.stbcSupported = true; // A forged policy cannot add a TX chain.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforePolicyError))
        return 22;
    request.rate[0].stbc = false;
    request.rate[0].rateCode = 0x0b;
    request.rate[0].shortGuardInterval = true;
    policy.shortGuardIntervalAuthorized = true;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforePolicyError))
        return 23;
    request.rate[0].shortGuardInterval = false;
    request.rate[0].ht40 = true;
    policy.ht40Authorized = true;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforePolicyError))
        return 24;
    request.rate[0].ht40 = false;
    request.rts = true;
    request.rtsCtsRateCode = 0x80; // RTS cannot use an HT modulation.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforePolicyError))
        return 25;
    request.rts = false;
    request.rtsCtsRateCode = 0x1b; // Stale control rate without an RTS/CTS.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforePolicyError))
        return 26;
    request.rtsCtsRateCode = 0;
    request.rate[0].rateCode = 0x80; // Single-stream MCS0 is supported.
    if (encodeTxControls(request, policy, descriptor) != TxControlError::Ok ||
        !validTxPointerDescriptor(descriptor))
        return 27;

    // Ordinary management Beacon/ProbeResponse frames are not CCMP
    // encrypted. This limited encoder has no BIP/PMF robust-management
    // protection path; a forged key-installed policy must not authorize it.
    const TxDescriptor beforeProtectedManagement = descriptor;
    request.crypto = TxCrypto::Ccmp;
    request.keyCacheIndex = 3;
    policy.hardwareKeyInstalled = true;
    request.packetType = TxPacketType::Beacon;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedCipher ||
        !same(descriptor, beforeProtectedManagement))
        return 31;
    request.packetType = TxPacketType::ProbeResponse;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedCipher ||
        !same(descriptor, beforeProtectedManagement))
        return 32;
    // Valid CCMP data is still representable after independently verified
    // hardware key installation and matching TX length/power policy.
    request.packetType = TxPacketType::Normal;
    if (encodeTxControls(request, policy, descriptor) != TxControlError::Ok ||
        !validTxPointerDescriptor(descriptor))
        return 33;

    // Beacon is broadcast, carries no ACK exchange, and must use an
    // interoperable legacy basic rate. The control encoder must not allow
    // a caller to request retries/RTS or HT modulation for this packet type.
    request.packetType = TxPacketType::Beacon;
    request.crypto = TxCrypto::Clear;
    request.keyCacheIndex = 0xff;
    request.rate[0].rateCode = 0x1b; // 1 Mbps basic CCK rate.
    const TxDescriptor beforeBeaconPolicy = descriptor;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforeBeaconPolicy))
        return 34;
    request.noAck = true;
    request.rts = true;
    request.rtsCtsRateCode = 0x1b;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforeBeaconPolicy))
        return 35;
    request.rts = false;
    request.rtsCtsRateCode = 0;
    request.rate[0].rateCode = 0x80; // HT MCS0 is not a beacon basic rate.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforeBeaconPolicy))
        return 36;
    request.rate[0].rateCode = 0x1b;
    request.rate[0].attempts = 1; // One broadcast Beacon attempt.
    if (encodeTxControls(request, policy, descriptor) != TxControlError::Ok ||
        !validTxPointerDescriptor(descriptor) ||
        (descriptor.word[12] & 0x01000000u) == 0)
        return 37;

    // Probe Response is transmitted before association, so the recipient
    // cannot be assumed to support HT MCS rates. Reject HT management TX
    // rather than silently using a data-only modulation, preserving the
    // untouched descriptor on failure. A normal legacy-rate response works.
    request.packetType = TxPacketType::ProbeResponse;
    request.noAck = false;
    request.rate[0].rateCode = 0x80; // MCS0 cannot carry Probe Response.
    const TxDescriptor beforeProbeRate = descriptor;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforeProbeRate))
        return 47;
    request.rate[0].rateCode = 0x1b;
    if (encodeTxControls(request, policy, descriptor) != TxControlError::Ok ||
        !validTxPointerDescriptor(descriptor))
        return 48;
    request.packetType = TxPacketType::Beacon;
    request.noAck = true;

    // Linux ath9k beacon.c: pkt_len = skb->len + FCS_LEN, but buf_len
    // = roundup(skb->len, 4). The 560-byte mapped DMA span is valid for
    // Beacon on-air sizes 561..564, including 0..3 bytes of tail padding.
    for (uint16_t onAir = 561; onAir <= 564; ++onAir)
    {
        request.onAirFrameLength = onAir;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::Ok ||
            (descriptor.word[11] & 0xfffu) != onAir)
            return 38;
    }
    const TxDescriptor beforeInvalidPadding = descriptor;
    request.onAirFrameLength = 560; // Would need four padding bytes.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::FrameLengthInvalid ||
        !same(descriptor, beforeInvalidPadding))
        return 39;
    request.onAirFrameLength = 565; // Too few mapped bytes for the frame.
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::FrameLengthInvalid ||
        !same(descriptor, beforeInvalidPadding))
        return 40;
    // Other frame types never inherit the Beacon-only padding exception.
    request.packetType = TxPacketType::Normal;
    request.noAck = false;
    request.onAirFrameLength = 561;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::FrameLengthInvalid ||
        !same(descriptor, beforeInvalidPadding))
        return 41;
    request.packetType = TxPacketType::ProbeResponse;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::FrameLengthInvalid ||
        !same(descriptor, beforeInvalidPadding))
        return 42;

    // No station ACKs broadcast beacons. Unlike data retries, a beacon
    // must have exactly one transmit attempt in its first rate series.
    // Compare Linux ath9k beacon.c: series[0].Tries = 1.
    request.packetType = TxPacketType::Beacon;
    request.noAck = true;
    request.onAirFrameLength = 564;
    request.rate[0].attempts = 2;
    const TxDescriptor beforeBeaconRetries = descriptor;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforeBeaconRetries))
        return 43;
    request.rate[0].attempts = 1;
    request.rate[1].attempts = 1;
    request.rate[1].rateCode = 0x1b;
    request.rate[1].antennaChainMask = 1;
    request.rate[1].powerIndex = 1;
    policy.maximumTxPowerIndex[1] = 8;
    if (encodeTxControls(request, policy, descriptor) !=
            TxControlError::UnsupportedControl ||
        !same(descriptor, beforeBeaconRetries))
        return 44;
    request.rate[1] = {};
    if (encodeTxControls(request, policy, descriptor) != TxControlError::Ok ||
        ((descriptor.word[13] >> 16u) & 0xffffu) != 1u)
        return 45;
    // Multi-rate retries are still supported for ordinary data frames.
    request.packetType = TxPacketType::Normal;
    request.noAck = false;
    request.rate[0].attempts = 2;
    request.rate[1].attempts = 1;
    request.rate[1].rateCode = 0x0b;
    request.rate[1].antennaChainMask = 1;
    request.rate[1].powerIndex = 1;
    if (encodeTxControls(request, policy, descriptor) != TxControlError::Ok ||
        ((descriptor.word[13] >> 16u) & 0xffu) != 0x12u)
        return 46;

    RxStatusWords rx {};
    rx.word[0] = 0x168c0000u;
    rx.word[1] = 0x0b000000u;
    rx.word[2] = 128u;
    rx.word[3] = 7654u;
    rx.word[5] = 0xd8000000u; // -40 dBm signed RSSI.
    rx.word[11] = 3u;         // Done, valid frame.
    RxStatus decoded {};
    if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
        !decoded.completed || !decoded.frameValid ||
        decoded.frameLength != 128 || decoded.rateCode != 0x0b ||
        decoded.timestamp != 7654u || decoded.combinedRssi != -40)
        return 12;
    // Without a reviewed A-MPDU deaggregation/reorder/BlockAck pipeline,
    // aggregate fragments cannot be authorized for native RX delivery solely
    // by a successful per-buffer CRC and DMA completion bit. The codec must
    // not publish any status that asserts aggregate membership or continuation.
    const uint32_t aggregateFlags[] = {0x00010000u, 0x00020000u, 0x20000000u,
                                       0x20030000u};
    for (uint32_t aggregate : aggregateFlags)
    {
        rx.word[11] = 3u | aggregate;
        decoded.completed = true;
        decoded.frameValid = true;
        decoded.frameLength = 128;
        if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
            decoded.completed || decoded.frameValid || decoded.frameLength ||
            decoded.aggregated || decoded.aggregationFirst ||
            decoded.aggregationContinues)
            return 61;
    }
    rx.word[11] = 3u;
    // AR_RxMore is a chained DMA buffer, not a complete on-air MPDU.
    // Even an apparently good FCS bit cannot authorize forwarding a partial
    // buffer without a separately verified RX-chain reassembly path.
    rx.word[2] |= 0x1000u;
    if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
        decoded.completed || decoded.frameValid || decoded.frameLength)
        return 49;
    rx.word[2] &= ~0x1000u;
    if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
        !decoded.frameValid || decoded.frameLength != 128u)
        return 50;
    // The single-buffer, non-aggregating RX path has no reviewed MPDU
    // larger than the IEEE 802.11 2346-octet limit including its FCS.
    // A 12-bit hardware length alone cannot authorize a 4095-byte frame.
    rx.word[2] = 2346u;
    if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
        !decoded.frameValid || decoded.frameLength != 2346u)
        return 51;
    rx.word[2] = 2347u;
    if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
        decoded.completed || decoded.frameValid || decoded.frameLength)
        return 52;
    rx.word[2] = 4095u;
    if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
        decoded.completed || decoded.frameValid || decoded.frameLength)
        return 53;
    rx.word[2] = 128u;
    rx.word[11] = 0;
    if (decodeRxStatus(rx, decoded) != DescriptorError::Incomplete ||
        decoded.completed || decoded.frameValid || decoded.frameLength)
        return 13;
    rx.word[11] = 7u; // CRC error.
    if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
        decoded.completed || decoded.frameValid || decoded.frameLength)
        return 14;
    rx.word[0] = 0;
    if (decodeRxStatus(rx, decoded) != DescriptorError::InvalidVendor ||
        decoded.completed || decoded.frameLength)
        return 15;

    TxCompletionWords tx {};
    tx.word[8] = 24u << 1u; // No Done yet, regardless of bogus vendor.
    TxCompletion completed {};
    completed.frameTransmitOk = true;
    if (decodeTxCompletion(tx, completed) != DescriptorError::Incomplete ||
        completed.frameTransmitOk || completed.sequenceNumber)
        return 16;
    tx.word[8] |= 1u; // Device has now set Done.
    tx.word[0] = 0x168c8000u | (9u << 8u);
    tx.word[3] = 1u;
    tx.word[4] = 4433u;
    if (decodeTxCompletion(tx, completed) != DescriptorError::Ok ||
        completed.queue != 9 || completed.sequenceNumber != 24 ||
        completed.timestamp != 4433u || !completed.frameTransmitOk)
        return 17;
    tx.word[0] = 0x168c8000u | (15u << 8u);
    if (decodeTxCompletion(tx, completed) != DescriptorError::CorruptStatus ||
        completed.queue || completed.frameTransmitOk ||
        completed.sequenceNumber)
        return 18;

    // A matching DMA pointer length does not make a 2347-byte standalone
    // MPDU legal. Aggregation/fragmentation are not implemented by this TX
    // codec; enforce the same 2346-byte on-air ceiling as the data encoder.
    TxPointerBlock oversizedPointer {};
    oversizedPointer.queue = 9;
    oversizedPointer.segmentCount = 1;
    oversizedPointer.segment[0] = {0x1000ull, 2343};
    TxDescriptor oversizedDescriptor {};
    if (encodeTxPointers(oversizedPointer, oversizedDescriptor) !=
        DescriptorError::Ok)
        return 54;
    TxControlRequest oversizedRequest {};
    oversizedRequest.onAirFrameLength = 2347;
    oversizedRequest.packetType = TxPacketType::Normal;
    oversizedRequest.crypto = TxCrypto::Clear;
    oversizedRequest.keyCacheIndex = 0xff;
    oversizedRequest.rate[0].attempts = 1;
    oversizedRequest.rate[0].rateCode = 0x0b;
    oversizedRequest.rate[0].antennaChainMask = 1;
    oversizedRequest.rate[0].powerIndex = 1;
    const TxDescriptor beforeOversizedTx = oversizedDescriptor;
    if (encodeTxControls(oversizedRequest, policy, oversizedDescriptor) !=
            TxControlError::FrameLengthInvalid ||
        !same(oversizedDescriptor, beforeOversizedTx))
        return 55;
    oversizedPointer.segment[0].length = 4091;
    oversizedRequest.onAirFrameLength = 4095;
    if (encodeTxPointers(oversizedPointer, oversizedDescriptor) !=
            DescriptorError::Ok ||
        encodeTxControls(oversizedRequest, policy, oversizedDescriptor) !=
            TxControlError::FrameLengthInvalid)
        return 56;
    // Exactly 2346 on-air octets with the matching 2342-byte DMA payload
    // remain representable when all of the separate policy gates pass.
    oversizedPointer.segment[0].length = 2342;
    oversizedRequest.onAirFrameLength = 2346;
    if (encodeTxPointers(oversizedPointer, oversizedDescriptor) !=
            DescriptorError::Ok ||
        encodeTxControls(oversizedRequest, policy, oversizedDescriptor) !=
            TxControlError::Ok)
        return 57;

    // A completed descriptor cannot report both successful transmission and
    // a terminal failure. Reject forged/incoherent status words rather than
    // leaking a false success to the future TX completion handler.
    tx.word[0] = 0x168c8000u | (9u << 8u);
    tx.word[8] = (24u << 1u) | 1u;
    const uint32_t terminalFailureBits[] = {0x00000002u, 0x00000008u,
                                            0x00040000u, 0x00080000u};
    for (uint32_t terminal : terminalFailureBits)
    {
        tx.word[3] = terminal | 1u; // AR_FrmXmitOK and a terminal failure.
        completed.frameTransmitOk = true;
        if (decodeTxCompletion(tx, completed) !=
                DescriptorError::CorruptStatus ||
            completed.frameTransmitOk || completed.excessiveRetries ||
            completed.sequenceNumber)
            return 58;
    }
    tx.word[3] = 1u;
    tx.word[8] |= 0x00020000u; // TXOP exceeded despite XmitOK.
    completed.frameTransmitOk = true;
    if (decodeTxCompletion(tx, completed) != DescriptorError::CorruptStatus ||
        completed.frameTransmitOk || completed.txOpportunityExceeded ||
        completed.sequenceNumber)
        return 59;
    // An ordinary failed TX retains its explicit diagnostic bits, but never
    // gets upgraded to a successful transmission.
    tx.word[8] &= ~0x00020000u;
    tx.word[3] = 0x00000002u;
    if (decodeTxCompletion(tx, completed) != DescriptorError::Ok ||
        completed.frameTransmitOk || !completed.excessiveRetries ||
        completed.sequenceNumber != 24u)
        return 60;
    return 0;
}
