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
    if (encodeTxControls(request, policy, descriptor) != TxControlError::Ok ||
        !validTxPointerDescriptor(descriptor) ||
        (descriptor.word[12] & 0x01000000u) == 0)
        return 37;

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
    return 0;
}
