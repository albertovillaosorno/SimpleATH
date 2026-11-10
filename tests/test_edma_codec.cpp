// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Portable AR9003 descriptor codec contract only; no DMA mapping or hardware.
#include "hardware/Ar9003Descriptors.hpp"
#include "hardware/Ar9003TxControl.hpp"

#include <cstdint>
#include <cstring>
#include <limits>

namespace
{
    // Exact synthetic wire/descriptor fixture values: these named constants
    // keep the original encoded lengths, bit fields and address test vectors
    // recognizable without treating unexplained literals as runtime policy.
    constexpr auto kFixtureDec5 = 5;
    constexpr auto kFixtureDec8 = 8;
    constexpr auto kFixtureDec9 = 9;
    constexpr auto kFixtureDec10 = 10;
    constexpr auto kFixtureDec11 = 11;
    constexpr auto kFixtureDec12 = 12;
    constexpr auto kFixtureDec13 = 13;
    constexpr auto kFixtureDec14 = 14;
    constexpr auto kFixtureDec24 = 24;
    constexpr auto kFixtureDec40 = 40;
    constexpr auto kFixtureDec48 = 48;
    constexpr auto kFixtureDec7u = 7U;
    constexpr auto kFixtureDec8u = 8U;
    constexpr auto kFixtureDec9u = 9U;
    constexpr auto kFixtureDec128 = 128;
    constexpr auto kFixtureDec14u = 14U;
    constexpr auto kFixtureDec15u = 15U;
    constexpr auto kFixtureDec16u = 16U;
    constexpr auto kFixtureDec24u = 24U;
    constexpr auto kFixtureDec48u = 48U;
    constexpr auto kFixtureDec512 = 512;
    constexpr auto kFixtureDec560 = 560;
    constexpr auto kFixtureDec561 = 561;
    constexpr auto kFixtureDec563 = 563;
    constexpr auto kFixtureDec564 = 564;
    constexpr auto kFixtureDec565 = 565;
    constexpr auto kFixtureDec128u = 128U;
    constexpr auto kFixtureDec2342 = 2342;
    constexpr auto kFixtureDec2343 = 2343;
    constexpr auto kFixtureDec2346 = 2346;
    constexpr auto kFixtureDec2347 = 2347;
    constexpr auto kFixtureDec4091 = 4091;
    constexpr auto kFixtureDec4095 = 4095;
    constexpr auto kFixtureDec512u = 512U;
    constexpr auto kFixtureDec564u = 564U;
    constexpr auto kFixtureDec2346u = 2346U;
    constexpr auto kFixtureDec2347u = 2347U;
    constexpr auto kFixtureDec4095u = 4095U;
    constexpr auto kFixtureDec4433u = 4433U;
    constexpr auto kFixtureDec7654u = 7654U;
    constexpr auto kFixtureHex0b = 0x0b;
    constexpr auto kFixtureHex1b = 0x1b;
    constexpr auto kFixtureHex80 = 0x80;
    constexpr auto kFixtureHex88 = 0x88;
    constexpr auto kFixtureHexff = 0xff;
    constexpr auto kFixtureHex0bu = 0x0bU;
    constexpr auto kFixtureHex12u = 0x12U;
    constexpr auto kFixtureHexffu = 0xffU;
    constexpr auto kFixtureHexfffu = 0xfffU;
    constexpr auto kFixtureHex1000u = 0x1000U;
    constexpr auto kFixtureHex2000u = 0x2000U;
    constexpr auto kFixtureHex3000u = 0x3000U;
    constexpr auto kFixtureHex4000u = 0x4000U;
    constexpr auto kFixtureHexffffu = 0xffffU;
    constexpr auto kFixtureHex1000ull = 0x1000ULL;
    constexpr auto kFixtureHex6000ull = 0x6000ULL;
    constexpr auto kFixtureHex00010000u = 0x00010000U;
    constexpr auto kFixtureHex00020000u = 0x00020000U;
    constexpr auto kFixtureHex01000000u = 0x01000000U;
    constexpr auto kFixtureHex0b000000u = 0x0b000000U;
    constexpr auto kFixtureHex168c0000u = 0x168c0000U;
    constexpr auto kFixtureHex168c8000u = 0x168c8000U;
    constexpr auto kFixtureHex80000000u = 0x80000000U;
    constexpr auto kFixtureHexd8000000u = 0xd8000000U;
    constexpr auto kFixtureHex00001000ull = 0x00001000ULL;
    constexpr auto kFixtureHex00004000ull = 0x00004000ULL;
    constexpr auto kFixtureHexfffffff0ull = 0xfffffff0ULL;
    constexpr auto kFixtureHex100000000ull = 0x100000000ULL;

    // Stable exit codes identify the original independent EDMA cases.
    enum class Failure : int
    {
        Scenario1 = 1,
        Scenario2 = 2,
        Scenario3 = 3,
        Scenario4 = 4,
        Scenario5 = 5,
        Scenario6 = 6,
        Scenario7 = 7,
        Scenario8 = 8,
        Scenario9 = 9,
        Scenario10 = 10,
        Scenario11 = 11,
        Scenario12 = 12,
        Scenario13 = 13,
        Scenario14 = 14,
        Scenario15 = 15,
        Scenario16 = 16,
        Scenario17 = 17,
        Scenario18 = 18,
        Scenario19 = 19,
        Scenario20 = 20,
        Scenario21 = 21,
        Scenario22 = 22,
        Scenario23 = 23,
        Scenario24 = 24,
        Scenario25 = 25,
        Scenario26 = 26,
        Scenario27 = 27,
        Scenario28 = 28,
        Scenario29 = 29,
        Scenario30 = 30,
        Scenario31 = 31,
        Scenario32 = 32,
        Scenario33 = 33,
        Scenario34 = 34,
        Scenario35 = 35,
        Scenario36 = 36,
        Scenario37 = 37,
        Scenario38 = 38,
        Scenario39 = 39,
        Scenario40 = 40,
        Scenario41 = 41,
        Scenario42 = 42,
        Scenario43 = 43,
        Scenario44 = 44,
        Scenario45 = 45,
        Scenario46 = 46,
        Scenario47 = 47,
        Scenario48 = 48,
        Scenario49 = 49,
        Scenario50 = 50,
        Scenario51 = 51,
        Scenario52 = 52,
        Scenario53 = 53,
        Scenario54 = 54,
        Scenario55 = 55,
        Scenario56 = 56,
        Scenario57 = 57,
        Scenario58 = 58,
        Scenario59 = 59,
        Scenario60 = 60,
        Scenario61 = 61,
        Scenario62 = 62,
        Scenario63 = 63,
        Scenario64 = 64,
        Scenario65 = 65,
        Scenario66 = 66,
        Scenario67 = 67,
        Scenario68 = 68,
        Scenario69 = 69,
        Scenario70 = 70,
        Scenario71 = 71,
        Scenario72 = 72,
        Scenario73 = 73,
    };

    constexpr int kLegacyWhitelistFailure = 72;

    template <typename T> bool same(const T &left, const T &right)
    {
        return std::memcmp(&left, &right, sizeof(T)) == 0;
    }

    bool exactLegacyRateWhitelist()
    {
        using simpleath::edma::supportedAr9565LegacyRate;
        const uint8_t expectedCodes[] {
            0x1b, 0x1a, 0x19, 0x1e, 0x1d, 0x18, 0x1c, 0x0b,
            0x0f, 0x0a, 0x0e, 0x09, 0x0d, 0x08, 0x0c,
        };
        for (unsigned candidate = 0;
             candidate <= std::numeric_limits<uint8_t>::max(); ++candidate)
        {
            bool expected = false;
            for (const uint8_t code : expectedCodes)
            {
                expected |= candidate == code;
            }
            if (supportedAr9565LegacyRate(static_cast<uint8_t>(candidate)) !=
                expected)
            {
                return false;
            }
        }
        return true;
    }

    struct CodecScenario
    {
            simpleath::edma::TxDescriptor descriptor {};
            simpleath::edma::TxDescriptor beforePolicyError {};
            simpleath::edma::TxControlRequest request {};
            simpleath::edma::TxSafetyPolicy policy {};
            simpleath::edma::RxStatusWords rx {};
            simpleath::edma::RxStatus decoded {};
            simpleath::edma::TxCompletionWords tx {};
            simpleath::edma::TxCompletion completed {};
    };

    int checkPointerAndShortFrames(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &descriptor = state.descriptor;
        auto &request = state.request;
        auto &policy = state.policy;

        TxPointerBlock pointer {};
        pointer.queue = kFixtureDec9;
        pointer.segmentCount = 2;
        pointer.segment[0] = {kFixtureHex00001000ull, kFixtureDec512};
        pointer.segment[1] = {kFixtureHex00004000ull, kFixtureDec48};
        if (encodeTxPointers(pointer, descriptor) != DescriptorError::Ok ||
            !validTxPointerDescriptor(descriptor) ||
            descriptor.word[2] != kFixtureHex1000u ||
            descriptor.word[3] != (kFixtureDec512u << kFixtureDec16u) ||
            descriptor.word[4] != kFixtureHex4000u ||
            descriptor.word[kFixtureDec5] !=
                (kFixtureDec48u << kFixtureDec16u) ||
            descriptor.word[kFixtureDec10] != txPointerChecksum(descriptor))
        {
            return static_cast<int>(Failure::Scenario1);
        }

        const TxDescriptor beforeInvalid = descriptor;
        if (setNextTxDescriptor(descriptor, 3) !=
                DescriptorError::InvalidLink ||
            !same(descriptor, beforeInvalid) ||
            setNextTxDescriptor(descriptor, kFixtureHex2000u) !=
                DescriptorError::Ok ||
            !validTxPointerDescriptor(descriptor) ||
            descriptor.word[1] != kFixtureHex2000u)
        {
            return static_cast<int>(Failure::Scenario2);
        }
        const TxDescriptor beforeCorruption = descriptor;
        descriptor.word[3] |= 1U; // Reserved low bits forbidden.
        if (validTxPointerDescriptor(descriptor) ||
            setNextTxDescriptor(descriptor, kFixtureHex3000u) !=
                DescriptorError::InvalidDescriptor ||
            descriptor.word[1] != beforeCorruption.word[1])
        {
            return static_cast<int>(Failure::Scenario3);
        }
        descriptor = beforeCorruption;

        TxPointerBlock invalid = pointer;
        invalid.segment[1].busAddress = kFixtureHex100000000ull;
        if (encodeTxPointers(invalid, descriptor) !=
                DescriptorError::InvalidAddress ||
            !same(descriptor, beforeCorruption))
        {
            return static_cast<int>(Failure::Scenario4);
        }
        invalid = pointer;
        invalid.segmentCount = 0;
        if (encodeTxPointers(invalid, descriptor) !=
                DescriptorError::InvalidSegmentCount ||
            !same(descriptor, beforeCorruption))
        {
            return static_cast<int>(Failure::Scenario5);
        }
        invalid = pointer;
        invalid.segment[1].busAddress = kFixtureHexfffffff0ull;
        invalid.segment[1].length = kFixtureDec48;
        if (encodeTxPointers(invalid, descriptor) !=
                DescriptorError::InvalidAddress ||
            !same(descriptor, beforeCorruption))
        {
            return static_cast<int>(Failure::Scenario6);
        }

        request.onAirFrameLength =
            kFixtureDec564; // 560 mapped payload octets plus 4-byte FCS.
        request.packetType = TxPacketType::Normal;
        request.crypto = TxCrypto::Clear;
        request.keyCacheIndex = kFixtureHexff;
        request.rate[0].attempts = 2;
        request.rate[0].rateCode = kFixtureHex0bu;
        request.rate[0].antennaChainMask = 1;
        request.rate[0].powerIndex = 1;
        policy.siliconIdentified = true;
        policy.boardCalibrationValidated = true;
        policy.channelRegulatoryAuthorized = true;
        policy.transmitPowerLimitsValidated = true;
        policy.radioAwake = true;
        policy.rfKillUnblocked = true;
        policy.dmaMappingValid = true;
        policy.maximumTxPowerIndex[0] = kFixtureDec8;

        // Even a correctly matched DMA payload cannot describe a completed
        // 802.11 MPDU shorter than the ten-byte ACK/CTS header plus four FCS
        // bytes. Preserve the 14-byte boundary for the downstream subtype gate.
        TxPointerBlock shortPointer {};
        shortPointer.queue = kFixtureDec9;
        shortPointer.segmentCount = 1;
        shortPointer.segment[0] = {kFixtureHex6000ull, 1};
        TxDescriptor shortDescriptor {};
        TxControlRequest shortRequest = request;
        const uint16_t tooShort[] {5U, 9U, 13U};
        for (const uint16_t onAir : tooShort)
        {
            shortPointer.segment[0].length = onAir - 4U;
            if (encodeTxPointers(shortPointer, shortDescriptor) !=
                DescriptorError::Ok)
            {
                return static_cast<int>(Failure::Scenario69);
            }
            const TxDescriptor beforeShort = shortDescriptor;
            shortRequest.onAirFrameLength = onAir;
            if (encodeTxControls(shortRequest, policy, shortDescriptor) !=
                    TxControlError::FrameLengthInvalid ||
                !same(shortDescriptor, beforeShort))
            {
                return static_cast<int>(Failure::Scenario70);
            }
        }
        shortPointer.segment[0].length = kFixtureDec10;
        shortRequest.onAirFrameLength = kFixtureDec14;
        if (encodeTxPointers(shortPointer, shortDescriptor) !=
                DescriptorError::Ok ||
            encodeTxControls(shortRequest, policy, shortDescriptor) !=
                TxControlError::Ok ||
            (shortDescriptor.word[kFixtureDec11] & kFixtureHexfffu) !=
                kFixtureDec14u)
        {
            return static_cast<int>(Failure::Scenario71);
        }

        return 0;
    }

    int checkInitialTxControls(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &descriptor = state.descriptor;
        auto &beforePolicyError = state.beforePolicyError;
        auto &request = state.request;
        auto &policy = state.policy;

        const TxDescriptor beforeControl = descriptor;
        policy.boardCalibrationValidated = false;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::RegulatoryNotVerified ||
            !same(descriptor, beforeControl))
        {
            return static_cast<int>(Failure::Scenario7);
        }
        policy.boardCalibrationValidated = true;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::Ok ||
            !validTxPointerDescriptor(descriptor) ||
            descriptor.word[kFixtureDec11] !=
                (kFixtureDec564u | (1U << kFixtureDec16u)) ||
            descriptor.word[kFixtureDec13] != (2U << kFixtureDec16u) ||
            descriptor.word[kFixtureDec14] != kFixtureHex0bu)
        {
            return static_cast<int>(Failure::Scenario8);
        }
        // The descriptor's ten pointer words and checksum are byte-exact
        // across a TX-control update; compare the fixed prefix as bytes.
        constexpr size_t kPointerPrefixWords = 11U;
        if (std::memcmp(&descriptor.word, &beforeControl.word,
                        kPointerPrefixWords * sizeof(uint32_t)) != 0)
        {
            return static_cast<int>(Failure::Scenario9);
        }
        // The descriptor's four pointer segment lengths cover 560 payload
        // octets. The control field includes exactly four further hardware FCS
        // octets, not an independently forged length that could mismatch DMA.
        const TxDescriptor beforeLengthMismatch = descriptor;
        request.onAirFrameLength = kFixtureDec128;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::FrameLengthInvalid ||
            !same(descriptor, beforeLengthMismatch))
        {
            return static_cast<int>(Failure::Scenario28);
        }
        request.onAirFrameLength =
            kFixtureDec563; // Even a one-byte shortfall is invalid.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::FrameLengthInvalid ||
            !same(descriptor, beforeLengthMismatch))
        {
            return static_cast<int>(Failure::Scenario29);
        }
        request.onAirFrameLength =
            kFixtureDec565; // Reject overreading the pointer payload.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::FrameLengthInvalid ||
            !same(descriptor, beforeLengthMismatch))
        {
            return static_cast<int>(Failure::Scenario30);
        }
        request.onAirFrameLength = kFixtureDec564;
        beforePolicyError = descriptor;
        request.crypto = TxCrypto::Ccmp;
        request.keyCacheIndex = 1;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::KeyUnavailable ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario10);
        }
        request.crypto = TxCrypto::Clear;
        request.keyCacheIndex = kFixtureHexff;
        request.rate[0].powerIndex = kFixtureDec9;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::InvalidPower ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario11);
        }

        return 0;
    }

    int checkLegacyRateRestrictions(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &descriptor = state.descriptor;
        const auto &beforePolicyError = state.beforePolicyError;
        auto &request = state.request;
        auto &policy = state.policy;

        // 1x1 AR9565 cannot use an arbitrary nonzero rate, multiple chains,
        // STBC, or HT-only flags on a legacy rate, regardless of caller policy.
        request.rate[0].powerIndex = 1;
        request.rate[0].rateCode =
            kFixtureHex88; // MCS8 is a second spatial stream.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::InvalidRate ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario19);
        }
        request.rate[0].rateCode = 0x04; // Unrecognized legacy encoding.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::InvalidRate ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario20);
        }
        request.rate[0].rateCode = kFixtureHex80;
        request.rate[0].antennaChainMask = 2;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::InvalidChain ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario21);
        }
        request.rate[0].antennaChainMask = 1;
        request.rate[0].stbc = true;
        policy.stbcSupported = true; // A forged policy cannot add a TX chain.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario22);
        }
        request.rate[0].stbc = false;
        request.rate[0].rateCode = kFixtureHex0b;
        request.rate[0].shortGuardInterval = true;
        policy.shortGuardIntervalAuthorized = true;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario23);
        }
        request.rate[0].shortGuardInterval = false;
        request.rate[0].ht40 = true;
        policy.ht40Authorized = true;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario24);
        }
        request.rate[0].ht40 = false;
        request.rts = true;
        request.rtsCtsRateCode =
            kFixtureHex80; // RTS cannot use an HT modulation.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario25);
        }
        request.rts = false;
        request.rtsCtsRateCode =
            kFixtureHex1b; // Stale control rate without an RTS/CTS.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforePolicyError))
        {
            return static_cast<int>(Failure::Scenario26);
        }
        request.rtsCtsRateCode = 0;
        request.rate[0].rateCode =
            kFixtureHex80; // Single-stream MCS0 is supported.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::Ok ||
            !validTxPointerDescriptor(descriptor))
        {
            return static_cast<int>(Failure::Scenario27);
        }

        return 0;
    }

    int checkProtectedManagement(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &descriptor = state.descriptor;
        auto &request = state.request;
        auto &policy = state.policy;

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
        {
            return static_cast<int>(Failure::Scenario31);
        }
        request.packetType = TxPacketType::ProbeResponse;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedCipher ||
            !same(descriptor, beforeProtectedManagement))
        {
            return static_cast<int>(Failure::Scenario32);
        }
        // Valid CCMP data is still representable after independently verified
        // hardware key installation and matching TX length/power policy.
        request.packetType = TxPacketType::Normal;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::Ok ||
            !validTxPointerDescriptor(descriptor))
        {
            return static_cast<int>(Failure::Scenario33);
        }

        // Beacon is broadcast, carries no ACK exchange, and must use an
        // interoperable legacy basic rate. The control encoder must not allow
        // a caller to request retries/RTS or HT modulation for this packet
        // type.
        request.packetType = TxPacketType::Beacon;
        request.crypto = TxCrypto::Clear;
        request.keyCacheIndex = kFixtureHexff;
        request.rate[0].rateCode = kFixtureHex1b; // 1 Mbps basic CCK rate.
        const TxDescriptor beforeBeaconPolicy = descriptor;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforeBeaconPolicy))
        {
            return static_cast<int>(Failure::Scenario34);
        }
        request.noAck = true;
        request.rts = true;
        request.rtsCtsRateCode = kFixtureHex1b;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforeBeaconPolicy))
        {
            return static_cast<int>(Failure::Scenario35);
        }
        request.rts = false;
        request.rtsCtsRateCode = 0;
        request.rate[0].rateCode =
            kFixtureHex80; // HT MCS0 is not a beacon basic rate.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforeBeaconPolicy))
        {
            return static_cast<int>(Failure::Scenario36);
        }
        request.rate[0].rateCode = kFixtureHex1b;
        request.rate[0].attempts = 1; // One broadcast Beacon attempt.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::Ok ||
            !validTxPointerDescriptor(descriptor) ||
            (descriptor.word[kFixtureDec12] & kFixtureHex01000000u) == 0)
        {
            return static_cast<int>(Failure::Scenario37);
        }

        return 0;
    }

    int checkProbeAndBeaconPadding(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &descriptor = state.descriptor;
        auto &request = state.request;
        const auto &policy = state.policy;

        // Probe Response is transmitted before association, so the recipient
        // cannot be assumed to support HT MCS rates. Reject HT management TX
        // rather than silently using a data-only modulation, preserving the
        // untouched descriptor on failure. A normal legacy-rate response works.
        request.packetType = TxPacketType::ProbeResponse;
        request.noAck = false;
        request.rate[0].rateCode =
            kFixtureHex80; // MCS0 cannot carry Probe Response.
        const TxDescriptor beforeProbeRate = descriptor;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforeProbeRate))
        {
            return static_cast<int>(Failure::Scenario47);
        }
        request.rate[0].rateCode = kFixtureHex1b;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::Ok ||
            !validTxPointerDescriptor(descriptor))
        {
            return static_cast<int>(Failure::Scenario48);
        }
        request.packetType = TxPacketType::Beacon;
        request.noAck = true;

        // Linux ath9k beacon.c: pkt_len = skb->len + FCS_LEN, but buf_len
        // = roundup(skb->len, 4). The 560-byte mapped DMA span is valid for
        // Beacon on-air sizes 561..564, including 0..3 bytes of tail padding.
        for (uint16_t onAir = kFixtureDec561; onAir <= kFixtureDec564; ++onAir)
        {
            request.onAirFrameLength = onAir;
            if (encodeTxControls(request, policy, descriptor) !=
                    TxControlError::Ok ||
                (descriptor.word[kFixtureDec11] & kFixtureHexfffu) != onAir)
            {
                return static_cast<int>(Failure::Scenario38);
            }
        }
        const TxDescriptor beforeInvalidPadding = descriptor;
        request.onAirFrameLength =
            kFixtureDec560; // Would need four padding bytes.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::FrameLengthInvalid ||
            !same(descriptor, beforeInvalidPadding))
        {
            return static_cast<int>(Failure::Scenario39);
        }
        request.onAirFrameLength =
            kFixtureDec565; // Too few mapped bytes for the frame.
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::FrameLengthInvalid ||
            !same(descriptor, beforeInvalidPadding))
        {
            return static_cast<int>(Failure::Scenario40);
        }
        // Other frame types never inherit the Beacon-only padding exception.
        request.packetType = TxPacketType::Normal;
        request.noAck = false;
        request.onAirFrameLength = kFixtureDec561;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::FrameLengthInvalid ||
            !same(descriptor, beforeInvalidPadding))
        {
            return static_cast<int>(Failure::Scenario41);
        }
        request.packetType = TxPacketType::ProbeResponse;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::FrameLengthInvalid ||
            !same(descriptor, beforeInvalidPadding))
        {
            return static_cast<int>(Failure::Scenario42);
        }

        return 0;
    }

    int checkBeaconRetries(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &descriptor = state.descriptor;
        auto &request = state.request;
        auto &policy = state.policy;

        // No station ACKs broadcast beacons. Unlike data retries, a beacon
        // must have exactly one transmit attempt in its first rate series.
        // Compare Linux ath9k beacon.c: series[0].Tries = 1.
        request.packetType = TxPacketType::Beacon;
        request.noAck = true;
        request.onAirFrameLength = kFixtureDec564;
        request.rate[0].attempts = 2;
        const TxDescriptor beforeBeaconRetries = descriptor;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforeBeaconRetries))
        {
            return static_cast<int>(Failure::Scenario43);
        }
        request.rate[0].attempts = 1;
        request.rate[1].attempts = 1;
        request.rate[1].rateCode = kFixtureHex1b;
        request.rate[1].antennaChainMask = 1;
        request.rate[1].powerIndex = 1;
        policy.maximumTxPowerIndex[1] = kFixtureDec8;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::UnsupportedControl ||
            !same(descriptor, beforeBeaconRetries))
        {
            return static_cast<int>(Failure::Scenario44);
        }
        request.rate[1] = {};
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::Ok ||
            ((descriptor.word[kFixtureDec13] >> kFixtureDec16u) &
             kFixtureHexffffu) != 1U)
        {
            return static_cast<int>(Failure::Scenario45);
        }
        // Multi-rate retries are still supported for ordinary data frames.
        request.packetType = TxPacketType::Normal;
        request.noAck = false;
        request.rate[0].attempts = 2;
        request.rate[1].attempts = 1;
        request.rate[1].rateCode = kFixtureHex0b;
        request.rate[1].antennaChainMask = 1;
        request.rate[1].powerIndex = 1;
        if (encodeTxControls(request, policy, descriptor) !=
                TxControlError::Ok ||
            ((descriptor.word[kFixtureDec13] >> kFixtureDec16u) &
             kFixtureHexffu) != kFixtureHex12u)
        {
            return static_cast<int>(Failure::Scenario46);
        }

        return 0;
    }

    int checkInitialReceive(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &rx = state.rx;
        auto &decoded = state.decoded;

        rx.word[0] = kFixtureHex168c0000u;
        rx.word[1] = kFixtureHex0b000000u;
        rx.word[2] = kFixtureDec128u;
        rx.word[3] = kFixtureDec7654u;
        rx.word[kFixtureDec5] = kFixtureHexd8000000u; // -40 dBm signed RSSI.
        rx.word[kFixtureDec11] = 3U;                  // Done, valid frame.
        if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
            !decoded.completed || !decoded.frameValid ||
            decoded.frameLength != kFixtureDec128 ||
            decoded.rateCode != kFixtureHex0b ||
            decoded.timestamp != kFixtureDec7654u ||
            decoded.combinedRssi != -kFixtureDec40)
        {
            return static_cast<int>(Failure::Scenario12);
        }
        // AR9565 has one RX chain and cannot report a successful 2-stream MCS8
        // or arbitrary/undefined modulation. A forged DMA status claiming FCS
        // success must not authorize that packet for native delivery.
        const uint8_t unsupportedRates[] {0x00, 0x04, 0x88, 0xff};
        for (const uint8_t rate : unsupportedRates)
        {
            rx.word[1] = static_cast<uint32_t>(rate) << kFixtureDec24u;
            decoded.completed = true;
            decoded.frameValid = true;
            decoded.frameLength = kFixtureDec128;
            if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
                decoded.completed || decoded.frameValid ||
                (decoded.frameLength != 0U))
            {
                return static_cast<int>(Failure::Scenario62);
            }
        }
        rx.word[1] =
            kFixtureHex80000000u; // AR9565 MCS0 is a supported single stream.
        if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
            !decoded.frameValid || decoded.rateCode != kFixtureHex80)
        {
            return static_cast<int>(Failure::Scenario63);
        }
        rx.word[4] = 0x2U; // HT40 PHY flag is coherent with an HT rate only.
        if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
            !decoded.frameValid || !decoded.ht40)
        {
            return static_cast<int>(Failure::Scenario64);
        }
        rx.word[1] = kFixtureHex0b000000u; // Legacy 6 Mbps cannot be HT40.
        if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
            decoded.completed || decoded.frameValid ||
            (decoded.frameLength != 0U))
        {
            return static_cast<int>(Failure::Scenario65);
        }
        rx.word[4] = 0;
        if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
            !decoded.frameValid || decoded.rateCode != kFixtureHex0b)
        {
            return static_cast<int>(Failure::Scenario66);
        }
        return 0;
    }

    int checkAggregatedReceive(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &rx = state.rx;
        auto &decoded = state.decoded;

        // Without a reviewed A-MPDU deaggregation/reorder/BlockAck pipeline,
        // aggregate fragments cannot be authorized for native RX delivery
        // solely by a successful per-buffer CRC and DMA completion bit. The
        // codec must not publish any status that asserts aggregate membership
        // or continuation.
        const uint32_t aggregateFlags[] = {
            0x00010000U,
            0x00020000U,
            0x20000000U,
            0x20030000U,
        };
        for (const uint32_t aggregate : aggregateFlags)
        {
            rx.word[kFixtureDec11] = 3U | aggregate;
            decoded.completed = true;
            decoded.frameValid = true;
            decoded.frameLength = kFixtureDec128;
            if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
                decoded.completed || decoded.frameValid ||
                (decoded.frameLength != 0U) || decoded.aggregated ||
                decoded.aggregationFirst || decoded.aggregationContinues)
            {
                return static_cast<int>(Failure::Scenario61);
            }
        }
        rx.word[kFixtureDec11] = 3U;
        // AR_RxMore is a chained DMA buffer, not a complete on-air MPDU.
        // Even an apparently good FCS bit cannot authorize forwarding a partial
        // buffer without a separately verified RX-chain reassembly path.
        rx.word[2] |= kFixtureHex1000u;
        if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
            decoded.completed || decoded.frameValid ||
            (decoded.frameLength != 0U))
        {
            return static_cast<int>(Failure::Scenario49);
        }
        rx.word[2] &= ~kFixtureHex1000u;
        if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
            !decoded.frameValid || decoded.frameLength != kFixtureDec128u)
        {
            return static_cast<int>(Failure::Scenario50);
        }
        // Even a control ACK/CTS MPDU has a ten-byte MAC header plus four
        // radio-received FCS octets. A forged completed status shorter than 14
        // bytes cannot be a valid 802.11 frame. Fourteen stays representable so
        // the downstream frame parser can classify/reject control subtypes.
        const uint32_t invalidShortLengths[] {1U, 4U, 13U};
        for (const uint32_t tooShort : invalidShortLengths)
        {
            rx.word[2] = tooShort;
            decoded.completed = true;
            decoded.frameValid = true;
            decoded.frameLength = static_cast<uint16_t>(tooShort);
            if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
                decoded.completed || decoded.frameValid ||
                (decoded.frameLength != 0U))
            {
                return static_cast<int>(Failure::Scenario67);
            }
        }
        rx.word[2] = kFixtureDec14u;
        if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
            !decoded.frameValid || decoded.frameLength != kFixtureDec14u)
        {
            return static_cast<int>(Failure::Scenario68);
        }
        return 0;
    }

    int checkReceiveBoundaries(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &rx = state.rx;
        auto &decoded = state.decoded;

        // The single-buffer, non-aggregating RX path has no reviewed MPDU
        // larger than the IEEE 802.11 2346-octet limit including its FCS.
        // A 12-bit hardware length alone cannot authorize a 4095-byte frame.
        rx.word[2] = kFixtureDec2346u;
        if (decodeRxStatus(rx, decoded) != DescriptorError::Ok ||
            !decoded.frameValid || decoded.frameLength != kFixtureDec2346u)
        {
            return static_cast<int>(Failure::Scenario51);
        }
        rx.word[2] = kFixtureDec2347u;
        if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
            decoded.completed || decoded.frameValid ||
            (decoded.frameLength != 0U))
        {
            return static_cast<int>(Failure::Scenario52);
        }
        rx.word[2] = kFixtureDec4095u;
        if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
            decoded.completed || decoded.frameValid ||
            (decoded.frameLength != 0U))
        {
            return static_cast<int>(Failure::Scenario53);
        }
        rx.word[2] = kFixtureDec128u;
        rx.word[kFixtureDec11] = 0;
        if (decodeRxStatus(rx, decoded) != DescriptorError::Incomplete ||
            decoded.completed || decoded.frameValid ||
            (decoded.frameLength != 0U))
        {
            return static_cast<int>(Failure::Scenario13);
        }
        rx.word[kFixtureDec11] = kFixtureDec7u; // CRC error.
        if (decodeRxStatus(rx, decoded) != DescriptorError::ReceiveError ||
            decoded.completed || decoded.frameValid ||
            (decoded.frameLength != 0U))
        {
            return static_cast<int>(Failure::Scenario14);
        }
        rx.word[0] = 0;
        if (decodeRxStatus(rx, decoded) != DescriptorError::InvalidVendor ||
            decoded.completed || (decoded.frameLength != 0U))
        {
            return static_cast<int>(Failure::Scenario15);
        }

        return 0;
    }

    int checkInitialCompletion(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &tx = state.tx;
        auto &completed = state.completed;

        tx.word[kFixtureDec8] =
            kFixtureDec24u << 1U; // No Done yet, regardless of bogus vendor.
        completed.frameTransmitOk = true;
        if (decodeTxCompletion(tx, completed) != DescriptorError::Incomplete ||
            completed.frameTransmitOk || (completed.sequenceNumber != 0U))
        {
            return static_cast<int>(Failure::Scenario16);
        }
        tx.word[kFixtureDec8] |= 1U; // Device has now set Done.
        tx.word[0] = kFixtureHex168c8000u | (kFixtureDec9u << kFixtureDec8u);
        tx.word[3] = 1U;
        tx.word[4] = kFixtureDec4433u;
        if (decodeTxCompletion(tx, completed) != DescriptorError::Ok ||
            completed.queue != kFixtureDec9 ||
            completed.sequenceNumber != kFixtureDec24 ||
            completed.timestamp != kFixtureDec4433u ||
            !completed.frameTransmitOk)
        {
            return static_cast<int>(Failure::Scenario17);
        }
        tx.word[0] = kFixtureHex168c8000u | (kFixtureDec15u << kFixtureDec8u);
        if (decodeTxCompletion(tx, completed) !=
                DescriptorError::CorruptStatus ||
            (completed.queue != 0U) || completed.frameTransmitOk ||
            (completed.sequenceNumber != 0U))
        {
            return static_cast<int>(Failure::Scenario18);
        }

        return 0;
    }

    int checkTxLengthBoundaries(const CodecScenario &state)
    {
        using namespace simpleath::edma;
        const auto &policy = state.policy;

        // A matching DMA pointer length does not make a 2347-byte standalone
        // MPDU legal. Aggregation/fragmentation are not implemented by this TX
        // codec; enforce the same 2346-byte on-air ceiling as the data encoder.
        TxPointerBlock oversizedPointer {};
        oversizedPointer.queue = kFixtureDec9;
        oversizedPointer.segmentCount = 1;
        oversizedPointer.segment[0] = {kFixtureHex1000ull, kFixtureDec2343};
        TxDescriptor oversizedDescriptor {};
        if (encodeTxPointers(oversizedPointer, oversizedDescriptor) !=
            DescriptorError::Ok)
        {
            return static_cast<int>(Failure::Scenario54);
        }
        TxControlRequest oversizedRequest {};
        oversizedRequest.onAirFrameLength = kFixtureDec2347;
        oversizedRequest.packetType = TxPacketType::Normal;
        oversizedRequest.crypto = TxCrypto::Clear;
        oversizedRequest.keyCacheIndex = kFixtureHexff;
        oversizedRequest.rate[0].attempts = 1;
        oversizedRequest.rate[0].rateCode = kFixtureHex0b;
        oversizedRequest.rate[0].antennaChainMask = 1;
        oversizedRequest.rate[0].powerIndex = 1;
        const TxDescriptor beforeOversizedTx = oversizedDescriptor;
        if (encodeTxControls(oversizedRequest, policy, oversizedDescriptor) !=
                TxControlError::FrameLengthInvalid ||
            !same(oversizedDescriptor, beforeOversizedTx))
        {
            return static_cast<int>(Failure::Scenario55);
        }
        oversizedPointer.segment[0].length = kFixtureDec4091;
        oversizedRequest.onAirFrameLength = kFixtureDec4095;
        if (encodeTxPointers(oversizedPointer, oversizedDescriptor) !=
                DescriptorError::Ok ||
            encodeTxControls(oversizedRequest, policy, oversizedDescriptor) !=
                TxControlError::FrameLengthInvalid)
        {
            return static_cast<int>(Failure::Scenario56);
        }
        // Exactly 2346 on-air octets with the matching 2342-byte DMA payload
        // remain representable when all of the separate policy gates pass.
        oversizedPointer.segment[0].length = kFixtureDec2342;
        oversizedRequest.onAirFrameLength = kFixtureDec2346;
        if (encodeTxPointers(oversizedPointer, oversizedDescriptor) !=
                DescriptorError::Ok ||
            encodeTxControls(oversizedRequest, policy, oversizedDescriptor) !=
                TxControlError::Ok)
        {
            return static_cast<int>(Failure::Scenario57);
        }

        return 0;
    }

    int checkTerminalTxStatus(CodecScenario &state)
    {
        using namespace simpleath::edma;
        auto &tx = state.tx;
        auto &completed = state.completed;

        // A completed descriptor cannot report both successful transmission and
        // a terminal failure. Reject forged/incoherent status words rather than
        // leaking a false success to the future TX completion handler.
        tx.word[0] = kFixtureHex168c8000u | (kFixtureDec9u << kFixtureDec8u);
        tx.word[kFixtureDec8] = (kFixtureDec24u << 1U) | 1U;
        const uint32_t terminalFailureBits[] = {
            0x00000002U, 0x00000004U, 0x00000008U, 0x00040000U, 0x00080000U,
        };
        for (const uint32_t terminal : terminalFailureBits)
        {
            tx.word[3] = terminal | 1U; // AR_FrmXmitOK and a terminal failure.
            completed.frameTransmitOk = true;
            if (decodeTxCompletion(tx, completed) !=
                    DescriptorError::CorruptStatus ||
                completed.frameTransmitOk || completed.excessiveRetries ||
                completed.fifoUnderrun || (completed.sequenceNumber != 0U))
            {
                return static_cast<int>(Failure::Scenario58);
            }
        }
        tx.word[3] = 1U;
        tx.word[kFixtureDec8] |=
            kFixtureHex00020000u; // TXOP exceeded despite XmitOK.
        completed.frameTransmitOk = true;
        if (decodeTxCompletion(tx, completed) !=
                DescriptorError::CorruptStatus ||
            completed.frameTransmitOk || completed.txOpportunityExceeded ||
            (completed.sequenceNumber != 0U))
        {
            return static_cast<int>(Failure::Scenario59);
        }
        // An ordinary failed TX retains its explicit diagnostic bits, but never
        // gets upgraded to a successful transmission.
        tx.word[kFixtureDec8] &= ~kFixtureHex00020000u;
        tx.word[3] = 0x00000002U;
        if (decodeTxCompletion(tx, completed) != DescriptorError::Ok ||
            completed.frameTransmitOk || !completed.excessiveRetries ||
            completed.sequenceNumber != kFixtureDec24u)
        {
            return static_cast<int>(Failure::Scenario60);
        }
        // A completed failure may legitimately carry the FIFO diagnostic bit,
        // but it must not be reported as successful transmission.
        tx.word[3] = 0x00000004U;
        if (decodeTxCompletion(tx, completed) != DescriptorError::Ok ||
            completed.frameTransmitOk || !completed.fifoUnderrun ||
            completed.sequenceNumber != kFixtureDec24u)
        {
            return static_cast<int>(Failure::Scenario71);
        }
        // AR_TxDataUnderrun and AR_TxDelimUnderrun are independent diagnostic
        // flags, unlike AR_FIFOUnderrun. Keep their exact status for a future
        // TX trigger-level owner without fabricating a terminal TX error.
        const uint32_t warningBits[] {0x00010000U, 0x00020000U, 0x00030000U};
        for (const uint32_t warning : warningBits)
        {
            tx.word[3] = 1U | warning;
            if (decodeTxCompletion(tx, completed) != DescriptorError::Ok ||
                !completed.frameTransmitOk ||
                completed.delimiterUnderrun !=
                    ((warning & kFixtureHex00010000u) != 0) ||
                completed.dataUnderrun !=
                    ((warning & kFixtureHex00020000u) != 0))
            {
                return static_cast<int>(Failure::Scenario72);
            }
        }
        tx.word[3] = 1U;
        if (decodeTxCompletion(tx, completed) != DescriptorError::Ok ||
            !completed.frameTransmitOk || completed.delimiterUnderrun ||
            completed.dataUnderrun)
        {
            return static_cast<int>(Failure::Scenario73);
        }
        return 0;
    }

} // namespace

int main()
{
    if (!exactLegacyRateWhitelist())
    {
        return kLegacyWhitelistFailure;
    }
    CodecScenario state {};
    const int checkPointerAndShortFramesResult =
        checkPointerAndShortFrames(state);
    if (checkPointerAndShortFramesResult != 0)
    {
        return checkPointerAndShortFramesResult;
    }
    const int checkInitialTxControlsResult = checkInitialTxControls(state);
    if (checkInitialTxControlsResult != 0)
    {
        return checkInitialTxControlsResult;
    }
    const int checkLegacyRateRestrictionsResult =
        checkLegacyRateRestrictions(state);
    if (checkLegacyRateRestrictionsResult != 0)
    {
        return checkLegacyRateRestrictionsResult;
    }
    const int checkProtectedManagementResult = checkProtectedManagement(state);
    if (checkProtectedManagementResult != 0)
    {
        return checkProtectedManagementResult;
    }
    const int checkProbeAndBeaconPaddingResult =
        checkProbeAndBeaconPadding(state);
    if (checkProbeAndBeaconPaddingResult != 0)
    {
        return checkProbeAndBeaconPaddingResult;
    }
    const int checkBeaconRetriesResult = checkBeaconRetries(state);
    if (checkBeaconRetriesResult != 0)
    {
        return checkBeaconRetriesResult;
    }
    const int checkInitialReceiveResult = checkInitialReceive(state);
    if (checkInitialReceiveResult != 0)
    {
        return checkInitialReceiveResult;
    }
    const int checkAggregatedReceiveResult = checkAggregatedReceive(state);
    if (checkAggregatedReceiveResult != 0)
    {
        return checkAggregatedReceiveResult;
    }
    const int checkReceiveBoundariesResult = checkReceiveBoundaries(state);
    if (checkReceiveBoundariesResult != 0)
    {
        return checkReceiveBoundariesResult;
    }
    const int checkInitialCompletionResult = checkInitialCompletion(state);
    if (checkInitialCompletionResult != 0)
    {
        return checkInitialCompletionResult;
    }
    const int checkTxLengthBoundariesResult = checkTxLengthBoundaries(state);
    if (checkTxLengthBoundariesResult != 0)
    {
        return checkTxLengthBoundariesResult;
    }
    const int checkTerminalTxStatusResult = checkTerminalTxStatus(state);
    if (checkTerminalTxStatusResult != 0)
    {
        return checkTerminalTxStatusResult;
    }
    return 0;
}
