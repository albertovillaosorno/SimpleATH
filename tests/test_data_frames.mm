// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Alberto Villa Osorno.
// Objective-C++ frontend plus real portable RX parser, without Apple frameworks.
#include "wifi/DataFrames.hpp"

#if !defined(__OBJC__) || !defined(__cplusplus)
#error This test requires the Objective-C++ frontend.
#endif

int main()
{
    using namespace simpleath::ieee80211;
    const char *encoding = @encode(uint32_t);
    if (!encoding || !encoding[0])
        return 1;
    uint8_t frame[33] {};
    frame[0] = 0x08; // Data.
    frame[1] = 0x02; // From DS.
    frame[4] = frame[10] = frame[16] = 0x02;
    frame[9] = 0x01;
    frame[15] = 0x02;
    frame[21] = 0x03;
    frame[24] = frame[25] = 0xaa;
    frame[26] = 0x03;
    frame[30] = 0x08; // RFC1042 IPv4 EtherType.
    frame[32] = 0x45;
    Msdu payload {};
    if (decodeLlcData(frame, sizeof(frame), false, false, payload) != Result::Ok ||
        payload.payload != frame + 32 || payload.payloadLength != 1 ||
        payload.etherType != 0x0800)
        return 2;
    frame[1] |= 0x40; // Protected data without verified decryption/MIC/PN.
    if (decodeLlcData(frame, sizeof(frame), false, false, payload) !=
            Result::InvalidSecurity ||
        payload.payload || payload.payloadLength)
        return 3;
    frame[1] = 0x02;
    frame[30] = 0x80;
    frame[31] = 0xf3; // AARP with ordinary RFC1042 OUI is unsupported.
    if (decodeLlcData(frame, sizeof(frame), false, false, payload) !=
        Result::UnsupportedFrame)
        return 4;
    frame[29] = 0xf8; // Bridge-tunnel OUI supports that Ethernet-II frame.
    if (decodeLlcData(frame, sizeof(frame), false, false, payload) != Result::Ok ||
        payload.etherType != 0x80f3)
        return 5;
    // Bridge-tunnel SNAP is reserved for AARP and IPX. An EAPOL-Key with
    // bridge-tunnel OUI is not a valid RFC 1042 WPA2 handshake payload.
    frame[30] = 0x88;
    frame[31] = 0x8e;
    if (decodeLlcData(frame, sizeof(frame), false, false, payload) !=
            Result::UnsupportedFrame ||
        payload.payload || payload.payloadLength)
        return 11;
    // Nor can an ordinary IPv4 frame borrow this exceptional SNAP OUI.
    frame[30] = 0x08;
    frame[31] = 0x00;
    if (decodeLlcData(frame, sizeof(frame), false, false, payload) !=
            Result::UnsupportedFrame ||
        payload.payload || payload.payloadLength)
        return 12;
    frame[30] = 0x81;
    frame[31] = 0x37; // Valid bridge-tunnel IPX still passes.
    if (decodeLlcData(frame, sizeof(frame), false, false, payload) != Result::Ok ||
        payload.etherType != 0x8137)
        return 13;
    frame[30] = 0x80;
    frame[31] = 0xf3;
    if (decodeLlcData(nullptr, 0, false, false, payload) != Result::NullBuffer ||
        payload.payload || payload.payloadLength)
        return 6;

    // A single legacy Data MPDU cannot exceed 2346 bytes on air, including
    // its four-byte FCS. Without an FCS in the borrowed buffer the limit is
    // 2342. Oversized frames must never reach Ethernet payload delivery.
    uint8_t oversized[2347] {};
    for (size_t i = 0; i < sizeof(frame); ++i)
        oversized[i] = frame[i];
    if (decodeLlcData(oversized, 2342, false, false, payload) != Result::Ok ||
        payload.payloadLength != 2310 || payload.payload != oversized + 32)
        return 7;
    if (decodeLlcData(oversized, 2346, true, false, payload) != Result::Ok ||
        payload.payloadLength != 2310 || payload.payload != oversized + 32)
        return 8;
    if (decodeLlcData(oversized, 2343, false, false, payload) !=
            Result::InvalidFrame ||
        payload.payload || payload.payloadLength)
        return 9;
    if (decodeLlcData(oversized, sizeof(oversized), true, false, payload) !=
            Result::InvalidFrame ||
        payload.payload || payload.payloadLength)
        return 10;
    return 0;
}
