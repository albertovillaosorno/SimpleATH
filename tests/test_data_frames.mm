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
    if (decodeLlcData(nullptr, 0, false, false, payload) != Result::NullBuffer ||
        payload.payload || payload.payloadLength)
        return 6;
    return 0;
}
