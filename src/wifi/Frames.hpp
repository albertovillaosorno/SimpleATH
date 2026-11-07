// SPDX-License-Identifier: AGPL-3.0-only
// Portable 802.11 management frame parser and frame serializers.
// Parsing an AP beacon is not equivalent to having a working Wi-Fi radio.
#ifndef SIMPLEATH_IEEE80211_FRAMES_HPP
#define SIMPLEATH_IEEE80211_FRAMES_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath {
namespace ieee80211 {

enum class Result : uint8_t {
    Ok,
    NullBuffer,
    Truncated,
    InvalidFrame,
    UnsupportedFrame,
    InvalidElement,
    InvalidSecurity,
    BufferTooSmall,
    InvalidAddress,
    InvalidSsid
};

enum class FrameType : uint8_t {
    Management,
    Control,
    Data,
    Extension
};

enum class Security : uint8_t {
    Open,
    LegacyProtected,
    Wpa2Personal,
    Wpa2Enterprise,
    Wpa3Personal,
    UnsupportedRsn
};

struct Mac {
    uint8_t bytes[6];
};
bool sameMac(const Mac &left, const Mac &right);
bool validStationMac(const Mac &address);

struct Frame {
    FrameType type;
    uint8_t subtype;
    bool protectedFrame;
    bool moreFragments;
    bool toDs;
    bool fromDs;
    uint16_t sequence;
    uint8_t fragment;
    size_t headerLength;
    Mac destination;
    Mac source;
    Mac bssid; // Only defined for management or single-DS data frames.
};

Result parseFrame(const uint8_t *bytes, size_t length, Frame &out);

// The caller checks the parser result; malformed or unrecognized RSN suites
// must never be silently converted into a trusted open network.
struct Rsn {
    bool present;
    bool valid;
    bool pairwiseCcmp;
    bool groupCcmp;
    bool pairwiseTkip;
    bool akmPsk;
    bool akmEnterprise;
    bool akmSae;
    bool pmfCapable;
    bool pmfRequired;
    Security security;
};

struct Beacon {
    Mac bssid;
    uint8_t ssid[32];
    uint8_t ssidLength; // Binary SSID, not necessarily printable or null terminated.
    bool hiddenSsid;
    bool infrastructure;
    uint8_t channel; // 0 if the beacon does not advertise a channel.
    bool htSupported;
    bool ht40Allowed;
    uint64_t timestamp;
    uint16_t intervalTu;
    uint16_t capabilities;
    Rsn rsn;
};

struct Element {
    uint8_t id;
    const uint8_t *data;
    uint8_t length;
};

enum class CursorStatus : uint8_t { Element, End, Truncated };
class Elements {
public:
    Elements(const uint8_t *data, size_t length);
    CursorStatus next(Element &out);
private:
    const uint8_t *data_;
    size_t length_;
    size_t offset_;
};

Result parseRsn(const uint8_t *data, size_t length, Rsn &out);
Result parseBeacon(const uint8_t *frame, size_t length, Beacon &out);

// Serializers generate frame payloads only. The radio transport is NOT
// authorized to send them without EEPROM, regulatory and PHY initialization.
// They omit FCS, which the hardware TX chain is expected to generate.
Result makeProbeRequest(const Mac &station, const uint8_t *ssid,
                        size_t ssidLength, uint16_t sequence,
                        uint8_t *output, size_t capacity, size_t &written);
Result makeOpenAuthenticationRequest(const Mac &station, const Mac &bssid,
                                     uint16_t sequence, uint8_t *output,
                                     size_t capacity, size_t &written);

// Only open and WPA2-PSK (CCMP group and pairwise) association templates.
// No credentials or traffic keys are installed by this serializer.
Result makeAssociationRequest(const Mac &station, const Beacon &network,
                              uint16_t sequence, uint8_t *output,
                              size_t capacity, size_t &written);
Result parseAuthenticationResponse(const uint8_t *bytes, size_t length,
                                   const Mac &station, const Mac &bssid,
                                   uint16_t &statusCode);
Result parseAssociationResponse(const uint8_t *bytes, size_t length,
                                const Mac &station, const Mac &bssid,
                                uint16_t &statusCode, uint16_t &associationId);

} // namespace ieee80211
} // namespace simpleath
#endif
