// Synthetic modern WCL byte-envelope fixtures. No native service or PMK I/O.
#include "platform/tahoe/TahoeJoinCodec.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>

namespace
{
    using simpleath::tahoe::clearJoin;
    using simpleath::tahoe::decodeJoin;
    using simpleath::tahoe::JoinSelection;
    using simpleath::tahoe::kWclJoinRequestBytes;
    using simpleath::tahoe::kWclPmkBytes;

    constexpr size_t kLowerAuthOffset = 0x10U;
    constexpr size_t kUpperAuthOffset = 0x14U;
    constexpr size_t kSsidLengthOffset = 0x1cU;
    constexpr size_t kSsidOffset = 0x20U;
    constexpr size_t kKeyLengthOffset = 0x44U;
    constexpr size_t kKeyCipherOffset = 0x48U;
    constexpr size_t kKeyOffset = 0x50U;
    constexpr size_t kRsnLengthOffset = 0xd4U;
    constexpr size_t kRsnOffset = 0xd6U;
    constexpr size_t kMloFlagsOffset = 0x1e0U;
    constexpr size_t kCandidateCountOffset = 0x214U;
    constexpr size_t kBssidOffset = 0x21cU;
    constexpr size_t kChannelSpecOffset = 0x228U;
    constexpr uint32_t kWpa2PskAuth = 1U << 3U;
    constexpr uint32_t kWclPmkCipher = 6U;
    constexpr uint32_t kWclPmksaCipher = 7U;
    constexpr uint32_t kWclPasswordCipher = 10U;
    constexpr size_t kPasswordBytes = 8U;
    constexpr int kPasswordFixtureFailure = 5;
    constexpr std::array<uint8_t, kPasswordBytes> kPassword {
        {
            'p',
            'a',
            's',
            's',
            'w',
            'o',
            'r',
            'd',
        },
    };
    constexpr std::array<uint8_t, kWclPmkBytes> kExpectedPasswordPmk {
        {
            0x04, 0x22, 0x1a, 0x7d, 0x2b, 0xb5, 0x2b, 0x87, 0x08, 0xd9, 0x6e,
            0xa2, 0xf5, 0xac, 0x3e, 0x0f, 0xe2, 0x60, 0x9a, 0x34, 0xdd, 0xfc,
            0x16, 0xa3, 0xc9, 0xf4, 0x64, 0xd2, 0xf5, 0xa7, 0x85, 0x0d,
        },
    };
    constexpr uint32_t kWpa3SaeAuth = 1U << 12U;
    constexpr uint32_t kOpenAuth = 1U;
    constexpr uint32_t kTestSsidLength = 4U;
    constexpr uint16_t k2GhzChannel6 = 0x1006U;
    constexpr uint16_t k5GhzChannel6 = 0xd006U;
    constexpr uint16_t k6GhzChannel6 = 0x5006U;
    constexpr uint16_t k40MhzChannel6 = 0x1806U;
    constexpr uint32_t kCountTooLarge = 11U;
    constexpr uint8_t kRsnElement = 48U;
    constexpr uint16_t kRsnVersion = 1U;
    constexpr uint16_t kShortRsnBytes = 4U;
    constexpr uint8_t kPrivacyFrame = 0x80U;
    constexpr uint8_t kPmkFirst = 0x51U;
    constexpr uint8_t kBssidLast = 0x55U;
    constexpr uint8_t kWrongPmkMarker = 0xaeU;
    constexpr uint8_t kWrongChannelMarker = 0xfcU;
    constexpr size_t kMacLastByteOffset = 5U;
    constexpr uint8_t kTestChannel = 6U;
    constexpr uint32_t kSsidTooLong = 33U;
    constexpr uint32_t kKeyTooLong = 63U;
    constexpr uint16_t kRsnTooLong = 258U;
    constexpr uint16_t kEmptyChannel = 0x1000U;

    using Wire = std::array<uint8_t, kWclJoinRequestBytes>;

    template <typename T> void write(Wire &wire, size_t offset, T value)
    {
        std::memcpy(&wire.at(offset), &value, sizeof(value));
    }

    Wire makeWpa2()
    {
        Wire wire {};
        write<uint32_t>(wire, kLowerAuthOffset, kOpenAuth);
        write<uint32_t>(wire, kUpperAuthOffset, kWpa2PskAuth);
        write<uint32_t>(wire, kSsidLengthOffset, kTestSsidLength);
        wire.at(kSsidOffset) = 'T';
        wire.at(kSsidOffset + 1U) = 'e';
        wire.at(kSsidOffset + 2U) = 's';
        wire.at(kSsidOffset + 3U) = 't';
        write<uint32_t>(wire, kKeyLengthOffset, kWclPmkBytes);
        write<uint32_t>(wire, kKeyCipherOffset, kWclPmkCipher);
        wire.at(kKeyOffset) = kPmkFirst;
        write<uint16_t>(wire, kRsnLengthOffset, kShortRsnBytes);
        wire.at(kRsnOffset) = kRsnElement;
        wire.at(kRsnOffset + 1U) = 2U;
        write<uint16_t>(wire, kRsnOffset + 2U, kRsnVersion);
        write<uint32_t>(wire, kCandidateCountOffset, 1U);
        wire.at(kBssidOffset) = 0x02U;
        wire.at(kBssidOffset + kMacLastByteOffset) = kBssidLast;
        write<uint16_t>(wire, kChannelSpecOffset, k2GhzChannel6);
        return wire;
    }

    bool checkPmkAndErase()
    {
        Wire request = makeWpa2();
        JoinSelection selection {};
        if (!decodeJoin(request.data(), request.size(), selection) ||
            !selection.wpa2Personal || selection.channel != kTestChannel ||
            selection.ssidLength != kTestSsidLength ||
            selection.ssid[0] != 'T' ||
            selection.bssid[kMacLastByteOffset] != kBssidLast ||
            selection.pmk[0] != kPmkFirst)
        {
            return false;
        }
        clearJoin(selection);
        if (!std::all_of(std::begin(selection.pmk), std::end(selection.pmk),
                         [](uint8_t byte)
                         {
                             return byte == 0;
                         }) ||
            !std::all_of(std::begin(selection.ssid), std::end(selection.ssid),
                         [](uint8_t byte)
                         {
                             return byte == 0;
                         }) ||
            !std::all_of(std::begin(selection.bssid), std::end(selection.bssid),
                         [](uint8_t byte)
                         {
                             return byte == 0;
                         }) ||
            selection.ssidLength != 0 || selection.channel != 0 ||
            selection.wpa2Personal)
        {
            return false;
        }
        // The source is always a borrow: scrubbing the private selection
        // never erases or mutates the owner-provided fixed native request.
        return request.at(kKeyOffset) == kPmkFirst;
    }

    bool checkOpenAndOtherPmk()
    {
        Wire request = makeWpa2();
        write<uint32_t>(request, kUpperAuthOffset, 0U);
        write<uint32_t>(request, kKeyLengthOffset, 0U);
        write<uint32_t>(request, kKeyCipherOffset, 0U);
        write<uint16_t>(request, kRsnLengthOffset, 0U);
        JoinSelection selection {};
        if (!decodeJoin(request.data(), request.size(), selection) ||
            selection.wpa2Personal || selection.channel != kTestChannel ||
            std::any_of(std::begin(selection.pmk), std::end(selection.pmk),
                        [](uint8_t value)
                        {
                            return value != 0;
                        }))
        {
            return false;
        }
        write<uint32_t>(request, kUpperAuthOffset, kWpa2PskAuth);
        write<uint32_t>(request, kKeyLengthOffset, kWclPmkBytes);
        write<uint32_t>(request, kKeyCipherOffset, kWclPmksaCipher);
        write<uint16_t>(request, kRsnLengthOffset, kShortRsnBytes);
        if (!decodeJoin(request.data(), request.size(), selection) ||
            !selection.wpa2Personal)
        {
            return false;
        }
        clearJoin(selection);
        return true;
    }

    bool identicalSelection(const JoinSelection &left,
                            const JoinSelection &right)
    {
        return std::equal(std::begin(left.ssid), std::end(left.ssid),
                          std::begin(right.ssid)) &&
               std::equal(std::begin(left.bssid), std::end(left.bssid),
                          std::begin(right.bssid)) &&
               std::equal(std::begin(left.pmk), std::end(left.pmk),
                          std::begin(right.pmk)) &&
               left.ssidLength == right.ssidLength &&
               left.channel == right.channel &&
               left.wpa2Personal == right.wpa2Personal;
    }

    bool acceptsPasswordWithExpectedPbkdf2()
    {
        Wire request = makeWpa2();
        write<uint32_t>(request, kKeyCipherOffset, kWclPasswordCipher);
        write<uint32_t>(request, kKeyLengthOffset, kPasswordBytes);
        std::fill_n(std::next(request.begin(), kKeyOffset), kWclPmkBytes, 0);
        std::copy(kPassword.begin(), kPassword.end(),
                  std::next(request.begin(), kKeyOffset));
        JoinSelection output {};
        if (!decodeJoin(request.data(), request.size(), output) ||
            !output.wpa2Personal ||
            !std::equal(kExpectedPasswordPmk.begin(),
                        kExpectedPasswordPmk.end(), std::begin(output.pmk)))
        {
            clearJoin(output);
            return false;
        }
        clearJoin(output);
        // Reject embedded NUL instead of deriving a different key from it.
        request.at(kKeyOffset + 1U) = 0U;
        return !decodeJoin(request.data(), request.size(), output);
    }

    bool rejectsMalformed()
    {
        const Wire valid = makeWpa2();
        JoinSelection sentinel {};
        sentinel.pmk[0] = kWrongPmkMarker;
        sentinel.channel = kWrongChannelMarker;
        const auto rejected = [&](const Wire &wire) -> bool
        {
            JoinSelection selection = sentinel;
            return !decodeJoin(wire.data(), wire.size(), selection) &&
                   identicalSelection(selection, sentinel);
        };
        const auto rejectedField = [&](size_t offset, auto value) -> bool
        {
            Wire wire = valid;
            write(wire, offset, value);
            return rejected(wire);
        };
        Wire truncated = valid;
        if (decodeJoin(nullptr, valid.size(), sentinel) ||
            decodeJoin(truncated.data(), truncated.size() - 1U, sentinel) ||
            !rejectedField(kCandidateCountOffset, uint32_t {0U}) ||
            !rejectedField(kCandidateCountOffset, kCountTooLarge) ||
            !rejectedField(kSsidLengthOffset, uint32_t {0U}) ||
            !rejectedField(kSsidLengthOffset, kSsidTooLong) ||
            !rejectedField(kLowerAuthOffset, uint32_t {0U}) ||
            !rejectedField(kUpperAuthOffset, kWpa3SaeAuth) ||
            !rejectedField(kUpperAuthOffset, kWpa2PskAuth | 1U) ||
            !rejectedField(kKeyLengthOffset, kKeyTooLong) ||
            !rejectedField(kRsnLengthOffset, kRsnTooLong) ||
            !rejectedField(kRsnLengthOffset, uint16_t {3U}) ||
            !rejectedField(kChannelSpecOffset, k5GhzChannel6) ||
            !rejectedField(kChannelSpecOffset, k6GhzChannel6) ||
            !rejectedField(kChannelSpecOffset, k40MhzChannel6) ||
            !rejectedField(kChannelSpecOffset, kEmptyChannel) ||
            !rejectedField(kMloFlagsOffset, kPrivacyFrame))
        {
            return false;
        }
        truncated.at(kBssidOffset) = 0U;
        truncated.at(kBssidOffset + kMacLastByteOffset) = 0U;
        if (!rejected(truncated))
        {
            return false;
        }
        truncated = valid;
        truncated.at(kBssidOffset) = 1U;
        if (!rejected(truncated))
        {
            return false;
        }
        truncated = valid;
        truncated.at(kKeyOffset) = 0;
        if (!rejected(truncated))
        {
            return false;
        }
        truncated = valid;
        truncated.at(kRsnOffset) = 0U;
        if (!rejected(truncated))
        {
            return false;
        }
        truncated = valid;
        truncated.at(kRsnOffset + 1U) = 3U;
        if (!rejected(truncated))
        {
            return false;
        }
        truncated = valid;
        write<uint16_t>(truncated, kRsnOffset + 2U, 2U);
        if (!rejected(truncated))
        {
            return false;
        }
        return sentinel.pmk[0] == kWrongPmkMarker &&
               sentinel.channel == kWrongChannelMarker;
    }

    bool rejectsOverlappingOutput()
    {
        alignas(JoinSelection) std::array<uint8_t, kWclJoinRequestBytes> wire =
            makeWpa2();
        // No output may overwrite borrowed bytes or a PMK in the WCL frame.
        // Deliberately form an adversarial overlapping native output view.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto *aliased = reinterpret_cast<JoinSelection *>(wire.data());
        const Wire before = wire;
        return !decodeJoin(wire.data(), wire.size(), *aliased) &&
               wire == before;
    }
} // namespace

int main()
{
    if (!checkPmkAndErase())
    {
        return 1;
    }
    if (!checkOpenAndOtherPmk())
    {
        return 2;
    }
    if (!acceptsPasswordWithExpectedPbkdf2())
    {
        return kPasswordFixtureFailure;
    }
    if (!rejectsMalformed())
    {
        return 3;
    }
    if (!rejectsOverlappingOutput())
    {
        return 4;
    }
    return 0;
}
