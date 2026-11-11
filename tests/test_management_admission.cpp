// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Offline regression cases for management admission.
// - Must-Not:
//   - Require physical hardware, mutate installed drivers, or suppress
//     failures.
// - Allows:
//   - Inputs: isolated fixtures and reproducible source-under-test inputs.
//   - Outputs: assertions and observable regression verdicts.
//   - Side effects: test-local temporary files and bounded subprocesses only.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Offline regression cases for management admission.
// - Description:
//   - Implements or verifies the test_management_admission source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for management admission.
// Host-only 802.11 admission regressions; no RF, Apple80211 or DMA inputs.
#include "wifi/Frames.hpp"
#include <cstdint>
#include <cstring>

namespace
{
    // Exact synthetic over-the-air bytes, corrupted input sizes and expected
    // fixture statuses are named, not inferred from untrusted frame lengths.
    constexpr auto kFixtureInt5 = 5;
    constexpr auto kFixtureInt6 = 6;
    constexpr auto kFixtureInt7 = 7;
    constexpr auto kFixtureHex08 = 0x08;
    constexpr auto kFixtureInt8 = 8;
    constexpr auto kFixtureInt9 = 9;
    constexpr auto kFixtureInt10 = 10;
    constexpr auto kFixtureInt11 = 11;
    constexpr auto kFixtureHex0c = 0x0c;
    constexpr auto kFixtureInt12 = 12;
    constexpr auto kFixtureInt13 = 13;
    constexpr auto kFixtureInt14 = 14;
    constexpr auto kFixtureInt15 = 15;
    constexpr auto kFixtureHex10 = 0x10;
    constexpr auto kFixtureInt16 = 16;
    constexpr auto kFixtureHex11 = 0x11;
    constexpr auto kFixtureHex11U = 0x11U;
    constexpr auto kFixtureInt17 = 17;
    constexpr auto kFixtureHex12 = 0x12;
    constexpr auto kFixtureInt18 = 18;
    constexpr auto kFixtureInt19 = 19;
    constexpr auto kFixtureInt20 = 20;
    constexpr auto kFixtureInt21 = 21;
    constexpr auto kFixtureInt22 = 22;
    constexpr auto kFixtureInt23 = 23;
    constexpr auto kFixtureInt24 = 24;
    constexpr auto kFixtureInt25 = 25;
    constexpr auto kFixtureInt26 = 26;
    constexpr auto kFixtureInt28 = 28;
    constexpr auto kFixtureInt29 = 29;
    constexpr auto kFixtureInt30 = 30;
    constexpr auto kFixtureInt31 = 31;
    constexpr auto kFixtureInt32 = 32;
    constexpr auto kFixtureInt33 = 33;
    constexpr auto kFixtureHex22 = 0x22;
    constexpr auto kFixtureInt34 = 34;
    constexpr auto kFixtureInt35 = 35;
    constexpr auto kFixtureInt36 = 36;
    constexpr auto kFixtureInt37 = 37;
    constexpr auto kFixtureInt38 = 38;
    constexpr auto kFixtureInt39 = 39;
    constexpr auto kFixtureInt40 = 40;
    constexpr auto kFixtureInt41 = 41;
    constexpr auto kFixtureInt42 = 42;
    constexpr auto kFixtureInt43 = 43;
    constexpr auto kFixtureInt44 = 44;
    constexpr auto kFixtureInt45 = 45;
    constexpr auto kFixtureInt46 = 46;
    constexpr auto kFixtureInt47 = 47;
    constexpr auto kFixtureInt48 = 48;
    constexpr auto kFixtureInt50 = 50;
    constexpr auto kFixtureInt55 = 55;
    constexpr auto kFixtureInt61 = 61;
    constexpr auto kFixtureHex40 = 0x40;
    constexpr auto kFixtureInt64 = 64;
    constexpr auto kFixtureHex44 = 0x44;
    constexpr auto kFixtureInt77 = 77;
    constexpr auto kFixtureHex50 = 0x50;
    constexpr auto kFixtureHex55 = 0x55;
    constexpr auto kFixtureInt88 = 88;
    constexpr auto kFixtureHex5a = 0x5a;
    constexpr auto kFixtureInt96 = 96;
    constexpr auto kFixtureInt99 = 99;
    constexpr auto kFixtureInt100 = 100;
    constexpr auto kFixtureInt123 = 123;
    constexpr auto kFixtureHex7f = 0x7f;
    constexpr auto kFixtureHex80 = 0x80;
    constexpr auto kFixtureInt128 = 128;
    constexpr auto kFixtureHex82 = 0x82;
    constexpr auto kFixtureHex84 = 0x84;
    constexpr auto kFixtureHex8c = 0x8c;
    constexpr auto kFixtureHexa5 = 0xa5;
    constexpr auto kFixtureHexb0 = 0xb0;
    constexpr auto kFixtureHexc0 = 0xc0;
    constexpr auto kFixtureHexdd = 0xdd;
    constexpr auto kFixtureInt221 = 221;
    constexpr auto kFixtureHexfe = 0xfe;
    constexpr auto kFixtureHexff = 0xff;
    constexpr auto kFixtureInt321 = 321;
    constexpr auto kFixtureInt456 = 456;
    constexpr auto kFixtureInt543 = 543;
    constexpr auto kFixtureInt777 = 777;
    constexpr auto kFixtureInt789 = 789;
    constexpr auto kFixtureInt888 = 888;
    constexpr auto kFixtureInt999 = 999;
    constexpr auto kFixtureHexffff = 0xffff;
    constexpr auto kFixtureHexffffU = 0xffffU;
    constexpr auto kFixtureHex11223344U = 0x11223344U;

    template <typename T, size_t N> T *arrayData(T (&array)[N])
    {
        return &array[0U];
    }

    template <typename T, size_t N> T &arrayAt(T (&array)[N], size_t index)
    {
        for (T &item : array)
        {
            if (index == 0U)
            {
                return item;
            }
            --index;
        }
        __builtin_trap();
    }

    // These tests intentionally alias an output object with hostile input
    // bytes; copy the pointer representation rather than type-punning it.
    // Byte-preserving pointer conversion is required when the fixture
    // deliberately aliases raw input and the corresponding output object.
    template <typename T> uint8_t *byteView(T &object)
    {
        const T *const original = &object;
        uintptr_t address = 0U;
        static_assert(sizeof(const T *) == sizeof(address),
                      "Host pointer width required for alias regression");
        __builtin_memcpy(static_cast<void *>(&address),
                         static_cast<const void *>(&original), sizeof(address));
        uint8_t *result = nullptr;
        __builtin_memcpy(static_cast<void *>(&result),
                         static_cast<const void *>(&address), sizeof(result));
        return result;
    }

    template <typename T> const uint8_t *byteView(const T &object)
    {
        const T *const original = &object;
        uintptr_t address = 0U;
        static_assert(sizeof(const T *) == sizeof(address),
                      "Host pointer width required for alias regression");
        __builtin_memcpy(static_cast<void *>(&address),
                         static_cast<const void *>(&original), sizeof(address));
        const uint8_t *result = nullptr;
        __builtin_memcpy(static_cast<void *>(&result),
                         static_cast<const void *>(&address), sizeof(result));
        return result;
    }

    uint8_t *byteAt(uint8_t *base, size_t extent, size_t index)
    {
        if (base == nullptr || index >= extent)
        {
            __builtin_trap();
        }
        uintptr_t address = 0U;
        static_assert(sizeof(uint8_t *) == sizeof(address),
                      "Host byte pointer must fit an address");
        __builtin_memcpy(static_cast<void *>(&address),
                         static_cast<const void *>(&base), sizeof(address));
        if (index == 0U)
        {
            return base;
        }
        if (index > UINTPTR_MAX - address)
        {
            __builtin_trap();
        }
        address += index;
        uint8_t *result = nullptr;
        __builtin_memcpy(static_cast<void *>(&result),
                         static_cast<const void *>(&address), sizeof(result));
        return result;
    }

    using namespace simpleath::ieee80211;

    constexpr size_t kBeaconBytes = 49;
    constexpr size_t kAssocBytes = 34;
    constexpr uint8_t kAp[6] {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    constexpr uint8_t kStation[6] {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa};

    template <size_t N> void makeBeacon(uint8_t (&out)[N])
    {
        static_assert(N >= kBeaconBytes, "Beacon fixture capacity");
        std::memset(arrayData(out), 0, kBeaconBytes);
        out[0] = kFixtureHex80; // Beacon management subtype.
        std::memset(&arrayAt(out, 4), kFixtureHexff, kFixtureInt6);
        std::memcpy(&arrayAt(out, kFixtureInt10), arrayData(kAp), kFixtureInt6);
        std::memcpy(&arrayAt(out, kFixtureInt16), arrayData(kAp), kFixtureInt6);
        out[kFixtureInt32] = kFixtureInt100; // Beacon interval.
        out[kFixtureInt34] = 1;              // Infrastructure BSS.
        out[kFixtureInt36] = 0;              // SSID element.
        out[kFixtureInt37] = 4;
        std::memcpy(&arrayAt(out, kFixtureInt38), "Test", 4);
        out[kFixtureInt42] = 1; // Supported Rates.
        out[kFixtureInt43] = 2;
        out[kFixtureInt44] = kFixtureHex82;
        out[kFixtureInt45] = kFixtureHex84;
        out[kFixtureInt46] = 3; // DS parameter set.
        out[kFixtureInt47] = 1;
        out[kFixtureInt48] = kFixtureInt6;
    }

    template <size_t N> void makeAssoc(uint8_t (&out)[N])
    {
        static_assert(N >= kAssocBytes, "Assoc fixture capacity");
        std::memset(arrayData(out), 0, kAssocBytes);
        out[0] = kFixtureHex10; // Association response.
        std::memcpy(&arrayAt(out, 4), arrayData(kStation), kFixtureInt6);
        std::memcpy(&arrayAt(out, kFixtureInt10), arrayData(kAp), kFixtureInt6);
        std::memcpy(&arrayAt(out, kFixtureInt16), arrayData(kAp), kFixtureInt6);
        out[kFixtureInt24] = 1;    // Infrastructure capability.
        out[kFixtureInt28] = 0x01; // AID 1, with required top two bits set.
        out[kFixtureInt29] = kFixtureHexc0;
        out[kFixtureInt30] = 1; // Supported rates IE.
        out[kFixtureInt31] = 2;
        out[kFixtureInt32] = kFixtureHex82;
        out[kFixtureInt33] = kFixtureHex84;
    }

    bool rejectStaleElementCursorViews()
    {
        uint8_t valid[] {0, 1, 'A'};
        Elements cursor(arrayData(valid), sizeof(valid));
        Element item {};
        if (cursor.next(item) != CursorStatus::Element || item.id != 0 ||
            item.length != 1 || item.data != &arrayAt(valid, 2))
        {
            return false;
        }
        // End must revoke the last borrowed payload pointer; the owner may
        // release DMA-backed bytes after parsing finishes.
        if (cursor.next(item) != CursorStatus::End || item.data != nullptr ||
            item.length != 0 || item.id != 0)
        {
            return false;
        }

        uint8_t truncated[] {0, 1, 'B', 2, 3, 'C'};
        Elements malformed(arrayData(truncated), sizeof(truncated));
        if (malformed.next(item) != CursorStatus::Element ||
            item.data != &arrayAt(truncated, 2))
        {
            return false;
        }
        // A truncated next element must not retain a previously accepted
        // borrowed pointer, or advance past the malformed element.
        if (malformed.next(item) != CursorStatus::Truncated ||
            item.data != nullptr || item.length != 0 || item.id != 0 ||
            malformed.next(item) != CursorStatus::Truncated)
        {
            return false;
        }

        // An output that points into the input frame must not erase its
        // bytes, or cause the cursor to advance on a rejected attempt.
        struct Storage
        {
                Element output;
                uint8_t tail[kFixtureInt16];
        } storage {};

        auto *frame = byteView(storage);
        *byteAt(frame, sizeof(storage), 0U) = 0U;
        *byteAt(frame, sizeof(storage), 1U) = 0U;
        uint8_t original[sizeof(storage)] {};
        std::memcpy(arrayData(original), frame, sizeof(storage));
        Elements aliased(frame, sizeof(storage));
        if (aliased.next(storage.output) != CursorStatus::Truncated ||
            std::memcmp(arrayData(original), frame, sizeof(storage)) != 0)
        {
            return false;
        }
        if (aliased.next(item) != CursorStatus::Element || item.id != 0 ||
            item.length != 0 || item.data != byteAt(frame, sizeof(storage), 2U))
        {
            return false;
        }
        return true;
    }

    bool rejectOversizedManagementMpdu()
    {
        // A single legacy management MPDU cannot exceed 2346 bytes on air.
        // The parser must reject a corrupt oversized DMA length before
        // walking an attacker-controlled information-element stream.
        constexpr size_t kMaximumMpduBytes = 2346;
        uint8_t frame[kMaximumMpduBytes + 1] {};
        makeBeacon(frame);
        Frame header {};
        if (parseFrame(arrayData(frame), kMaximumMpduBytes, header) !=
                Result::Ok ||
            header.type != FrameType::Management)
        {
            return false;
        }
        if (parseFrame(arrayData(frame), sizeof(frame), header) !=
                Result::InvalidFrame ||
            (header.headerLength != 0U) || (header.subtype != 0U))
        {
            return false;
        }
        Beacon beacon {};
        if (parseBeacon(arrayData(frame), sizeof(frame), beacon) !=
                Result::InvalidFrame ||
            (beacon.ssidLength != 0U) ||
            beacon.rsn.security != Security::UnsupportedRsn)
        {
            return false;
        }
        // Data MPDUs keep their own, stricter admission/fragmentation gates.
        frame[0] = kFixtureHex08;
        return parseFrame(arrayData(frame), sizeof(frame), header) ==
                   Result::Ok &&
               header.type == FrameType::Data;
    }

    bool validBeacon()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon parsed {};
        if (parseBeacon(arrayData(frame), sizeof(frame), parsed) !=
                Result::Ok ||
            !parsed.infrastructure || parsed.hiddenSsid ||
            parsed.channel != kFixtureInt6 ||
            parsed.intervalTu != kFixtureInt100 || parsed.rateCount != 2 ||
            parsed.rates[0] != kFixtureHex82 || parsed.ssidLength != 4 ||
            parsed.ssid[0] != 'T')
        {
            return false;
        }
        Frame header {};
        return parseFrame(arrayData(frame), sizeof(frame), header) ==
                   Result::Ok &&
               header.type == FrameType::Management &&
               header.subtype == kFixtureInt8 && !header.moreFragments &&
               header.fragment == 0;
    }

    bool rejectZeroBeaconInterval()
    {
        // A zero TU interval is not a valid AP advertisement. A direct
        // parser consumer must not retain an earlier BSSID/security verdict
        // when the next Beacon or Probe Response has invalid fixed fields.
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon parsed {};
        if (parseBeacon(arrayData(frame), sizeof(frame), parsed) != Result::Ok)
        {
            return false;
        }
        frame[kFixtureInt32] = 0;
        frame[kFixtureInt33] = 0;
        if (parseBeacon(arrayData(frame), sizeof(frame), parsed) !=
                Result::InvalidFrame ||
            parsed.intervalTu != 0 || parsed.ssidLength != 0 ||
            parsed.bssid.bytes[0] != 0 ||
            parsed.rsn.security != Security::UnsupportedRsn)
        {
            return false;
        }
        makeBeacon(frame);
        frame[0] = kFixtureHex50; // A directed Probe Response has the same
                                  // fixed fields.
        std::memcpy(&arrayAt(frame, 4), arrayData(kStation), kFixtureInt6);
        frame[kFixtureInt32] = 0;
        return parseBeacon(arrayData(frame), sizeof(frame), parsed) ==
                   Result::InvalidFrame &&
               parsed.intervalTu == 0 && parsed.ssidLength == 0;
    }

    bool rejectHiddenAssociationName()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        // A hidden AP can advertise a fixed-length, entirely zero SSID.
        // It must not be serialized into an association as a visible name.
        std::memset(&arrayAt(frame, kFixtureInt38), 0, 4);
        Beacon hidden {};
        if (parseBeacon(arrayData(frame), sizeof(frame), hidden) !=
                Result::Ok ||
            !hidden.hiddenSsid || hidden.ssidLength != 4)
        {
            return false;
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[kFixtureInt96] {};
        std::memset(arrayData(output), kFixtureHexa5, sizeof(output));
        size_t written = kFixtureInt77;
        if (makeAssociationRequest(station, hidden, 1, arrayData(output),
                                   sizeof(output),
                                   written) != Result::InvalidSsid ||
            written != 0 || output[0] != kFixtureHexa5)
        {
            return false;
        }
        // A forged Beacon may lie about its hidden flag. Only a genuinely
        // nonzero visible name should be eligible for serialization.
        hidden.hiddenSsid = false;
        written = kFixtureInt77;
        if (makeAssociationRequest(station, hidden, 2, arrayData(output),
                                   sizeof(output),
                                   written) != Result::InvalidSsid ||
            written != 0 || output[0] != kFixtureHexa5)
        {
            return false;
        }
        makeBeacon(frame);
        Beacon visible {};
        return parseBeacon(arrayData(frame), sizeof(frame), visible) ==
                   Result::Ok &&
               makeAssociationRequest(station, visible, 3, arrayData(output),
                                      sizeof(output), written) == Result::Ok &&
               written != 0 && output[0] == 0;
    }

    bool rejectSelfBssidManagementTx()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Beacon network {};
        if (parseBeacon(arrayData(advertisement), sizeof(advertisement),
                        network) != Result::Ok)
        {
            return false;
        }
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[kFixtureInt128] {};
        std::memset(arrayData(output), kFixtureHexa5, sizeof(output));
        size_t written = kFixtureInt77;
        // Public serializers can be called without Station::select.
        // Refuse a self-AP identity before publishing any on-air bytes.
        if (makeOpenAuthenticationRequest(ap, ap, 1, arrayData(output),
                                          sizeof(output),
                                          written) != Result::InvalidAddress ||
            written != 0 || output[0] != kFixtureHexa5)
        {
            return false;
        }
        written = kFixtureInt77;
        if (makeAssociationRequest(ap, network, 2, arrayData(output),
                                   sizeof(output),
                                   written) != Result::InvalidAddress ||
            written != 0 || output[0] != kFixtureHexa5)
        {
            return false;
        }
        // Ordinary distinct station/AP addresses remain accepted.
        if (makeOpenAuthenticationRequest(station, ap, 3, arrayData(output),
                                          sizeof(output),
                                          written) != Result::Ok ||
            written != kFixtureInt30)
        {
            return false;
        }
        return makeAssociationRequest(station, network, 4, arrayData(output),
                                      sizeof(output), written) == Result::Ok &&
               written != 0;
    }

    bool rejectFragmentsAndForeignBssid()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon out {};
        frame[1] = static_cast<uint8_t>(
            static_cast<unsigned>(frame[1]) |
            static_cast<unsigned>(0x04)); // More Fragments on initial fragment.
        if (parseBeacon(arrayData(frame), sizeof(frame), out) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        makeBeacon(frame);
        frame[kFixtureInt22] = 0x01; // Nonzero fragment index.
        if (parseBeacon(arrayData(frame), sizeof(frame), out) !=
            Result::UnsupportedFrame)
        {
            return false;
        }
        makeBeacon(frame);
        frame[kFixtureInt15] = static_cast<uint8_t>(
            static_cast<unsigned>(frame[kFixtureInt15]) ^
            static_cast<unsigned>(0x02)); // AP's source differs from BSSID.
        if (parseBeacon(arrayData(frame), sizeof(frame), out) !=
            Result::InvalidFrame)
        {
            return false;
        }
        makeBeacon(frame);
        std::memcpy(&arrayAt(frame, 4), arrayData(kStation),
                    kFixtureInt6); // Beacon must be broadcast.
        if (parseBeacon(arrayData(frame), sizeof(frame), out) !=
            Result::InvalidFrame)
        {
            return false;
        }
        makeBeacon(frame);
        frame[4] =
            kFixtureHexfe; // Other group-addressed beacons are not broadcast.
        if (parseBeacon(arrayData(frame), sizeof(frame), out) !=
            Result::InvalidFrame)
        {
            return false;
        }
        makeBeacon(frame);
        frame[0] =
            kFixtureHex50; // A Probe Response may be directed to our station.
        std::memcpy(&arrayAt(frame, 4), arrayData(kStation), kFixtureInt6);
        if (parseBeacon(arrayData(frame), sizeof(frame), out) != Result::Ok)
        {
            return false;
        }
        makeBeacon(frame);
        frame[1] = static_cast<uint8_t>(
            static_cast<unsigned>(frame[1]) |
            static_cast<unsigned>(
                kFixtureHex40)); // Protected management frame without decrypt.
        return parseBeacon(arrayData(frame), sizeof(frame), out) ==
               Result::InvalidFrame;
    }

    bool rejectConflictingBssModes()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon parsed {};
        // IEEE 802.11 ESS and IBSS are mutually exclusive. A forged
        // advertisement setting both must not be selected as infrastructure.
        frame[kFixtureInt34] = 3;
        if (parseBeacon(arrayData(frame), sizeof(frame), parsed) !=
            Result::InvalidFrame)
        {
            return false;
        }
        makeBeacon(frame);
        frame[kFixtureInt34] =
            2; // A legitimate IBSS remains non-infrastructure.
        if (parseBeacon(arrayData(frame), sizeof(frame), parsed) !=
                Result::Ok ||
            parsed.infrastructure)
        {
            return false;
        }
        makeBeacon(frame);
        return parseBeacon(arrayData(frame), sizeof(frame), parsed) ==
                   Result::Ok &&
               parsed.infrastructure;
    }

    bool rejectInvalidAssociationTimingAndChannel()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Beacon network {};
        if (parseBeacon(arrayData(advertisement), sizeof(advertisement),
                        network) != Result::Ok)
        {
            return false;
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[kFixtureInt128] {};
        const auto rejected = [&]() -> bool
        {
            std::memset(arrayData(output), kFixtureHexa5, sizeof(output));
            size_t written = kFixtureInt47;
            const size_t needed = associationRequestLength(network);
            const Result result =
                makeAssociationRequest(station, network, 1, arrayData(output),
                                       sizeof(output), written);
            return needed == 0 && result == Result::InvalidFrame &&
                   written == 0 && output[0] == kFixtureHexa5;
        };

        // Public clients can synthesize Beacon metadata without parseBeacon
        // or Station::select. Neither a zero beacon cadence nor a missing or
        // invalid channel is a viable association request destination.
        network.intervalTu = 0;
        if (!rejected())
        {
            return false;
        }
        network.intervalTu = kFixtureInt100;
        network.channel = 0;
        if (!rejected())
        {
            return false;
        }
        network.channel = kFixtureInt15;
        if (!rejected())
        {
            return false;
        }
        network.channel = kFixtureInt6;
        size_t written = 0;
        return associationRequestLength(network) != 0 &&
               makeAssociationRequest(station, network, 2, arrayData(output),
                                      sizeof(output), written) == Result::Ok &&
               written != 0 && output[0] == 0;
    }

    bool rejectForgedBssAssociationTx()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Beacon network {};
        if (parseBeacon(arrayData(advertisement), sizeof(advertisement),
                        network) != Result::Ok)
        {
            return false;
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[kFixtureInt128] {};
        std::memset(arrayData(output), kFixtureHexa5, sizeof(output));
        // A caller-built Beacon can forge the infrastructure flag. The
        // serializer must independently enforce ESS-only capabilities.
        const uint16_t invalidModes[] {0U, 2U, 3U};
        for (const uint16_t mode : invalidModes)
        {
            network.capabilities = mode;
            size_t written = kFixtureInt77;
            if (makeAssociationRequest(station, network, 1, output,
                                       sizeof(output),
                                       written) != Result::InvalidFrame ||
                written != 0 || output[0] != kFixtureHexa5)
            {
                return false;
            }
        }
        // Correct infrastructure metadata still produces a request.
        network.capabilities = 1U;
        size_t written = 0;
        return makeAssociationRequest(station, network, 2, arrayData(output),
                                      sizeof(output), written) == Result::Ok &&
               written != 0 && output[0] == 0;
    }

    bool rejectForgedPrivacyAssociationTx()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Beacon network {};
        if (parseBeacon(arrayData(advertisement), sizeof(advertisement),
                        network) != Result::Ok)
        {
            return false;
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[kFixtureInt128] {};
        const auto rejected = [&]() -> bool
        {
            std::memset(arrayData(output), kFixtureHexa5, sizeof(output));
            size_t written = kFixtureInt37;
            return makeAssociationRequest(station, network, 1,
                                          arrayData(output), sizeof(output),
                                          written) == Result::InvalidSecurity &&
                   written == 0 && output[0] == kFixtureHexa5;
        };

        // Beacon::rsn.security and RSN suite flags are caller-controlled.
        // Neither an Open downgrade of a privacy BSS, nor a forged WPA2
        // upgrade without a real matching RSNE, may emit association bytes.
        network.capabilities = kFixtureHex11U; // Privacy on but labeled Open.
        if (!rejected())
        {
            return false;
        }
        network.capabilities = 1U;
        network.rsn.security = Security::Wpa2Personal;
        network.rsn.present = true;
        network.rsn.valid = true;
        network.rsn.groupCcmp = true;
        network.rsn.pairwiseCcmp = true;
        network.rsn.akmPsk = true;
        if (!rejected())
        { // Privacy off, RSNE absent.
            return false;
        }
        network.capabilities = kFixtureHex11U;
        if (!rejected())
        { // Privacy on, RSNE still absent.
            return false;
        }
        const uint8_t rsnIe[22] {
            48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
            0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
        };
        std::memcpy(arrayData(network.rsnIe), arrayData(rsnIe), sizeof(rsnIe));
        network.rsnIeLength = sizeof(rsnIe);
        network.rsnIe[kFixtureInt7] =
            2; // Fake metadata says CCMP; RSNE says TKIP.
        if (!rejected())
        {
            return false;
        }
        network.rsnIe[kFixtureInt7] = 4;
        size_t written = 0;
        return makeAssociationRequest(station, network, 2, arrayData(output),
                                      sizeof(output), written) == Result::Ok &&
               written != 0 && output[0] == 0;
    }

    bool rejectInvalidRates()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon out {};
        frame[kFixtureInt42] =
            kFixtureInt50; // Extended rates alone cannot replace base rates.
        if (parseBeacon(arrayData(frame), sizeof(frame), out) !=
            Result::InvalidElement)
        {
            return false;
        }
        makeBeacon(frame);
        frame[kFixtureInt44] = kFixtureHex80; // Invalid zero-valued basic rate.
        if (parseBeacon(arrayData(frame), sizeof(frame), out) !=
            Result::InvalidElement)
        {
            return false;
        }
        makeBeacon(frame);
        frame[kFixtureInt48] = kFixtureInt15; // Unsupported 2.4 GHz channel.
        return parseBeacon(arrayData(frame), sizeof(frame), out) ==
               Result::InvalidElement;
    }

    bool rejectRsnDowngradeAndDuplicates()
    {
        // WPA2-PSK/CCMP RSN IE and privacy bit on an otherwise valid beacon.
        constexpr uint8_t rsnIe[22] {
            48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
            0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
        };
        uint8_t frame[kBeaconBytes + (2 * sizeof(rsnIe))] {};
        makeBeacon(frame);
        frame[kFixtureInt34] = kFixtureHex11;
        std::memcpy(&arrayAt(frame, kBeaconBytes), arrayData(rsnIe),
                    sizeof(rsnIe));
        Beacon parsed {};
        if (parseBeacon(arrayData(frame), kBeaconBytes + sizeof(rsnIe),
                        parsed) != Result::Ok ||
            parsed.rsn.security != Security::Wpa2Personal ||
            !parsed.rsn.pairwiseCcmp || !parsed.rsn.akmPsk ||
            parsed.rsnIeLength != sizeof(rsnIe) ||
            std::memcmp(arrayData(parsed.rsnIe), arrayData(rsnIe),
                        sizeof(rsnIe)) != 0)
        {
            return false;
        }

        // Pairwise CCMP and PSK do not make a group-TKIP (or unknown group)
        // advertisement usable by this CCMP-only station. Preserve the
        // parsed suite metadata, but classify it as unsupported for scanning.
        frame[kBeaconBytes + kFixtureInt7] = 2; // Group cipher TKIP.
        if (parseBeacon(arrayData(frame), kBeaconBytes + sizeof(rsnIe),
                        parsed) != Result::Ok ||
            parsed.rsn.security != Security::UnsupportedRsn ||
            parsed.rsn.groupCcmp || !parsed.rsn.pairwiseCcmp ||
            !parsed.rsn.akmPsk)
        {
            return false;
        }
        frame[kBeaconBytes + kFixtureInt7] =
            kFixtureHex7f; // Unknown group cipher.
        if (parseBeacon(arrayData(frame), kBeaconBytes + sizeof(rsnIe),
                        parsed) != Result::Ok ||
            parsed.rsn.security != Security::UnsupportedRsn)
        {
            return false;
        }
        frame[kBeaconBytes + kFixtureInt7] =
            4;                       // Restore compatible CCMP group.
        frame[kFixtureInt34] = 0x01; // Forged RSN on an Open capability BSS.
        if (parseBeacon(arrayData(frame), kBeaconBytes + sizeof(rsnIe),
                        parsed) != Result::InvalidSecurity)
        {
            return false;
        }
        frame[kFixtureInt34] = kFixtureHex11;
        std::memcpy(&arrayAt(frame, kBeaconBytes + sizeof(rsnIe)),
                    arrayData(rsnIe), sizeof(rsnIe));
        if (parseBeacon(arrayData(frame), sizeof(frame), parsed) !=
            Result::InvalidSecurity)
        {
            return false;
        }
        // Unsupported AKM must not silently change the advertised BSS to Open.
        frame[kBeaconBytes + kFixtureInt19] = kFixtureHex7f;
        return parseBeacon(arrayData(frame), kBeaconBytes + sizeof(rsnIe),
                           parsed) == Result::Ok &&
               parsed.rsn.security == Security::UnsupportedRsn;
    }

    bool enforceDsHtConsistency()
    {
        uint8_t frame[kBeaconBytes + kFixtureInt24] {};
        makeBeacon(frame);
        frame[kBeaconBytes] = kFixtureInt61; // HT Operation.
        frame[kBeaconBytes + 1] =
            kFixtureInt22; // Fixed HT Operation IE length.
        frame[kBeaconBytes + 2] = kFixtureInt11; // Conflicts with DS channel 6.
        Beacon parsed {};
        if (parseBeacon(arrayData(frame), sizeof(frame), parsed) !=
            Result::InvalidElement)
        {
            return false;
        }
        frame[kBeaconBytes + 2] = kFixtureInt6;
        if (parseBeacon(arrayData(frame), sizeof(frame), parsed) !=
                Result::Ok ||
            parsed.channel != kFixtureInt6)
        {
            return false;
        }
        frame[kBeaconBytes + 1] =
            kFixtureInt21; // Truncated/malformed HT Operation.
        return parseBeacon(arrayData(frame), sizeof(frame), parsed) ==
               Result::InvalidElement;
    }

    bool rejectOverlappingManagementTx()
    {
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        size_t written = kFixtureInt123;

        // A caller-owned SSID inside the output buffer must survive a failed
        // probe request unchanged, even though normal serialization zeroes
        // its output before copying the SSID.
        uint8_t probe[kFixtureInt96] {};
        std::memset(arrayData(probe), kFixtureHex5a, sizeof(probe));
        probe[kFixtureInt40] = 'T';
        probe[kFixtureInt41] = 'e';
        probe[kFixtureInt42] = 's';
        probe[kFixtureInt43] = 't';
        uint8_t previousProbe[sizeof(probe)] {};
        std::memcpy(arrayData(previousProbe), arrayData(probe), sizeof(probe));
        if (makeProbeRequest(station, &arrayAt(probe, kFixtureInt40), 4, 1,
                             arrayData(probe), sizeof(probe),
                             written) != Result::OverlappingBuffers ||
            written != kFixtureInt123 ||
            std::memcmp(arrayData(probe), arrayData(previousProbe),
                        sizeof(probe)) != 0)
        {
            return false;
        }

        struct StationBuffer
        {
                Mac input;
                uint8_t spare[kFixtureInt64];
        } stationBuffer {station, {}};

        uint8_t previousStation[sizeof(stationBuffer)] {};
        std::memcpy(arrayData(previousStation), &stationBuffer,
                    sizeof(stationBuffer));
        written = kFixtureInt456;
        if (makeOpenAuthenticationRequest(
                stationBuffer.input, ap, 2, byteView(stationBuffer),
                sizeof(stationBuffer), written) != Result::OverlappingBuffers ||
            written != kFixtureInt456 ||
            std::memcmp(&stationBuffer, arrayData(previousStation),
                        sizeof(stationBuffer)) != 0)
        {
            return false;
        }

        Beacon network {};
        network.bssid = ap;
        network.infrastructure = true;
        network.ssidLength = 4;
        std::memcpy(arrayData(network.ssid), "Test", 4);
        network.rsn.security = Security::Open;
        uint8_t previousNetwork[sizeof(network)] {};
        std::memcpy(arrayData(previousNetwork), &network, sizeof(network));
        written = kFixtureInt789;
        if (makeAssociationRequest(station, network, 3, byteView(network),
                                   sizeof(network),
                                   written) != Result::OverlappingBuffers ||
            written != kFixtureInt789 ||
            std::memcmp(byteView(network), arrayData(previousNetwork),
                        sizeof(network)) != 0)
        {
            return false;
        }

        // The count is also a caller-owned reference. Do not zero it when
        // that reference lives inside the destination buffer.
        struct CountBuffer
        {
                size_t count;
                uint8_t spare[kFixtureInt96];
        } countBuffer {kFixtureInt321, {}};

        uint8_t previousCount[sizeof(countBuffer)] {};
        std::memcpy(arrayData(previousCount), &countBuffer,
                    sizeof(countBuffer));
        const uint8_t ssid[4] {'T', 'e', 's', 't'};
        if (makeProbeRequest(station, arrayData(ssid), sizeof(ssid), 4,
                             byteView(countBuffer), sizeof(countBuffer),
                             countBuffer.count) != Result::OverlappingBuffers ||
            std::memcmp(&countBuffer, arrayData(previousCount),
                        sizeof(countBuffer)) != 0)
        {
            return false;
        }

        // An absent TX buffer must not bypass alias safety: written may also
        // contain a borrowed SSID source, and clearing it before rejecting
        // the missing buffer would silently mutate the caller's input.
        size_t aliasedLength = kFixtureHex11223344U;
        const auto *borrowedSsid = byteView(aliasedLength);
        if (makeProbeRequest(station, borrowedSsid, sizeof(aliasedLength),
                             kFixtureInt5, nullptr, 0,
                             aliasedLength) != Result::OverlappingBuffers ||
            aliasedLength != kFixtureHex11223344U)
        {
            return false;
        }
        aliasedLength = kFixtureInt99;
        return makeProbeRequest(station, arrayData(ssid), sizeof(ssid),
                                kFixtureInt5, nullptr, 0,
                                aliasedLength) == Result::NullBuffer &&
               aliasedLength == 0;
    }

    bool revokeRejectedRsnSecurity()
    {
        // A reused RSN output must not retain WPA2 authorization after a
        // malformed or absent replacement element. Alias rejection below
        // remains separately required to preserve the input's original bytes.
        constexpr uint8_t validRsn[20] {
            1,    0, 0, 0x0f, 0xac, 4,    1,    0, 0, 0x0f,
            0xac, 4, 1, 0,    0,    0x0f, 0xac, 2, 0, 0,
        };
        Rsn parsed {};
        if (parseRsn(arrayData(validRsn), sizeof(validRsn), parsed) !=
                Result::Ok ||
            !parsed.valid || parsed.security != Security::Wpa2Personal)
        {
            return false;
        }
        const uint8_t truncated[2] {1, 0};
        if (parseRsn(arrayData(truncated), sizeof(truncated), parsed) !=
                Result::InvalidSecurity ||
            parsed.valid || parsed.present ||
            parsed.security != Security::UnsupportedRsn)
        {
            return false;
        }
        if (parseRsn(arrayData(validRsn), sizeof(validRsn), parsed) !=
            Result::Ok)
        {
            return false;
        }
        uint8_t incorrectVersion[sizeof(validRsn)] {};
        std::memcpy(arrayData(incorrectVersion), arrayData(validRsn),
                    sizeof(validRsn));
        incorrectVersion[0] = 2;
        if (parseRsn(arrayData(incorrectVersion), sizeof(incorrectVersion),
                     parsed) != Result::InvalidSecurity ||
            parsed.valid || parsed.present ||
            parsed.security != Security::UnsupportedRsn)
        {
            return false;
        }
        if (parseRsn(arrayData(validRsn), sizeof(validRsn), parsed) !=
            Result::Ok)
        {
            return false;
        }
        return parseRsn(nullptr, 0, parsed) == Result::NullBuffer &&
               !parsed.valid && !parsed.present &&
               parsed.security == Security::UnsupportedRsn;
    }

    bool revokeRejectedFrameMetadata()
    {
        // Caller-owned parser output may be reused across DMA frames. An
        // unsupported or incomplete header must revoke the earlier BSSID and
        // address rather than leaving it available after a failed result.
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        Frame parsed {};
        if (parseFrame(arrayData(advertisement), sizeof(advertisement),
                       parsed) != Result::Ok ||
            parsed.headerLength != kFixtureInt24 ||
            parsed.source.bytes[0] != kAp[0])
        {
            return false;
        }
        advertisement[0] = static_cast<uint8_t>(
            static_cast<unsigned>(advertisement[0]) |
            static_cast<unsigned>(1)); // Nonzero 802.11 protocol version.
        if (parseFrame(arrayData(advertisement), sizeof(advertisement),
                       parsed) != Result::UnsupportedFrame ||
            parsed.headerLength != 0 || parsed.source.bytes[0] != 0 ||
            parsed.bssid.bytes[0] != 0)
        {
            return false;
        }
        makeBeacon(advertisement);
        if (parseFrame(arrayData(advertisement), sizeof(advertisement),
                       parsed) != Result::Ok)
        {
            return false;
        }
        if (parseFrame(arrayData(advertisement), 1, parsed) !=
                Result::Truncated ||
            parsed.headerLength != 0 || parsed.bssid.bytes[0] != 0)
        {
            return false;
        }
        if (parseFrame(arrayData(advertisement), sizeof(advertisement),
                       parsed) != Result::Ok)
        {
            return false;
        }
        return parseFrame(nullptr, 0, parsed) == Result::NullBuffer &&
               parsed.headerLength == 0 && parsed.source.bytes[0] == 0;
    }

    bool revokeRejectedBeaconSecurity()
    {
        // A valid WPA2 BSS may precede a malformed or unsupported beacon.
        // Reject the replacement without retaining SSID, BSSID or RSNE
        // authorization from the earlier successful parse.
        constexpr uint8_t rsnIe[22] {
            48,   20,   1, 0, 0, 0x0f, 0xac, 4,    1, 0, 0,
            0x0f, 0xac, 4, 1, 0, 0,    0x0f, 0xac, 2, 0, 0,
        };
        uint8_t advertisement[kBeaconBytes + sizeof(rsnIe)] {};
        makeBeacon(advertisement);
        advertisement[kFixtureInt34] = static_cast<uint8_t>(
            static_cast<unsigned>(advertisement[kFixtureInt34]) |
            static_cast<unsigned>(kFixtureHex10)); // Privacy bit.
        std::memcpy(&arrayAt(advertisement, kBeaconBytes), arrayData(rsnIe),
                    sizeof(rsnIe));
        Beacon parsed {};
        const auto accepted = [&]
        {
            return parseBeacon(arrayData(advertisement), sizeof(advertisement),
                               parsed) == Result::Ok &&
                   parsed.rsn.security == Security::Wpa2Personal &&
                   parsed.rsnIeLength == sizeof(rsnIe) &&
                   parsed.ssidLength == 4 && parsed.bssid.bytes[0] == kAp[0];
        };
        if (!accepted())
        {
            return false;
        }
        advertisement[0] =
            kFixtureHex40; // Probe request is not an advertisement.
        if (parseBeacon(arrayData(advertisement), sizeof(advertisement),
                        parsed) != Result::UnsupportedFrame ||
            parsed.rsn.valid ||
            parsed.rsn.security != Security::UnsupportedRsn ||
            (parsed.rsnIeLength != 0U) || (parsed.ssidLength != 0U) ||
            (parsed.bssid.bytes[0] != 0U))
        {
            return false;
        }
        advertisement[0] = kFixtureHex80;
        if (!accepted())
        {
            return false;
        }
        if (parseBeacon(arrayData(advertisement), 3, parsed) !=
                Result::Truncated ||
            parsed.rsn.valid ||
            parsed.rsn.security != Security::UnsupportedRsn ||
            (parsed.rsnIeLength != 0U) || (parsed.ssidLength != 0U) ||
            (parsed.bssid.bytes[0] != 0U))
        {
            return false;
        }
        if (!accepted())
        {
            return false;
        }
        return parseBeacon(nullptr, 0, parsed) == Result::NullBuffer &&
               !parsed.rsn.valid &&
               parsed.rsn.security == Security::UnsupportedRsn &&
               parsed.rsnIeLength == 0 && parsed.ssidLength == 0 &&
               parsed.bssid.bytes[0] == 0;
    }

    bool rejectOverlappingManagementRx()
    {
        Frame parsedFrame {};
        uint8_t previousFrame[sizeof(parsedFrame)] {};
        std::memcpy(arrayData(previousFrame), &parsedFrame,
                    sizeof(parsedFrame));
        if (parseFrame(byteView(parsedFrame), sizeof(parsedFrame),
                       parsedFrame) != Result::OverlappingBuffers ||
            std::memcmp(byteView(parsedFrame), arrayData(previousFrame),
                        sizeof(parsedFrame)) != 0)
        {
            return false;
        }

        struct RsnStorage
        {
                Rsn result;
                uint8_t trailing[kFixtureInt32];
        } rsnStorage {};

        constexpr uint8_t rsnBody[20] {
            1,    0, 0, 0x0f, 0xac, 4,    1,    0, 0, 0x0f,
            0xac, 4, 1, 0,    0,    0x0f, 0xac, 2, 0, 0,
        };
        std::memcpy(&rsnStorage, arrayData(rsnBody), sizeof(rsnBody));
        uint8_t previousRsn[sizeof(rsnStorage)] {};
        std::memcpy(arrayData(previousRsn), &rsnStorage, sizeof(rsnStorage));
        if (parseRsn(byteView(rsnStorage), sizeof(rsnBody),
                     rsnStorage.result) != Result::OverlappingBuffers ||
            std::memcmp(&rsnStorage, arrayData(previousRsn),
                        sizeof(rsnStorage)) != 0)
        {
            return false;
        }

        Beacon parsedBeacon {};
        uint8_t beacon[kBeaconBytes] {};
        makeBeacon(beacon);
        std::memcpy(&parsedBeacon, arrayData(beacon), sizeof(beacon));
        uint8_t previousBeacon[sizeof(parsedBeacon)] {};
        std::memcpy(arrayData(previousBeacon), &parsedBeacon,
                    sizeof(parsedBeacon));
        if (parseBeacon(byteView(parsedBeacon), sizeof(beacon), parsedBeacon) !=
                Result::OverlappingBuffers ||
            std::memcmp(byteView(parsedBeacon), arrayData(previousBeacon),
                        sizeof(parsedBeacon)) != 0)
        {
            return false;
        }

        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};

        struct ResponseBuffer
        {
                uint16_t status;
                uint8_t rest[kFixtureInt32];
        } response {};

        auto *responseBytes = byteView(response);
        *byteAt(responseBytes, sizeof(response), 0U) =
            kFixtureHexb0; // Authentication response subtype.
        std::memcpy(byteAt(responseBytes, sizeof(response), 4U),
                    arrayData(kStation), kFixtureInt6);
        std::memcpy(byteAt(responseBytes, sizeof(response), kFixtureInt10),
                    arrayData(kAp), kFixtureInt6);
        std::memcpy(byteAt(responseBytes, sizeof(response), kFixtureInt16),
                    arrayData(kAp), kFixtureInt6);
        *byteAt(responseBytes, sizeof(response), kFixtureInt26) =
            2U; // Open-system response transaction.
        uint8_t previousResponse[sizeof(response)] {};
        std::memcpy(arrayData(previousResponse), &response, sizeof(response));
        if (parseAuthenticationResponse(responseBytes, kFixtureInt30, station,
                                        ap, response.status) !=
                Result::OverlappingBuffers ||
            std::memcmp(&response, arrayData(previousResponse),
                        sizeof(response)) != 0)
        {
            return false;
        }

        uint8_t association[kAssocBytes] {};
        makeAssoc(association);
        uint16_t sharedResult = kFixtureInt543;
        return parseAssociationResponse(
                   arrayData(association), sizeof(association), station, ap,
                   sharedResult, sharedResult) == Result::OverlappingBuffers &&
               sharedResult == kFixtureInt543;
    }

    bool rejectTrailingOpenAuthenticationBody()
    {
        // IEEE 802.11 Open System transaction 2 has six fixed bytes. The
        // optional vendor-specific IE suffix must be complete and cannot
        // smuggle arbitrary unparsed bytes into an accepted response.
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint8_t response[kFixtureInt40] {};
        response[0] = kFixtureHexb0;
        std::memcpy(&arrayAt(response, 4), arrayData(kStation), kFixtureInt6);
        std::memcpy(&arrayAt(response, kFixtureInt10), arrayData(kAp),
                    kFixtureInt6);
        std::memcpy(&arrayAt(response, kFixtureInt16), arrayData(kAp),
                    kFixtureInt6);
        response[kFixtureInt26] = 2;
        uint16_t status = kFixtureInt777;
        if (parseAuthenticationResponse(arrayData(response), kFixtureInt30,
                                        station, ap, status) != Result::Ok ||
            status != 0)
        {
            return false;
        }
        status = kFixtureInt777;
        response[kFixtureInt30] = kFixtureHexdd;
        if (parseAuthenticationResponse(arrayData(response), kFixtureInt31,
                                        station, ap,
                                        status) != Result::InvalidElement ||
            status != kFixtureHexffffU)
        {
            return false;
        }
        // Vendor-specific IEs (OUI plus optional vendor bytes) are legal
        // suffixes and must not break otherwise valid infrastructure auth.
        response[kFixtureInt30] = kFixtureInt221;
        response[kFixtureInt31] = 3;
        response[kFixtureInt32] = 0x00;
        response[kFixtureInt33] = kFixtureHex11;
        response[kFixtureInt34] = kFixtureHex22;
        if (parseAuthenticationResponse(arrayData(response), kFixtureInt35,
                                        station, ap, status) != Result::Ok ||
            status != 0)
        {
            return false;
        }
        response[kFixtureInt35] = kFixtureInt221;
        response[kFixtureInt36] = 3;
        response[kFixtureInt37] = 0x00;
        response[kFixtureInt38] = kFixtureHex44;
        response[kFixtureInt39] = kFixtureHex55;
        if (parseAuthenticationResponse(arrayData(response), sizeof(response),
                                        station, ap, status) != Result::Ok ||
            status != 0)
        {
            return false;
        }
        status = kFixtureInt777;
        response[kFixtureInt30] =
            1; // Non-vendor IE is not defined for Open System.
        if (parseAuthenticationResponse(arrayData(response), kFixtureInt35,
                                        station, ap,
                                        status) != Result::InvalidElement ||
            status != kFixtureHexffffU)
        {
            return false;
        }
        response[kFixtureInt30] = kFixtureInt221;
        response[kFixtureInt31] = 2; // Vendor IE must carry its three-byte OUI.
        return parseAuthenticationResponse(arrayData(response), kFixtureInt34,
                                           station, ap,
                                           status) == Result::InvalidElement &&
               status == kFixtureHexffffU;
    }

    bool rejectInvalidManagementRxIdentities()
    {
        const Mac empty {};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t auth[kFixtureInt30] {};
        auth[0] =
            kFixtureHexb0; // Successful Open authentication transaction 2.
        auth[kFixtureInt26] = 2;
        uint16_t status = kFixtureInt777;
        // Equality of forged addresses does not make either identity a
        // physical unicast AP or station.
        if (parseAuthenticationResponse(arrayData(auth), sizeof(auth), empty,
                                        empty,
                                        status) != Result::InvalidAddress ||
            status != kFixtureHexffffU)
        {
            return false;
        }
        std::memcpy(&arrayAt(auth, 4), arrayData(kAp), kFixtureInt6);
        std::memcpy(&arrayAt(auth, kFixtureInt10), arrayData(kAp),
                    kFixtureInt6);
        std::memcpy(&arrayAt(auth, kFixtureInt16), arrayData(kAp),
                    kFixtureInt6);
        if (parseAuthenticationResponse(arrayData(auth), sizeof(auth), ap, ap,
                                        status) != Result::InvalidAddress ||
            status != kFixtureHexffffU)
        {
            return false;
        }
        std::memcpy(&arrayAt(auth, 4), arrayData(kStation), kFixtureInt6);
        if (parseAuthenticationResponse(arrayData(auth), sizeof(auth), station,
                                        ap, status) != Result::Ok ||
            status != 0)
        {
            return false;
        }

        uint8_t association[kAssocBytes] {};
        makeAssoc(association);
        std::memset(&arrayAt(association, 4), 0, kFixtureInt18);
        status = kFixtureInt777;
        uint16_t aid = kFixtureInt888;
        if (parseAssociationResponse(arrayData(association),
                                     sizeof(association), empty, empty, status,
                                     aid) != Result::InvalidAddress ||
            status != kFixtureHexffffU || aid != 0)
        {
            return false;
        }
        makeAssoc(association);
        std::memcpy(&arrayAt(association, 4), arrayData(kAp), kFixtureInt6);
        if (parseAssociationResponse(arrayData(association),
                                     sizeof(association), ap, ap, status,
                                     aid) != Result::InvalidAddress ||
            status != kFixtureHexffffU || aid != 0)
        {
            return false;
        }
        makeAssoc(association);
        return parseAssociationResponse(arrayData(association),
                                        sizeof(association), station, ap,
                                        status, aid) == Result::Ok &&
               status == 0 && aid == 1;
    }

    bool revokeRejectedManagementResponseStatus()
    {
        // Public parsers may be called repeatedly with the same outputs.
        // A rejected later response must not leave an earlier successful
        // association ID or status=0 available as apparent authorization.
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint8_t auth[kFixtureInt30] {};
        auth[0] = kFixtureHexb0;
        std::memcpy(&arrayAt(auth, 4), arrayData(kStation), kFixtureInt6);
        std::memcpy(&arrayAt(auth, kFixtureInt10), arrayData(kAp),
                    kFixtureInt6);
        std::memcpy(&arrayAt(auth, kFixtureInt16), arrayData(kAp),
                    kFixtureInt6);
        auth[kFixtureInt26] = 2;
        uint16_t status = kFixtureInt55;
        if (parseAuthenticationResponse(arrayData(auth), sizeof(auth), station,
                                        ap, status) != Result::Ok ||
            status != 0)
        {
            return false;
        }
        auth[kFixtureInt26] =
            1; // Wrong transaction after accepted authentication.
        if (parseAuthenticationResponse(arrayData(auth), sizeof(auth), station,
                                        ap,
                                        status) != Result::UnsupportedFrame ||
            status != kFixtureHexffffU)
        {
            return false;
        }

        uint8_t association[kAssocBytes] {};
        makeAssoc(association);
        uint16_t aid = kFixtureInt88;
        if (parseAssociationResponse(arrayData(association),
                                     sizeof(association), station, ap, status,
                                     aid) != Result::Ok ||
            status != 0 || aid != 1)
        {
            return false;
        }
        association[kFixtureInt29] =
            0; // Invalid AID after successful association.
        return parseAssociationResponse(arrayData(association),
                                        sizeof(association), station, ap,
                                        status, aid) == Result::InvalidFrame &&
               status == kFixtureHexffffU && aid == 0;
    }

    bool rejectNonInfrastructureAssociation()
    {
        uint8_t frame[kAssocBytes] {};
        makeAssoc(frame);
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint16_t status = kFixtureInt999;
        uint16_t aid = kFixtureInt999;
        frame[kFixtureInt24] = 0; // No ESS capability bit.
        if (parseAssociationResponse(arrayData(frame), sizeof(frame), station,
                                     ap, status, aid) != Result::InvalidFrame ||
            status != kFixtureHexffffU || aid != 0)
        {
            return false;
        }
        frame[kFixtureInt24] = 3; // ESS and IBSS must not both be set.
        if (parseAssociationResponse(arrayData(frame), sizeof(frame), station,
                                     ap, status, aid) != Result::InvalidFrame)
        {
            return false;
        }
        frame[kFixtureInt24] = 0;
        frame[kFixtureInt26] =
            1; // Failed association is still a valid rejection.
        return parseAssociationResponse(arrayData(frame), sizeof(frame),
                                        station, ap, status,
                                        aid) == Result::Ok &&
               status == 1 && aid == 0;
    }

    bool rejectUnserializableAssociationLengths()
    {
        uint8_t frame[kBeaconBytes] {};
        makeBeacon(frame);
        Beacon valid {};
        if (parseBeacon(arrayData(frame), sizeof(frame), valid) != Result::Ok ||
            associationRequestLength(valid) == 0)
        {
            return false;
        }

        // The public size preflight is also used to rank joinable BSSes.
        // A positive length must never authorize a management request that
        // the actual serializer will reject for its advertised identity,
        // network type, hidden SSID or privacy/security policy.
        Beacon invalid = valid;
        invalid.hiddenSsid = true;
        if (associationRequestLength(invalid) != 0)
        {
            return false;
        }
        invalid = valid;
        invalid.capabilities = 0x03; // Simultaneous ESS + IBSS.
        if (associationRequestLength(invalid) != 0)
        {
            return false;
        }
        invalid = valid;
        invalid.capabilities = kFixtureHex11; // Privacy without a valid RSNE.
        if (associationRequestLength(invalid) != 0)
        {
            return false;
        }
        invalid = valid;
        invalid.rsn.security = Security::Wpa2Personal;
        if (associationRequestLength(invalid) != 0)
        {
            return false;
        }
        invalid = valid;
        invalid.bssid.bytes[0] = static_cast<uint8_t>(
            static_cast<unsigned>(invalid.bssid.bytes[0]) |
            static_cast<unsigned>(1)); // Group-addressed AP.
        if (associationRequestLength(invalid) != 0)
        {
            return false;
        }
        invalid = valid;
        for (size_t index = 0; index < invalid.ssidLength; ++index)
        {
            arrayAt(invalid.ssid, index) = 0U;
        }
        return associationRequestLength(invalid) == 0;
    }

    bool rejectChannel14NonCckAssociation()
    {
        uint8_t advertisement[kBeaconBytes] {};
        makeBeacon(advertisement);
        advertisement[kFixtureInt48] =
            kFixtureInt14; // Parsed BSS on the Japan-only channel.
        Beacon network {};
        if (parseBeacon(arrayData(advertisement), sizeof(advertisement),
                        network) != Result::Ok ||
            network.channel != kFixtureInt14)
        {
            return false;
        }
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        uint8_t output[kFixtureInt128] {};
        size_t written = 0;

        // Baseline CCK-only channel-14 BSS remains joinable.
        if (associationRequestLength(network) == 0 ||
            makeAssociationRequest(station, network, 1, arrayData(output),
                                   sizeof(output), written) != Result::Ok ||
            output[kFixtureInt34] != 1 || output[kFixtureInt35] != 2 ||
            output[kFixtureInt36] != kFixtureHex82 ||
            output[kFixtureInt37] != kFixtureHex84)
        {
            return false;
        }

        // An optional OFDM rate must not appear in an association request,
        // while the same rate is allowed on ordinary 2.4-GHz channels.
        network.rates[0] = kFixtureHex0c;
        if (associationRequestLength(network) == 0 ||
            associationRateSupported(network, kFixtureHex0c) ||
            !associationRateSupported(network, kFixtureHex84) ||
            makeAssociationRequest(station, network, 2, arrayData(output),
                                   sizeof(output), written) != Result::Ok ||
            output[kFixtureInt35] != 1 ||
            output[kFixtureInt36] != kFixtureHex84)
        {
            return false;
        }
        network.channel = kFixtureInt13;
        if (associationRequestLength(network) == 0 ||
            !associationRateSupported(network, kFixtureHex0c) ||
            makeAssociationRequest(station, network, 3, arrayData(output),
                                   sizeof(output), written) != Result::Ok ||
            output[kFixtureInt35] != 2 ||
            output[kFixtureInt36] != kFixtureHex0c)
        {
            return false;
        }

        // A mandatory OFDM rate makes channel 14 unjoinable, even when
        // another local CCK rate overlaps. Rejected serialization must leave
        // the caller's TX buffer untouched and clear its stale byte count.
        network.channel = kFixtureInt14;
        network.rates[0] = kFixtureHex8c;
        std::memset(arrayData(output), kFixtureHexa5, sizeof(output));
        written = kFixtureInt77;
        if (associationRequestLength(network) != 0 ||
            associationRateSupported(network, kFixtureHex84) ||
            makeAssociationRequest(station, network, 4, arrayData(output),
                                   sizeof(output),
                                   written) != Result::InvalidElement ||
            written != 0 || output[0] != kFixtureHexa5)
        {
            return false;
        }

        // An OFDM-only AP cannot join by advertising the unsupported rate as
        // optional; a forged HT metadata flag is also invalid on channel 14.
        network.rates[0] = kFixtureHex0c;
        network.rates[1] = kFixtureHex12;
        if (associationRequestLength(network) != 0)
        {
            return false;
        }
        network.rates[0] = kFixtureHex82;
        network.rates[1] = kFixtureHex84;
        network.htSupported = true;
        if (associationRequestLength(network) != 0 ||
            makeAssociationRequest(station, network, kFixtureInt5,
                                   arrayData(output), sizeof(output),
                                   written) != Result::InvalidFrame)
        {
            return false;
        }
        network.htSupported = false;
        return associationRequestLength(network) != 0;
    }

    bool enforceAssociationAdmission()
    {
        uint8_t frame[kAssocBytes] {};
        makeAssoc(frame);
        const Mac station {{0x02, 0x66, 0x77, 0x88, 0x99, 0xaa}};
        const Mac ap {{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
        uint16_t status = kFixtureHexffff;
        uint16_t aid = kFixtureHexffff;
        if (parseAssociationResponse(arrayData(frame), sizeof(frame), station,
                                     ap, status, aid) != Result::Ok ||
            status != 0 || aid != 1)
        {
            return false;
        }
        makeAssoc(frame);
        frame[kFixtureInt29] = 0; // Successful AID requires both high bits set.
        if (parseAssociationResponse(arrayData(frame), sizeof(frame), station,
                                     ap, status, aid) != Result::InvalidFrame)
        {
            return false;
        }
        makeAssoc(frame);
        if (parseAssociationResponse(arrayData(frame), kFixtureInt30, station,
                                     ap, status, aid) != Result::InvalidElement)
        {
            return false;
        }
        makeAssoc(frame);
        frame[kFixtureInt32] = kFixtureHex80; // Invalid zero-valued rate.
        if (parseAssociationResponse(arrayData(frame), sizeof(frame), station,
                                     ap, status, aid) != Result::InvalidElement)
        {
            return false;
        }
        makeAssoc(frame);
        frame[1] = 0x04; // Fragmented management handshake response.
        return parseAssociationResponse(arrayData(frame), sizeof(frame),
                                        station, ap, status,
                                        aid) == Result::UnsupportedFrame;
    }

    // Keep each admission check's distinct exit status while retaining a
    // bounded entrypoint for the full host regression suite.
    int checkOversizedManagementMpdu()
    {
        return rejectOversizedManagementMpdu() ? 0 : kFixtureInt26;
    }
} // namespace

int main()
{
    if (!validBeacon())
    {
        return 1;
    }
    if (!rejectFragmentsAndForeignBssid())
    {
        return 2;
    }
    if (!rejectInvalidRates())
    {
        return 3;
    }
    if (!rejectRsnDowngradeAndDuplicates())
    {
        return 4;
    }
    if (!enforceDsHtConsistency())
    {
        return kFixtureInt5;
    }
    if (!enforceAssociationAdmission())
    {
        return kFixtureInt6;
    }
    if (!rejectOverlappingManagementTx())
    {
        return kFixtureInt7;
    }
    if (!rejectOverlappingManagementRx())
    {
        return kFixtureInt8;
    }
    if (!rejectNonInfrastructureAssociation())
    {
        return kFixtureInt9;
    }
    if (!rejectStaleElementCursorViews())
    {
        return kFixtureInt10;
    }
    if (!rejectHiddenAssociationName())
    {
        return kFixtureInt11;
    }
    if (!rejectSelfBssidManagementTx())
    {
        return kFixtureInt12;
    }
    if (!rejectInvalidManagementRxIdentities())
    {
        return kFixtureInt13;
    }
    if (!rejectTrailingOpenAuthenticationBody())
    {
        return kFixtureInt22;
    }
    if (!revokeRejectedManagementResponseStatus())
    {
        return kFixtureInt23;
    }
    if (!rejectConflictingBssModes())
    {
        return kFixtureInt14;
    }
    if (!rejectForgedBssAssociationTx())
    {
        return kFixtureInt15;
    }
    if (!rejectForgedPrivacyAssociationTx())
    {
        return kFixtureInt16;
    }
    if (!revokeRejectedRsnSecurity())
    {
        return kFixtureInt17;
    }
    if (!revokeRejectedFrameMetadata())
    {
        return kFixtureInt18;
    }
    if (!revokeRejectedBeaconSecurity())
    {
        return kFixtureInt19;
    }
    if (!rejectZeroBeaconInterval())
    {
        return kFixtureInt20;
    }
    if (!rejectInvalidAssociationTimingAndChannel())
    {
        return kFixtureInt21;
    }
    if (!rejectUnserializableAssociationLengths())
    {
        return kFixtureInt24;
    }
    if (!rejectChannel14NonCckAssociation())
    {
        return kFixtureInt25;
    }
    return checkOversizedManagementMpdu();
}
