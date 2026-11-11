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
//   - Offline regression cases for tahoe capabilities.
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
//   - Offline regression cases for tahoe capabilities.
// - Description:
//   - Implements or verifies the test_tahoe_capabilities source boundary.
// - Usage:
//   - Executed by offline host test discovery or the native test harness.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Offline regression cases for tahoe capabilities.

// Native card capability layout and station/security inventory, no RF I/O.
#include "platform/tahoe/TahoeCapabilities.hpp"
#include "platform/tahoe/TahoeDataPathAdmission.hpp"
#include <array>
#include <cstdint>
#include <cstring>

namespace
{
    constexpr size_t kExpectedWireBytes = 28U;
    constexpr size_t kCompletionByte = 5U;
    constexpr size_t kBitmapWireOffset = 4U;
    constexpr size_t kGuardOffset = 1U;
    constexpr uint8_t kCcmpBitmap = 0x08U;
    constexpr uint8_t kStationBitmap = 0x46U;
    constexpr uint8_t kScanBitmap = 0x40U;
    constexpr uint8_t kGuardByte = 0xaaU;
    constexpr int kWireMismatchExit = 5;
    constexpr int kStationEnvelopeExit = 6;
    constexpr int kStationReservedExit = 7;
    constexpr int kStationNssWireExit = 8;
    constexpr int kStationPowerSaveWireExit = 9;
    constexpr int kDataPortAdmissionExit = 10;
    constexpr uint64_t kRequestEpoch = 51;
    constexpr uint64_t kNewRadioEpoch = 52;

    bool packetPortAdmission()
    {
        using namespace simpleath::tahoe;
        NativeDataPathAdmission state {
            kRequestEpoch, kRequestEpoch, 1,    true, true,
            true,          false,         true, true, true,
        };
        if (!mayEnableNativeDataPath(state))
        {
            return false;
        }
        // A request from a previous PCI epoch may not reopen the port.
        state.radioEpoch = kNewRadioEpoch;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.radioEpoch = kRequestEpoch;
        state.requestEpoch = 0;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.requestEpoch = kRequestEpoch;
        state.associationGeneration = 0;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.associationGeneration = 1;
        state.requested = false;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.requested = true;
        state.radioAvailable = false;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.radioAvailable = true;
        state.powered = false;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.powered = true;
        state.rfKillBlocked = true;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.rfKillBlocked = false;
        state.associated = false;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.associated = true;
        state.controlledPortOpen = false;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.controlledPortOpen = true;
        state.associatedBeaconObserved = false;
        if (mayEnableNativeDataPath(state))
        {
            return false;
        }
        state.associatedBeaconObserved = true;
        return mayEnableNativeDataPath(state);
    }
} // namespace

int main()
{
    if (!packetPortAdmission())
    {
        return kDataPortAdmissionExit;
    }
    using namespace simpleath::tahoe;
    const auto record = ar9565Capabilities();
    if (record.version != 1 || sizeof(record) != kExpectedWireBytes)
    {
        return 1;
    }
    std::array<uint8_t, kNativeCapabilityBytes> expected {};
    expected.at(0) = kCcmpBitmap;
    expected.at(1) = kStationBitmap;
    expected.at(2) = kScanBitmap;
    expected.at(kCompletionByte) = kScanBitmap;
    // Later native bitmap bytes control 6GHz, HE, EHT, SAE and OWE. They
    // must contain actual zeroed output, never old kernel-buffer contents.
    size_t index = 0;
    for (const auto value : record.capabilities)
    {
        if (value != expected.at(index++))
        {
            return 2;
        }
    }
    for (const auto value : record.reserved)
    {
        if (value != 0U)
        {
            return 3;
        }
    }
    std::array<uint8_t, kExpectedWireBytes + 2U> envelope {};
    envelope.fill(kGuardByte);
    std::memcpy(&envelope.at(kGuardOffset), &record, sizeof(record));
    if (envelope.front() != kGuardByte || envelope.back() != kGuardByte ||
        envelope.at(kGuardOffset) != 1U)
    {
        return 4;
    }
    index = kGuardOffset + kBitmapWireOffset;
    for (const auto value : expected)
    {
        if (envelope.at(index++) != value)
        {
            return kWireMismatchExit;
        }
    }
    // Both native getters overwrite only their SDK-declared 8-byte records;
    // reserved NSS bytes are scrubbed, with no invented PSM/second chain.
    constexpr size_t kStatusSize = 8U;
    const auto powerSave = ar9565PowerSaveStatus();
    const auto spatialStreams = ar9565NssStatus();
    if (sizeof(powerSave) != kStatusSize ||
        sizeof(spatialStreams) != kStatusSize || powerSave.version != 1U ||
        powerSave.powersaveLevel != 0U || spatialStreams.version != 1U ||
        spatialStreams.streams != 1U)
    {
        return kStationEnvelopeExit;
    }
    if (spatialStreams.reserved[0] != 0U || spatialStreams.reserved[1] != 0U ||
        spatialStreams.reserved[2] != 0U)
    {
        return kStationReservedExit;
    }
    std::array<uint8_t, kStatusSize + 2U> statusWire {};
    statusWire.fill(kGuardByte);
    std::memcpy(&statusWire.at(kGuardOffset), &spatialStreams,
                sizeof(spatialStreams));
    if (statusWire.front() != kGuardByte || statusWire.back() != kGuardByte ||
        statusWire.at(kGuardOffset) != 1U ||
        statusWire.at(kGuardOffset + 4U) != 1U)
    {
        return kStationNssWireExit;
    }
    statusWire.fill(kGuardByte);
    std::memcpy(&statusWire.at(kGuardOffset), &powerSave, sizeof(powerSave));
    if (statusWire.front() != kGuardByte || statusWire.back() != kGuardByte ||
        statusWire.at(kGuardOffset) != 1U ||
        statusWire.at(kGuardOffset + 4U) != 0U)
    {
        return kStationPowerSaveWireExit;
    }
    return 0;
}
