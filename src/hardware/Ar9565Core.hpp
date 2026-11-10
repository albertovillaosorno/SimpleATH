// SPDX-License-Identifier: AGPL-3.0-only
// SimpleATH native AR9565 hardware core.
// MacKernelSDK-independent algorithms. The PCI/MMIO transport is supplied
// separately; no code from Linux ath9k is linked into this implementation.
#ifndef SIMPLEATH_AR9565_CORE_HPP
#define SIMPLEATH_AR9565_CORE_HPP

#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    constexpr size_t kPermanentMacBytes = 6;

    enum : uint16_t
    {
        kPciVendor = 0x168c,
        kPciDevice = 0x0036,
        kPciLegacySpoof = 0x0030,
        kMacFamily = 0x02c0,
    };

    enum : uint32_t
    {
        kRevisionRegister = 0x4020,
        kRtcStatusRegister = 0x7044,
        kEepromStatusRegister = 0x401c,
        kWorkaroundRegister = 0x4004,
        kRtcStatusMask = 0x0f,
        kRtcOn = 0x02,
        kEepromAbsent = 0x100,
        kEepromCorrupt = 0x200,
    };

    enum class Result : uint8_t
    {
        Ok,
        UnsupportedPci,
        BusNotReady,
        InvalidRegister,
        RegisterReadFailed,
        UnsupportedSilicon,
        UnsupportedRevision,
        RadioAsleep,
        EepromUnavailable,
        EepromCorrupt,
        InvalidMacAddress,
        InvalidChannel,
        WrongState,
        RadioNotImplemented,
        NetworkingNotImplemented,
    };

    enum class Revision : uint8_t
    {
        Unknown,
        V1_0,
        V1_0_1,
        V1_1,
    };

    enum class Stage : uint8_t
    {
        Detached,
        PciMatched,
        RegisterTransportReady,
        SiliconIdentified,
        EepromStatusValidated,
        AwaitingResetAndCalibration,
        RadioOperational,
        NetworkRegistered,
    };

    // The register I/O implementation MUST verify its BAR mapping and ensure
    // all reads/writes are ordered. The inspection path intentionally uses
    // read32 only.
    struct RegisterBus
    {
            void *context;
            bool (*read32)(void *context, uint32_t byteOffset, uint32_t *value);
            bool (*write32)(void *context, uint32_t byteOffset, uint32_t value);
            uint32_t barLengthBytes;
    };

    // Detect a specific card without relying on a spoof for chip revision.
    struct Identity
    {
            uint16_t vendorId;
            uint16_t deviceId;
            uint16_t subsystemVendorId;
            uint16_t subsystemDeviceId;
            bool spoofPossible;
    };

    // Silicon revisions require different initialization tables and coexistence
    // paths. The actual table programming is deliberately NOT implemented here.
    struct Silicon
    {
            uint16_t macFamily;
            uint8_t macRevision;
            Revision revision;
            bool usesPcie;
            uint32_t rawSrev;
    };

    struct Status
    {
            Stage stage;
            Result lastResult;
            Identity pci;
            Silicon silicon;
            uint32_t rtcStatus;
            uint32_t eepromStatus;
            bool eepromAccessible;
            bool calibrated;
            bool txEnabled;
            bool rxEnabled;
            bool networkRegistered;
    };

    // A safe channel descriptor. Regulatory permissions must come from a proper
    // board EEPROM + OS/country authority, not from this static 2.4 GHz
    // mapping.
    struct Channel
    {
            uint8_t number;
            uint16_t centerMhz;
            bool requiresJapanAuthorization;
    };

    enum class InitStep : uint8_t
    {
        PowerOnReset,
        WakeRtc,
        ReadAndValidateEeprom,
        ValidateRegulatoryDomain,
        ProgramSocPreamble,
        ProgramMacCore,
        ProgramBasebandCore,
        ProgramRadioCore,
        ProgramRxGain,
        ProgramTxGain,
        ProgramSocPostamble,
        ProgramMacPostamble,
        ProgramBasebandPostamble,
        ProgramRadioPostamble,
        CalibrateRxIq,
        CalibrateTxIq,
        ProgramBluetoothCoexistence,
        AllocateTxRxDma,
        InstallInterrupts,
        RegisterNativeWirelessInterface,
    };

    struct InitPlan
    {
            Revision revision;
            const char *linuxReference;
            const InitStep *steps;
            size_t stepCount;
            // No plan is safe to execute without verified PCI transport, board
            // calibration data and regulatory rules.
            bool executable;
    };

    // Type-2 SREV word decoder for the AR9565. No live hardware access.
    Result decodeRevision(uint32_t raw, Silicon &out);
    bool isSupportedPci(uint16_t vendor, uint16_t device);
    // Out is cleared if the channel number is invalid; no regulatory approval.
    Result mapChannel(uint8_t ieeeChannel, Channel &out);
    bool validatePermanentMac(const uint8_t mac[kPermanentMacBytes]);
    // Out is cleared on ordinary failure when nonnull, including null source
    // words. An invalid source overlapping out fails untouched to preserve
    // borrowed EEPROM bytes; a valid source may still be decoded in-place.
    Result decodeEepromMac(const uint16_t words[3],
                           uint8_t out[kPermanentMacBytes]);
    InitPlan planForRevision(Revision revision);

    class Device
    {
        public:
            Device();

            // No hardware accesses. Caller must supply physical
            // configuration-space values under a PCI ownership/power contract,
            // not registry properties.
            Result matchPci(uint16_t vendor, uint16_t device,
                            uint16_t subsystemVendor, uint16_t subsystemDevice);

            // Hardware transport registration itself never enables PCI
            // decoding. The supplied descriptor must not alias this Device;
            // its callback context must not point inside that descriptor.
            // An enclosing session may use its own base as callback context.
            Result attachReadOnlyBus(const RegisterBus &bus);

            // Checks mapped SREV, RTC and EEPROM status. Never writes to
            // PCI/MMIO. This does not mean the radio is operational or the
            // device is ready.
            Result inspect();

            // Revoke callbacks BEFORE their mapping/provider/context is
            // released. Caller serializes all operations; Device itself is not
            // thread-safe.
            void detach();

            const Status &status() const
            {
                return status_;
            }

            static bool canTransmit()
            {
                return false;
            }

            static bool canReceive()
            {
                return false;
            }

        private:
            Result fail(Result result);
            Result readRegister(uint32_t offset, uint32_t &value) const;
            Status status_;
            RegisterBus bus_;
            // Detach invalidates even a callback that reattaches an identical
            // function/context before an outstanding read returns.
            uint64_t busEpoch_ {0};
    };

} // namespace simpleath

#endif // SIMPLEATH_AR9565_CORE_HPP
