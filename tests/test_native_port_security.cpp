// Standalone fail-closed driver-owned WPA2 controlled-port policy fixture.
#include "wifi/NativePortSecurityAdmission.hpp"

namespace
{
    using simpleath::ieee80211::nativeControlledPortSecurityReady;
    using simpleath::ieee80211::NativePortSecurityEvidence;
    using simpleath::ieee80211::Security;
    using simpleath::ieee80211::StationState;

    bool validateOpen()
    {
        NativePortSecurityEvidence e {};
        e.selectedSecurity = Security::Open;
        e.station = StationState::AssociatedOpen;
        e.hardwareKeyOwnerMatches = true;
        if (!nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.softwarePairwiseTxInstalled = true;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.softwarePairwiseTxInstalled = false;
        e.hardwarePairwiseInstalled = true;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.hardwarePairwiseInstalled = false;
        e.hardwareGroupInstalled = true;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.hardwareGroupInstalled = false;
        e.softwareGroupRxInstalled = true;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.softwareGroupRxInstalled = false;
        e.softwarePairwiseRxInstalled = true;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.softwarePairwiseRxInstalled = false;
        e.station = StationState::WaitingForWpa2Keys;
        return !nativeControlledPortSecurityReady(e);
    }

    bool validateM4Completion()
    {
        using simpleath::ieee80211::NativeM4CompletionEvidence;
        using simpleath::ieee80211::nativeM4TransmitCompleted;
        NativeM4CompletionEvidence evidence {};
        evidence.completedToken = 7;
        evidence.pendingToken = 7;
        evidence.joinEpoch = 12;
        evidence.radioEpoch = 12;
        evidence.hardwareKeyEpoch = 12;
        evidence.station = StationState::HardwareKeysInstalled;
        evidence.frameTransmitOk = true;
        if (!nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.completedToken = 8;
        if (nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.completedToken = 7;
        evidence.pendingToken = 0;
        if (nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.pendingToken = 7;
        evidence.joinEpoch = 13;
        if (nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.joinEpoch = 12;
        evidence.hardwareKeyEpoch = 13;
        if (nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.hardwareKeyEpoch = 12;
        evidence.frameTransmitOk = false;
        if (nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.frameTransmitOk = true;
        evidence.excessiveRetries = true;
        if (nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.excessiveRetries = false;
        evidence.filtered = true;
        if (nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.filtered = false;
        evidence.station = StationState::WaitingForWpa2Keys;
        if (nativeM4TransmitCompleted(evidence))
        {
            return false;
        }
        evidence.station = StationState::HardwareKeysInstalled;
        evidence.radioEpoch = 0;
        return !nativeM4TransmitCompleted(evidence);
    }

    bool validateWpa2()
    {
        NativePortSecurityEvidence e {};
        e.selectedSecurity = Security::Wpa2Personal;
        e.station = StationState::HardwareKeysInstalled;
        e.hardwareKeyOwnerMatches = true;
        e.hardwarePairwiseInstalled = true;
        e.hardwareGroupInstalled = true;
        e.softwarePairwiseTxInstalled = true;
        e.softwarePairwiseRxInstalled = true;
        e.softwareGroupRxInstalled = true;
        e.m4TransmitConfirmed = true;
        e.authenticatedProtectedRxObserved = true;
        if (!nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        // Every security proof is independent. A real M4 must be ACKed,
        // decrypted RX must authenticate its MIC/PN, and each key must be
        // present for this hardware owner epoch.
        bool *requirements[] = {
            &e.hardwareKeyOwnerMatches,     &e.hardwarePairwiseInstalled,
            &e.hardwareGroupInstalled,      &e.softwarePairwiseTxInstalled,
            &e.softwarePairwiseRxInstalled, &e.softwareGroupRxInstalled,
            &e.m4TransmitConfirmed,         &e.authenticatedProtectedRxObserved,
        };
        for (bool *required : requirements)
        {
            *required = false;
            if (nativeControlledPortSecurityReady(e))
            {
                return false;
            }
            *required = true;
        }
        e.pairwiseKeyRevoked = true;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.pairwiseKeyRevoked = false;
        e.hardwareKeyRequiresReset = true;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.hardwareKeyRequiresReset = false;
        e.osSupplicantOwnsWpa2 = true;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.osSupplicantOwnsWpa2 = false;
        e.station = StationState::WaitingForWpa2Keys;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.station = StationState::AssociatedOpen;
        if (nativeControlledPortSecurityReady(e))
        {
            return false;
        }
        e.station = StationState::HardwareKeysInstalled;
        const Security unsupportedModes[] {
            Security::LegacyProtected,
            Security::Wpa2Enterprise,
            Security::Wpa3Personal,
            Security::UnsupportedRsn,
            Security::Open,
        };
        for (const Security unsupported : unsupportedModes)
        {
            e.selectedSecurity = unsupported;
            if (nativeControlledPortSecurityReady(e))
            {
                return false;
            }
        }
        return true;
    }
} // namespace

int main()
{
    return validateOpen() && validateWpa2() && validateM4Completion() ? 0 : 1;
}
