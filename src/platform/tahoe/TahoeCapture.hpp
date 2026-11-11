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
//   - Native driver contracts and implementation for tahoe capture.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for tahoe capture.
// - Description:
//   - Implements or verifies the TahoeCapture source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for tahoe capture.

#ifndef SIMPLEATH_TAHOE_CAPTURE_HPP
#define SIMPLEATH_TAHOE_CAPTURE_HPP

#include "TahoeControllerABI.hpp"
#include <IOKit/IOService.h>
#include <libkern/c++/OSObject.h>

namespace simpleath
{
    namespace tahoe
    {
        // Native objects are factory-allocated by 25G332 CoreCapture. We own
        // retained OSObject prefixes, never guessed private object layouts.
        // The controller serializes start/stop; all pipes outlive the native
        // IO80211 superclass's stop and every borrower of getLogger().
        class TahoeCapture final
        {
            public:
                TahoeCapture() = default;
                TahoeCapture(const TahoeCapture &) = delete;
                TahoeCapture &operator=(const TahoeCapture &) = delete;
                TahoeCapture(TahoeCapture &&) = delete;
                TahoeCapture &operator=(TahoeCapture &&) = delete;
                ~TahoeCapture() = default;

                bool start(IOService *owner, IOWorkLoop *loop);
                void stop();
                CCLogStream *logger() const;
                CommonFaultReporter *faultReporter() const;
                bool pipes(CCPipe **logs, CCPipe **data,
                           CCPipe **snapshots) const;

            private:
                OSObject *driverPipe_ {nullptr};
                OSObject *dataPipe_ {nullptr};
                OSObject *snapshotsPipe_ {nullptr};
                OSObject *logger_ {nullptr};
                OSObject *faultStream_ {nullptr};
                OSObject *coreFaultReporter_ {nullptr};
                OSObject *faultReporter_ {nullptr};
                bool driverStarted_ {false};
                bool dataStarted_ {false};
                bool snapshotsStarted_ {false};
        };
    } // namespace tahoe
} // namespace simpleath
#endif
