// SPDX-License-Identifier: AGPL-3.0-only
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
