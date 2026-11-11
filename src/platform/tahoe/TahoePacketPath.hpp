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
//   - Native driver contracts and implementation for tahoe packet path.
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
//   - Native driver contracts and implementation for tahoe packet path.
// - Description:
//   - Implements or verifies the TahoePacketPath source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for tahoe packet path.

#ifndef SIMPLEATH_TAHOE_PACKET_PATH_HPP
#define SIMPLEATH_TAHOE_PACKET_PATH_HPP
#include <IOKit/IOReturn.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSObject.h>
class IO80211SkywalkInterface;
class SimpleATHTahoeController;

namespace simpleath
{
    namespace tahoe
    {
        // Native factory-owned Skywalk objects; no private object allocation,
        // Ethernet provider impersonation or borrowed DMA storage.
        class TahoePacketPath final
        {
            public:
                TahoePacketPath() = default;
                ~TahoePacketPath();
                TahoePacketPath(const TahoePacketPath &) = delete;
                TahoePacketPath &operator=(const TahoePacketPath &) = delete;
                IOReturn start(IO80211SkywalkInterface *interface,
                               SimpleATHTahoeController *controller);
                void stop();
                IOReturn enable();
                void disable();
                void poll();
                OSObject *txSubmission() const;
                OSObject *txCompletion() const;
                OSObject *rxCompletion() const;
                OSObject *txPool() const;
                OSObject *rxPool() const;
                bool registered() const;

            private:
                static constexpr unsigned int kCapacity = 64;
                static unsigned int submit(OSObject *, OSObject *,
                                           OSObject *const *, unsigned int,
                                           void *context);
                static unsigned int complete(OSObject *, OSObject *,
                                             OSObject **, unsigned int,
                                             void *context);
                static unsigned int receive(OSObject *, OSObject *, OSObject **,
                                            unsigned int, void *context);
                unsigned int submitPackets(OSObject *const *, unsigned int);
                unsigned int completePackets(OSObject **, unsigned int);
                unsigned int receivePackets(OSObject **, unsigned int);
                void flushCompletions();
                SimpleATHTahoeController *controller_ {nullptr};
                IO80211SkywalkInterface *interface_ {nullptr};
                IOWorkLoop *loop_ {nullptr};
                OSObject *txPool_ {nullptr};
                OSObject *rxPool_ {nullptr};
                // TX submission, TX completion, RX completion. RX buffers are
                // allocated from the kernel pool on demand, not USB/PCI DMA.
                OSObject *queues_[3] {};
                unsigned int addedSources_ {0};
                OSObject *completed_[kCapacity] {};
                unsigned int completedHead_ {0};
                unsigned int completedCount_ {0};
                bool registered_ {false};
                bool enabled_ {false};
        };
    } // namespace tahoe
} // namespace simpleath
#endif
