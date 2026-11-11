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
//   - Native driver contracts and implementation for ar9565 rf bus.
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
//   - Native driver contracts and implementation for ar9565 rf bus.
// - Description:
//   - Implements or verifies the Ar9565RfBus source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for ar9565 rf bus.

#include "Ar9565RfBus.hpp"
#include "Ar9565Channel.hpp"
#include "Ar9565RfIni.hpp"
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        // Linux ath9k ar9003_phy.c: ar9003_hw_rfbus_req/done
// Linux reference: drivers/net/wireless/ath/ath9k/ar9003_phy.c
        constexpr uint32_t kRfBusRequest = 0xa23c;
        constexpr uint32_t kRfBusGrant = 0xa240;
        constexpr uint32_t kPhyRxDelay = 0xa254;
        constexpr uint32_t kRfBusEnable = 0x1;
        constexpr uint32_t kPhyDelayMask = 0x3fff;
        constexpr uint32_t kQuantumMicros = 10;
        constexpr uint32_t kActivateMicros = 100;
        constexpr size_t kMaxPolls = 100000 / kQuantumMicros;

        bool validBackend(const RfChannelBackend &backend)
        {
            const auto &io = backend.io;
            return io.context != nullptr && io.ownerEpoch != 0 &&
                   io.barLengthBytes != 0 && io.permitWrite != nullptr &&
                   io.write32 != nullptr && io.delayMicros != nullptr &&
                   backend.read32 != nullptr;
        }

        bool validBar(uint32_t length)
        {
            return length >= kPhyRxDelay + sizeof(uint32_t);
        }

        bool permitted(const RfIniBackend &io, RfBusProgress &progress,
                       const RfBusLease &lease)
        {
            if (io.permitWrite(io.context, io.ownerEpoch))
            {
                return true;
            }
            progress.result = RfBusResult::OwnershipLost;
            progress.requiresReset = lease.requestPosted;
            return false;
        }
    } // namespace

    RfBusProgress requestAr9565RfBus(const RfChannelBackend &backend,
                                     RfBusLease &lease)
    {
        RfBusProgress progress {
            RfBusResult::InvalidBackend,
            0,
            0,
            false,
        };
        const RfChannelBackend stable = backend;
        if (!validBackend(stable))
        {
            return progress;
        }
        progress.result = RfBusResult::InvalidBar;
        if (!validBar(stable.io.barLengthBytes))
        {
            return progress;
        }
        progress.result = RfBusResult::AlreadyRequested;
        if (lease.requestPosted || lease.granted || lease.requiresReset)
        {
            progress.requiresReset = lease.requiresReset;
            return progress;
        }
        const RfIniBackend &io = stable.io;
        progress.result = RfBusResult::OwnershipLost;
        if (!permitted(io, progress, lease))
        {
            return progress;
        }
        // Set the lease BEFORE submitting the write: a failed MMIO callback
        // can still have reached hardware and requires reset/recovery.
        lease.ownerContext = io.context;
        lease.ownerEpoch = io.ownerEpoch;
        lease.requestPosted = true;
        lease.requiresReset = true;
        progress.requiresReset = true;
        if (!io.write32(io.context, kRfBusRequest, kRfBusEnable))
        {
            progress.result = RfBusResult::WriteFailed;
            return progress;
        }
        for (size_t count = 0; count < kMaxPolls; ++count)
        {
            if (!permitted(io, progress, lease))
            {
                return progress;
            }
            uint32_t grant = 0;
            if (!stable.read32(io.context, kRfBusGrant, &grant))
            {
                progress.result = RfBusResult::ReadFailed;
                return progress;
            }
            progress.lastGrant = grant;
            ++progress.polls;
            if ((grant & kRfBusEnable) != 0)
            {
                // Do not publish a grant after owner epoch revocation.
                if (!permitted(io, progress, lease))
                {
                    return progress;
                }
                lease.granted = true;
                lease.requiresReset = false;
                progress.requiresReset = false;
                progress.result = RfBusResult::Ok;
                return progress;
            }
            if (count + 1 < kMaxPolls)
            {
                io.delayMicros(io.context, kQuantumMicros);
            }
        }
        progress.result = RfBusResult::GrantTimeout;
        return progress;
    }

    RfBusProgress releaseAr9565RfBus(const RfChannelBackend &backend,
                                     RfBusLease &lease)
    {
        RfBusProgress progress {
            RfBusResult::InvalidBackend,
            0,
            0,
            false,
        };
        const RfChannelBackend stable = backend;
        if (!validBackend(stable))
        {
            return progress;
        }
        progress.result = RfBusResult::InvalidBar;
        if (!validBar(stable.io.barLengthBytes))
        {
            return progress;
        }
        const RfIniBackend &io = stable.io;
        progress.result = RfBusResult::LeaseMismatch;
        if (!lease.requestPosted || !lease.granted ||
            lease.ownerEpoch != io.ownerEpoch ||
            lease.ownerContext != io.context || lease.requiresReset)
        {
            progress.requiresReset = lease.requestPosted;
            return progress;
        }
        // Once release starts, an interrupted delay/read/write makes the
        // old lease ambiguous. Prevent retry without a native reset.
        lease.requiresReset = true;
        progress.requiresReset = true;
        if (!permitted(io, progress, lease))
        {
            return progress;
        }
        uint32_t rxDelay = 0;
        if (!stable.read32(io.context, kPhyRxDelay, &rxDelay))
        {
            progress.result = RfBusResult::ReadFailed;
            return progress;
        }
        if (!permitted(io, progress, lease))
        {
            return progress;
        }
        io.delayMicros(io.context,
                       ((rxDelay & kPhyDelayMask) / kQuantumMicros) +
                           kActivateMicros);
        if (!permitted(io, progress, lease))
        {
            return progress;
        }
        if (!io.write32(io.context, kRfBusRequest, 0))
        {
            progress.result = RfBusResult::WriteFailed;
            return progress;
        }
        // No stale grant may remain held by this owner after release.
        lease = {};
        progress.result = RfBusResult::Ok;
        progress.requiresReset = false;
        return progress;
    }
} // namespace simpleath
