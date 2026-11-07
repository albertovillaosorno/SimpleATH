// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_AR9565_NVM_READER_HPP
#define SIMPLEATH_AR9565_NVM_READER_HPP

#include "Ar9565Core.hpp"

namespace simpleath
{

    enum class NvmSource : uint8_t
    {
        Eeprom,
        Otp
    };
    enum class NvmResult : uint8_t
    {
        Ok,
        InvalidArgument,
        SessionUnavailable,
        UnsupportedIdentity,
        UnsupportedSilicon,
        RadioAsleep,
        InvalidRegister,
        RegisterReadFailed,
        StorageAbsent,
        ProtectedAccess,
        WordTimeout,
        CaptureTimeout,
        InvalidClock,
        UnstableStatus
    };

    // This is an ACTIVE NVM transaction capability, not the passive inspection
    // RegisterBus. Reading trigger registers starts EEPROM/OTP hardware access.
    // The future verified PCI owner supplies it only after exclusive claim, D0,
    // BAR ownership and explicit hardware authorization. No such backend is
    // wired into the current IOService. Never extend the passive register
    // allowlist. Caller serializes power/stop with this call and retains
    // context throughout.
    struct NvmReadBackend
    {
            // Retained, disjoint callback state: it must not overlap either
            // writable capture output. Its full size is opaque to this reader.
            void *context;
            bool (*ownerInD0)(void *context);
            // Must use ordered little-endian MMIO and report transport errors.
            // Erased NVM data may legitimately be all ones; do not
            // blanket-reject data words.
            bool (*read32)(void *context, uint32_t offset, uint32_t *value);
            // Monotonic microseconds; any observed regression aborts the
            // capture. All callbacks must be bounded/non-reentrant.
            uint64_t (*nowMicros)(void *context);
            void (*delayMicros)(void *context, uint32_t microseconds);
            uint32_t barLengthBytes;
    };

    struct NvmReadStatus
    {
            NvmResult result;
            NvmSource source;
            Silicon silicon;
            size_t bytesAcquired;
            uint32_t polls;
            uint32_t lastRegister;
            uint32_t lastValue;
            bool captureComplete;
    };

    // Capture ALREADY POWERED hardware's NVM into caller-owned
    // ascending-address byte storage for restoreEepromDump. Only the upstream
    // AR9565 origin search spans are supported: EEPROM <=4096 bytes, OTP <=1024
    // bytes. This does not claim to discover the physical storage capacity or
    // read its entire contents. Physical identity must come from this same
    // exclusive owner's live config. Requires thread/work-loop context, never a
    // hard interrupt handler. Polling is capped per word and per capture (2
    // seconds plus bounded callback overhead). Destination, status, backend and
    // identity storage must be disjoint, as must the backend context's full
    // allocation. A context pointer into either output is rejected before
    // writes, but deeper context-allocation overlaps remain a caller contract.
    // Only the return value is valid on an alias error. For a
    // valid destination span, other failures wipe its bytes; invalid arguments
    // do not establish a writable span.
    // captureComplete remains false on every failure. No reset/wake, EEPROM
    // writes, bus mastering, RF writes or TX occurs here.
    NvmResult captureAr9565Nvm(const NvmReadBackend &backend,
                               const Identity &physicalIdentity,
                               NvmSource source, uint8_t *destination,
                               size_t byteCount, NvmReadStatus &status);

} // namespace simpleath
#endif
