// SPDX-License-Identifier: AGPL-3.0-only
// Derived from permissive ath9k PCI EEPROM and AR9003 OTP read protocols.
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 * Copyright (c) 2010-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
// Local Linux source SHA-256:
// pci.c: c90324177f6e4f15fbdef18e8d207d62a5726c01249dc8412161f5417d02dd43
// hw.c: 8d06b4a22733dedd2d2a46247128f254b9345efae659de14189a8c2c0fd4731f
// reg.h: 629a6df177d63b2a99202ab97a3641c488b5f1ac738f6f15612c7b4ebacebade
// ar9003_eeprom.c:
// 9af461f68c73fdbe553619534f0474dca637a7c5191729251fa479af2ad75dc6
// ar9003_eeprom.h:
// 4de071df42f0d91df022c91779f9bb7d0aac57fa7803f240530b4f0acd457bbd
#include "Ar9565NvmReader.hpp"

namespace simpleath
{
    namespace
    {
        constexpr uint32_t kEepromWindow = 0x2000;
        constexpr uint32_t kEepromData = 0x4084;
        constexpr uint32_t kEepromBusy = 0x10000;
        constexpr uint32_t kEepromBusyAccess = 0x20000;
        constexpr uint32_t kEepromProtected = 0x40000;
        constexpr uint32_t kEepromAbsentAccess = 0x80000;
        constexpr uint32_t kOtpWindow = 0x14000;
        constexpr uint32_t kOtpStatus = 0x15f18;
        constexpr uint32_t kOtpData = 0x15f1c;
        constexpr uint32_t kPollMicros = 10;
        constexpr uint64_t kCaptureMicros = 2000000;
        constexpr uint32_t kMaximumPolls = 200000;

        class Capture
        {
            public:
                Capture(const NvmReadBackend &backend, NvmReadStatus &status)
                    : backend_(backend), status_(status),
                      started_(backend.nowMicros(backend.context)),
                      lastMicros_(started_)
                {
                }

                // A clock may regress without falling behind the first
                // timestamp of a word or capture. Check every observed sample,
                // including the ones read after a register callback, rather
                // than checking only elapsed bounds.
                NvmResult clock(uint64_t &now)
                {
                    // The time source can share the revoked PCI owner. Every
                    // call, including wait timestamps, requires a fresh D0
                    // preflight rather than relying on the previous MMIO read.
                    if (!backend_.ownerInD0(backend_.context))
                        return NvmResult::SessionUnavailable;
                    now = backend_.nowMicros(backend_.context);
                    // The clock callback itself may revoke the same owner.
                    // Fail before any next read32/delay through that context.
                    if (!backend_.ownerInD0(backend_.context))
                        return NvmResult::SessionUnavailable;
                    if (now < lastMicros_)
                        return NvmResult::InvalidClock;
                    lastMicros_ = now;
                    return NvmResult::Ok;
                }

                NvmResult budget()
                {
                    uint64_t now = 0;
                    const NvmResult result = clock(now);
                    if (result != NvmResult::Ok)
                        return result;
                    return now - started_ >= kCaptureMicros
                               ? NvmResult::CaptureTimeout
                               : NvmResult::Ok;
                }

                NvmResult read(uint32_t offset, uint32_t &value)
                {
                    NvmResult result = budget();
                    if (result != NvmResult::Ok)
                        return result;
                    if ((offset & 3u) || offset > backend_.barLengthBytes ||
                        backend_.barLengthBytes - offset < 4)
                        return NvmResult::InvalidRegister;
                    status_.lastRegister = offset;
                    status_.lastValue = 0;
                    if (!backend_.read32(backend_.context, offset, &value))
                        return NvmResult::RegisterReadFailed;
                    status_.lastValue = value;
                    return budget();
                }

                NvmResult wait(uint32_t reg, uint32_t mask, uint32_t expected,
                               uint32_t timeoutMicros, uint32_t &value)
                {
                    uint64_t wordStarted = 0;
                    NvmResult result = clock(wordStarted);
                    if (result != NvmResult::Ok)
                        return result;
                    for (uint32_t i = 0; i <= timeoutMicros / kPollMicros; ++i)
                    {
                        if (status_.polls >= kMaximumPolls)
                            return NvmResult::CaptureTimeout;
                        ++status_.polls;
                        result = read(reg, value);
                        if (result != NvmResult::Ok)
                            return result;
                        if (value == 0xffffffffu)
                            return NvmResult::RegisterReadFailed;
                        uint64_t now = 0;
                        result = clock(now);
                        if (result != NvmResult::Ok)
                            return result;
                        if (reg == kEepromData)
                        {
                            if (value & kEepromAbsentAccess)
                                return NvmResult::StorageAbsent;
                            // Protection is a terminal access fault, not a
                            // transient busy condition. Repeatedly polling a
                            // denied EEPROM word cannot make it readable.
                            if (value & kEepromProtected)
                                return NvmResult::ProtectedAccess;
                        }
                        if (now - wordStarted >= timeoutMicros)
                            break;
                        if ((value & mask) == expected)
                            return NvmResult::Ok;
                        if (i == timeoutMicros / kPollMicros)
                            break;
                        // The last clock callback may itself revoke D0. Do
                        // not issue a delay through its now-invalid context.
                        if (!backend_.ownerInD0(backend_.context))
                            return NvmResult::SessionUnavailable;
                        backend_.delayMicros(backend_.context, kPollMicros);
                    }
                    return NvmResult::WordTimeout;
                }

            private:
                const NvmReadBackend &backend_;
                NvmReadStatus &status_;
                uint64_t started_;
                uint64_t lastMicros_;
        };

        bool overlaps(const void *a, size_t aBytes, const void *b,
                      size_t bBytes)
        {
            const auto first = reinterpret_cast<uintptr_t>(a);
            const auto second = reinterpret_cast<uintptr_t>(b);
            return aBytes && bBytes &&
                   (first >= second ? first - second < bBytes
                                    : second - first < aBytes);
        }

        void clearBytes(uint8_t *destination, size_t length)
        {
            for (size_t i = 0; i < length; ++i)
                destination[i] = 0;
        }

        // This preflight is shared by raw discovery and the epoch lease.
        // Discovery must reject aliases before touching caller outputs; a
        // lease must reject the same aliases before erasing a live board.
        bool discoveryInputsDisjoint(
            const NvmReadBackend &backend, const Identity &physicalIdentity,
            const uint8_t *storage, size_t storageBytes, const uint8_t *scratch,
            size_t scratchBytes, const NvmBoardSelection &board,
            const NvmDiscoveryStatus &status)
        {
            struct Span
            {
                    const void *address;
                    size_t bytes;
            };

            const Span spans[] = {
                {storage, storageBytes},
                {scratch, scratchBytes},
                {&board, sizeof(board)},
                {&status, sizeof(status)},
                {&backend, sizeof(backend)},
                {&physicalIdentity, sizeof(physicalIdentity)}};
            for (size_t i = 0; i < sizeof(spans) / sizeof(spans[0]); ++i)
            {
                // The provider may mutate its opaque context while polling.
                // Neither the borrowed callback table nor the live PCI
                // identity is safe callback-owned storage, even though those
                // two inputs are not writable output buffers.
                if (overlaps(spans[i].address, spans[i].bytes, backend.context,
                             1))
                    return false;
                for (size_t j = i + 1; j < sizeof(spans) / sizeof(spans[0]);
                     ++j)
                {
                    if (overlaps(spans[i].address, spans[i].bytes,
                                 spans[j].address, spans[j].bytes))
                        return false;
                }
            }
            return true;
        }
    } // namespace

    // Internal byte-range capture is used for exact four-byte origin probes;
    // public captureAr9565Nvm retains its ascending-zero address semantics.
    static NvmResult captureRange(const NvmReadBackend &backend,
                                  const Identity &physicalIdentity,
                                  NvmSource source, size_t firstByte,
                                  uint8_t *destination, size_t byteCount,
                                  NvmReadStatus &status)
    {
        // The output could alias the caller's backend callbacks or identity.
        // Reject such a contract breach BEFORE clearing either output or
        // invoking a corrupted function pointer. On this error the returned
        // result, not the unwritable/aliased status field, is authoritative.
        // The opaque context's full allocation size is not known here. Its
        // pointer must at least not point into either writable output: clearing
        // that storage would corrupt callback state before the first call.
        // The caller still guarantees disjointness of the complete allocation.
        if (overlaps(destination, byteCount, &backend, sizeof(backend)) ||
            overlaps(destination, byteCount, &physicalIdentity,
                     sizeof(physicalIdentity)) ||
            overlaps(destination, byteCount, &status, sizeof(status)) ||
            overlaps(destination, byteCount, backend.context, 1) ||
            overlaps(&status, sizeof(status), &backend, sizeof(backend)) ||
            overlaps(&status, sizeof(status), &physicalIdentity,
                     sizeof(physicalIdentity)) ||
            overlaps(&status, sizeof(status), backend.context, 1) ||
            // A callback owns mutable context but cannot borrow its own
            // function table or the verified physical identity as that state.
            overlaps(backend.context, 1, &backend, sizeof(backend)) ||
            overlaps(backend.context, 1, &physicalIdentity,
                     sizeof(physicalIdentity)))
            return NvmResult::InvalidArgument;
        status = {};
        status.source = source;
        const size_t maximum = source == NvmSource::Eeprom ? 4096 : 1024;
        if (!destination || byteCount == 0 || firstByte >= maximum ||
            byteCount > maximum - firstByte ||
            (source != NvmSource::Eeprom && source != NvmSource::Otp))
            return status.result = NvmResult::InvalidArgument;
        clearBytes(destination, byteCount);
        if (!backend.context || !backend.ownerInD0 || !backend.read32 ||
            !backend.nowMicros || !backend.delayMicros)
            return status.result = NvmResult::InvalidArgument;
        if (!isSupportedPci(physicalIdentity.vendorId,
                            physicalIdentity.deviceId) ||
            physicalIdentity.spoofPossible)
            return status.result = NvmResult::UnsupportedIdentity;
        // The monotonic clock can belong to the same revoked PCI owner as
        // MMIO. Do not invoke it during Capture construction before the first
        // ownership check. Capture::budget rechecks ownership before reads.
        if (!backend.ownerInD0(backend.context))
            return status.result = NvmResult::SessionUnavailable;
        Capture capture(backend, status);
        uint32_t value = 0;
        NvmResult result = capture.read(kRevisionRegister, value);
        if (result != NvmResult::Ok)
            return status.result = result;
        // A disconnected BAR can read as all ones. This is a transport fault,
        // not evidence that a different silicon revision was discovered.
        if (value == 0xffffffffu)
            return status.result = NvmResult::RegisterReadFailed;
        if (decodeRevision(value, status.silicon) != Result::Ok)
            return status.result = NvmResult::UnsupportedSilicon;
        result = capture.read(kRtcStatusRegister, value);
        if (result != NvmResult::Ok)
            return status.result = result;
        if (value == 0xffffffffu)
            return status.result = NvmResult::RegisterReadFailed;
        if ((value & kRtcStatusMask) != kRtcOn)
            return status.result = NvmResult::RadioAsleep;

        const uint32_t wordBytes = source == NvmSource::Eeprom ? 2 : 4;
        const size_t firstWord = firstByte / wordBytes;
        const size_t words =
            (firstByte % wordBytes + byteCount + wordBytes - 1) / wordBytes;
        // Validate the entire requested MMIO span BEFORE a trigger read.
        const uint32_t lastTrigger =
            (source == NvmSource::Eeprom ? kEepromWindow : kOtpWindow) +
            static_cast<uint32_t>((firstWord + words - 1) * 4);
        const uint32_t lastRegister =
            source == NvmSource::Eeprom
                ? (lastTrigger > kEepromData ? lastTrigger : kEepromData)
                : kOtpData;
        if (lastRegister > backend.barLengthBytes ||
            backend.barLengthBytes - lastRegister < 4)
            return status.result = NvmResult::InvalidRegister;
        for (size_t word = 0; word < words; ++word)
        {
            const uint32_t trigger =
                (source == NvmSource::Eeprom ? kEepromWindow : kOtpWindow) +
                static_cast<uint32_t>((firstWord + word) * 4);
            result =
                capture.read(trigger, value); // Starts the NVM transaction.
            if (result != NvmResult::Ok)
                break;
            result =
                source == NvmSource::Eeprom
                    ? capture.wait(kEepromData, kEepromBusy | kEepromProtected,
                                   0, 100000, value)
                    : capture.wait(kOtpStatus, 7, 4, 1000, value);
            if (result != NvmResult::Ok)
                break;
            if (source == NvmSource::Eeprom)
            {
                // ath_pci_eeprom_read performs a SECOND status/data read
                // after the ready wait. The wait-loop sample is not payload.
                result = capture.read(kEepromData, value);
                if (result != NvmResult::Ok)
                    break;
                if (value == 0xffffffffu)
                    result = NvmResult::RegisterReadFailed;
                else if ((value & kEepromAbsentAccess) != 0)
                    result = NvmResult::StorageAbsent;
                else if ((value & kEepromProtected) != 0)
                    result = NvmResult::ProtectedAccess;
                else if ((value & (kEepromBusy | kEepromBusyAccess)) != 0)
                    // BUSY_ACCESS is separate from the upstream wait mask.
                    // Never accept a still-active second sample as data.
                    result = NvmResult::UnstableStatus;
                if (result != NvmResult::Ok)
                    break;
            }
            else
            {
                result = capture.read(kOtpData, value);
                if (result != NvmResult::Ok)
                    break;
            }
            for (uint32_t byte = 0; byte < wordBytes; ++byte)
            {
                const size_t absolute = (firstWord + word) * wordBytes + byte;
                if (absolute >= firstByte && absolute - firstByte < byteCount)
                    destination[status.bytesAcquired++] =
                        static_cast<uint8_t>(value >> (byte * 8));
            }
        }
        if (result != NvmResult::Ok)
        {
            clearBytes(destination, byteCount);
            return status.result = result;
        }
        status.captureComplete = true;
        return status.result = NvmResult::Ok;
    }

    NvmResult captureAr9565Nvm(const NvmReadBackend &backend,
                               const Identity &physicalIdentity,
                               NvmSource source, uint8_t *destination,
                               size_t byteCount, NvmReadStatus &status)
    {
        return captureRange(backend, physicalIdentity, source, 0, destination,
                            byteCount, status);
    }

    NvmDiscoveryResult discoverAr9565Nvm(const NvmReadBackend &backend,
                                         const Identity &physicalIdentity,
                                         uint8_t *storage, size_t storageBytes,
                                         uint8_t *scratch, size_t scratchBytes,
                                         NvmBoardSelection &board,
                                         NvmDiscoveryStatus &status)
    {
        // Check every writable span against all other spans before touching
        // status/board: even error cleanup may corrupt an aliased callback or
        // the physical identity otherwise. Context allocation disjointness
        // beyond its pointer remains an explicit backend-owner contract.
        if (!discoveryInputsDisjoint(backend, physicalIdentity, storage,
                                     storageBytes, scratch, scratchBytes, board,
                                     status))
            return NvmDiscoveryResult::InvalidArgument;
        board = {};
        board.txGain = TxGainProfile::Unknown;
        board.rxGain = RxGainProfile::Unknown;
        status = {};
        if (!storage || storageBytes < 4096 || !scratch ||
            scratchBytes < kAr9565EepromScratchBytes)
            return status.result = NvmDiscoveryResult::InvalidArgument;

        struct Candidate
        {
                NvmSource source;
                uint16_t origin;
        };

        // The reference search falls back to OTP only after EEPROM has no
        // usable header. Never infer an EEPROM's size from a BAR window.
        constexpr Candidate candidates[] = {{NvmSource::Eeprom, 0x3ff},
                                            {NvmSource::Eeprom, 0xfff},
                                            {NvmSource::Eeprom, 0x1ff},
                                            {NvmSource::Otp, 0x3ff},
                                            {NvmSource::Otp, 0x1ff}};
        NvmDiscoveryResult outcome = NvmDiscoveryResult::NoValidImage;
        const EepromTemplates templates = pinnedEepromTemplates();
        for (const auto &candidate : candidates)
        {
            status.lastSource = candidate.source;
            status.lastOrigin = candidate.origin;
            ++status.attempts;
            const size_t length = static_cast<size_t>(candidate.origin) + 1;
            // ath9k checks only the four bytes at the origin before
            // selecting a source. Once a nonempty header has been found,
            // NONE of the later read/restore/board errors permits fallback.
            uint8_t header[4] {};
            const NvmResult probeResult =
                captureRange(backend, physicalIdentity, candidate.source,
                             length - sizeof(header), header, sizeof(header),
                             status.lastCapture);
            if (probeResult == NvmResult::StorageAbsent)
                continue;
            if (probeResult != NvmResult::Ok)
            {
                outcome = NvmDiscoveryResult::CaptureFailed;
                break;
            }
            bool empty = true, erased = true;
            for (const uint8_t byte : header)
            {
                empty = empty && byte == 0;
                erased = erased && byte == 0xff;
            }
            if (empty || erased)
                continue;
            const uint32_t probedSrev = status.lastCapture.silicon.rawSrev;
            // A second bounded capture gathers the entire chosen storage
            // chain. StorageAbsent here is a fatal mid-transaction fault.
            const NvmResult captureResult =
                captureAr9565Nvm(backend, physicalIdentity, candidate.source,
                                 storage, length, status.lastCapture);
            if (captureResult != NvmResult::Ok)
            {
                outcome = NvmDiscoveryResult::CaptureFailed;
                break;
            }
            if (status.lastCapture.silicon.rawSrev != probedSrev)
            {
                status.lastCapture.captureComplete = false;
                status.lastCapture.result = NvmResult::UnstableStatus;
                outcome = NvmDiscoveryResult::CaptureFailed;
                break;
            }
            // Reject any change to the selected header between the probe
            // and full acquisition (including a disappearing/replaced NVM).
            bool headerStable = true;
            for (size_t i = 0; i < sizeof(header); ++i)
                headerStable =
                    headerStable &&
                    header[i] == storage[length - sizeof(header) + i];
            if (!headerStable)
            {
                outcome = NvmDiscoveryResult::CorruptImage;
                break;
            }
            status.lastRestore = {};
            const EepromResult restored = restoreEepromDump(
                storage, length, candidate.origin, templates, scratch,
                scratchBytes, board.image, status.lastRestore);
            if (restored != EepromResult::Ok)
            {
                outcome = NvmDiscoveryResult::CorruptImage;
                break;
            }
            const EepromResult parsed =
                summarizeBoardData(board.image, board.summary);
            status.lastBoardResult = parsed;
            if (parsed != EepromResult::Ok)
            {
                outcome = NvmDiscoveryResult::CorruptImage;
                break;
            }
            // A correctly checksummed delta may still replace the 2-GHz
            // calibration pier frequencies with zeros, out-of-band values or
            // a nonincreasing sequence. Keep the raw summary diagnostic API
            // permissive, but never publish that image as selected board data.
            if (!board.summary.calibrationPierBinsPlausible)
            {
                status.lastBoardResult = EepromResult::UnsupportedFormat;
                outcome = NvmDiscoveryResult::CorruptImage;
                break;
            }
            // Pinned dictionaries contain placeholder MAC addresses; a
            // reference/delta with no actual board MAC must not be promoted
            // to a recovered device identity, even if its chain mask fits.
            constexpr uint8_t templateIds[] = {2, 3, 4, 5, 6};
            bool placeholderMac = false;
            for (const uint8_t id : templateIds)
            {
                size_t templateLength = 0;
                const uint8_t *defaults =
                    templates.find(templates.context, id, &templateLength);
                if (!defaults || templateLength != sizeof(board.image.bytes))
                    continue;
                bool identical = true;
                for (size_t i = 0; i < sizeof(board.summary.mac); ++i)
                    identical =
                        identical && board.summary.mac[i] == defaults[2 + i];
                if (identical)
                {
                    placeholderMac = true;
                    break;
                }
            }
            if (placeholderMac)
            {
                status.lastBoardResult = EepromResult::InvalidBoardIdentity;
                outcome = NvmDiscoveryResult::CorruptImage;
                break;
            }
            const EepromResult gains = selectBoardGainProfiles(
                board.summary, board.txGain, board.rxGain);
            status.lastBoardResult = gains;
            if (gains != EepromResult::Ok)
            {
                outcome = NvmDiscoveryResult::CorruptImage;
                break;
            }
            board.source = candidate.source;
            board.origin = candidate.origin;
            board.silicon = status.lastCapture.silicon;
            board.valid = true;
            outcome = NvmDiscoveryResult::Ok;
            break;
        }
        // Erase all transient NVM bytes, even when a reconstructed immutable
        // snapshot was accepted. Never hand back a partially accepted image.
        clearBytes(storage, 4096);
        clearBytes(scratch, kAr9565EepromScratchBytes);
        if (outcome != NvmDiscoveryResult::Ok)
        {
            board = {};
            board.txGain = TxGainProfile::Unknown;
            board.rxGain = RxGainProfile::Unknown;
        }
        return status.result = outcome;
    }

    NvmBoardLease::NvmBoardLease()
        : board_ {}, activeEpoch_(0), lastEpoch_(0), acquiring_(false),
          revoked_(false)
    {
        board_.txGain = TxGainProfile::Unknown;
        board_.rxGain = RxGainProfile::Unknown;
    }

    NvmBoardLease::~NvmBoardLease()
    {
        // Destruction while acquisition is active violates the single-owner
        // lifetime. The owner must drain operations before deleting the lease.
        eraseBoard();
    }

    void NvmBoardLease::eraseBoard()
    {
        // Volatile byte erasure prevents a dead-store optimization from
        // retaining the prior board MAC, calibration and regulatory fields.
        volatile uint8_t *bytes = reinterpret_cast<volatile uint8_t *>(&board_);
        for (size_t i = 0; i < sizeof(board_); ++i)
            bytes[i] = 0;
        board_.txGain = TxGainProfile::Unknown;
        board_.rxGain = RxGainProfile::Unknown;
        activeEpoch_ = 0;
    }

    void NvmBoardLease::invalidate()
    {
        activeEpoch_ = 0;
        if (acquiring_)
        {
            // Never erase storage while the in-flight parser writes it.
            // Rejected at publication even if the device read succeeds.
            revoked_ = true;
            return;
        }
        eraseBoard();
        revoked_ = false;
    }

    const NvmBoardSelection *NvmBoardLease::view(uint64_t ownerEpoch) const
    {
        return ownerEpoch && activeEpoch_ == ownerEpoch && !acquiring_ &&
                       !revoked_ && board_.valid
                   ? &board_
                   : nullptr;
    }

    NvmDiscoveryResult NvmBoardLease::acquire(
        const NvmReadBackend &backend, const Identity &physicalIdentity,
        uint64_t ownerEpoch, uint8_t *storage, size_t storageBytes,
        uint8_t *scratch, size_t scratchBytes, NvmDiscoveryStatus &status)
    {
        // A rejected alias must leave both the lease and aliased caller
        // memory untouched; otherwise erasure could corrupt callback state.
        if (acquiring_ ||
            !discoveryInputsDisjoint(backend, physicalIdentity, storage,
                                     storageBytes, scratch, scratchBytes,
                                     board_, status) ||
            overlaps(backend.context, 1, this, sizeof(*this)) ||
            overlaps(storage, storageBytes, this, sizeof(*this)) ||
            overlaps(scratch, scratchBytes, this, sizeof(*this)) ||
            overlaps(&status, sizeof(status), this, sizeof(*this)) ||
            overlaps(&backend, sizeof(backend), this, sizeof(*this)) ||
            overlaps(&physicalIdentity, sizeof(physicalIdentity), this,
                     sizeof(*this)))
            return NvmDiscoveryResult::InvalidArgument;
        // Any non-alias attempt invalidates a prior board. An epoch may only
        // advance, never roll back or reuse a previously retired generation.
        invalidate();
        if (!ownerEpoch || ownerEpoch <= lastEpoch_)
        {
            // A rejected generation must not expose the previous successful
            // capture status after invalidating its board lease. Aliases were
            // rejected above, so these diagnostics are safe to clear.
            status = {};
            return status.result = NvmDiscoveryResult::InvalidArgument;
        }
        lastEpoch_ = ownerEpoch;
        acquiring_ = true;
        const NvmDiscoveryResult result =
            discoverAr9565Nvm(backend, physicalIdentity, storage, storageBytes,
                              scratch, scratchBytes, board_, status);
        acquiring_ = false;
        if (revoked_ || result != NvmDiscoveryResult::Ok)
        {
            const bool wasRevoked = revoked_;
            invalidate();
            if (wasRevoked)
                status.result = NvmDiscoveryResult::OwnerEpochRevoked;
            return wasRevoked ? NvmDiscoveryResult::OwnerEpochRevoked : result;
        }
        activeEpoch_ = ownerEpoch;
        return result;
    }

} // namespace simpleath
