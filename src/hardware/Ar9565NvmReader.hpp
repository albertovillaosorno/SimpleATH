#ifndef SIMPLEATH_AR9565_NVM_READER_HPP
#define SIMPLEATH_AR9565_NVM_READER_HPP

#include "Ar9565Core.hpp"
#include "Ar9565Eeprom.hpp"

namespace simpleath
{

    enum class NvmSource : uint8_t
    {
        Eeprom,
        Otp,
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
        UnstableStatus,
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
            // Retained, disjoint callback state: it must not overlap any
            // writable output, this callback table or the borrowed physical
            // identity. Its full size is opaque to this reader.
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
    // allocation. A context pointer into either output or either borrowed
    // input is rejected before callbacks/writes, but deeper context-allocation
    // overlaps remain a caller contract.
    // Only the return value is valid on an alias error. For a
    // valid destination span, other failures wipe its bytes; invalid arguments
    // do not establish a writable span.
    // captureComplete remains false on every failure. No reset/wake, EEPROM
    // writes, bus mastering, RF writes or TX occurs here.
    NvmResult captureAr9565Nvm(const NvmReadBackend &backend,
                               const Identity &physicalIdentity,
                               NvmSource source, uint8_t *destination,
                               size_t byteCount, NvmReadStatus &status);

    enum class NvmDiscoveryResult : uint8_t
    {
        Ok,
        InvalidArgument,
        NoValidImage,
        CaptureFailed,
        CorruptImage,
        OwnerEpochRevoked,
    };

    // A recovered image and its structurally checked board summary, NOT RF
    // authorization. Source, origin and silicon come from the same serialized
    // exclusive PCI transaction; "valid" means only that the pinned delta
    // chain, permanent MAC, single chain and supported gain indexes passed
    // static checks, including plausible ordered 2-GHz calibration pier bins.
    // Calibration/regulatory flags stay false. No fallbacks to template-only
    // images. Caller owns lifetime and must discard on teardown,
    // D0 loss, reset/resume or a subsequent acquisition failure.
    struct NvmBoardSelection
    {
            EepromImage image;
            BoardDataSummary summary;
            Silicon silicon;
            NvmSource source;
            uint16_t origin;
            TxGainProfile txGain;
            RxGainProfile rxGain;
            bool valid;
    };

    struct NvmDiscoveryStatus
    {
            NvmDiscoveryResult result;
            NvmReadStatus lastCapture;
            EepromRestoreStatus lastRestore;
            EepromResult lastBoardResult;
            NvmSource lastSource;
            uint16_t lastOrigin;
            uint8_t attempts;
    };

    // Bounded ath9k origin order: EEPROM 0x3ff, 0xfff, 0x1ff, then OTP
    // 0x3ff, 0x1ff. Probes each four-byte origin header first, then captures
    // the full span only for the first nonempty selected candidate.
    // Storage >=4096 and scratch >=kAr9565EepromScratchBytes are caller-owned;
    // no kernel-stack-sized allocations. Outputs, inputs, backend, physical
    // identity and callback context allocation must remain disjoint. Detectable
    // aliases return InvalidArgument without altering output; other failures
    // wipe board, storage and scratch. A blank header or StorageAbsent during
    // the four-byte probe may advance; once a header is selected, all later
    // failures (including mid-capture absence, layout, checksum or identity)
    // abort instead of silently choosing another board. At most five probes
    // plus one full capture, each bounded by the reader's 2 s cap.
    // Recheck D0 after software restoration, before publishing a board.
    // Does not grant permission to access devices or transmit: no native
    // owner is currently connected, and board calibration is incomplete.
    NvmDiscoveryResult discoverAr9565Nvm(const NvmReadBackend &backend,
                                         const Identity &physicalIdentity,
                                         uint8_t *storage, size_t storageBytes,
                                         uint8_t *scratch, size_t scratchBytes,
                                         NvmBoardSelection &board,
                                         NvmDiscoveryStatus &status);

    // A private, reset-invalidatable snapshot for a SINGLE owner's serial
    // lifetime. Epochs must come from the verified exclusive PCI/power owner:
    // strictly increasing, never reused after failure, stop or resume.
    // No public method accepts a fabricated image or sets RF readiness.
    // Data is borrowed read-only under the owner gate; callers must not keep
    // the pointer beyond that gate, owner revocation, or the next acquisition.
    // `invalidate` can mark an in-flight operation revoked without touching
    // a buffer the operation is still writing; owner callbacks must separately
    // stop active device accesses and drain the operation before BAR teardown.
    // Not a substitute for the missing native owner or board calibration.
    class NvmBoardLease final
    {
        public:
            NvmBoardLease();
            ~NvmBoardLease();
            NvmBoardLease(const NvmBoardLease &) = delete;
            NvmBoardLease &operator=(const NvmBoardLease &) = delete;
            NvmBoardLease(NvmBoardLease &&) = delete;
            NvmBoardLease &operator=(NvmBoardLease &&) = delete;
            NvmDiscoveryResult acquire(const NvmReadBackend &backend,
                                       const Identity &physicalIdentity,
                                       uint64_t ownerEpoch, uint8_t *storage,
                                       size_t storageBytes, uint8_t *scratch,
                                       size_t scratchBytes,
                                       NvmDiscoveryStatus &status);
            void invalidate();
            const NvmBoardSelection *view(uint64_t ownerEpoch) const;

        private:
            void eraseBoard();
            NvmBoardSelection board_;
            uint64_t activeEpoch_ {0};
            uint64_t lastEpoch_ {0};
            bool acquiring_ {false};
            bool revoked_ {false};
    };

} // namespace simpleath
#endif
