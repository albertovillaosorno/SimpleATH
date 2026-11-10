// SPDX-License-Identifier: AGPL-3.0-only
// Offline 168c:0036 fake MMIO only: no PCI access or kext build.
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565NvmReader.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace
{
    // Physical offsets and probe limits in the deterministic fake MMIO map.
    constexpr size_t kEepromBytes = 4096U;
    constexpr size_t kOtpBytes = 1024U;
    constexpr uint32_t kRevisionShift = 12U;
    constexpr uint32_t kRevisionOriginal = 0xffU;
    constexpr uint32_t kRevisionChanged = 0x1ffU;
    constexpr uint32_t kEepromStart = 0x2000U;
    constexpr uint32_t kEepromLimit = 0x4000U;
    constexpr uint32_t kEepromReadStatus = 0x4084U;
    constexpr uint32_t kEepromMissing = 0x80000U;
    constexpr uint32_t kOtpStart = 0x14000U;
    constexpr uint32_t kOtpLimit = 0x14400U;
    constexpr uint32_t kOtpReadStatus = 0x15f18U;
    constexpr uint32_t kOtpReadData = 0x15f1cU;
    constexpr uint32_t kBarLength = 0x16000U;
    constexpr size_t kFinalEepromHeader = 0x3ffU;
    constexpr uint16_t kNextEepromHeader = 0xfffU;
    constexpr uint16_t kFinalOtpHeader = 0x1ffU;
    constexpr uint32_t kFinalEepromWord = 511U;
    constexpr uint32_t kMissingWordIndex = 5U;
    constexpr uint32_t kByteShift = 8U;
    constexpr uint32_t kDoubleByteShift = 16U;
    constexpr uint32_t kTripleByteShift = 24U;
    constexpr uint8_t kBlankByte = 0xffU;
    constexpr uint8_t kStoragePoison = 0xccU;
    constexpr uint8_t kOverlapPoison = 0xaaU;
    constexpr uint8_t kLeaseOverlapPoison = 0xa5U;
    constexpr uint8_t kBoardMacByte = 0xa0U;
    constexpr uint8_t kUnsupportedHeader = 0xe2U;
    constexpr uint8_t kDeltaHeader = 0x62U;
    constexpr uint8_t kInvalidPierOffset = 105U;
    constexpr size_t kCompressedFrameBytes = 6U;
    constexpr size_t kFrameAllocationBytes = 9U;
    constexpr uint32_t kBlankProbeReadBound = 100U;
    constexpr uint32_t kExpireDuringOwnerCheck = 20U;
    constexpr uint64_t kPriorLeaseEpoch = 10U;
    constexpr uint64_t kFirstLeaseEpoch = 11U;
    constexpr uint64_t kSecondLeaseEpoch = 12U;
    constexpr uint64_t kCorruptLeaseEpoch = 13U;
    constexpr uint64_t kRevokedLeaseEpoch = 14U;
    constexpr uint64_t kRecoveredLeaseEpoch = 15U;
    constexpr uint64_t kRejectedLeaseEpoch = 16U;
    constexpr uint32_t kMaximumDiscoveryAttempts = 5U;
    constexpr uint32_t kRevocationOwnerCheck = 10U;
    constexpr size_t kChecksumHighOffset = 5U;

    // Distinct exit codes locate the failed source-only regression scenario.
    enum class Failure : int
    {
        EepromBoard = 1,
        EepromFallback = 2,
        OtpFallback = 3,
        EmptySources = 4,
        CorruptEeprom = 5,
        PowerLoss = 6,
        CompressionCode = 7,
        GenericMac = 8,
        PartialOwnerLoss = 9,
        PartialEepromAbsence = 10,
        MutatedHeader = 11,
        SiliconRevisionChange = 12,
        OverlapRawBuffers = 13,
        ValidLeaseView = 14,
        RejectReplay = 15,
        RenewLease = 16,
        RejectRevokedEpoch = 17,
        CorruptReacquisition = 18,
        RevokeDuringAcquisition = 19,
        ReacquireAfterRevoke = 20,
        OverlapLeaseBuffers = 21,
        OverlapStatus = 22,
        OverlapContext = 23,
        OverlapLeaseState = 24,
        InvalidateLease = 25,
        OverlapBackend = 26,
        OverlapIdentity = 27,
        RejectRawIdentityAlias = 28,
        RejectRawBackendAlias = 29,
        InvalidCalibrationPier = 30,
        FinalDataRevocation = 31,
    };

    struct Fake
    {
            std::array<uint8_t, kEepromBytes> eeprom {};
            std::array<uint8_t, kOtpBytes> otp {};
            uint32_t currentWord = 0;
            uint32_t finalReads = 0;
            uint32_t readCount = 0;
            uint32_t ownerChecks = 0;
            uint64_t time = 0;
            bool eepromAbsent = false;
            bool absentOnWordFive = false;
            bool mutateHeaderOnFullRead = false;
            bool mutateSrevBetweenReads = false;
            uint32_t revisionReads = 0;
            simpleath::NvmBoardLease *leaseToRevoke = nullptr;
            uint32_t revokeAtOwnerCheck = 0;
            // Simulate a power loss on the final successful ownership check
            // after the last EEPROM word, before software reconstruction.
            bool revokeAfterFinalEepromWord = false;
            bool fullEepromCapture = false;
            bool finalEepromWordRead = false;
            uint32_t finalWordOwnerChecks = 0;
            bool d0 = true;
            uint32_t failOwnerAfter = 0;
    };

    template <size_t Count>
    void fill(std::array<uint8_t, Count> &bytes, uint8_t value)
    {
        bytes.fill(value);
    }

    template <size_t Count> bool zeroed(const std::array<uint8_t, Count> &bytes)
    {
        return std::all_of(bytes.begin(), bytes.end(),
                           [](uint8_t byte)
                           {
                               return byte == 0U;
                           });
    }

    // Observe the pointer representation only. These intentionally invalid
    // output spans are rejected by preflight before any byte is dereferenced.
    template <typename T> uint8_t *bytesOf(T &object)
    {
        const T *const typed = &object;
        uint8_t *untyped = nullptr;
        static_assert(sizeof(T *) == sizeof(uint8_t *),
                      "test pointers must have matching widths");
        __builtin_memcpy(static_cast<void *>(&untyped),
                         static_cast<const void *>(&typed), sizeof(uint8_t *));
        return untyped;
    }

    bool owner(void *context)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.ownerChecks;
        if ((fake.leaseToRevoke != nullptr) &&
            fake.ownerChecks == fake.revokeAtOwnerCheck)
        {
            fake.leaseToRevoke->invalidate();
        }
        if (fake.revokeAfterFinalEepromWord && fake.finalEepromWordRead &&
            ++fake.finalWordOwnerChecks == 2)
        {
            // The capture's post-read clock gets one last true response;
            // any later owner gate must observe the lost D0 state.
            fake.d0 = false;
            return true;
        }
        return fake.d0 && ((fake.failOwnerAfter == 0U) ||
                           fake.ownerChecks < fake.failOwnerAfter);
    }

    bool neverOwned(void * /*unused*/)
    {
        return false;
    }

    bool readEepromWord(Fake &fake, uint32_t *value)
    {
        ++fake.finalReads;
        if (fake.eepromAbsent ||
            (fake.absentOnWordFive && fake.currentWord == kMissingWordIndex))
        {
            *value = kEepromMissing;
        }
        else if (fake.finalReads == 1)
        {
            *value = 0;
        }
        else
        {
            if (fake.revokeAfterFinalEepromWord && fake.fullEepromCapture &&
                fake.currentWord == kFinalEepromWord)
            {
                fake.finalEepromWordRead = true;
            }
            const uint32_t index = fake.currentWord * 2;
            *value = fake.eeprom.at(index) |
                     (static_cast<uint32_t>(fake.eeprom.at(index + 1))
                      << kByteShift);
        }
        return true;
    }

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.readCount;
        if (offset == simpleath::kRevisionRegister)
        {
            ++fake.revisionReads;
            *value = (static_cast<uint32_t>(simpleath::kMacFamily)
                      << kRevisionShift) |
                     (fake.mutateSrevBetweenReads && fake.revisionReads > 1
                          ? kRevisionChanged
                          : kRevisionOriginal);
        }
        else if (offset == simpleath::kRtcStatusRegister)
        {
            *value = simpleath::kRtcOn;
        }
        else if (offset >= kEepromStart && offset < kEepromLimit &&
                 (offset & 3U) == 0)
        {
            fake.currentWord = (offset - kEepromStart) / 4;
            if (fake.currentWord == 0)
            {
                fake.fullEepromCapture = true;
            }
            fake.finalReads = 0;
            if (fake.mutateHeaderOnFullRead && fake.currentWord == 0)
            {
                // The header probe at word 510/511 already succeeded.
                fake.eeprom.at(kFinalEepromHeader) ^= 1U;
                fake.mutateHeaderOnFullRead = false;
            }
            *value = 0;
        }
        else if (offset == kEepromReadStatus)
        {
            return readEepromWord(fake, value);
        }
        else if (offset >= kOtpStart && offset < kOtpLimit &&
                 (offset & 3U) == 0)
        {
            fake.currentWord = (offset - kOtpStart) / 4;
            *value = 0;
        }
        else if (offset == kOtpReadStatus)
        {
            *value = 4;
        }
        else if (offset == kOtpReadData)
        {
            const uint32_t i = fake.currentWord * 4;
            *value =
                static_cast<uint32_t>(fake.otp.at(i)) |
                (static_cast<uint32_t>(fake.otp.at(i + 1)) << kByteShift) |
                (static_cast<uint32_t>(fake.otp.at(i + 2))
                 << kDoubleByteShift) |
                (static_cast<uint32_t>(fake.otp.at(i + 3)) << kTripleByteShift);
        }
        else
        {
            return false;
        }
        return true;
    }

    uint64_t now(void *context)
    {
        return ++static_cast<Fake *>(context)->time;
    }

    void delay(void * /*unused*/, uint32_t /*unused*/)
    {
    }

    void reset(Fake &fake)
    {
        fake = {};
        fill(fake.eeprom, kBlankByte);
        fill(fake.otp, kBlankByte);
    }

    // The pinned id-2 template has a generic 0x77 chain mask. This valid
    // compressed frame MUST supply a distinct actual-board MAC and 0x11 mask;
    // no naked/default template can pass selection for AR9565.
    template <size_t Capacity>
    void writeBoard(std::array<uint8_t, Capacity> &bytes, uint16_t origin,
                    bool corrupt, bool placeholderMac = false,
                    bool malformedPier = false)
    {
        constexpr std::array<uint8_t, 11U> payload {
            2, 6, 0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 24, 1, 0x11,
        };
        std::array<uint8_t, payload.size() + kFrameAllocationBytes> frame {};
        std::array<uint8_t, payload.size() + 3U> updated {};
        for (size_t i = 0; i < payload.size(); ++i)
        {
            updated.at(i) = payload.at(i);
        }
        size_t payloadBytes = payload.size();
        if (malformedPier)
        {
            // Previous records ended at byte 33. A valid, checksummed
            // delta can replace the first 2-GHz calibration bin at 138.
            updated.at(payloadBytes++) = kInvalidPierOffset;
            updated.at(payloadBytes++) = 1;
            updated.at(payloadBytes++) = 0; // Invalid 2300-MHz bin.
        }
        if (placeholderMac)
        {
            constexpr std::array<uint8_t, 6U> genericMac {{0, 2, 3, 4, 5, 6}};
            for (size_t i = 0; i < genericMac.size(); ++i)
            {
                updated.at(2 + i) = genericMac.at(i);
            }
        }
        frame.at(0) = kDeltaHeader; // block compression, pinned template id 2.
        frame.at(1) = 0;
        frame.at(2) =
            static_cast<uint8_t>(static_cast<uint32_t>(payloadBytes) << 4U);
        frame.at(3) = 1;
        uint16_t checksum = 0;
        for (size_t i = 0; i < payloadBytes; ++i)
        {
            frame.at(4 + i) = updated.at(i);
            checksum = static_cast<uint16_t>(checksum + updated.at(i));
        }
        frame.at(4 + payloadBytes) = static_cast<uint8_t>(checksum);
        frame.at(kChecksumHighOffset + payloadBytes) =
            static_cast<uint8_t>(checksum >> kByteShift);
        for (size_t i = 0; i < payloadBytes + kCompressedFrameBytes; ++i)
        {
            bytes.at(origin - i) = frame.at(i);
        }
        if (corrupt)
        {
            bytes.at(origin - kChecksumHighOffset) ^= 1U;
        }
    }

    struct Fixture
    {
            Fake fake;
            std::array<uint8_t, kEepromBytes> storage {};
            std::array<uint8_t, simpleath::kAr9565EepromScratchBytes>
                scratch {};
            simpleath::NvmBoardSelection board {};
            simpleath::NvmDiscoveryStatus status {};
    };

    simpleath::NvmDiscoveryResult run(Fixture &fixture)
    {
        const simpleath::NvmReadBackend backend {
            &fixture.fake, owner, read, now, delay, 0x16000,
        };
        const simpleath::Identity identity {
            simpleath::kPciVendor, simpleath::kPciDevice, 0, 0, false,
        };
        fill(fixture.storage, kStoragePoison);
        fill(fixture.scratch, kStoragePoison);
        fixture.board.valid = true; // Prove reentry does not retain old state.
        return simpleath::discoverAr9565Nvm(
            backend, identity, fixture.storage.data(), fixture.storage.size(),
            fixture.scratch.data(), fixture.scratch.size(), fixture.board,
            fixture.status);
    }

    simpleath::NvmDiscoveryResult
    runLease(Fixture &fixture, simpleath::NvmBoardLease &lease, uint64_t epoch)
    {
        const simpleath::NvmReadBackend backend {
            &fixture.fake, owner, read, now, delay, 0x16000,
        };
        const simpleath::Identity identity {
            simpleath::kPciVendor, simpleath::kPciDevice, 0, 0, false,
        };
        fill(fixture.storage, kStoragePoison);
        fill(fixture.scratch, kStoragePoison);
        return lease.acquire(backend, identity, epoch, fixture.storage.data(),
                             fixture.storage.size(), fixture.scratch.data(),
                             fixture.scratch.size(), fixture.status);
    }

    bool clean(const Fixture &fixture)
    {
        return zeroed(fixture.storage) && zeroed(fixture.scratch);
    }

    using simpleath::NvmDiscoveryResult;
    using simpleath::NvmSource;

    int verifyDiscoveryOrigins(Fixture &fixture)
    {
        // First candidate: actual EEPROM delta, checksum and board identity.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        if (run(fixture) != NvmDiscoveryResult::Ok || !fixture.board.valid ||
            fixture.board.source != NvmSource::Eeprom ||
            fixture.board.origin != kFinalEepromHeader ||
            fixture.status.attempts != 1 ||
            fixture.status.lastRestore.appliedBlocks != 1 ||
            fixture.board.summary.mac[1] != kBoardMacByte ||
            fixture.board.summary.txChainMask != 1 ||
            fixture.board.summary.rxChainMask != 1 ||
            fixture.board.summary.calibrationValidated ||
            fixture.board.summary.regulatoryAuthorized || !clean(fixture))
        {
            return static_cast<int>(Failure::EepromBoard);
        }

        // A blank first EEPROM header falls back to 4K in upstream order.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kNextEepromHeader, false);
        if (run(fixture) != NvmDiscoveryResult::Ok || !fixture.board.valid ||
            fixture.board.origin != kNextEepromHeader ||
            fixture.status.attempts != 2 || !clean(fixture))
        {
            return static_cast<int>(Failure::EepromFallback);
        }

        // An absent EEPROM may still have a valid OTP at 512B; don't assume
        // absent EEPROM is proof of absent OTP, nor synthesize from a template.
        reset(fixture.fake);
        fixture.fake.eepromAbsent = true;
        writeBoard(fixture.fake.otp, kFinalOtpHeader, false);
        if (run(fixture) != NvmDiscoveryResult::Ok || !fixture.board.valid ||
            fixture.board.source != NvmSource::Otp ||
            fixture.board.origin != kFinalOtpHeader ||
            fixture.status.attempts != kMaximumDiscoveryAttempts ||
            !clean(fixture))
        {
            return static_cast<int>(Failure::OtpFallback);
        }

        // All headers erased: no fabricated image despite available
        // dictionaries.
        reset(fixture.fake);
        if (run(fixture) != NvmDiscoveryResult::NoValidImage ||
            fixture.board.valid || fixture.board.image.restored ||
            fixture.status.attempts != kMaximumDiscoveryAttempts ||
            fixture.fake.readCount >= kBlankProbeReadBound || !clean(fixture))
        {
            return static_cast<int>(Failure::EmptySources);
        }
        return 0;
    }

    int verifyDiscoveryFailures(Fixture &fixture)
    {
        // A nonblank, corrupted checksum is fatal: don't accept a later origin.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, true);
        writeBoard(fixture.fake.otp, kFinalOtpHeader, false);
        if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
            fixture.board.valid || fixture.board.image.restored ||
            fixture.status.attempts != 1 || !clean(fixture))
        {
            return static_cast<int>(Failure::CorruptEeprom);
        }

        // Revoked D0 must abort immediately and erase any previous selection.
        reset(fixture.fake);
        fixture.fake.d0 = false;
        writeBoard(fixture.fake.otp, kFinalOtpHeader, false);
        if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
            fixture.board.valid || fixture.board.image.restored ||
            fixture.status.attempts != 1 || !clean(fixture))
        {
            return static_cast<int>(Failure::PowerLoss);
        }

        // The FIRST nonempty header selects the source even if its compression
        // layout is unsupported. A later valid board cannot silently replace
        // it.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        fixture.fake.eeprom.at(kFinalEepromHeader) =
            kUnsupportedHeader; // Compression code 7, template id 2.
        writeBoard(fixture.fake.eeprom, kNextEepromHeader, false);
        if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
            fixture.board.valid || fixture.board.image.restored ||
            fixture.status.attempts != 1 || !clean(fixture))
        {
            return static_cast<int>(Failure::CompressionCode);
        }

        // Generic pinned-template MAC is not recovered board provenance, even
        // if the delta supplies the AR9565 chain mask and has a valid checksum.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false, true);
        if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
            fixture.board.valid || fixture.board.image.restored ||
            fixture.status.lastBoardResult !=
                simpleath::EepromResult::InvalidBoardIdentity ||
            fixture.status.attempts != 1 || !clean(fixture))
        {
            return static_cast<int>(Failure::GenericMac);
        }

        // D0 revocation after partial acquisition is not a reason to probe OTP.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        fixture.fake.failOwnerAfter = kExpireDuringOwnerCheck;
        if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
            fixture.status.attempts != 1 || fixture.board.valid ||
            fixture.board.image.restored || !clean(fixture))
        {
            return static_cast<int>(Failure::PartialOwnerLoss);
        }

        // A full capture can go absent AFTER its header was positively
        // selected; this fault must stop discovery, not fall back to valid OTP.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        writeBoard(fixture.fake.otp, kFinalOtpHeader, false);
        fixture.fake.absentOnWordFive = true;
        if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
            fixture.status.lastCapture.result !=
                simpleath::NvmResult::StorageAbsent ||
            fixture.status.attempts != 1 || fixture.board.valid ||
            fixture.board.image.restored || !clean(fixture))
        {
            return static_cast<int>(Failure::PartialEepromAbsence);
        }
        return 0;
    }

    int verifyDiscoveryRaces(Fixture &fixture)
    {
        // A source replacing its selected header between probe and full read
        // cannot silently promote the altered payload to a valid board image.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        fixture.fake.mutateHeaderOnFullRead = true;
        if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
            fixture.status.attempts != 1 || fixture.board.valid ||
            fixture.board.image.restored ||
            (fixture.status.lastRestore.appliedBlocks != 0U) || !clean(fixture))
        {
            return static_cast<int>(Failure::MutatedHeader);
        }

        // A changed but still supported silicon revision between the probe and
        // full capture must not accept a board snapshot across owner epochs.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        fixture.fake.mutateSrevBetweenReads = true;
        if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
            fixture.status.lastCapture.result !=
                simpleath::NvmResult::UnstableStatus ||
            fixture.status.lastCapture.captureComplete ||
            fixture.status.attempts != 1 || fixture.board.valid ||
            fixture.board.image.restored || !clean(fixture))
        {
            return static_cast<int>(Failure::SiliconRevisionChange);
        }

        // A fully overlapping pair of writable buffers is rejected without
        // touching any output or triggering a single active NVM read.
        reset(fixture.fake);
        fill(fixture.storage, kOverlapPoison);
        fixture.board.valid = true;
        const simpleath::NvmReadBackend backend {
            &fixture.fake, owner, read, now, delay, 0x16000,
        };
        const simpleath::Identity identity {
            simpleath::kPciVendor, simpleath::kPciDevice, 0, 0, false,
        };
        if (simpleath::discoverAr9565Nvm(
                backend, identity, fixture.storage.data(),
                fixture.storage.size(), fixture.storage.data(),
                fixture.storage.size(), fixture.board,
                fixture.status) != NvmDiscoveryResult::InvalidArgument ||
            fixture.fake.readCount != 0 || !fixture.board.valid ||
            fixture.storage.at(0) != kOverlapPoison)
        {
            return static_cast<int>(Failure::OverlapRawBuffers);
        }
        return 0;
    }

    int verifyLeaseEpochs(Fixture &fixture, simpleath::NvmBoardLease &lease)
    {
        // Only a successful real discovery can publish a board for its unique
        // exclusive owner epoch. Neither a different nor a stale epoch can
        // view.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        if (runLease(fixture, lease, kFirstLeaseEpoch) !=
                NvmDiscoveryResult::Ok ||
            (lease.view(kFirstLeaseEpoch) == nullptr) ||
            (lease.view(kPriorLeaseEpoch) != nullptr) ||
            (lease.view(kSecondLeaseEpoch) != nullptr) ||
            !lease.view(kFirstLeaseEpoch)->valid || !clean(fixture))
        {
            return static_cast<int>(Failure::ValidLeaseView);
        }

        // Replaying an epoch is a failed acquisition, not permission to retain
        // a previous image (including after invalidation and power resume).
        if (runLease(fixture, lease, kFirstLeaseEpoch) !=
                NvmDiscoveryResult::InvalidArgument ||
            (lease.view(kFirstLeaseEpoch) != nullptr) ||
            fixture.status.result != NvmDiscoveryResult::InvalidArgument ||
            fixture.status.lastCapture.captureComplete ||
            (fixture.status.attempts != 0U))
        {
            return static_cast<int>(Failure::RejectReplay);
        }
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        if (runLease(fixture, lease, kSecondLeaseEpoch) !=
                NvmDiscoveryResult::Ok ||
            (lease.view(kSecondLeaseEpoch) == nullptr))
        {
            return static_cast<int>(Failure::RenewLease);
        }
        lease.invalidate();
        if ((lease.view(kSecondLeaseEpoch) != nullptr) ||
            runLease(fixture, lease, kSecondLeaseEpoch) !=
                NvmDiscoveryResult::InvalidArgument ||
            (lease.view(kSecondLeaseEpoch) != nullptr) ||
            fixture.status.result != NvmDiscoveryResult::InvalidArgument ||
            fixture.status.lastCapture.captureComplete ||
            (fixture.status.attempts != 0U))
        {
            return static_cast<int>(Failure::RejectRevokedEpoch);
        }

        // A rejected corrupt reacquisition wipes the formerly accepted board,
        // while a later strictly larger owner generation can still be acquired.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, true);
        if (runLease(fixture, lease, kCorruptLeaseEpoch) !=
                NvmDiscoveryResult::CorruptImage ||
            (lease.view(kCorruptLeaseEpoch) != nullptr) || !clean(fixture))
        {
            return static_cast<int>(Failure::CorruptReacquisition);
        }

        // A gate/owner revocation callback during acquisition marks the pending
        // transaction unusable, even if the synthetic MMIO data remains
        // readable.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        fixture.fake.leaseToRevoke = &lease;
        fixture.fake.revokeAtOwnerCheck = kRevocationOwnerCheck;
        if (runLease(fixture, lease, kRevokedLeaseEpoch) !=
                NvmDiscoveryResult::OwnerEpochRevoked ||
            fixture.status.result != NvmDiscoveryResult::OwnerEpochRevoked ||
            (lease.view(kRevokedLeaseEpoch) != nullptr) || !clean(fixture))
        {
            return static_cast<int>(Failure::RevokeDuringAcquisition);
        }

        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        if (runLease(fixture, lease, kRecoveredLeaseEpoch) !=
                NvmDiscoveryResult::Ok ||
            (lease.view(kRecoveredLeaseEpoch) == nullptr))
        {
            return static_cast<int>(Failure::ReacquireAfterRevoke);
        }
        return 0;
    }

    int verifyLeaseAliases(Fixture &fixture, simpleath::NvmBoardLease &lease)
    {
        // Buffer aliases with the private lease state cannot erase or mutate
        // the live snapshot: failure is signaled by the return value only.
        const simpleath::NvmReadBackend guardedBackend {
            &fixture.fake, owner, read, now, delay, 0x16000,
        };
        const simpleath::Identity guardedIdentity {
            simpleath::kPciVendor, simpleath::kPciDevice, 0, 0, false,
        };
        // Invalid discovery buffer contracts must also be rejected BEFORE the
        // lease revokes its previous good board. The raw discovery preflight
        // already checks these, but checking only inside discovery is too late.
        fill(fixture.storage, kLeaseOverlapPoison);
        const uint32_t readsBeforeAlias = fixture.fake.readCount;
        if (lease.acquire(guardedBackend, guardedIdentity, kRejectedLeaseEpoch,
                          fixture.storage.data(), fixture.storage.size(),
                          fixture.storage.data(), fixture.storage.size(),
                          fixture.status) !=
                NvmDiscoveryResult::InvalidArgument ||
            (lease.view(kRecoveredLeaseEpoch) == nullptr) ||
            fixture.storage.at(0) != kLeaseOverlapPoison ||
            fixture.fake.readCount != readsBeforeAlias)
        {
            return static_cast<int>(Failure::OverlapLeaseBuffers);
        }
        if (lease.acquire(guardedBackend, guardedIdentity, kRejectedLeaseEpoch,
                          fixture.storage.data(), fixture.storage.size(),
                          bytesOf(fixture.status), fixture.scratch.size(),
                          fixture.status) !=
                NvmDiscoveryResult::InvalidArgument ||
            (lease.view(kRecoveredLeaseEpoch) == nullptr) ||
            fixture.storage.at(0) != kLeaseOverlapPoison ||
            fixture.fake.readCount != readsBeforeAlias)
        {
            return static_cast<int>(Failure::OverlapStatus);
        }
        const simpleath::NvmReadBackend contextAlias {
            fixture.storage.data(), owner, read, now, delay, 0x16000,
        };
        if (lease.acquire(contextAlias, guardedIdentity, kRejectedLeaseEpoch,
                          fixture.storage.data(), fixture.storage.size(),
                          fixture.scratch.data(), fixture.scratch.size(),
                          fixture.status) !=
                NvmDiscoveryResult::InvalidArgument ||
            (lease.view(kRecoveredLeaseEpoch) == nullptr) ||
            fixture.storage.at(0) != kLeaseOverlapPoison ||
            fixture.fake.readCount != readsBeforeAlias)
        {
            return static_cast<int>(Failure::OverlapContext);
        }
        if (lease.acquire(guardedBackend, guardedIdentity, kRejectedLeaseEpoch,
                          bytesOf(lease), fixture.storage.size(),
                          fixture.scratch.data(), fixture.scratch.size(),
                          fixture.status) !=
                NvmDiscoveryResult::InvalidArgument ||
            (lease.view(kRecoveredLeaseEpoch) == nullptr))
        {
            return static_cast<int>(Failure::OverlapLeaseState);
        }
        // A callback context inside the input table or physical PCI identity
        // must not revoke an already accepted board lease or touch scratch. A
        // callback can mutate its context; this cannot be an input to
        // selection.
        simpleath::NvmReadBackend aliasedBackend {
            nullptr, neverOwned, read, now, delay, kBarLength,
        };
        aliasedBackend.context = &aliasedBackend;
        if (lease.acquire(aliasedBackend, guardedIdentity, kRejectedLeaseEpoch,
                          fixture.storage.data(), fixture.storage.size(),
                          fixture.scratch.data(), fixture.scratch.size(),
                          fixture.status) !=
                NvmDiscoveryResult::InvalidArgument ||
            (lease.view(kRecoveredLeaseEpoch) == nullptr) ||
            fixture.storage.at(0) != kLeaseOverlapPoison ||
            fixture.fake.readCount != readsBeforeAlias)
        {
            return static_cast<int>(Failure::OverlapBackend);
        }
        simpleath::Identity mutableIdentity = guardedIdentity;
        aliasedBackend.context = &mutableIdentity;
        if (lease.acquire(aliasedBackend, mutableIdentity, kRejectedLeaseEpoch,
                          fixture.storage.data(), fixture.storage.size(),
                          fixture.scratch.data(), fixture.scratch.size(),
                          fixture.status) !=
                NvmDiscoveryResult::InvalidArgument ||
            (lease.view(kRecoveredLeaseEpoch) == nullptr) ||
            fixture.storage.at(0) != kLeaseOverlapPoison ||
            fixture.fake.readCount != readsBeforeAlias)
        {
            return static_cast<int>(Failure::OverlapIdentity);
        }
        lease.invalidate();
        if (lease.view(kRecoveredLeaseEpoch) != nullptr)
        {
            return static_cast<int>(Failure::InvalidateLease);
        }

        // Raw discovery must reject the same malformed borrowed inputs before
        // clearing a previous board or invoking a provider callback.
        fixture.board.valid = true;
        fixture.status.result = NvmDiscoveryResult::Ok;
        if (simpleath::discoverAr9565Nvm(
                aliasedBackend, mutableIdentity, fixture.storage.data(),
                fixture.storage.size(), fixture.scratch.data(),
                fixture.scratch.size(), fixture.board,
                fixture.status) != NvmDiscoveryResult::InvalidArgument ||
            !fixture.board.valid ||
            fixture.status.result != NvmDiscoveryResult::Ok ||
            fixture.storage.at(0) != kLeaseOverlapPoison)
        {
            return static_cast<int>(Failure::RejectRawIdentityAlias);
        }
        aliasedBackend.context = &aliasedBackend;
        if (simpleath::discoverAr9565Nvm(
                aliasedBackend, mutableIdentity, fixture.storage.data(),
                fixture.storage.size(), fixture.scratch.data(),
                fixture.scratch.size(), fixture.board,
                fixture.status) != NvmDiscoveryResult::InvalidArgument ||
            !fixture.board.valid ||
            fixture.status.result != NvmDiscoveryResult::Ok ||
            fixture.storage.at(0) != kLeaseOverlapPoison)
        {
            return static_cast<int>(Failure::RejectRawBackendAlias);
        }
        return 0;
    }

    int verifyFinalRevocation(Fixture &fixture)
    {
        // A frame can have a correct checksum and board identity yet replace a
        // calibration pier with an invalid bin. Do not publish it as selected
        // board data, even though RF TX is still separately disabled.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false, false, true);
        if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
            fixture.board.valid || fixture.board.image.restored ||
            fixture.status.lastBoardResult !=
                simpleath::EepromResult::UnsupportedFormat ||
            fixture.status.attempts != 1 || !clean(fixture))
        {
            return static_cast<int>(Failure::InvalidCalibrationPier);
        }

        // D0 can disappear after the final data read and clock check, while the
        // recovered frame is still being restored. Reject publication on a
        // fresh owner preflight, rather than trusting that old capture
        // authorization.
        reset(fixture.fake);
        writeBoard(fixture.fake.eeprom, kFinalEepromHeader, false);
        fixture.fake.revokeAfterFinalEepromWord = true;
        if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
            fixture.status.lastCapture.result !=
                simpleath::NvmResult::SessionUnavailable ||
            fixture.status.lastCapture.captureComplete || fixture.board.valid ||
            fixture.board.image.restored || fixture.fake.d0 || !clean(fixture))
        {
            return static_cast<int>(Failure::FinalDataRevocation);
        }
        return 0;
    }

} // namespace

int main()
{
    Fixture fixture {};
    simpleath::NvmBoardLease lease;
    if (const int failure = verifyDiscoveryOrigins(fixture))
    {
        return failure;
    }
    if (const int failure = verifyDiscoveryFailures(fixture))
    {
        return failure;
    }
    if (const int failure = verifyDiscoveryRaces(fixture))
    {
        return failure;
    }
    if (const int failure = verifyLeaseEpochs(fixture, lease))
    {
        return failure;
    }
    if (const int failure = verifyLeaseAliases(fixture, lease))
    {
        return failure;
    }
    return verifyFinalRevocation(fixture);
}
