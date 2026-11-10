// SPDX-License-Identifier: AGPL-3.0-only
// Offline 168c:0036 fake MMIO only: no PCI access or kext build.
#include "hardware/Ar9565Core.hpp"
#include "hardware/Ar9565Eeprom.hpp"
#include "hardware/Ar9565NvmReader.hpp"
#include <cstddef>
#include <cstdint>

namespace
{
    struct Fake
    {
            uint8_t eeprom[4096] {};
            uint8_t otp[1024] {};
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

    void fill(uint8_t *bytes, size_t length, uint8_t value)
    {
        for (size_t i = 0; i < length; ++i)
        {
            bytes[i] = value;
        }
    }

    bool zeroed(const uint8_t *bytes, size_t length)
    {
        for (size_t i = 0; i < length; ++i)
        {
            if (bytes[i] != 0)
            {
                return false;
            }
        }
        return true;
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

    bool read(void *context, uint32_t offset, uint32_t *value)
    {
        auto &fake = *static_cast<Fake *>(context);
        ++fake.readCount;
        if (offset == simpleath::kRevisionRegister)
        {
            ++fake.revisionReads;
            *value =
                (static_cast<uint32_t>(simpleath::kMacFamily) << 12) |
                (fake.mutateSrevBetweenReads && fake.revisionReads > 1 ? 0x1ffU
                                                                       : 0xffU);
        }
        else if (offset == simpleath::kRtcStatusRegister)
        {
            *value = simpleath::kRtcOn;
        }
        else if (offset >= 0x2000 && offset < 0x4000 && (offset & 3U) == 0)
        {
            fake.currentWord = (offset - 0x2000) / 4;
            if (fake.currentWord == 0)
            {
                fake.fullEepromCapture = true;
            }
            fake.finalReads = 0;
            if (fake.mutateHeaderOnFullRead && fake.currentWord == 0)
            {
                // The header probe at word 510/511 already succeeded.
                fake.eeprom[0x3ff] ^= 1;
                fake.mutateHeaderOnFullRead = false;
            }
            *value = 0;
        }
        else if (offset == 0x4084)
        {
            ++fake.finalReads;
            if (fake.eepromAbsent ||
                (fake.absentOnWordFive && fake.currentWord == 5))
            {
                *value = 0x80000;
            }
            else if (fake.finalReads == 1)
            {
                *value = 0;
            }
            else
            {
                if (fake.revokeAfterFinalEepromWord && fake.fullEepromCapture &&
                    fake.currentWord == 511)
                {
                    fake.finalEepromWordRead = true;
                }
                const uint32_t index = fake.currentWord * 2;
                *value = fake.eeprom[index] |
                         (static_cast<uint32_t>(fake.eeprom[index + 1]) << 8);
            }
        }
        else if (offset >= 0x14000 && offset < 0x14400 && (offset & 3U) == 0)
        {
            fake.currentWord = (offset - 0x14000) / 4;
            *value = 0;
        }
        else if (offset == 0x15f18)
        {
            *value = 4;
        }
        else if (offset == 0x15f1c)
        {
            const uint32_t i = fake.currentWord * 4;
            *value = static_cast<uint32_t>(fake.otp[i]) |
                     (static_cast<uint32_t>(fake.otp[i + 1]) << 8) |
                     (static_cast<uint32_t>(fake.otp[i + 2]) << 16) |
                     (static_cast<uint32_t>(fake.otp[i + 3]) << 24);
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
        fill(fake.eeprom, sizeof(fake.eeprom), 0xff);
        fill(fake.otp, sizeof(fake.otp), 0xff);
    }

    // The pinned id-2 template has a generic 0x77 chain mask. This valid
    // compressed frame MUST supply a distinct actual-board MAC and 0x11 mask;
    // no naked/default template can pass selection for AR9565.
    void writeBoard(uint8_t *bytes, uint16_t origin, bool corrupt,
                    bool placeholderMac = false, bool malformedPier = false)
    {
        constexpr uint8_t payload[] = {
            2, 6, 0x02, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 24, 1, 0x11,
        };
        uint8_t frame[sizeof(payload) + 3 + 6] {};
        uint8_t updated[sizeof(payload) + 3] {};
        for (size_t i = 0; i < sizeof(payload); ++i)
        {
            updated[i] = payload[i];
        }
        size_t payloadBytes = sizeof(payload);
        if (malformedPier)
        {
            // Previous records ended at byte 33. A valid, checksummed
            // delta can replace the first 2-GHz calibration bin at 138.
            updated[payloadBytes++] = 105;
            updated[payloadBytes++] = 1;
            updated[payloadBytes++] = 0; // Invalid 2300-MHz bin.
        }
        if (placeholderMac)
        {
            constexpr uint8_t genericMac[] = {0, 2, 3, 4, 5, 6};
            for (size_t i = 0; i < sizeof(genericMac); ++i)
            {
                updated[2 + i] = genericMac[i];
            }
        }
        frame[0] = 0x62; // block compression, pinned template id 2.
        frame[1] = 0;
        frame[2] = static_cast<uint8_t>(payloadBytes << 4);
        frame[3] = 1;
        uint16_t checksum = 0;
        for (size_t i = 0; i < payloadBytes; ++i)
        {
            frame[4 + i] = updated[i];
            checksum = static_cast<uint16_t>(checksum + updated[i]);
        }
        frame[4 + payloadBytes] = static_cast<uint8_t>(checksum);
        frame[5 + payloadBytes] = static_cast<uint8_t>(checksum >> 8);
        for (size_t i = 0; i < payloadBytes + 6; ++i)
        {
            bytes[origin - i] = frame[i];
        }
        if (corrupt)
        {
            bytes[origin - 5] ^= 1;
        }
    }

    struct Fixture
    {
            Fake fake;
            uint8_t storage[4096] {};
            uint8_t scratch[simpleath::kAr9565EepromScratchBytes] {};
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
        fill(fixture.storage, sizeof(fixture.storage), 0xcc);
        fill(fixture.scratch, sizeof(fixture.scratch), 0xcc);
        fixture.board.valid = true; // Prove reentry does not retain old state.
        return simpleath::discoverAr9565Nvm(
            backend, identity, fixture.storage, sizeof(fixture.storage),
            fixture.scratch, sizeof(fixture.scratch), fixture.board,
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
        fill(fixture.storage, sizeof(fixture.storage), 0xcc);
        fill(fixture.scratch, sizeof(fixture.scratch), 0xcc);
        return lease.acquire(backend, identity, epoch, fixture.storage,
                             sizeof(fixture.storage), fixture.scratch,
                             sizeof(fixture.scratch), fixture.status);
    }

    bool clean(const Fixture &fixture)
    {
        return zeroed(fixture.storage, sizeof(fixture.storage)) &&
               zeroed(fixture.scratch, sizeof(fixture.scratch));
    }
} // namespace

int main()
{
    using simpleath::NvmDiscoveryResult;
    using simpleath::NvmSource;
    Fixture fixture {};

    // First candidate: actual EEPROM delta, checksum and board identity.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    if (run(fixture) != NvmDiscoveryResult::Ok || !fixture.board.valid ||
        fixture.board.source != NvmSource::Eeprom ||
        fixture.board.origin != 0x3ff || fixture.status.attempts != 1 ||
        fixture.status.lastRestore.appliedBlocks != 1 ||
        fixture.board.summary.mac[1] != 0xa0 ||
        fixture.board.summary.txChainMask != 1 ||
        fixture.board.summary.rxChainMask != 1 ||
        fixture.board.summary.calibrationValidated ||
        fixture.board.summary.regulatoryAuthorized || !clean(fixture))
    {
        return 1;
    }

    // A blank first EEPROM header falls back to 4K in upstream order.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0xfff, false);
    if (run(fixture) != NvmDiscoveryResult::Ok || !fixture.board.valid ||
        fixture.board.origin != 0xfff || fixture.status.attempts != 2 ||
        !clean(fixture))
    {
        return 2;
    }

    // An absent EEPROM may still have a valid OTP at 512B; don't assume
    // absent EEPROM is proof of absent OTP, nor synthesize from a template.
    reset(fixture.fake);
    fixture.fake.eepromAbsent = true;
    writeBoard(fixture.fake.otp, 0x1ff, false);
    if (run(fixture) != NvmDiscoveryResult::Ok || !fixture.board.valid ||
        fixture.board.source != NvmSource::Otp ||
        fixture.board.origin != 0x1ff || fixture.status.attempts != 5 ||
        !clean(fixture))
    {
        return 3;
    }

    // All headers erased: no fabricated image despite available dictionaries.
    reset(fixture.fake);
    if (run(fixture) != NvmDiscoveryResult::NoValidImage ||
        fixture.board.valid || fixture.board.image.restored ||
        fixture.status.attempts != 5 || fixture.fake.readCount >= 100 ||
        !clean(fixture))
    {
        return 4;
    }

    // A nonblank, corrupted checksum is fatal: don't accept a later origin.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, true);
    writeBoard(fixture.fake.otp, 0x1ff, false);
    if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
        fixture.board.valid || fixture.board.image.restored ||
        fixture.status.attempts != 1 || !clean(fixture))
    {
        return 5;
    }

    // Revoked D0 must abort immediately and erase any previous selection.
    reset(fixture.fake);
    fixture.fake.d0 = false;
    writeBoard(fixture.fake.otp, 0x1ff, false);
    if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
        fixture.board.valid || fixture.board.image.restored ||
        fixture.status.attempts != 1 || !clean(fixture))
    {
        return 6;
    }

    // The FIRST nonempty header selects the source even if its compression
    // layout is unsupported. A later valid board cannot silently replace it.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    fixture.fake.eeprom[0x3ff] = 0xe2; // Compression code 7, template id 2.
    writeBoard(fixture.fake.eeprom, 0xfff, false);
    if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
        fixture.board.valid || fixture.board.image.restored ||
        fixture.status.attempts != 1 || !clean(fixture))
    {
        return 7;
    }

    // Generic pinned-template MAC is not recovered board provenance, even
    // if the delta supplies the AR9565 chain mask and has a valid checksum.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false, true);
    if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
        fixture.board.valid || fixture.board.image.restored ||
        fixture.status.lastBoardResult !=
            simpleath::EepromResult::InvalidBoardIdentity ||
        fixture.status.attempts != 1 || !clean(fixture))
    {
        return 8;
    }

    // D0 revocation after partial acquisition is not a reason to probe OTP.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    fixture.fake.failOwnerAfter = 20;
    if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
        fixture.status.attempts != 1 || fixture.board.valid ||
        fixture.board.image.restored || !clean(fixture))
    {
        return 9;
    }

    // A full capture can go absent AFTER its header was positively selected;
    // this fault must stop discovery, not fall back to valid OTP.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    writeBoard(fixture.fake.otp, 0x1ff, false);
    fixture.fake.absentOnWordFive = true;
    if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
        fixture.status.lastCapture.result !=
            simpleath::NvmResult::StorageAbsent ||
        fixture.status.attempts != 1 || fixture.board.valid ||
        fixture.board.image.restored || !clean(fixture))
    {
        return 10;
    }

    // A source replacing its selected header between probe and full read
    // cannot silently promote the altered payload to a valid board image.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    fixture.fake.mutateHeaderOnFullRead = true;
    if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
        fixture.status.attempts != 1 || fixture.board.valid ||
        fixture.board.image.restored ||
        (fixture.status.lastRestore.appliedBlocks != 0U) || !clean(fixture))
    {
        return 11;
    }

    // A changed but still supported silicon revision between the probe and
    // full capture must not accept a board snapshot across owner epochs.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    fixture.fake.mutateSrevBetweenReads = true;
    if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
        fixture.status.lastCapture.result !=
            simpleath::NvmResult::UnstableStatus ||
        fixture.status.lastCapture.captureComplete ||
        fixture.status.attempts != 1 || fixture.board.valid ||
        fixture.board.image.restored || !clean(fixture))
    {
        return 12;
    }

    // A fully overlapping pair of writable buffers is rejected without
    // touching any output or triggering a single active NVM read.
    reset(fixture.fake);
    fill(fixture.storage, sizeof(fixture.storage), 0xaa);
    fixture.board.valid = true;
    const simpleath::NvmReadBackend backend {
        &fixture.fake, owner, read, now, delay, 0x16000,
    };
    const simpleath::Identity identity {
        simpleath::kPciVendor, simpleath::kPciDevice, 0, 0, false,
    };
    if (simpleath::discoverAr9565Nvm(
            backend, identity, fixture.storage, sizeof(fixture.storage),
            fixture.storage, sizeof(fixture.storage), fixture.board,
            fixture.status) != NvmDiscoveryResult::InvalidArgument ||
        fixture.fake.readCount != 0 || !fixture.board.valid ||
        fixture.storage[0] != 0xaa)
    {
        return 13;
    }

    // Only a successful real discovery can publish a board for its unique
    // exclusive owner epoch. Neither a different nor a stale epoch can view.
    simpleath::NvmBoardLease lease;
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    if (runLease(fixture, lease, 11) != NvmDiscoveryResult::Ok ||
        (lease.view(11) == nullptr) || (lease.view(10) != nullptr) ||
        (lease.view(12) != nullptr) || !lease.view(11)->valid ||
        !clean(fixture))
    {
        return 14;
    }

    // Replaying an epoch is a failed acquisition, not permission to retain
    // a previous image (including after invalidation and power resume).
    if (runLease(fixture, lease, 11) != NvmDiscoveryResult::InvalidArgument ||
        (lease.view(11) != nullptr) ||
        fixture.status.result != NvmDiscoveryResult::InvalidArgument ||
        fixture.status.lastCapture.captureComplete ||
        (fixture.status.attempts != 0U))
    {
        return 15;
    }
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    if (runLease(fixture, lease, 12) != NvmDiscoveryResult::Ok ||
        (lease.view(12) == nullptr))
    {
        return 16;
    }
    lease.invalidate();
    if ((lease.view(12) != nullptr) ||
        runLease(fixture, lease, 12) != NvmDiscoveryResult::InvalidArgument ||
        (lease.view(12) != nullptr) ||
        fixture.status.result != NvmDiscoveryResult::InvalidArgument ||
        fixture.status.lastCapture.captureComplete ||
        (fixture.status.attempts != 0U))
    {
        return 17;
    }

    // A rejected corrupt reacquisition wipes the formerly accepted board,
    // while a later strictly larger owner generation can still be acquired.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, true);
    if (runLease(fixture, lease, 13) != NvmDiscoveryResult::CorruptImage ||
        (lease.view(13) != nullptr) || !clean(fixture))
    {
        return 18;
    }

    // A gate/owner revocation callback during acquisition marks the pending
    // transaction unusable, even if the synthetic MMIO data remains readable.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    fixture.fake.leaseToRevoke = &lease;
    fixture.fake.revokeAtOwnerCheck = 10;
    if (runLease(fixture, lease, 14) != NvmDiscoveryResult::OwnerEpochRevoked ||
        fixture.status.result != NvmDiscoveryResult::OwnerEpochRevoked ||
        (lease.view(14) != nullptr) || !clean(fixture))
    {
        return 19;
    }

    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    if (runLease(fixture, lease, 15) != NvmDiscoveryResult::Ok ||
        (lease.view(15) == nullptr))
    {
        return 20;
    }

    // Buffer aliases with the private lease state cannot erase or mutate the
    // live snapshot: failure is signaled by the return value only.
    const simpleath::NvmReadBackend guardedBackend {
        &fixture.fake, owner, read, now, delay, 0x16000,
    };
    const simpleath::Identity guardedIdentity {
        simpleath::kPciVendor, simpleath::kPciDevice, 0, 0, false,
    };
    // Invalid discovery buffer contracts must also be rejected BEFORE the
    // lease revokes its previous good board. The raw discovery preflight
    // already checks these, but checking only inside discovery is too late.
    fill(fixture.storage, sizeof(fixture.storage), 0xa5);
    const uint32_t readsBeforeAlias = fixture.fake.readCount;
    if (lease.acquire(guardedBackend, guardedIdentity, 16, fixture.storage,
                      sizeof(fixture.storage), fixture.storage,
                      sizeof(fixture.storage),
                      fixture.status) != NvmDiscoveryResult::InvalidArgument ||
        (lease.view(15) == nullptr) || fixture.storage[0] != 0xa5 ||
        fixture.fake.readCount != readsBeforeAlias)
    {
        return 21;
    }
    if (lease.acquire(guardedBackend, guardedIdentity, 16, fixture.storage,
                      sizeof(fixture.storage),
                      reinterpret_cast<uint8_t *>(&fixture.status),
                      sizeof(fixture.scratch),
                      fixture.status) != NvmDiscoveryResult::InvalidArgument ||
        (lease.view(15) == nullptr) || fixture.storage[0] != 0xa5 ||
        fixture.fake.readCount != readsBeforeAlias)
    {
        return 22;
    }
    const simpleath::NvmReadBackend contextAlias {
        fixture.storage, owner, read, now, delay, 0x16000,
    };
    if (lease.acquire(contextAlias, guardedIdentity, 16, fixture.storage,
                      sizeof(fixture.storage), fixture.scratch,
                      sizeof(fixture.scratch),
                      fixture.status) != NvmDiscoveryResult::InvalidArgument ||
        (lease.view(15) == nullptr) || fixture.storage[0] != 0xa5 ||
        fixture.fake.readCount != readsBeforeAlias)
    {
        return 23;
    }
    if (lease.acquire(guardedBackend, guardedIdentity, 16,
                      reinterpret_cast<uint8_t *>(&lease),
                      sizeof(fixture.storage), fixture.scratch,
                      sizeof(fixture.scratch),
                      fixture.status) != NvmDiscoveryResult::InvalidArgument ||
        (lease.view(15) == nullptr))
    {
        return 24;
    }
    // A callback context inside the input table or physical PCI identity
    // must not revoke an already accepted board lease or touch scratch. A
    // callback can mutate its context; this cannot be an input to selection.
    simpleath::NvmReadBackend aliasedBackend {
        nullptr, neverOwned, read, now, delay, 0x16000,
    };
    aliasedBackend.context = &aliasedBackend;
    if (lease.acquire(aliasedBackend, guardedIdentity, 16, fixture.storage,
                      sizeof(fixture.storage), fixture.scratch,
                      sizeof(fixture.scratch),
                      fixture.status) != NvmDiscoveryResult::InvalidArgument ||
        (lease.view(15) == nullptr) || fixture.storage[0] != 0xa5 ||
        fixture.fake.readCount != readsBeforeAlias)
    {
        return 26;
    }
    simpleath::Identity mutableIdentity = guardedIdentity;
    aliasedBackend.context = &mutableIdentity;
    if (lease.acquire(aliasedBackend, mutableIdentity, 16, fixture.storage,
                      sizeof(fixture.storage), fixture.scratch,
                      sizeof(fixture.scratch),
                      fixture.status) != NvmDiscoveryResult::InvalidArgument ||
        (lease.view(15) == nullptr) || fixture.storage[0] != 0xa5 ||
        fixture.fake.readCount != readsBeforeAlias)
    {
        return 27;
    }
    lease.invalidate();
    if (lease.view(15) != nullptr)
    {
        return 25;
    }

    // Raw discovery must reject the same malformed borrowed inputs before
    // clearing a previous board or invoking a provider callback.
    fixture.board.valid = true;
    fixture.status.result = NvmDiscoveryResult::Ok;
    if (simpleath::discoverAr9565Nvm(aliasedBackend, mutableIdentity,
                                     fixture.storage, sizeof(fixture.storage),
                                     fixture.scratch, sizeof(fixture.scratch),
                                     fixture.board, fixture.status) !=
            NvmDiscoveryResult::InvalidArgument ||
        !fixture.board.valid ||
        fixture.status.result != NvmDiscoveryResult::Ok ||
        fixture.storage[0] != 0xa5)
    {
        return 28;
    }
    aliasedBackend.context = &aliasedBackend;
    if (simpleath::discoverAr9565Nvm(aliasedBackend, mutableIdentity,
                                     fixture.storage, sizeof(fixture.storage),
                                     fixture.scratch, sizeof(fixture.scratch),
                                     fixture.board, fixture.status) !=
            NvmDiscoveryResult::InvalidArgument ||
        !fixture.board.valid ||
        fixture.status.result != NvmDiscoveryResult::Ok ||
        fixture.storage[0] != 0xa5)
    {
        return 29;
    }

    // A frame can have a correct checksum and board identity yet replace a
    // calibration pier with an invalid bin. Do not publish it as selected
    // board data, even though RF TX is still separately disabled.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false, false, true);
    if (run(fixture) != NvmDiscoveryResult::CorruptImage ||
        fixture.board.valid || fixture.board.image.restored ||
        fixture.status.lastBoardResult !=
            simpleath::EepromResult::UnsupportedFormat ||
        fixture.status.attempts != 1 || !clean(fixture))
    {
        return 30;
    }

    // D0 can disappear after the final data read and clock check, while the
    // recovered frame is still being restored. Reject publication on a fresh
    // owner preflight, rather than trusting that old capture authorization.
    reset(fixture.fake);
    writeBoard(fixture.fake.eeprom, 0x3ff, false);
    fixture.fake.revokeAfterFinalEepromWord = true;
    if (run(fixture) != NvmDiscoveryResult::CaptureFailed ||
        fixture.status.lastCapture.result !=
            simpleath::NvmResult::SessionUnavailable ||
        fixture.status.lastCapture.captureComplete || fixture.board.valid ||
        fixture.board.image.restored || fixture.fake.d0 || !clean(fixture))
    {
        return 31;
    }
    return 0;
}
