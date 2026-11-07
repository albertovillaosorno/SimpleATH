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
                    now = backend_.nowMicros(backend_.context);
                    if (now < lastMicros_)
                        return NvmResult::InvalidClock;
                    lastMicros_ = now;
                    return NvmResult::Ok;
                }

                NvmResult budget()
                {
                    if (!backend_.ownerInD0(backend_.context))
                        return NvmResult::SessionUnavailable;
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
                        if (reg == kEepromData && (value & kEepromAbsentAccess))
                            return NvmResult::StorageAbsent;
                        if (now - wordStarted >= timeoutMicros)
                            break;
                        if ((value & mask) == expected)
                            return NvmResult::Ok;
                        if (i == timeoutMicros / kPollMicros)
                            break;
                        backend_.delayMicros(backend_.context, kPollMicros);
                    }
                    return reg == kEepromData && (value & kEepromProtected)
                               ? NvmResult::ProtectedAccess
                               : NvmResult::WordTimeout;
                }

            private:
                const NvmReadBackend &backend_;
                NvmReadStatus &status_;
                uint64_t started_;
                uint64_t lastMicros_;
        };

        void clearBytes(uint8_t *destination, size_t length)
        {
            for (size_t i = 0; i < length; ++i)
                destination[i] = 0;
        }
    } // namespace

    NvmResult captureAr9565Nvm(const NvmReadBackend &backend,
                               const Identity &physicalIdentity,
                               NvmSource source, uint8_t *destination,
                               size_t byteCount, NvmReadStatus &status)
    {
        // Destination/status/backend storage must be disjoint and caller-owned.
        status = {};
        status.source = source;
        const size_t maximum = source == NvmSource::Eeprom ? 4096 : 1024;
        if (!destination || byteCount == 0 || byteCount > maximum ||
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
        const size_t words = (byteCount + wordBytes - 1) / wordBytes;
        // Validate the entire requested MMIO span BEFORE a trigger read.
        const uint32_t lastTrigger =
            (source == NvmSource::Eeprom ? kEepromWindow : kOtpWindow) +
            static_cast<uint32_t>((words - 1) * 4);
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
                static_cast<uint32_t>(word * 4);
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
            if (source == NvmSource::Otp)
            {
                result = capture.read(kOtpData, value);
                if (result != NvmResult::Ok)
                    break;
            }
            for (uint32_t byte = 0;
                 byte < wordBytes && status.bytesAcquired < byteCount; ++byte)
                destination[status.bytesAcquired++] =
                    static_cast<uint8_t>(value >> (byte * 8));
        }
        if (result != NvmResult::Ok)
        {
            clearBytes(destination, byteCount);
            return status.result = result;
        }
        status.captureComplete = true;
        return status.result = NvmResult::Ok;
    }

} // namespace simpleath
