// SPDX-License-Identifier: AGPL-3.0-only
#include "hardware/Ar9565MacControl.hpp"
#include <cstdint>
#include <initializer_list>

namespace
{
    struct Hardware
    {
            uint32_t rtc = 2;
            uint32_t diagnostic = 0x40;
            uint32_t rx = 0x0c;
            uint32_t tx = 0x3ff;
            uint32_t observe = 0x00100000;
            unsigned int delays = 0;
            unsigned int writes = 0;
            unsigned int macReads = 0;
            bool revoked = false;
            bool stuck = false;
            bool wakeAfterDelay = false;
            bool failWrite = false;
            bool stopWritten = false;
    };

    bool read(void *opaque, uint32_t reg, uint32_t *value)
    {
        auto &h = *static_cast<Hardware *>(opaque);
        if (h.revoked)
            return false;
        switch (reg)
        {
            case 0x7044:
                *value = h.rtc;
                return true;
            case 0x8048:
                *value = h.diagnostic;
                break;
            case 0x0008:
                *value = h.rx;
                break;
            case 0x0840:
                *value = h.tx;
                break;
            case 0x806c:
                *value = h.observe;
                break;
            default:
                return false;
        }
        ++h.macReads;
        return true;
    }

    bool write(void *opaque, uint32_t reg, uint32_t value)
    {
        auto &h = *static_cast<Hardware *>(opaque);
        if (h.revoked || h.failWrite)
            return false;
        ++h.writes;
        if (reg == 0x8048)
            h.diagnostic = value;
        else if (reg == 0x0880)
            h.stopWritten = value == 0x3ff;
        else if (reg != 0x0024 && reg != 0x402c && reg != 0x0008)
            return false;
        return true;
    }

    void delay(void *opaque, uint32_t)
    {
        auto &h = *static_cast<Hardware *>(opaque);
        ++h.delays;
        if (h.wakeAfterDelay && h.rtc == 8)
            h.rtc = 2;
        if (!h.stuck && h.stopWritten)
            h.rx = h.tx = h.observe = 0;
    }

    simpleath::MacStopResult stop(Hardware &h)
    {
        const simpleath::RegisterBus bus {&h, read, write, 0x20000};
        return simpleath::quiesceAr9565Mac(bus, delay);
    }
} // namespace

int main()
{
    using simpleath::MacStopResult;
    Hardware active;
    if (stop(active) != MacStopResult::Ok || active.delays != 1 ||
        active.writes != 5 || !active.stopWritten ||
        active.diagnostic != (0x40U | 0x02000026U))
        return 1;
    for (uint32_t rtc : {1U, 4U})
    {
        Hardware asleep;
        asleep.rtc = rtc;
        if (stop(asleep) != MacStopResult::Ok || asleep.writes != 1 ||
            asleep.macReads || asleep.delays || asleep.stopWritten)
            return 2;
    }
    Hardware stuck;
    stuck.stuck = true;
    if (stop(stuck) != MacStopResult::Timeout || stuck.delays != 1000)
        return 3;
    Hardware removed;
    removed.revoked = true;
    if (stop(removed) != MacStopResult::ReadFailed || removed.writes)
        return 4;
    Hardware failure;
    failure.failWrite = true;
    if (stop(failure) != MacStopResult::WriteFailed || failure.macReads)
        return 5;
    Hardware invalid;
    invalid.rtc = 0xffffffffU;
    if (stop(invalid) != MacStopResult::ReadFailed || invalid.writes)
        return 6;
    invalid.rtc = 15;
    if (stop(invalid) != MacStopResult::UnknownRtcState || invalid.writes)
        return 7;
    Hardware waking;
    waking.rtc = 8;
    if (stop(waking) != MacStopResult::Timeout || waking.macReads ||
        waking.delays != 1000)
        return 8;
    Hardware wakeThenStop;
    wakeThenStop.rtc = 8;
    wakeThenStop.wakeAfterDelay = true;
    if (stop(wakeThenStop) != MacStopResult::Ok || wakeThenStop.delays != 2 ||
        wakeThenStop.writes != 5)
        return 10;
    for (uint32_t unknown : {0U, 3U})
    {
        Hardware unsupported;
        unsupported.rtc = unknown;
        if (stop(unsupported) != MacStopResult::UnknownRtcState ||
            unsupported.writes)
            return 11;
    }
    simpleath::RegisterBus missing {};
    if (simpleath::quiesceAr9565Mac(missing, delay) !=
        MacStopResult::InvalidBackend)
        return 9;
    return 0;
}
