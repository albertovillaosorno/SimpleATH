// Synthetic RF grant/lease protocol; no hardware, kernel or RF IO.
#include "hardware/Ar9565Channel.hpp"
#include "hardware/Ar9565RfBus.hpp"
#include <cstddef>
#include <cstdint>

using namespace simpleath;

namespace
{
    constexpr uint64_t kEpoch = 77;
    constexpr uint32_t kBar = 0x20000;
    constexpr uint32_t kRfRequest = 0xa23c;
    constexpr uint32_t kRfGrant = 0xa240;
    constexpr uint32_t kRxDelay = 0xa254;
    constexpr uint32_t kEnable = 1;
    constexpr uint32_t kRawDelay = 57;
    constexpr uint32_t kExpectedSettle = 105;
    constexpr uint32_t kPollDelay = 10;
    constexpr size_t kMaxPolls = 10000;
    constexpr size_t kGrantAfter = 3;
    constexpr size_t kOneWrite = 1;
    constexpr size_t kTwoWrites = 2;
    constexpr size_t kRevokeOnRead = 3;

    struct Mock
    {
            size_t permits = 0;
            size_t revokeAt = 0;
            size_t grantAfter = kGrantAfter;
            size_t grantReads = 0;
            size_t writes = 0;
            size_t failWriteAt = 0;
            size_t delays = 0;
            uint32_t lastDelay = 0;
            uint32_t requestValue = 0;
            uint32_t rawDelay = kRawDelay;
            bool failGrantRead = false;
            bool failDelayRead = false;
            bool deny = false;
    };

    bool permit(void *context, uint64_t epoch)
    {
        auto &m = *static_cast<Mock *>(context);
        ++m.permits;
        return epoch == kEpoch && !m.deny &&
               (m.revokeAt == 0 || m.permits < m.revokeAt);
    }

    bool read(void *context, uint32_t address, uint32_t *value)
    {
        auto &m = *static_cast<Mock *>(context);
        if (address == kRfGrant)
        {
            ++m.grantReads;
            if (m.failGrantRead)
            {
                return false;
            }
            *value = m.grantReads >= m.grantAfter ? kEnable : 0;
            return true;
        }
        if (address == kRxDelay && !m.failDelayRead)
        {
            *value = m.rawDelay;
            return true;
        }
        return false;
    }

    bool write(void *context, uint32_t address, const uint32_t value)
    {
        auto &m = *static_cast<Mock *>(context);
        if (address != kRfRequest ||
            (m.failWriteAt != 0 && m.writes + 1 == m.failWriteAt))
        {
            return false;
        }
        m.requestValue = value;
        ++m.writes;
        return true;
    }

    void delay(void *context, uint32_t usec)
    {
        auto &m = *static_cast<Mock *>(context);
        ++m.delays;
        m.lastDelay = usec;
    }

    RfChannelBackend backend(Mock &m)
    {
        return {
            {
                &m,
                kEpoch,
                kBar,
                permit,
                write,
                delay,
            },
            read,
        };
    }

    bool testGrantAndRelease()
    {
        Mock m {};
        const auto io = backend(m);
        RfBusLease lease {};
        auto result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::Ok || result.requiresReset ||
            result.polls != kGrantAfter || m.delays != kGrantAfter - 1 ||
            m.lastDelay != kPollDelay || m.requestValue != kEnable ||
            m.writes != kOneWrite || !lease.granted || lease.requiresReset ||
            lease.ownerEpoch != kEpoch || lease.ownerContext != &m)
        {
            return false;
        }
        result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::AlreadyRequested ||
            m.writes != kOneWrite)
        {
            return false;
        }
        result = releaseAr9565RfBus(io, lease);
        if (result.result != RfBusResult::Ok || result.requiresReset ||
            m.lastDelay != kExpectedSettle || m.writes != kTwoWrites ||
            m.requestValue != 0 || lease.requestPosted || lease.granted ||
            lease.requiresReset)
        {
            return false;
        }
        // The cleared lease cannot be released twice or grant TX authority.
        result = releaseAr9565RfBus(io, lease);
        return result.result == RfBusResult::LeaseMismatch &&
               !result.requiresReset && m.writes == kTwoWrites;
    }

    bool testRejection()
    {
        Mock m {};
        auto io = backend(m);
        RfBusLease lease {};
        m.deny = true;
        auto result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::OwnershipLost ||
            result.requiresReset || m.writes != 0 || lease.requestPosted)
        {
            return false;
        }
        m = {};
        io.io.barLengthBytes = kRxDelay;
        result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::InvalidBar || m.writes != 0)
        {
            return false;
        }
        io = backend(m);
        m.failWriteAt = kOneWrite;
        result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::WriteFailed ||
            !result.requiresReset || !lease.requiresReset ||
            !lease.requestPosted || lease.granted)
        {
            return false;
        }
        result = requestAr9565RfBus(io, lease);
        return result.result == RfBusResult::AlreadyRequested &&
               result.requiresReset;
    }

    bool testPollingFailures()
    {
        Mock m {};
        const auto io = backend(m);
        RfBusLease lease {};
        m.failGrantRead = true;
        auto result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::ReadFailed || !result.requiresReset ||
            !lease.requiresReset)
        {
            return false;
        }
        m = {};
        lease = {};
        m.revokeAt = kRevokeOnRead;
        result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::OwnershipLost ||
            !result.requiresReset || !lease.requiresReset)
        {
            return false;
        }
        m = {};
        lease = {};
        m.grantAfter = kMaxPolls + 1;
        result = requestAr9565RfBus(io, lease);
        return result.result == RfBusResult::GrantTimeout &&
               result.polls == kMaxPolls && m.delays == kMaxPolls - 1 &&
               !lease.granted && lease.requiresReset && result.requiresReset;
    }

    bool testReleaseFailures()
    {
        Mock m {};
        const auto io = backend(m);
        RfBusLease lease {};
        m.grantAfter = 1;
        auto result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::Ok)
        {
            return false;
        }
        const auto wrong = [&]
        {
            auto mismatched = io;
            mismatched.io.ownerEpoch++;
            return releaseAr9565RfBus(mismatched, lease);
        };
        result = wrong();
        if (result.result != RfBusResult::LeaseMismatch ||
            !result.requiresReset || !lease.granted)
        {
            return false;
        }
        m.failDelayRead = true;
        result = releaseAr9565RfBus(io, lease);
        if (result.result != RfBusResult::ReadFailed || !result.requiresReset ||
            !lease.requiresReset)
        {
            return false;
        }
        result = releaseAr9565RfBus(io, lease);
        if (result.result != RfBusResult::LeaseMismatch ||
            !result.requiresReset)
        {
            return false;
        }
        m = {};
        lease = {};
        m.grantAfter = 1;
        result = requestAr9565RfBus(io, lease);
        if (result.result != RfBusResult::Ok)
        {
            return false;
        }
        m.failWriteAt = kTwoWrites;
        result = releaseAr9565RfBus(io, lease);
        return result.result == RfBusResult::WriteFailed &&
               result.requiresReset && lease.requiresReset &&
               m.requestValue == kEnable;
    }
} // namespace

int main()
{
    return testGrantAndRelease() && testRejection() && testPollingFailures() &&
                   testReleaseFailures()
               ? 0
               : 1;
}
