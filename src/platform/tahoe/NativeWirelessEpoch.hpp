// Epoch policy for provider-to-Tahoe Ethernet callbacks. Portable by design.
#ifndef SIMPLEATH_TAHOE_NATIVE_WIRELESS_EPOCH_HPP
#define SIMPLEATH_TAHOE_NATIVE_WIRELESS_EPOCH_HPP
#include <stdint.h>

namespace simpleath
{
    namespace tahoe
    {
        // A callback from a retired PCI epoch or a superseded same-epoch AP
        // association cannot be granted access to a successor's mailbox.
        // An epoch advance becomes visible through notify()/snapshot(); a
        // receive callback must NEVER advance the consumer epoch itself.
        inline bool acceptWirelessReceiveIdentity(uint64_t callbackEpoch,
                                                  uint64_t activeEpoch,
                                                  uint64_t callbackAssociation,
                                                  uint64_t activeAssociation,
                                                  bool providerStopped)
        {
            return !providerStopped && callbackEpoch != 0U &&
                   callbackEpoch == activeEpoch && callbackAssociation != 0U &&
                   callbackAssociation == activeAssociation;
        }
    } // namespace tahoe
} // namespace simpleath
#endif
