#ifndef SIMPLEATH_ATH3K_USB_HPP
#define SIMPLEATH_ATH3K_USB_HPP

#include <cstddef>
#include <cstdint>

namespace simpleath
{
    struct Ath3kUsbIdentity
    {
            uint16_t vendorId;
            uint16_t productId;
            uint16_t deviceRevision;
            uint8_t interfaceNumber;
    };

    enum class Ath3kBootResult : uint8_t
    {
        AwaitReenumeration,
        AlreadyOperational,
        UnsupportedDevice,
        InvalidBackend,
        IdentityLost,
        InvalidFirmware,
        FirmwareUnavailable,
        UnsupportedClock,
        VersionMismatch,
        UsbTransferFailed,
    };

    enum class Ath3kBootPhase : uint8_t
    {
        Probe,
        ReadState,
        ReadVersion,
        LoadPatch,
        LoadConfiguration,
        EnterNormalMode,
        SwitchIdentity,
        Done,
    };

    struct Ath3kControl
    {
            uint8_t request;
            uint8_t requestType;
    };

    struct Ath3kFirmwareImage
    {
            const uint8_t *data;
            size_t size;
    };

    struct Ath3kIo
    {
            void *context;
            uint64_t epoch;
            // The native USB provider owns serialization, power, interface 0,
            // firmware byte lifetimes and the precise USB identity/epoch.
            bool (*permit)(void *context, uint64_t epoch);
            bool (*controlIn)(void *context, Ath3kControl command,
                              uint8_t *buffer, size_t bytes);
            bool (*controlOut)(void *context, Ath3kControl command,
                               const uint8_t *buffer, size_t bytes);
            bool (*bulkOut)(void *context, uint8_t endpoint,
                            const uint8_t *buffer, size_t bytes,
                            size_t *transferred);
            bool (*loadFirmware)(void *context, const char *fileName,
                                 Ath3kFirmwareImage *image);
            void (*delayMicros)(void *context, uint32_t micros);
    };

    struct Ath3kBootProgress
    {
            Ath3kBootResult result;
            Ath3kBootPhase phase;
            size_t firmwareBytesTransferred;
            // If USB writes happened and an error occurred, the native owner
            // must reset/re-enumerate the function before another attempt.
            bool requiresUsbReset;
    };

    // Linux ath3k v6.12 has independent USB IDs for its AR3012 bootstrap.
    // The WLAN PCI 168c:0036 ID is NOT a USB matching criterion. Matching
    // these published USB IDs is necessary, not proof of Dell board identity.
    bool isSupportedAth3kUsbIdentity(const Ath3kUsbIdentity &identity);

    // Published Linux btusb ATH3012 HCI IDs after successful firmware
    // startup (bcdDevice > 0x0001). This is a necessary physical USB match,
    // not proof of QCA9565 board provenance or macOS Bluetooth ownership.
    // Refuse an unrelated generic Bluetooth USB controller even if its
    // interface uses the standard HCI class/subclass/protocol descriptors.
    bool isSupportedAth3kHciIdentity(const Ath3kUsbIdentity &identity);

    // Runs the physical Atheros USB firmware bootstrap synchronously on the
    // USB owner's serialized gate (never on the WLAN PCI owner).
    // A successfully switched USB device MUST re-enumerate and attach the
    // separate HCI transport before Bluetooth can be reported available.
    Ath3kBootProgress bootstrapAth3kUsb(const Ath3kUsbIdentity &identity,
                                        const Ath3kIo &io);
} // namespace simpleath
#endif
