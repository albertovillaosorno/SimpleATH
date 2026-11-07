# WPA2-PSK cryptographic source — uncompiled and not validated

**Status (2026-11-06): source only.** Algorithms in src/wifi/crypto/
have not been compiled, run, tested against known-answer vectors,
audited for timing behavior, or installed on the target Dell.

Do not use the new code as a verified cryptographic provider. Do not
claim that the device has a usable WPA2 association.

## New primitives and integration

- Wpa2Primitives.cpp: 4096-round PBKDF2-HMAC-SHA1 to derive the 32-byte
  WPA2 PMK from an 8..63-byte passphrase and 1..32-byte SSID.
- Wpa2Primitives.cpp: WPA2-CCMP PRF-384 for 48-byte PTK using the
  sorted AP/station MAC addresses and sorted authenticator/station nonces.
- Wpa2Primitives.cpp: SHA-1/HMAC-SHA1-128 for EAPOL-Key version 2 MIC.
- Wpa2Primitives.cpp: AES-128 inverse cipher and RFC3394 AES key unwrap,
  requiring the standard key-wrap integrity check before output.
- AesTables.hpp: generated substitution tables calculated from Rijndael
  finite-field and affine formulas, not copied from third-party tables.
- Wpa2CryptoAdapter.cpp: real primitive callback wiring to the existing
  Wpa2Supplicant. Random nonces, CCMP pairwise/group hardware keycache
  programming and key removal require a separate native platform backend.

These are new AGPL-3.0-only C++ sources built from published specifications
(FIPS 180-4, RFC 2104, RFC 2898, FIPS 197, RFC 3394, IEEE 802.11).
No new third-party implementation is copied or bundled.

The code wipes PMK/PTK, digest scratch, AES round keys and intermediate GTK
when possible. The source is unaudited: volatile wiping cannot guarantee
elimination from registers, duplicate OS buffers or compiler temporaries.

## Unexecuted known-answer vectors

Do not execute this validation until the owner authorizes tests.

- WPA2 passphrase password, SSID IEEE -> PMK:
  f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e
- RFC3394, 128-bit KEK 000102030405060708090a0b0c0d0e0f,
  plaintext 00112233445566778899aabbccddeeff,
  wrapped 1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5.
- FIPS197 AES-128 inverse cipher block:
  key 000102030405060708090a0b0c0d0e0f,
  cipher 69c4e0d86a7b0430d8cdb78070b4c55a,
  plaintext 00112233445566778899aabbccddeeff.
- SHA-1/HMAC-SHA1 official vectors; IEEE 802.11 PTK and EAPOL
  M1/M2/M3/M4 known-good captures with synthetic passwords.
- Malformed lengths, overlap, nonces, replay, invalid MIC, AES integrity,
  missing entropy and partially installed keycache: all must fail closed.

Review required: side-channel exposure, C++14 ABI compatibility, kernel
stack, key lifetime, DMA and secret erasure before shipping.

## Still absent

There is no platform-backed CSPRNG, actual AR9565 CCMP keycache
programming, hardware replay/PN management, compatible Tahoe native Wi-Fi
interface, operational RF/DMA TX/RX, or usable WPA2 connection.

Build, tests, EFI installation and physical verification remain prohibited
without explicit owner authorization. The vectors above are specifications
for later validation, not recorded test results.

## Source-only EAPOL hardening (2026-11-06)

- The M3 GTK KDE parser accepts the standard AES-wrap trailing padding
  (`0xdd`, then zero octets), while continuing to reject truncated,
  malformed and duplicate GTK KDEs. A `0xdd` vendor KDE with nonzero
  content is still parsed as an element. IEEE 802.11-2007 (Key Data
  AES-wrap padding) and hostapd authenticator key-data construction
  provide public specification and implementation evidence.
- The supplicant now arms keycache rollback **before** calling the first
  pairwise-key installation callback. A false return must not leave a
  partially written pairwise key slot; the backend's removal callback
  must be idempotent and clean up attempted pairwise/group installs.
- This is static reasoning and source change only: neither the parser nor
  the hardware keycache callback has been executed or verified.

Public evidence (reviewed 2026-11-06):

- IEEE 802.11-2007, clause 8.5 Key Data and GTK KDE:
  https://people.iith.ac.in/tbr/teaching/docs/802.11-2007.pdf
- hostapd authenticator reference, `src/ap/wpa_auth.c` (BSD terms):
  https://github.com/wertarbyte/hostap/blob/master/src/ap/wpa_auth.c

## Binding M3 security to the chosen BSS (2026-11-06)

- `WifiEngine` supplies the selected Beacon/Probe Response's exact RSNE
  to `Wpa2Supplicant::begin`. The supplicant rejects missing, malformed,
  non-CCMP/PSK, or PMF-required RSNE input before starting the handshake.
- After authenticated M3 decryption, its RSNE must match that saved IE
  byte-for-byte and occur exactly once. Missing, changed or duplicate
  RSNEs prevent GTK/PTK keycache installation and clear handshake secrets.
  An unsupported optional second RSNE also fails closed rather than
  silently overriding the negotiated security policy.
- IEEE 802.11-2007, clause 8.5 (4-Way Handshake M3), requires the
  supplicant to validate the AP's RSNE against the Beacon/Probe Response.
  These are source-level constraints, not hardware verification.

## EAPOL Key Information and outbound length review (2026-11-06)

- The M2 and M4 serializers now set the EAPOL-Key Key Length to **zero**;
  a 16-byte CCMP key length is required on incoming M1/M3, not the
  Supplicant's responses. This follows IEEE Std 802.11-2012 sections
  11.6.6.3 and 11.6.6.5 and the public hostapd RSN supplicant source.
- RSN EAPOL-Key parsing rejects nonzero legacy Key Index, unsupported
  PeerKey/SMK or reserved information bits, MIC flag/value disagreement,
  and encrypted-data flags on cleartext M1/M2/M4/Group2. Group messages
  remain unimplemented by the station state machine.
- Source-level static review only; no EAPOL capture, protocol tests,
  compilation or radio access was performed.

References:

- IEEE Std 802.11-2012, section 11.6.6:
  https://mrncciew.com/wp-content/uploads/2014/10/ieee-802-11-2012.pdf
- hostapd `src/rsn_supp/wpa.c` (BSD licensed):
  https://chromium.googlesource.com/chromiumos/third_party/hostap/+/refs/heads/firmware-R130-16032.B-wpa_supplicant-2.10.0/src/rsn_supp/wpa.c
- hostapd wireless test monitor `wlantest/rx_eapol.c`:
  https://fuchsia.googlesource.com/third_party/hostap/+/3aed10f3b7f643f288f6aa1c5aef223c5c679b9e/wlantest/rx_eapol.c

## Outbound EAPOL boundary (2026-11-06)

- `WifiEngine::encodeOutgoingEthernet` refuses WPA2 EAPOL EtherType
  `0x888e` after keys are installed. The generic data serializer emits
  unprotected frames and must never substitute for an authenticated
  group-rekey or other post-key EAPOL transport.
- Only the engine's private `packageEapol` path may prepare M2/M4 in the
  clear during this limited initial 4-way handshake. Explicit group
  rekey, protected EAPOL and hardware TX ordering remain unimplemented.
- Source-level guard only; no test, build, or network exchange performed.
