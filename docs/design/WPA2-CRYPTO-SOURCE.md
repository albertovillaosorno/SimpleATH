# WPA2-PSK cryptographic source — limited portable host validation

**Status (2026-11-07): source and isolated host test only.** The
`tests/test_wpa2_public_alias.cpp` compiles portable `Wpa2Primitives.cpp`
and `Frames.cpp` with host Clang. The offline fixture checks the published
WPA2 passphrase/SSID PBKDF2 PMK vector, synthetic PTK and EAPOL MIC reference
outputs independently calculated using Python's `hmac`/`hashlib`, and the
RFC3394 AES-128 unwrap 128-bit known-answer vector. It also checks rejection
of altered ciphertext without publishing plaintext and key/identity/output
alias guards. This is neither a complete cryptographic or timing audit nor a
Tahoe kext build. No kernel Wi-Fi, DMA or Dell hardware was exercised.

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
- The public EAPOL replay guard now binds MIC, key RSC and key-data borrowed
  pointers to the exact packet offsets, as it already does for the nonce and
  scalar replay fields. A forged detached field is rejected before M1/M3
  state publication; synthetic red/green tests cover all three pointers for
  each message. This is no substitute for MIC verification or CCMP PN checks.
- The supplicant now binds each M2/M3/M4 MIC result to the exact call-local
  EAPOL bytes handed to the synchronous crypto provider. An incorrectly
  implemented provider that writes through a borrowed const input after
  producing a MIC cannot substitute the M3 GTK ciphertext, GTK receive RSC,
  or outgoing M2/M4 bytes. The handshake fails before key installation or
  response publication, and the snapshot is wiped when its scope ends.
  Synthetic C++14/C++17 red/green tests modify M3 RSC and ciphertext and
  outgoing M2/M4 fields via deliberately contract-violating callbacks.
  This is not proof that a malicious or buggy provider computes a valid MIC.
- The same authenticated M3 snapshot is now checked again after GTK unwrap,
  preventing a callback from modifying signed ciphertext before hardware key
  installation. Call-local PTK bytes are also compared with retained session
  keys after M3 MIC, GTK unwrap and M4 MIC callbacks: a provider writing
  through const KCK/KEK inputs must fail before installing keys or emitting
  M4. Fake callbacks that mutate these inputs failed the original regression
  and now pass C++14/C++17 ASan/UBSan rejection cases. This tests defensive
  source boundaries, not native keycache, crypto assurance or radio behavior.

These are independently authored C++ sources without a project-wide license
grant, built from published specifications
(FIPS 180-4, RFC 2104, RFC 2898, FIPS 197, RFC 3394, IEEE 802.11).
No new third-party implementation is copied or bundled.

The callback bridge must preserve the primitive's input/output alias checks.
In particular, the unwrap callback must never clear its output-length
reference ahead of `unwrapKey`: that reference might overlap the KEK or an
incoming EAPOL ciphertext buffer. The adapter now delegates length
initialization to the primitive after alias rejection, and nonce, PTK, MIC,
GTK plaintext and unwrap-length outputs are rejected when they overlap the
adapter's own retained callback state. Alias errors leave the adapter and the
aliased input untouched; this is source-only behavior, not proof of a secure
platform keycache backend. Successful pairwise/GTK install callbacks are
also checked against the adapter's retained configuration generation after
the call. A callback returning success after it clears and reconfigures the
adapter no longer publishes stale installed-key readiness; isolated red/green
host regressions exercise both paths. This cannot verify actual keycache
programming, serialize power loss or replace the native owner's teardown gate.

The code wipes PMK/PTK, digest scratch, AES round keys and intermediate GTK
when possible. The source is unaudited: volatile wiping cannot guarantee
elimination from registers, duplicate OS buffers or compiler temporaries.

## Known-answer vectors and validation scope

The current project instructions authorize isolated host tests through
`python3 -B tools/validate.py`, not kext builds or device activity.
The portable host fixture executes the PMK and RFC3394 vectors, plus a
synthetic PRF-384 PTK reference constructed from that PMK, sorted MAC/nonces
and the standard label/counter, and an independently calculated
HMAC-SHA1-128 EAPOL MIC (with the MIC field cleared). These passed on the
host only; the remaining vectors and full WPA2 protocol checks are proposals.
This limited coverage cannot establish a secure WPA2 stack.

- WPA2 passphrase password, SSID IEEE -> PMK:
  f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e
- RFC3394, 128-bit KEK 000102030405060708090a0b0c0d0e0f,
  plaintext 00112233445566778899aabbccddeeff,
  wrapped 1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5.
- FIPS197 AES-128 inverse cipher block:
  key 000102030405060708090a0b0c0d0e0f,
  cipher 69c4e0d86a7b0430d8cdb78070b4c55a,
  plaintext 00112233445566778899aabbccddeeff.
- SHA-1/HMAC-SHA1 official vectors; complete IEEE 802.11 PTK and EAPOL
  M1/M2/M3/M4 known-good message captures with synthetic passwords.
- Malformed lengths, overlap, nonces, replay, invalid MIC, AES integrity,
  missing entropy and partially installed keycache: all must fail closed.

Review required: side-channel exposure, C++14 ABI compatibility, kernel
stack, key lifetime, DMA and secret erasure before shipping.

## Synthetic M3 state and key rollback regression (2026-11-07)

`tests/test_wpa2_supplicant_alias.cpp` now drives the bounded M1-to-M3
state machine with synthetic EAPOL-Key bytes and deliberate fake crypto
callbacks. The mock MIC is a fixed test value and the mock unwrap returns
an RSNE/GTK KDE with AES-wrap-shaped padding; neither operation provides
real cryptographic authentication. Host C++14 and C++17 strict-warning runs
and a C++14 AddressSanitizer/UndefinedBehaviorSanitizer run passed.

The cases check successful M4 generation, pairwise then group key callback
ordering and GTK key ID/RSC forwarding; they also check fail-closed MIC,
replay, invalid high RSC and altered M3 RSNE handling. Simulated failures
in either pairwise or group installation trigger exactly one rollback of
attempted key slots. A subsequent reset must not repeat the rollback.

This **only** demonstrates source-level state/error-path handling for fake
inputs; no IEEE 802.11 known-good M1–M4 capture, real encrypted M3, live
keycache, controlled RF transfer, or native driver session was tested.

## Still absent

There is no platform-backed CSPRNG, actual AR9565 CCMP keycache
programming, hardware replay/PN management, compatible Tahoe native Wi-Fi
interface, operational RF/DMA TX/RX, or usable WPA2 connection.

Kext compilation, CI, EFI installation and physical verification remain
prohibited without separate owner authorization. Isolated host fixtures are
permitted by the project's current `AGENTS.md` and `TODO.md`; these
host-only passes are not native ABI, RF, association or kernel-security
results.

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
- As of this 2026-11-06 source record, neither the parser nor actual
  hardware keycache callback had been exercised. The later 2026-11-07
  synthetic fixture exercises the parser with fake callbacks only; no
  platform/hardware keycache backend has been executed or verified.

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

## MIC-bound group replay initialization (2026-11-06)

- EAPOL parsing now exposes the 8-octet Key RSC from the fixed descriptor.
  After M3 MIC verification, the supplicant snapshots that RSC from the
  MIC-verified local EAPOL copy, not the caller-owned RX/DMA buffer.
- For CCMP, octets 0..5 carry the received GTK packet number, least
  significant octet first; octets 6 and 7 must be zero. Nonzero high
  octets fail the handshake before any key is programmed.
- The group-key callback now **requires** the original authenticated RSC
  and must atomically install the GTK plus the hardware RX replay/PN
  baseline. If it cannot program that state, it must fail, allowing the
  supplicant's rollback callback to remove all attempted key installs.
- IEEE Std 802.11i-2004, EAPOL-Key Key RSC field and GTK installation:
  https://www.normsplash.com/Samples/ISO/914742298/ISO-IEC-8802-11-2005-Amd-6-2006-en-2.pdf
- This remains an unimplemented hardware callback contract: no installed
  AR9565 GTK/PN state or actual replay resistance has been demonstrated.

## Link-loss packet gates (2026-11-06)

- `LinkMonitor` changes to `ReconnectPending` on beacon timeout or
  accepted AP deauthentication/disassociation. Its state can change before
  the native owner quiesces DMA or clears the separate station state.
- The portable Wi-Fi engine now refuses both decoded data delivery and
  generic Ethernet TX unless **both** station association state and
  `LinkMonitor::Associated` remain valid. It does not remove keys or touch
  hardware in the link-loss event path; the owner must still quiesce and
  call the appropriate reset/reconnect entrypoints in order.
- Source-only state coupling; no runtime event or actual recovery tested.

## Network selection downgrade guard (2026-11-06)

- `WifiEngine::chooseNetwork` requires a nonempty, explicit SSID (maximum
  32 bytes). Wildcard scanning is not treated as authorization to connect
  to the strongest arbitrary BSS.
- When both Open and WPA2-PSK/CCMP were permitted by the caller, the
  bounded BSS selector prefers a compatible WPA2 BSS before comparing
  signal strength within the same security class. Incompatible advertised
  WPA2 suites and PMF-required BSSes remain unsupported.
- This is static selection policy, not a validated physical RF scan.

## M3 MIC snapshot consistency (2026-11-06)

- The received EAPOL M3 MIC is now copied from the same bounded private
  EAPOL frame snapshot used for HMAC-SHA1 verification, before its MIC
  field is zeroed for signing. A caller-owned/DMA-backed frame cannot
  change the MIC bytes independently between snapshot and comparison.
- The temporary received MIC is wiped on both success and provider
  failure, alongside the expected MIC and signed-frame snapshot. This is
  static dataflow hardening, not evidence of a safe native RX DMA owner.
- M1 also snapshots and reparses its bounded EAPOL input before copying
  the replay/ANonce and deriving the PTK. M1 is not MIC-protected; this is
  protection against inconsistent DMA buffer views, not AP authentication.
- The original KeyFrame also held borrowed nonce and wrapped GTK pointers
  into the caller's potentially mutable RX/DMA buffer. M3 handling now
  uses an initial parse only to bound the local copy, then reparses that
  snapshot and checks MIC, replay/ANonce, Key RSC and encrypted GTK from
  the same bytes. The buffer remains alive until AES unwrap and is wiped
  on every post-copy failure or completion path. Changing the original
  DMA image after the copy cannot substitute unauthenticated key data.
  This is a source-level guarantee, not proof of native DMA ownership.
