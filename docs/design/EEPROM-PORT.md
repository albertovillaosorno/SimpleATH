# AR9565 EEPROM source port

Status: offline portable fake-I/O host tests pass; no kext build, native
owner connection or physical EEPROM/OTP read has occurred.

`Ar9565Eeprom.*` reconstructs one normalized ath9k NVM block at a time. It
implements the four-byte compression header, 16-bit additive payload checksum,
uncompressed images and reference/delta block compression. It bounds every
record before copying and rejects missing bases/templates, unsupported
compression, bad checksums, truncated records, destination overlap and more
than 100 applied blocks. Direct block callers must first zero-initialize or
explicitly discard the image; inconsistent restored/applied-block metadata
is rejected so a reference-free delta cannot reuse an incoherent base. Errors
are returned, not silently accepted. Block-info and restore-status buffers
are checked for overlap before diagnostic output is initialized; an alias
error leaves those buffers untouched and must be detected from the function
return value. A caller must discard the complete restore chain on any error.
This is deliberately stricter than upstream's default-image fallback and
ignored delta failures.

Reference-template lookup is a synchronous external callback after initial
checksum and delta validation. A broken provider can retain a separate pointer
to the borrowed frame and rewrite its skip/count fields even though its
context allocation does not alias the frame. The parser now rechecks the
original compression header, every delta bound and the original/final payload
checksum after lookup and **before** copying any template or delta bytes.
Synthetic red/green host regressions mutate the validated count, payload and
reference header during the callback; failures leave the prior image intact.
The parser also snapshots the parsed block metadata and restoration flags
across template lookup. A callback retaining a separate pointer to the output
metadata can otherwise substitute a different template reference after the
frame was authenticated; a pointer to the image can forge its block count.
Both violations now fail with `InvalidArgument` and wipe the image rather
than publishing a forged reconstruction. Ordinary input-validation failures
retain their previous image-preservation contract. These extra gates prevent
stale validation from becoming an out-of-bounds copy or a false successful
restore; they do not make arbitrary concurrent mutation or dishonest template
contents safe, nor prove physical EEPROM provenance.

The 1088-byte reconstructed image retains **all** board/calibration/target-power
and CTL bytes, including the unused 5 GHz area of the shared AR9300 format.
It does not claim that those bytes are valid calibration. The source now
supplies the five pinned upstream reconstruction dictionaries through the
explicit `pinnedEepromTemplates()` catalog. A reference-compressed block must
name a known template ID; unknown IDs fail. A template alone cannot identify
this board. No factory MAC, antenna or regulatory defaults are substituted.
Unsupported board gain indexes clear both gain-selector outputs to `Unknown`
rather than reusing a prior supported profile. Gain selection also rejects a
zero-initialized or structurally invalid summary (version, permanent MAC,
single-chain mask, 2 GHz capability, plausible ordered pier bins) before
choosing usable-looking zero-index tables. Direct gain-mapping callers cannot
bypass discovery's malformed-pier guard or its pinned dictionary MAC
placeholder rejection. A synthetic direct selector with the generic template
MAC previously returned usable-looking gains (host exit 22); the selector now
returns `InvalidBoardIdentity` and resets both outputs to `Unknown`.
Selected gains still confer no RF permission. These are structural checks,
not proof of NVM origin or calibration.
Initialization rejects `Unknown`.

The block parser consumes header/payload/checksum in descending NVM address
order, as produced by ath9k's ar9300_read_eeprom/read_otp. It does not read
hardware or implement OTP/EEPROM access/polling. `restoreEepromDump` accepts an
already acquired ascending-address byte dump and an explicit 0x3ff/0xfff/0x1ff
origin. It reverses each block, applies the chain in upstream order, recognizes
erased terminators, bounds storage/frames and enforces upstream's
below-1024-byte AR9565 payload limit. It wipes the recovered image on
malformed chains and never silently falls back to another origin or default
image. On an alias error, the caller must discard any prior image explicitly.
The caller supplies bounded scratch storage, avoiding a frame-sized kernel-stack
allocation. The separate [active NVM reader](NVM-READ-PROTOCOL.md) now stages
EEPROM/OTP access, word normalization and bounded candidate origin selection.
It selects EEPROM 0x3ff/0xfff/0x1ff before OTP 0x3ff/0x1ff, rejecting damaged
chains and unsupported board identity without using template MAC defaults.
The first nonempty four-byte header irrevocably selects one candidate:
subsequent capture/restore/identity errors abort rather than trying another
board source. An `NvmBoardLease` now retains the accepted image privately;
only a new owner epoch can acquire it, and failure/stop invalidates it.
Only the synthetic host backend exercises this path; the native PCI/power
owner and hardware authorization remain missing. The block primitive
supports full uncompressed 1088-byte images; these do not fit the
AR9565 compressed storage-chain limit.
Flash-format images require a separate validated path.

## Layout evidence

Offsets below were derived by static field-size inspection of the local
packed `ar9300_eeprom` definition, without compiling it:

| Field | Byte offset | Bytes |
| --- | ---: | ---: |
| Version, template, MAC, customer prefix | 0 | 28 |
| Base header (regDmn, chain masks, RF kill, gains, GPIO) | 28 | 25 |
| 2 GHz modal header (antenna, attenuation, timing, PAPRD) | 53 | 71 |
| Base extension 1 (including stored antenna diversity) | 124 | 14 |
| 2 GHz calibration frequency bins | 138 | 3 |
| 2 GHz per-chain/per-pier calibration | 141 | 54 |
| CCK/legacy/HT20/HT40 target frequency bins | 195 | 11 |
| CCK/legacy target power | 206 | 20 |
| HT20/HT40 target power | 226 | 84 |
| 2 GHz CTL indexes | 310 | 12 |
| 2 GHz CTL frequency bins | 322 | 48 |
| 2 GHz CTL edge power/flags | 370 | 48 |
| Shared-format 5 GHz modal/calibration/target/CTL area | 418 | 670 |

`summarizeBoardData` accepts only the version-2 little-endian format, a valid
unicast MAC and the AR9565 single-chain 0x11 mask with 2 GHz capability. These
are structural checks, not proof of board provenance. It extracts raw domains,
RF-silent GPIO/polarity, Bluetooth options, gain indexes, antenna controls/gain
and calibration frequency bins. Upstream overrides AR9565 EEP_ANT_DIV_CTL1 to
0xc9; both the stored value and this override are reported. Neither establishes
the Dell's physical antenna routing or the current RF-kill switch level.

The diagnostic board summary now also extracts the three chain-zero
2.4 GHz `ar9300_cal_data_per_freq_op_loop` records (6 bytes each, beginning at
packed offset 141): signed correction/refPower, voltage, temperature,
noise-floor calibration/power bytes and the noise temperature measurement.
The latter's zero value means the original ath9k path omits noise-floor data.
Frequency bins are mapped to 2300 + bin MHz only in the 2412..2484 MHz
range, and a separate monotonic/bin-plausibility bit records structural
sanity. Neither raw records, zero-filled template defaults, nor plausible
bins constitute calibrated gain/TPC data or permission to transmit. The
other two generic-format chains remain unparsed since AR9565 requires mask
0x11, and no assumption about the physical board's factory values is made.

`calibrationValidated` and `regulatoryAuthorized` remain false. This module
does not set the hardware core's EEPROM-valid state or create permission to
transmit. Calibration application, legal country intersection, CTL
interpolation, per-rate conducted/EIRP limits, RF-kill sampling, gain
selection and coexistence remain required. An OS locale or user-entered
country alone is insufficient.

`selectBoardGainProfiles` maps the AR9565-specific ath9k TX indexes 0/2 to
low-OB, 1 to high-OB and 3 to high-power; RX 0/1 selects standard/without-LNA.
It rejects higher indexes rather than borrowing generic AR9300 settings.
The 1.1 header aliases these gain arrays to the 1.0 arrays; its radio postamble
remains distinct in the generated catalog. Selecting a gain profile does not
apply calibration or program per-rate transmit-power limits.

The public `candidatePowerForRate` selector follows the AR9003 PHY's
conservative CCK target grouping: 1/2 Mbps use the 1L_5L entry, both 5.5
Mbps preambles use `min(1L_5L, 5S)`, and both 11 Mbps preambles use
`min(11L, 11S)`. Previously, the long/short 5.5 and 11 Mbps codes could
select different raw entries, including one above the PHY's common cap.
Synthetic C++14/C++17 host regressions cover both asymmetric directions;
this remains a half-dBm target calculation, not hardware TX authorization.
Reference: Linux `ar9003_phy.c`, `ar9003_hw_init_txpower_cck`:
https://github.com/torvalds/linux/tree/v6.12/drivers/net/wireless/ath/ath9k

## Licensing and reference integrity

`tools/generate_ar9300_templates.py` reads the packed field definitions and
restricted C initializers from the pinned local references. It generates only
`generated/Ar9300EepromTemplates.hpp`, preserving 1088 bytes per template,
upstream IDs/order, customer-data strings, signed fields, little-endian values,
frequency bins and CTL encodings. Unknown grammar/macros/fields or changed
input SHA-256 values abort generation. It does not compile or execute Linux C
or produce a binary file. It was run solely to generate C++ source; no parser
test suite, C/C++ compiler comparison or hardware validation was executed.

| ID | Upstream dictionary |
| --- | --- |
| 2 | ar9300_default |
| 5 | ar9300_x112 |
| 4 | ar9300_h116 |
| 3 | ar9300_h112 |
| 6 | ar9300_x113 |

Per-template hashes in the generated header pin the interpretation; they
are not independent proof that serialization matches a compiled upstream
structure. Byte-for-byte comparison and reconstruction vectors remain
required after test authorization.
The catalog is included through the already staged `Ar9565Eeprom.cpp`, without
linking Linux objects or changing the passive service's hardware behavior.

The algorithms and format come from the local Linux ath9k references. Their
permissive Atheros notice is retained in the new parser; new control code is
GPL-2.0-only. The original Linux files and generated INI tables are unchanged.
Reference SHA-256 values are recorded in `Ar9565Eeprom.cpp`. No GPL-only Linux
implementation has been copied into the new parser.

## Verification still required after owner authorization

Compile the modules in the Xcode target. Exercise known upstream frames and
both EEPROM/OTP byte orders, six-bit template IDs, valid/invalid checksums,
zero-length deltas, odd/truncated records, boundary-exact writes, missing bases,
overlapping buffers and sequences with a late malformed block. Compare a
complete reconstructed board dump byte-for-byte with ath9k's restoration.
Do not replace these checks with a successful desktop boot or an invented
EEPROM result. Hardware acquisition and RF activity require separate consent.
