#!/bin/bash
# SimpleATH Recovery APFS diagnostics for macOS Tahoe.
# No disk is repaired unless the operator supplies an exact APFS volume
# identifier and types an explicit second confirmation in macOS Recovery.
# The script never erases disks, deletes snapshots, changes NVRAM or edits EFI.
set -u
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

if [ "$(/usr/bin/uname -s)" != Darwin ]; then
    printf '%s\n' 'This command must run on macOS or macOS Recovery.' >&2
    exit 1
fi

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    printf '%s\n' 'Requesting administrator access for disk inspection.'
    exec /usr/bin/sudo /bin/bash "$0" "$@"
fi

DIR="$(CDPATH= cd -- "$(/usr/bin/dirname "$0")" && /bin/pwd -P)"
if [ ! -w "$DIR" ]; then
    printf '%s\n' "USB volume is not writable: $DIR" >&2
    exit 1
fi

OUT="$DIR/SimpleATH-Recovery-Reports/$(/bin/date -u '+%Y%m%d-%H%M%SZ')-$$"
if ! /bin/mkdir -p "$OUT"; then
    printf '%s\n' 'Failed to create a Recovery report on the USB volume.' >&2
    exit 1
fi

printf '%s\n' 'SimpleATH macOS Recovery / APFS diagnostics'
printf '%s\n' "Saving results on USB: $OUT"
printf '%s\n' 'This utility never selects a disk automatically.'
printf '%s\n' 'Never use eraseDisk, eraseVolume, deleteVolume or APFS snapshot deletion.'

# Each inventory command is independent; missing capabilities are recorded.
/usr/sbin/diskutil list > "$OUT/diskutil-list.txt" 2>&1
printf '\n%s\n' '===== diskutil list ====='
/bin/cat "$OUT/diskutil-list.txt"
/usr/sbin/diskutil apfs list > "$OUT/diskutil-apfs-list.txt" 2>&1
printf '\n%s\n' '===== APFS containers and volumes ====='
/bin/cat "$OUT/diskutil-apfs-list.txt"
/usr/sbin/diskutil info / > "$OUT/recovery-root-info.txt" 2>&1
/usr/bin/sw_vers > "$OUT/system-version.txt" 2>&1
/usr/bin/csrutil status > "$OUT/system-integrity-protection.txt" 2>&1
printf '\n%s\n' 'Startup root volume summary:'
/usr/bin/grep -E 'Device Identifier:|Volume Name:|Device Location:|File System Personality:' "$OUT/recovery-root-info.txt" || true

printf '\n%s\n' 'IMPORTANT: APFS names and disk identifiers may change in Recovery.'
printf '%s\n' 'Choose the internal Macintosh HD / Macintosh HD - Data volume,'
printf '%s\n' 'NOT the USB or OPENCORE volume. If you are unsure, press Enter.'
printf '%s\n' 'For broad repair, Apple recommends Disk Utility > View > Show All'
printf '%s\n' 'Devices > First Aid: each volume bottom-up, then container, then disk.'
printf '\nEnter ONE APFS volume identifier to VERIFY (e.g. disk1s5), or Enter to exit: '
IFS= read -r TARGET || TARGET=''
if [ -z "$TARGET" ]; then
    printf '%s\n' 'Inventory saved. No volume was checked or repaired.'
    exit 0
fi

# Deliberately accept only the simple APFS volume identifier syntax.
case "$TARGET" in
    disk[0-9]*s[0-9]*) ;;
    *) printf '%s\n' 'Invalid volume identifier. No action taken.' >&2; exit 2 ;;
esac
if ! [[ "$TARGET" =~ ^disk[0-9]+s[0-9]+$ ]]; then
    printf '%s\n' 'Invalid APFS volume identifier. No action taken.' >&2
    exit 2
fi

INFO="$OUT/selected-volume-$TARGET.txt"
if ! /usr/sbin/diskutil info "/dev/$TARGET" > "$INFO" 2>&1; then
    printf '%s\n' 'diskutil could not inspect the selected volume.' >&2
    /bin/cat "$INFO"
    exit 2
fi
/bin/cat "$INFO"
if ! /usr/bin/grep -Eq 'File System Personality:[[:space:]]*APFS|Type \(Bundle\):[[:space:]]*apfs' "$INFO"; then
    printf '%s\n' 'This does not appear to be an APFS volume. Refusing.' >&2
    exit 2
fi
if /usr/bin/grep -Eiq 'Volume Name:[[:space:]]*(USB|OPENCORE)([[:space:]]|$)' "$INFO"; then
    printf '%s\n' 'Refusing to operate on the diagnostic USB or EFI volume.' >&2
    exit 2
fi

printf '\n%s\n' "Listing APFS snapshots on $TARGET (read-only)."
/usr/sbin/diskutil apfs listSnapshots "/dev/$TARGET" \
    > "$OUT/snapshots-$TARGET.txt" 2>&1
/bin/cat "$OUT/snapshots-$TARGET.txt"

printf '\n%s\n' "Checking APFS volume $TARGET (verify only; no repairs yet)."
/usr/sbin/diskutil verifyVolume "/dev/$TARGET" > "$OUT/verify-$TARGET.txt" 2>&1
VERIFY_RESULT=$?
/bin/cat "$OUT/verify-$TARGET.txt"
printf 'verifyVolume exit code: %s\n' "$VERIFY_RESULT"

# Never automatically run repairVolume, even if verifyVolume failed.
if ! /usr/bin/grep -Eiq '(macOS Base System|OS X Base System|Recovery)' "$OUT/recovery-root-info.txt"; then
    printf '\n%s\n' 'Recovery environment not confirmed from the root volume.'
    printf '%s\n' 'Repair is disabled. Boot macOS Recovery before repairing.'
    exit 0
fi

printf '\n%s\n' 'WARNING: Repair can modify APFS metadata. Back up important data.'
printf '%s\n' 'Use Disk Utility First Aid first, particularly for the System/Data'
printf '%s\n' 'volume group, container and physical disk. Never erase the volume.'
printf '%s\n' 'To repair ONLY the selected APFS volume, type exactly:'
printf '  REPAIR %s\n' "$TARGET"
printf 'Or just press Enter to leave everything unchanged: '
IFS= read -r CONFIRM || CONFIRM=''
if [ "$CONFIRM" != "REPAIR $TARGET" ]; then
    printf '%s\n' 'Repair cancelled. Verification report remains on the USB.'
    exit 0
fi

printf '\n%s\n' "Running diskutil repairVolume /dev/$TARGET in macOS Recovery."
/usr/sbin/diskutil repairVolume "/dev/$TARGET" > "$OUT/repair-$TARGET.txt" 2>&1
REPAIR_RESULT=$?
/bin/cat "$OUT/repair-$TARGET.txt"
printf 'repairVolume exit code: %s\n' "$REPAIR_RESULT"
printf '%s\n' "Full report: $OUT"
if [ "$REPAIR_RESULT" -ne 0 ]; then
    printf '%s\n' 'Repair did not succeed. Keep the report and seek further help.'
fi
exit "$REPAIR_RESULT"
