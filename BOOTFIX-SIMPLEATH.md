# SimpleATH Stage 1 boot isolation repair

The first 12.55MB SimpleATH kernel extension compiled but failed to reach the Tahoe desktop. The 18:45 OpenCore log confirms injection but does not confirm runtime startup.

## Source bug found

The original SimpleATH start() called bcm::Bridge::publish() and bcm::publishLoader() unconditionally even when the Broadcom payload was disabled. A timer repeatedly called both functions. The supposed AtherosProbeOnly mode did not isolate Broadcom.

## Fix

- Build just SimpleATH.cpp as a tiny IOResources kernel service with no Broadcom bridge or payload.
- Keep upstream Broadcom source separately for later Atheros adaptation, but do not link or execute it.
- Remove native wireless and special Apple driver dependencies from the boot probe. Four KPI library dependencies: iokit, libkern, mach, private.
- Provide an IORegistry diagnostic service called SimpleATH and a -simpleathoff fallback boot argument.
- Compile on an Intel Mac GitHub Actions runner with Xcode 26.6.
- Not yet Wi-Fi capable; this stage tests boot and kext loading.

The IOVersatile error text provided was timestamped 18:16 (legacy V4 attempt), not the later 18:45 SimpleATH attempt. Similar errors appear in unrelated Tahoe boot failures. Not proof of causality.

No Tahoe SSD changes. Keep the known-good 13-kext EFI for rollback.
