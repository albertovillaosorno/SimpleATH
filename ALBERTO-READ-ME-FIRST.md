# SimpleATH – experimental probe-only build

Forked with attribution from laobamac/SimpleBCM v1.2.0. Original NOTICE.md retained.

Xcode project, kext, C++ class, bundle identifier, module start/stop, diagnostic names and build scripts are renamed to SimpleATH. Source native ABI data/checksums are preserved unchanged. The Broadcom payload is disabled by default, because the hardware is Qualcomm Atheros AR9565 168c:0036. The kext probes the kernel only and publishes SimpleATHMode=AtherosProbeOnly, SimpleATHVendorID=0x168c, SimpleATHDeviceID=0x0036, SimpleATHDriverReady=false. It cannot yet scan or associate to Wi-Fi. The original Broadcom payload can be explicitly requested using -simpleathpayload but should NOT be enabled on this Dell; -simpleathoff disables the wrapper. A boot proves only safe service registration, not a functioning Atheros driver.

Compile with Xcode on macos-26-intel using GitHub Actions. Build scripts will fetch pinned MacKernelSDK and proprietary OCLP payload archives only during build.
