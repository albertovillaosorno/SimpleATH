// Copyright:
//   - Copyright © 2026 laobamac. All rights reserved.
// SPDX-License-Identifier:
//   - LicenseRef-SimpleBCM-All-Rights-Reserved
// Confidential:
//   - false
// License-File:
//   - LICENSE-SIMPLEBCM
// Provenance:
//   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
//   - Originally authored by laobamac on 2026/11/1.
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for native skywalk.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for native skywalk.
// - Description:
//   - Implements or verifies the NativeSkywalk source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for native skywalk.

#ifndef SIMPLEATH_NATIVE_SKYWALK_HPP
#define SIMPLEATH_NATIVE_SKYWALK_HPP

#include "NativeProfile.hpp"
#include "Payload.hpp"
#include <IOKit/IOService.h>

namespace ath
{

    bool validateNativeSkywalk();
    bool prepareNativeSkywalk(LinkedImage *, size_t);
    void publishNativeSkywalk(IOService *);
    IOReturn nativeSkywalkUserClient(IOService *, task_t, void *, uint32_t,
                                     OSDictionary *, IOUserClient **);
    IOReturn createSkywalkUserClient(IOService *, task_t, void *, uint32_t,
                                     OSDictionary *, IOUserClient **);

} // namespace ath

#endif
