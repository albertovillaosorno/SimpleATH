//
//  NativeSkywalk.hpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

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
