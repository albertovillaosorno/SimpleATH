//
//  NativeUserClient.hpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEATH_NATIVE_USER_CLIENT_HPP
#define SIMPLEATH_NATIVE_USER_CLIENT_HPP

#include <IOKit/IOUserClient.h>

namespace ath
{

    bool prepareNativeUserClients();
    IOReturn wrapNativeUserClient(IOReturn status, task_t task, void *token,
                                  uint32_t type, OSDictionary *properties,
                                  IOUserClient **result);

} // namespace ath

#endif
