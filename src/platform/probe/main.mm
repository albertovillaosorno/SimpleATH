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
//   - Originally authored by laobamac on 2026/9/29.
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for main.
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
//   - Native driver contracts and implementation for main.
// - Description:
//   - Implements or verifies the main source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for main.

#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <dispatch/dispatch.h>
#include <sys/sysctl.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        const bool scan = argc == 2 && strcmp(argv[1], "--scan") == 0;
        if (argc > 1 && !scan) {
            fprintf(stderr, "usage: athprobe [--scan]\n");
            return 2;
        }
        NSMutableDictionary *report = [NSMutableDictionary dictionary];
        char build[64] = {};
        size_t buildSize = sizeof(build);
        if (sysctlbyname("kern.osversion", build, &buildSize, nullptr, 0) == 0)
            report[@"build"] = @(build);
        io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("SimpleATH"));
        if (service) {
            CFMutableDictionaryRef properties = nullptr;
            const auto result = IORegistryEntryCreateCFProperties(service, &properties, kCFAllocatorDefault, 0);
            if (result == KERN_SUCCESS && properties)
                report[@"SimpleATH"] = CFBridgingRelease(properties);
            else
                report[@"registryError"] = @(result);
            IOObjectRelease(service);
        } else {
            report[@"SimpleATH"] = @"not present";
        }
        NSMutableArray *interfaces = [NSMutableArray array];
        NSMutableSet<NSString *> *wirelessNames = [NSMutableSet set];
        for (CWInterface *interface in [CWWiFiClient sharedWiFiClient].interfaces) {
            NSMutableDictionary *info = [NSMutableDictionary dictionary];
            info[@"name"] = interface.interfaceName ?: @"";
            if (interface.interfaceName)
                [wirelessNames addObject:interface.interfaceName];
            info[@"power"] = @(interface.powerOn);
            info[@"rssi"] = @(interface.rssiValue);
            info[@"noise"] = @(interface.noiseMeasurement);
            info[@"txRate"] = @(interface.transmitRate);
            info[@"mode"] = @(interface.interfaceMode);
            if (scan) {
                __block NSError *error = nil;
                __block NSSet<CWNetwork *> *networks = nil;
                auto completion = dispatch_semaphore_create(0);
                dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                    networks = [interface scanForNetworksWithName:nil error:&error];
                    dispatch_semaphore_signal(completion);
                });
                const auto timedOut = dispatch_semaphore_wait(completion,
                    dispatch_time(DISPATCH_TIME_NOW, 30LL * NSEC_PER_SEC)) != 0;
                info[@"scanTimedOut"] = @(timedOut);
                if (!timedOut) {
                    info[@"scanCompleted"] = @(networks != nil);
                    if (networks)
                        info[@"scanCount"] = @(networks.count);
                    if (error)
                        info[@"scanError"] = @{@"domain": error.domain, @"code": @(error.code)};
                }
            }
            [interfaces addObject:info];
        }
        report[@"interfaces"] = interfaces;
        NSMutableArray *systemInterfaces = [NSMutableArray array];
        NSArray *systemList = CFBridgingRelease(SCNetworkInterfaceCopyAll());
        for (id item in systemList) {
            auto interface = (__bridge SCNetworkInterfaceRef)item;
            NSString *name = (__bridge NSString *)SCNetworkInterfaceGetBSDName(interface);
            if (!name || ![wirelessNames containsObject:name])
                continue;
            [systemInterfaces addObject:@{
                @"name": name,
                @"type": (__bridge NSString *)SCNetworkInterfaceGetInterfaceType(interface) ?: @"",
                @"displayName": (__bridge NSString *)SCNetworkInterfaceGetLocalizedDisplayName(interface) ?: @""
            }];
        }
        report[@"systemInterfaces"] = systemInterfaces;
        auto store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("athprobe"), nullptr, nullptr);
        auto preferences = SCPreferencesCreate(kCFAllocatorDefault, CFSTR("athprobe"), nullptr);
        NSMutableArray *services = [NSMutableArray array];
        NSArray *serviceList = preferences ? CFBridgingRelease(SCNetworkServiceCopyAll(preferences)) : nil;
        for (id item in serviceList) {
            auto service = (__bridge SCNetworkServiceRef)item;
            auto interface = SCNetworkServiceGetInterface(service);
            NSString *name = interface ? (__bridge NSString *)SCNetworkInterfaceGetBSDName(interface) : nil;
            if (!name || ![wirelessNames containsObject:name])
                continue;
            NSString *identifier = (__bridge NSString *)SCNetworkServiceGetServiceID(service);
            if (!identifier)
                continue;
            NSMutableDictionary *info = [@{
                @"name": name,
                @"serviceID": identifier,
                @"type": (__bridge NSString *)SCNetworkInterfaceGetInterfaceType(interface) ?: @"",
                @"enabled": @(SCNetworkServiceGetEnabled(service))
            } mutableCopy];
            if (store) {
                for (NSString *protocol in @[@"IPv4", @"IPv6"]) {
                    NSString *key = [NSString stringWithFormat:@"State:/Network/Service/%@/%@", identifier, protocol];
                    NSDictionary *value = CFBridgingRelease(SCDynamicStoreCopyValue(store, (__bridge CFStringRef)key));
                    if ([value isKindOfClass:[NSDictionary class]]) {
                        NSMutableDictionary *state = [NSMutableDictionary dictionary];
                        for (NSString *field in @[@"Addresses", @"Router", @"SubnetMasks", @"InterfaceName"])
                            if (value[field])
                                state[field] = value[field];
                        info[protocol] = state;
                    }
                }
            }
            [services addObject:info];
        }
        report[@"networkServices"] = services;
        if (preferences)
            CFRelease(preferences);
        if (store)
            CFRelease(store);
        NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
        if (!data)
            return 1;
        fwrite(data.bytes, 1, data.length, stdout);
        fputc('\n', stdout);
        return 0;
    }
}
