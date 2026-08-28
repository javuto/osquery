/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <AppKit/NSDocument.h>
#import <Foundation/Foundation.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/IOKitKeys.h>

#include <cstdio>
#include <iomanip>
#include <sstream>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/darwin/iokit_helpers.h>
#include <osquery/utils/darwin/system_profiler.h>

namespace osquery {
namespace tables {

namespace {

const char* kIOAcceleratorClassName = "IOAccelerator";

struct IOKitGpuInfo {
  std::string vendor_id;
  std::string model_id;
  std::string model;
  std::string driver;
  std::uint64_t vram = 0;
  std::uint32_t cores = 0;
  bool found = false;
};

std::string cfDataToHexString(CFDataRef data) {
  if (data == nullptr) {
    return {};
  }

  auto length = CFDataGetLength(data);
  if (length < 1) {
    return {};
  }

  const UInt8* bytes = CFDataGetBytePtr(data);
  std::stringstream ss;
  ss << "0x" << std::hex << std::setfill('0');
  // The vendor-id is stored little-endian; reverse for human-readable hex.
  for (CFIndex i = length - 1; i >= 0; --i) {
    ss << std::setw(2) << static_cast<int>(bytes[i]);
  }
  return ss.str();
}

std::uint64_t cfNumberToUint64(CFTypeRef value) {
  if (value == nullptr || CFGetTypeID(value) != CFNumberGetTypeID()) {
    return 0;
  }
  long long int n = 0;
  CFNumberGetValue(static_cast<CFNumberRef>(value), kCFNumberLongLongType, &n);
  return static_cast<std::uint64_t>(n);
}

// Enrich a row from the IOKit AGXAccelerator node matching the GPU model.
void enrichFromIOKit(const std::string& model_name, IOKitGpuInfo& info) {
  auto matching = IOServiceMatching(kIOAcceleratorClassName);
  if (matching == nullptr) {
    return;
  }

  io_iterator_t it = 0;
  auto kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &it);
  if (kr != KERN_SUCCESS) {
    return;
  }
  UniqueIoIterator it_ptr(it);

  io_service_t service = 0;
  while ((service = IOIteratorNext(it_ptr.get())) != 0) {
    UniqueIoService service_ptr(service);

    CFMutableDictionaryRef props = nullptr;
    kr = IORegistryEntryCreateCFProperties(
        service, &props, kCFAllocatorDefault, kNilOptions);
    if (kr != KERN_SUCCESS || props == nullptr) {
      continue;
    }
    UniqueCFMutableDictionaryRef props_ptr(props);

    // Match by model property.
    auto model_cf =
        static_cast<CFStringRef>(CFDictionaryGetValue(props, CFSTR("model")));
    if (model_cf == nullptr) {
      continue;
    }
    if (stringFromCFString(model_cf) != model_name) {
      continue;
    }

    info.found = true;

    // vendor-id: CFDataRef, 4 bytes, little-endian.
    auto vendor_id_data =
        static_cast<CFDataRef>(CFDictionaryGetValue(props, CFSTR("vendor-id")));
    if (vendor_id_data != nullptr &&
        CFGetTypeID(vendor_id_data) == CFDataGetTypeID()) {
      info.vendor_id = cfDataToHexString(vendor_id_data);
    }

    // driver: IOClass property.
    auto io_class =
        static_cast<CFStringRef>(CFDictionaryGetValue(props, CFSTR("IOClass")));
    if (io_class != nullptr) {
      info.driver = stringFromCFString(io_class);
    }

    // model_id: IONameMatched (e.g. "gpu,t6000") identifies the SoC GPU
    // variant. On Apple Silicon there is no PCI device-id; this is the closest
    // hardware identifier.
    auto name_matched = static_cast<CFStringRef>(
        CFDictionaryGetValue(props, CFSTR("IONameMatched")));
    if (name_matched != nullptr) {
      info.model_id = stringFromCFString(name_matched);
    }

    // cores: gpu-core-count (CFNumberRef).
    auto cores_cf = static_cast<CFTypeRef>(
        CFDictionaryGetValue(props, CFSTR("gpu-core-count")));
    if (cores_cf != nullptr) {
      info.cores = static_cast<std::uint32_t>(cfNumberToUint64(cores_cf));
    }

    // vram: PerformanceStatistics -> "Alloc system memory" (CFNumberRef).
    // On Apple Silicon the GPU uses unified memory; "Alloc system memory" is
    // the amount of system memory currently allocated to the GPU and is the
    // closest analog to dedicated VRAM.
    auto perf_stats = static_cast<CFDictionaryRef>(
        CFDictionaryGetValue(props, CFSTR("PerformanceStatistics")));
    if (perf_stats != nullptr) {
      auto alloc_mem = static_cast<CFTypeRef>(
          CFDictionaryGetValue(perf_stats, CFSTR("Alloc system memory")));
      if (alloc_mem != nullptr) {
        info.vram = cfNumberToUint64(alloc_mem);
      }
    }

    return;
  }
}

std::uint64_t vramBytesFromDict(NSDictionary* item) {
  id vram = [item valueForKey:@"spdisplays_vram"];
  if (vram == nil) {
    return 0;
  }

  if ([vram isKindOfClass:[NSNumber class]]) {
    return [vram unsignedLongLongValue];
  }

  NSString* vram_str = [vram description];
  std::string raw([vram_str UTF8String]);

  double multiplier = 0;
  if (raw.find("GB") != std::string::npos) {
    multiplier = 1024.0 * 1024.0 * 1024.0;
  } else if (raw.find("MB") != std::string::npos) {
    multiplier = 1024.0 * 1024.0;
  } else if (raw.find("KB") != std::string::npos) {
    multiplier = 1024.0;
  }

  if (multiplier == 0) {
    return 0;
  }

  try {
    return static_cast<std::uint64_t>(std::stod(raw) * multiplier);
  } catch (const std::exception&) {
    return 0;
  }
}

std::string stripPrefix(const std::string& str, const std::string& prefix) {
  if (str.find(prefix) == 0) {
    return str.substr(prefix.size());
  }
  return str;
}

} // namespace

QueryData genGpuInfo(QueryContext& context) {
  QueryData results;

  @autoreleasepool {
    NSDictionary* __autoreleasing result;
    Status status = getSystemProfilerReport("SPDisplaysDataType", result);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to get GPU information: " << status.getMessage();
      return results;
    }

    NSArray* items = [result objectForKey:@"_items"];
    if (items == nil) {
      return results;
    }

    std::int32_t device_id = 0;
    for (NSDictionary* item in items) {
      Row r;
      r["device_id"] = "GPU" + std::to_string(device_id++);

      std::string model_name;

      if (id name = [item valueForKey:@"_name"]) {
        r["name"] = SQL_TEXT([[name description] UTF8String]);
        model_name = r["name"];
      }

      if (id model = [item valueForKey:@"sppci_model"]) {
        if (r["name"].empty()) {
          r["name"] = SQL_TEXT([[model description] UTF8String]);
          model_name = r["name"];
        }
        r["model"] = SQL_TEXT([[model description] UTF8String]);
        if (model_name.empty()) {
          model_name = r["model"];
        }
      }

      if (id vendor = [item valueForKey:@"spdisplays_vendor"]) {
        std::string vendor_str([[vendor description] UTF8String]);
        r["vendor"] = SQL_TEXT(stripPrefix(vendor_str, "sppci_vendor_"));
      }

      if (id driver = [item valueForKey:@"spdisplays_driver"]) {
        r["driver"] = SQL_TEXT([[driver description] UTF8String]);
      }

      auto vram = vramBytesFromDict(item);
      if (vram > 0) {
        r["vram"] = BIGINT(vram);
      }

      if (id pci_slot = [item valueForKey:@"sppci_device_id"]) {
        r["pci_slot"] = SQL_TEXT([[pci_slot description] UTF8String]);
      } else if (id bus = [item valueForKey:@"sppci_bus"]) {
        std::string bus_str([[bus description] UTF8String]);
        if (bus_str != "spdisplays_builtin") {
          r["pci_slot"] = SQL_TEXT(bus_str);
        }
      }

      r["pci_class_id"] = "0x030000";

      // Enrich from IOKit AGXAccelerator for Apple Silicon (and discrete GPUs
      // that publish an IOAccelerator personality).
      if (!model_name.empty()) {
        IOKitGpuInfo iokit_info;
        enrichFromIOKit(model_name, iokit_info);
        if (iokit_info.found) {
          if (r["vendor_id"].empty()) {
            r["vendor_id"] = iokit_info.vendor_id;
          }
          if (r["model_id"].empty()) {
            r["model_id"] = iokit_info.model_id;
          }
          if (r["driver"].empty()) {
            r["driver"] = iokit_info.driver;
          }
          if (r["vram"].empty()) {
            r["vram"] = BIGINT(iokit_info.vram);
          }
          if (iokit_info.cores > 0) {
            r["cores"] = INTEGER(iokit_info.cores);
          }
        }
      }

      // metal_support from system_profiler.
      if (id metal = [item valueForKey:@"spdisplays_mtlgpufamilysupport"]) {
        r["metal_support"] =
            SQL_TEXT(stripPrefix([[metal description] UTF8String],
                                 "spdisplays_"));
      }

      results.push_back(r);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery