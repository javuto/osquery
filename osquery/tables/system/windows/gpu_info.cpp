/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

namespace {

// Parse a PNPDeviceID like "PCI\VEN_10DE&DEV_1B81&SUBSYS_..." to extract the
// vendor and device (model) IDs.
void parsePnpDeviceId(const std::string& pnp_id,
                      std::string& vendor_id,
                      std::string& model_id) {
  vendor_id.clear();
  model_id.clear();

  // The PNPDeviceID is of the form: PCI\VEN_xxxx&DEV_xxxx&SUBSYS_...
  auto vpos = pnp_id.find("VEN_");
  if (vpos != std::string::npos) {
    auto start = vpos + 4;
    auto end = pnp_id.find('&', start);
    if (end != std::string::npos) {
      vendor_id = "0x" + pnp_id.substr(start, end - start);
    }
  }

  auto dpos = pnp_id.find("DEV_");
  if (dpos != std::string::npos) {
    auto start = dpos + 4;
    auto end = pnp_id.find('&', start);
    if (end != std::string::npos) {
      model_id = "0x" + pnp_id.substr(start, end - start);
    }
  }
}

} // namespace

QueryData genGpuInfo(QueryContext& context) {
  QueryData results;

  const auto wmiReq =
      WmiRequest::CreateWmiRequest("SELECT * FROM Win32_VideoController");
  if (!wmiReq || wmiReq->results().empty()) {
    LOG(WARNING) << "Failed to retrieve GPU information";
    return results;
  }

  std::int32_t device_id = 0;
  for (const auto& wmiResult : wmiReq->results()) {
    Row r;
    r["device_id"] = "GPU" + std::to_string(device_id++);

    std::string pnp_device_id;
    wmiResult.GetString("PNPDeviceID", pnp_device_id);

    std::string vendor_id;
    std::string model_id;
    parsePnpDeviceId(pnp_device_id, vendor_id, model_id);

    if (!vendor_id.empty()) {
      r["vendor_id"] = vendor_id;
    }
    if (!model_id.empty()) {
      r["model_id"] = model_id;
    }

    // pci_slot: use the PNPDeviceID location portion (e.g. PCI\VEN_...&BUS_...)
    if (!pnp_device_id.empty()) {
      r["pci_slot"] = pnp_device_id;
    }

    wmiResult.GetString("Name", r["name"]);
    wmiResult.GetString("AdapterCompatibility", r["vendor"]);
    wmiResult.GetString("VideoProcessor", r["model"]);
    wmiResult.GetString("InstalledDisplayDrivers", r["driver"]);

    // VRAM: AdapterRAM is a uint32 and wraps at 4 GB. Try the registry-backed
    // WMI property first; fall back to AdapterRAM.
    unsigned long long adapter_ram = 0;
    if (wmiResult.GetUnsignedLongLong("AdapterRAM", adapter_ram).ok() &&
        adapter_ram > 0) {
      r["vram"] = BIGINT(adapter_ram);
    } else {
      unsigned long ram = 0;
      if (wmiResult.GetUnsignedLong("AdapterRAM", ram).ok() && ram > 0) {
        r["vram"] = BIGINT(ram);
      }
    }

    r["pci_class_id"] = "0x030000";

    // Windows-specific extended schema columns.
    wmiResult.GetString("DriverVersion", r["driver_version"]);
    std::string cim_driver_date;
    wmiResult.GetString("DriverDate", cim_driver_date);
    if (!cim_driver_date.empty()) {
      r["driver_date"] = BIGINT(cimDatetimeToUnixtime(cim_driver_date));
    }

    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery